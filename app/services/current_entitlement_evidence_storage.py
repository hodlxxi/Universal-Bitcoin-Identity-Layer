"""Injected SQLAlchemy repository for current-entitlement evidence."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timezone

from sqlalchemy import func, select

from app.models import CurrentEntitlementEvidence, User
from app.services.action_authorization import IdentityClass
from app.services.current_entitlement import EntitlementDenied, require_active_persisted_user
from app.services.current_entitlement_evidence import CurrentEntitlementEvidenceRecord


class CurrentEntitlementEvidenceStorageError(RuntimeError):
    """Evidence persistence is unavailable or contains malformed state."""

    def __init__(self):
        super().__init__("current entitlement evidence storage unavailable")


@dataclass(frozen=True)
class CompleteLatestEntitlementPopulation:
    """Closed proof that one bounded authoritative population read completed."""

    records: tuple[CurrentEntitlementEvidenceRecord, ...]
    maximum: int
    active_subjects: tuple[str, ...] = ()
    complete: bool = field(default=True, init=False)

    def __post_init__(self):
        if (
            type(self.records) is not tuple
            or type(self.maximum) is not int
            or type(self.active_subjects) is not tuple
            or len(self.records) > self.maximum
            or len(self.active_subjects) > self.maximum
        ):
            raise ValueError("invalid complete population")
        previous = None
        for subject in self.active_subjects:
            if type(subject) is not str or (previous is not None and subject <= previous):
                raise ValueError("invalid complete population")
            try:
                require_active_persisted_user(subject, {"pubkey": subject, "is_active": True})
            except EntitlementDenied as exc:
                raise ValueError("invalid complete population") from exc
            previous = subject


def _record(row: CurrentEntitlementEvidence) -> CurrentEntitlementEvidenceRecord:
    def db_utc(value):
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    return CurrentEntitlementEvidenceRecord(
        evidence_id=row.evidence_id,
        contract_version=row.contract_version,
        subject_pubkey=row.subject_pubkey,
        identity_class=IdentityClass(row.identity_class),
        current_full_relation_satisfied=row.current_full_relation_satisfied,
        evidence_source=row.evidence_source,
        evidence_version=row.evidence_version,
        source_evidence_sha256=row.source_evidence_sha256,
        observed_at=db_utc(row.observed_at),
        valid_until=db_utc(row.valid_until),
        revoked_at=db_utc(row.revoked_at),
        created_at=db_utc(row.created_at),
    )


class SqlAlchemyCurrentEntitlementEvidenceRepository:
    """Append and retrieve evidence through a caller-provided session factory."""

    def __init__(self, session_factory):
        self._session_factory = session_factory

    def append(self, evidence: CurrentEntitlementEvidenceRecord) -> None:
        try:
            evidence = CurrentEntitlementEvidenceRecord(**vars(evidence))
            with self._session_factory() as session:
                values = vars(evidence).copy()
                values["identity_class"] = evidence.identity_class.value
                session.add(CurrentEntitlementEvidence(**values))
                session.commit()
        except Exception:
            raise CurrentEntitlementEvidenceStorageError() from None

    def get_latest(self, subject_pubkey: str) -> CurrentEntitlementEvidenceRecord | None:
        try:
            with self._session_factory() as session:
                row = (
                    session.query(CurrentEntitlementEvidence)
                    .filter(CurrentEntitlementEvidence.subject_pubkey == subject_pubkey)
                    .order_by(
                        CurrentEntitlementEvidence.observed_at.desc(),
                        CurrentEntitlementEvidence.created_at.desc(),
                        CurrentEntitlementEvidence.evidence_id.desc(),
                    )
                    .first()
                )
                return None if row is None else _record(row)
        except Exception:
            raise CurrentEntitlementEvidenceStorageError() from None

    def get_latest_population(self, maximum: int) -> CompleteLatestEntitlementPopulation:
        """Return one latest row for every subject, or fail if the bound is exceeded."""

        try:
            if type(maximum) is not int or maximum < 0:
                raise ValueError
            ranked = select(
                CurrentEntitlementEvidence.evidence_id.label("evidence_id"),
                func.row_number()
                .over(
                    partition_by=CurrentEntitlementEvidence.subject_pubkey,
                    order_by=(
                        CurrentEntitlementEvidence.observed_at.desc(),
                        CurrentEntitlementEvidence.created_at.desc(),
                        CurrentEntitlementEvidence.evidence_id.desc(),
                    ),
                )
                .label("rank"),
                func.count(CurrentEntitlementEvidence.evidence_id)
                .over(
                    partition_by=(
                        CurrentEntitlementEvidence.subject_pubkey,
                        CurrentEntitlementEvidence.observed_at,
                        CurrentEntitlementEvidence.created_at,
                    )
                )
                .label("logical_tie_count"),
            ).subquery()
            with self._session_factory() as session:
                transaction = session.begin()
                try:
                    rows = session.execute(
                        select(
                            CurrentEntitlementEvidence,
                            User.pubkey.label("user_pubkey"),
                            User.is_active.label("user_is_active"),
                            ranked.c.logical_tie_count,
                        )
                        .join(ranked, ranked.c.evidence_id == CurrentEntitlementEvidence.evidence_id)
                        .outerjoin(User, User.pubkey == CurrentEntitlementEvidence.subject_pubkey)
                        .where(ranked.c.rank == 1)
                        .order_by(CurrentEntitlementEvidence.subject_pubkey)
                        .limit(maximum + 1)
                    ).all()
                    if len(rows) > maximum:
                        raise CurrentEntitlementEvidenceStorageError()
                    result = []
                    active_subjects = []
                    for row, user_pubkey, user_is_active, logical_tie_count in rows:
                        if logical_tie_count != 1:
                            raise CurrentEntitlementEvidenceStorageError()
                        record = _record(row)
                        try:
                            active_subject = require_active_persisted_user(
                                record.subject_pubkey,
                                {"pubkey": user_pubkey, "is_active": user_is_active},
                            )
                        except EntitlementDenied:
                            active_subject = None
                        if active_subject is not None:
                            active_subjects.append(active_subject)
                        result.append(record)
                except Exception:
                    if transaction.is_active:
                        transaction.rollback()
                    raise
                if transaction.is_active:
                    transaction.rollback()
                return CompleteLatestEntitlementPopulation(tuple(result), maximum, tuple(active_subjects))
        except CurrentEntitlementEvidenceStorageError:
            raise
        except Exception:
            raise CurrentEntitlementEvidenceStorageError() from None
