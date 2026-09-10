"""Injected SQLAlchemy repository for current-entitlement evidence."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import timezone

from sqlalchemy import func, select

from app.models import CurrentEntitlementEvidence, User
from app.services.action_authorization import IdentityClass
from app.services.current_entitlement_evidence import CurrentEntitlementEvidenceRecord
from app.services.current_full_entitlement_proof import (
    CurrentFullEntitlementProofState,
    CurrentFullEntitlementProofUnavailable,
    produce_verified_current_full_entitlement,
)

_SUBJECT_LOCK_DOMAIN = b"HODLXXI_CURRENT_FULL_ENTITLEMENT_SUBJECT_LOCK_V1\x00"


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


def _signed_int32(value: bytes) -> int:
    return int.from_bytes(value, "big", signed=False) - (1 << 32) if value[0] & 0x80 else int.from_bytes(value, "big")


def _subject_lock_keys(subject_pubkey: str) -> tuple[int, int]:
    digest = hashlib.sha256(_SUBJECT_LOCK_DOMAIN + subject_pubkey.encode("ascii")).digest()
    return _signed_int32(digest[:4]), _signed_int32(digest[4:8])


def _lock_subject_for_evidence_change(session, subject_pubkey: str) -> None:
    """Conflict with a transaction-bound Current-Full read on PostgreSQL."""

    bind = session.get_bind()
    dialect = getattr(getattr(bind, "dialect", None), "name", None)
    if dialect == "sqlite":
        return
    if dialect != "postgresql":
        raise ValueError("unsupported current entitlement storage dialect")
    first, second = _subject_lock_keys(subject_pubkey)
    session.execute(select(func.pg_advisory_xact_lock(first, second)))


class SqlAlchemyTransactionBoundCurrentFullVerifier:
    """Verify and lock Current-Full through an already-active caller session."""

    def __init__(self, session):
        if (
            not callable(getattr(session, "execute", None))
            or not callable(getattr(session, "get_bind", None))
            or not callable(getattr(session, "in_transaction", None))
        ):
            raise ValueError("invalid transaction-bound current-Full session")
        self._session = session

    def verify_in_transaction(self, subject: str, *, now):
        try:
            bind = self._session.get_bind()
            if getattr(getattr(bind, "dialect", None), "name", None) != "postgresql":
                raise ValueError
            if self._session.in_transaction() is not True:
                raise ValueError

            _lock_subject_for_evidence_change(self._session, subject)
            users = (
                self._session.execute(select(User).where(User.pubkey == subject).limit(2).with_for_update())
                .scalars()
                .all()
            )
            if len(users) != 1:
                raise ValueError
            user = users[0]
            if user.pubkey != subject or user.is_active is not True:
                raise ValueError

            rows = (
                self._session.execute(
                    select(CurrentEntitlementEvidence)
                    .where(CurrentEntitlementEvidence.subject_pubkey == subject)
                    .order_by(
                        CurrentEntitlementEvidence.observed_at.desc(),
                        CurrentEntitlementEvidence.created_at.desc(),
                        CurrentEntitlementEvidence.evidence_id.desc(),
                    )
                    .limit(2)
                    .with_for_update()
                )
                .scalars()
                .all()
            )
            if not rows:
                raise ValueError
            latest = _record(rows[0])
            if (
                len(rows) == 2
                and rows[1].observed_at == rows[0].observed_at
                and rows[1].created_at == rows[0].created_at
            ):
                raise ValueError
            return produce_verified_current_full_entitlement(
                CurrentFullEntitlementProofState(
                    user_id=user.id,
                    user_subject=user.pubkey,
                    user_is_active=user.is_active,
                    evidence=latest,
                ),
                now=now,
            )
        except CurrentFullEntitlementProofUnavailable:
            raise CurrentEntitlementEvidenceStorageError() from None
        except Exception:
            raise CurrentEntitlementEvidenceStorageError() from None


class SqlAlchemyCurrentEntitlementEvidenceRepository:
    """Append and retrieve evidence through a caller-provided session factory."""

    def __init__(self, session_factory):
        self._session_factory = session_factory

    def append(self, evidence: CurrentEntitlementEvidenceRecord) -> None:
        try:
            evidence = CurrentEntitlementEvidenceRecord(**vars(evidence))
            with self._session_factory() as session:
                _lock_subject_for_evidence_change(session, evidence.subject_pubkey)
                values = vars(evidence).copy()
                values["identity_class"] = evidence.identity_class.value
                session.add(CurrentEntitlementEvidence(**values))
                session.commit()
        except Exception:
            raise CurrentEntitlementEvidenceStorageError() from None

    def append_pair(
        self,
        evidence_pair: tuple[
            CurrentEntitlementEvidenceRecord,
            CurrentEntitlementEvidenceRecord,
        ],
    ) -> None:
        """Append exactly two synchronized subject records atomically."""

        session = None
        try:
            if type(evidence_pair) is not tuple or len(evidence_pair) != 2:
                raise ValueError()

            first, second = tuple(CurrentEntitlementEvidenceRecord(**vars(item)) for item in evidence_pair)

            if (
                first.evidence_id == second.evidence_id
                or first.subject_pubkey == second.subject_pubkey
                or first.observed_at != second.observed_at
                or first.valid_until != second.valid_until
                or first.created_at != second.created_at
            ):
                raise ValueError()

            rows = []
            for evidence in (first, second):
                values = vars(evidence).copy()
                values["identity_class"] = evidence.identity_class.value
                rows.append(CurrentEntitlementEvidence(**values))

            session = self._session_factory()
            for subject in sorted((first.subject_pubkey, second.subject_pubkey)):
                _lock_subject_for_evidence_change(session, subject)
            session.add_all(rows)
            session.commit()

        except (KeyboardInterrupt, SystemExit):
            if session is not None:
                try:
                    session.rollback()
                except BaseException:
                    pass
            raise

        except Exception:
            if session is not None:
                try:
                    session.rollback()
                except Exception:
                    pass
            raise CurrentEntitlementEvidenceStorageError() from None

        finally:
            if session is not None:
                session.close()

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
                            ranked.c.logical_tie_count,
                        )
                        .join(ranked, ranked.c.evidence_id == CurrentEntitlementEvidence.evidence_id)
                        .where(ranked.c.rank == 1)
                        .order_by(CurrentEntitlementEvidence.subject_pubkey)
                        .limit(maximum + 1)
                    ).all()
                    if len(rows) > maximum:
                        raise CurrentEntitlementEvidenceStorageError()
                    result = []
                    for row, logical_tie_count in rows:
                        if logical_tie_count != 1:
                            raise CurrentEntitlementEvidenceStorageError()
                        result.append(_record(row))
                except Exception:
                    if transaction.is_active:
                        transaction.rollback()
                    raise
                if transaction.is_active:
                    transaction.rollback()
                return CompleteLatestEntitlementPopulation(
                    tuple(result),
                    maximum,
                    tuple(record.subject_pubkey for record in result),
                )
        except CurrentEntitlementEvidenceStorageError:
            raise
        except Exception:
            raise CurrentEntitlementEvidenceStorageError() from None
