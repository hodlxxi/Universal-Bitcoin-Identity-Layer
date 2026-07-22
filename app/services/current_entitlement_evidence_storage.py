"""Injected SQLAlchemy repository for current-entitlement evidence."""

from __future__ import annotations

from datetime import timezone

from app.models import CurrentEntitlementEvidence
from app.services.action_authorization import IdentityClass
from app.services.current_entitlement_evidence import CurrentEntitlementEvidenceRecord


class CurrentEntitlementEvidenceStorageError(RuntimeError):
    """Evidence persistence is unavailable or contains malformed state."""

    def __init__(self):
        super().__init__("current entitlement evidence storage unavailable")


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
