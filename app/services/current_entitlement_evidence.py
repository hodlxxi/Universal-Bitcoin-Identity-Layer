"""Immutable contract for persisted current-entitlement evidence."""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from app.auth_api_core import canonical_xonly_pubkey
from app.services.action_authorization import IdentityClass

CONTRACT_VERSION = "hodlxxi.current_entitlement_evidence.v1"
MAX_VALIDITY = timedelta(seconds=900)
_LOWER_HEX_64 = re.compile(r"[0-9a-f]{64}").fullmatch


class InvalidCurrentEntitlementEvidence(ValueError):
    """Evidence is malformed or internally contradictory."""


def _bounded(value: object, maximum: int) -> str:
    if not isinstance(value, str) or not value or value.strip() != value or len(value) > maximum:
        raise InvalidCurrentEntitlementEvidence("invalid bounded string")
    return value


def _utc(value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise InvalidCurrentEntitlementEvidence("datetime must be timezone-aware")
    return value.astimezone(timezone.utc)


@dataclass(frozen=True)
class CurrentEntitlementEvidenceRecord:
    evidence_id: str
    contract_version: str
    subject_pubkey: str
    identity_class: IdentityClass
    current_full_relation_satisfied: bool
    evidence_source: str
    evidence_version: str
    source_evidence_sha256: str
    observed_at: datetime
    valid_until: datetime
    revoked_at: datetime | None
    created_at: datetime

    def __post_init__(self) -> None:
        try:
            if not isinstance(self.evidence_id, str) or str(uuid.UUID(self.evidence_id)) != self.evidence_id:
                raise InvalidCurrentEntitlementEvidence("invalid evidence id")
        except (ValueError, AttributeError, TypeError) as exc:
            raise InvalidCurrentEntitlementEvidence("invalid evidence id") from exc
        if self.contract_version != CONTRACT_VERSION:
            raise InvalidCurrentEntitlementEvidence("invalid contract version")
        try:
            if canonical_xonly_pubkey(self.subject_pubkey) != self.subject_pubkey:
                raise InvalidCurrentEntitlementEvidence("invalid subject")
        except (TypeError, ValueError) as exc:
            raise InvalidCurrentEntitlementEvidence("invalid subject") from exc
        if type(self.identity_class) is not IdentityClass or self.identity_class not in (
            IdentityClass.LIMITED,
            IdentityClass.FULL,
        ):
            raise InvalidCurrentEntitlementEvidence("invalid identity class")
        if type(self.current_full_relation_satisfied) is not bool:
            raise InvalidCurrentEntitlementEvidence("invalid relation flag")
        if (self.identity_class is IdentityClass.FULL) is not self.current_full_relation_satisfied:
            raise InvalidCurrentEntitlementEvidence("contradictory entitlement")
        _bounded(self.evidence_source, 128)
        _bounded(self.evidence_version, 64)
        if not isinstance(self.source_evidence_sha256, str) or _LOWER_HEX_64(self.source_evidence_sha256) is None:
            raise InvalidCurrentEntitlementEvidence("invalid source evidence hash")

        observed_at = _utc(self.observed_at)
        valid_until = _utc(self.valid_until)
        created_at = _utc(self.created_at)
        revoked_at = _utc(self.revoked_at) if self.revoked_at is not None else None
        if observed_at >= valid_until or valid_until - observed_at > MAX_VALIDITY:
            raise InvalidCurrentEntitlementEvidence("invalid validity window")
        if observed_at > created_at:
            raise InvalidCurrentEntitlementEvidence("invalid creation time")
        if revoked_at is not None and not observed_at <= revoked_at <= created_at:
            raise InvalidCurrentEntitlementEvidence("invalid revocation time")
        object.__setattr__(self, "observed_at", observed_at)
        object.__setattr__(self, "valid_until", valid_until)
        object.__setattr__(self, "created_at", created_at)
        object.__setattr__(self, "revoked_at", revoked_at)
