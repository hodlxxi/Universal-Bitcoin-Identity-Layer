"""Canonical content identity for transaction-bound current-Full state."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol

from app.auth_api_core import canonical_xonly_pubkey
from app.services.action_authorization import IdentityClass
from app.services.current_entitlement_evidence import CONTRACT_VERSION, CurrentEntitlementEvidenceRecord

SCHEMA = "hodlxxi.full_entitlement_proof.v1"
DOMAIN = "HODLXXI_FULL_ENTITLEMENT_V1"
VERSION = 1
PROOF_ID_PREFIX = "hodlxxi-full-entitlement-v1-sha256:"
UNAVAILABLE_MESSAGE = "current full entitlement proof unavailable"

_PROOF_ID = re.compile(r"hodlxxi-full-entitlement-v1-sha256:[0-9a-f]{64}\Z").fullmatch


class CurrentFullEntitlementProofUnavailable(RuntimeError):
    """Current-Full proof state is absent, invalid, or unavailable."""

    def __init__(self) -> None:
        super().__init__(UNAVAILABLE_MESSAGE)


@dataclass(frozen=True, slots=True)
class CurrentFullEntitlementProofState:
    """Exact authoritative rows observed by one transaction-bound reader."""

    user_id: str
    user_subject: str
    user_is_active: bool
    evidence: CurrentEntitlementEvidenceRecord


@dataclass(frozen=True, slots=True)
class VerifiedCurrentFullEntitlement:
    """Strict output trusted only when returned by an authority verifier."""

    proof_id: str
    subject: str
    valid_from: datetime
    expires_at: datetime


class TransactionBoundCurrentFullEntitlementVerifier(Protocol):
    """Structural contract for a verifier already bound to a caller transaction."""

    def verify_in_transaction(
        self,
        subject: str,
        *,
        now: datetime,
    ) -> VerifiedCurrentFullEntitlement: ...


def _utc_second(value: object) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError
    result = value.astimezone(timezone.utc)
    if result.microsecond:
        raise ValueError
    return result


def _timestamp(value: object) -> str:
    return _utc_second(value).isoformat(timespec="seconds").replace("+00:00", "Z")


def _subject(value: object) -> str:
    if type(value) is not str or canonical_xonly_pubkey(value) != value:
        raise ValueError
    return value


def _state(value: object) -> CurrentFullEntitlementProofState:
    if type(value) is not CurrentFullEntitlementProofState:
        raise ValueError
    if type(value.user_id) is not str or str(uuid.UUID(value.user_id)) != value.user_id:
        raise ValueError
    subject = _subject(value.user_subject)
    if value.user_is_active is not True or type(value.user_is_active) is not bool:
        raise ValueError
    if type(value.evidence) is not CurrentEntitlementEvidenceRecord:
        raise ValueError
    evidence = CurrentEntitlementEvidenceRecord(**vars(value.evidence))
    if (
        evidence.contract_version != CONTRACT_VERSION
        or evidence.subject_pubkey != subject
        or evidence.identity_class is not IdentityClass.FULL
        or evidence.current_full_relation_satisfied is not True
        or evidence.revoked_at is not None
    ):
        raise ValueError
    for timestamp in (evidence.observed_at, evidence.valid_until, evidence.created_at):
        _utc_second(timestamp)
    return CurrentFullEntitlementProofState(
        user_id=value.user_id,
        user_subject=subject,
        user_is_active=True,
        evidence=evidence,
    )


def canonical_full_entitlement_proof_preimage(value: object) -> bytes:
    """Return the exact compact ASCII state identity hashed for the proof ID."""

    try:
        state = _state(value)
        evidence = state.evidence
        payload = {
            "domain": DOMAIN,
            "proof": {
                "evidence": {
                    "contractVersion": evidence.contract_version,
                    "createdAt": _timestamp(evidence.created_at),
                    "currentFullRelationSatisfied": evidence.current_full_relation_satisfied,
                    "evidenceId": evidence.evidence_id,
                    "evidenceSource": evidence.evidence_source,
                    "evidenceVersion": evidence.evidence_version,
                    "identityClass": evidence.identity_class.value,
                    "observedAt": _timestamp(evidence.observed_at),
                    "revokedAt": None,
                    "sourceEvidenceSha256": evidence.source_evidence_sha256,
                    "subject": evidence.subject_pubkey,
                    "validUntil": _timestamp(evidence.valid_until),
                },
                "schema": SCHEMA,
                "user": {
                    "id": state.user_id,
                    "isActive": state.user_is_active,
                    "subject": state.user_subject,
                },
                "version": VERSION,
            },
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    except Exception:
        raise CurrentFullEntitlementProofUnavailable() from None


def produce_verified_current_full_entitlement(
    value: object,
    *,
    now: datetime,
) -> VerifiedCurrentFullEntitlement:
    """Produce a bounded proof identity from exact trusted transaction state."""

    try:
        state = _state(value)
        current_time = _utc_second(now)
        evidence = state.evidence
        if not evidence.observed_at <= current_time < evidence.valid_until:
            raise ValueError
        preimage = canonical_full_entitlement_proof_preimage(state)
        return VerifiedCurrentFullEntitlement(
            proof_id=PROOF_ID_PREFIX + hashlib.sha256(preimage).hexdigest(),
            subject=state.user_subject,
            valid_from=evidence.observed_at,
            expires_at=evidence.valid_until,
        )
    except CurrentFullEntitlementProofUnavailable:
        raise
    except Exception:
        raise CurrentFullEntitlementProofUnavailable() from None


def validate_verified_current_full_entitlement(
    value: object,
    *,
    subject: object,
    now: datetime,
) -> VerifiedCurrentFullEntitlement:
    """Validate a trusted producer result without treating its digest as authority."""

    try:
        if type(value) is not VerifiedCurrentFullEntitlement:
            raise ValueError
        expected_subject = _subject(subject)
        valid_from = _utc_second(value.valid_from)
        expires_at = _utc_second(value.expires_at)
        if (
            type(value.proof_id) is not str
            or _PROOF_ID(value.proof_id) is None
            or _subject(value.subject) != expected_subject
            or valid_from > _utc_second(now)
            or _utc_second(now) >= expires_at
        ):
            raise ValueError
        return VerifiedCurrentFullEntitlement(
            value.proof_id,
            expected_subject,
            valid_from,
            expires_at,
        )
    except Exception:
        raise CurrentFullEntitlementProofUnavailable() from None


__all__ = [
    "DOMAIN",
    "PROOF_ID_PREFIX",
    "SCHEMA",
    "UNAVAILABLE_MESSAGE",
    "VERSION",
    "CurrentFullEntitlementProofState",
    "CurrentFullEntitlementProofUnavailable",
    "TransactionBoundCurrentFullEntitlementVerifier",
    "VerifiedCurrentFullEntitlement",
    "canonical_full_entitlement_proof_preimage",
    "produce_verified_current_full_entitlement",
    "validate_verified_current_full_entitlement",
]
