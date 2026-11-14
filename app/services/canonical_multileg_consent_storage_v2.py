"""Dormant PostgreSQL-issued, exactly-once multileg consent v2.

Different schema and table from the historical exactly-two-outpoint V2
ledger. This service does not grant Full, authenticate browser sessions,
admit a participant or commit a SQLAlchemy transaction. The caller must
authenticate participants and commit/rollback the whole transaction.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, fields
from datetime import datetime, timezone
from typing import Callable

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.services.canonical_admission_consent_v2 import (
    CHALLENGE_SCHEMA,
    DOMAIN,
    NETWORK,
    CanonicalAdmissionConsentChallengeV2,
    CanonicalAdmissionConsentVerificationV2,
    canonical_admission_consent_challenge_v2_bytes,
)
from app.services.canonical_multi_outpoint_admission_proposal_v2 import (
    SCHEMA as PROPOSAL_SCHEMA,
    CanonicalMultiOutpointAdmissionProposalV2,
    canonical_multi_outpoint_admission_proposal_v2_bytes,
    canonical_multi_outpoint_admission_proposal_v2_sha256,
    issue_multi_outpoint_admission_challenge_v2,
    verify_multi_outpoint_admission_signatures_v2,
)

RUNTIME_ENABLED = False

INSERT_SQL = """
INSERT INTO public.canonical_multileg_consent_challenges_v2 (
    challenge_sha256, proposal_schema, proposal_sha256, nonce_hex,
    sponsor_compressed_pubkey, child_compressed_pubkey, issuer_session_pubkey,
    issued_at, expires_at
) VALUES (
    :challenge_sha256, :proposal_schema, :proposal_sha256, :nonce_hex,
    :sponsor_compressed_pubkey, :child_compressed_pubkey, :issuer_session_pubkey,
    :issued_at, :expires_at
) RETURNING challenge_sha256
"""

LOCK_SQL = """
SELECT challenge_sha256, proposal_schema, proposal_sha256, nonce_hex,
    sponsor_compressed_pubkey, child_compressed_pubkey, issuer_session_pubkey,
    issued_at, expires_at, consumed_at, verification_sha256
FROM public.canonical_multileg_consent_challenges_v2
WHERE challenge_sha256 = :challenge_sha256
FOR UPDATE
"""

CONSUME_SQL = """
UPDATE public.canonical_multileg_consent_challenges_v2
SET consumed_at = :consumed_at, verification_sha256 = :verification_sha256
WHERE challenge_sha256 = :challenge_sha256
    AND proposal_schema = :proposal_schema
    AND proposal_sha256 = :proposal_sha256
    AND nonce_hex = :nonce_hex
    AND sponsor_compressed_pubkey = :sponsor_compressed_pubkey
    AND child_compressed_pubkey = :child_compressed_pubkey
    AND issuer_session_pubkey = :sponsor_compressed_pubkey
    AND issued_at <= :consumed_at
    AND expires_at > :consumed_at
    AND consumed_at IS NULL
    AND verification_sha256 IS NULL
RETURNING challenge_sha256
"""


class MultiLegConsentLedgerUnavailableV2(RuntimeError):
    """Cannot establish the trusted database transaction or verifier."""


class MultiLegConsentReplayV2(ValueError):
    """Challenge was not issued, already consumed, expired or misbound."""


@dataclass(frozen=True, slots=True)
class PendingMultiLegChallengeV2:
    challenge: CanonicalAdmissionConsentChallengeV2
    challenge_sha256: str

    @property
    def durable(self) -> bool:
        return False

    @property
    def grants_full(self) -> bool:
        return False


@dataclass(frozen=True, slots=True)
class PendingMultiLegConsumptionV2:
    challenge_sha256: str
    verification_sha256: str
    verification: CanonicalAdmissionConsentVerificationV2

    @property
    def replay_protected(self) -> bool:
        return False

    @property
    def grants_full(self) -> bool:
        return False

    @property
    def is_effective(self) -> bool:
        return False


def _timestamp(value: object) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise MultiLegConsentLedgerUnavailableV2("valid_clock_required")
    value = value.astimezone(timezone.utc)
    if value.microsecond:
        raise MultiLegConsentLedgerUnavailableV2("second_precision_clock_required")
    return value


def _proposal(value: object) -> CanonicalMultiOutpointAdmissionProposalV2:
    if type(value) is not CanonicalMultiOutpointAdmissionProposalV2:
        raise MultiLegConsentReplayV2("multileg_proposal_type_required")
    try:
        canonical_multi_outpoint_admission_proposal_v2_bytes(value)
    except Exception:
        raise MultiLegConsentReplayV2("multileg_proposal_invalid") from None
    return value


def _digest(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _challenge_digest(value: CanonicalAdmissionConsentChallengeV2) -> str:
    return hashlib.sha256(canonical_admission_consent_challenge_v2_bytes(value)).hexdigest()


def _verification_digest(value: CanonicalAdmissionConsentVerificationV2) -> str:
    data = {
        field.name: (
            getattr(value, field.name).isoformat().replace("+00:00", "Z")
            if field.name == "verified_at"
            else getattr(value, field.name)
        )
        for field in fields(CanonicalAdmissionConsentVerificationV2)
    }
    return hashlib.sha256(
        json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    ).hexdigest()


class SqlAlchemyMultiLegConsentLedgerV2:
    """Caller-owned PostgreSQL transaction, no implicit commit or Full grant."""

    def __init__(self, session: Session, *, clock: Callable[[], datetime]) -> None:
        if (
            session is None
            or not callable(getattr(session, "execute", None))
            or not callable(clock)
        ):
            raise MultiLegConsentLedgerUnavailableV2("session_and_clock_required")
        self._session = session
        self._clock = clock

    def _transaction(self) -> None:
        try:
            if (
                not self._session.in_transaction()
                or self._session.get_bind().dialect.name != "postgresql"
                or self._session.get_transaction() is None
                or not self._session.get_transaction().is_active
            ):
                raise MultiLegConsentLedgerUnavailableV2("postgres_transaction_required")
        except MultiLegConsentLedgerUnavailableV2:
            raise
        except Exception:
            raise MultiLegConsentLedgerUnavailableV2("postgres_transaction_required") from None

    def issue(
        self,
        proposal: CanonicalMultiOutpointAdmissionProposalV2,
        *,
        authenticated_sponsor_pubkey: str,
    ) -> PendingMultiLegChallengeV2:
        """Store issued challenge, but no independent authentication or commit."""
        self._transaction()
        verified = _proposal(proposal)
        sponsor = verified.mirror.script_evidence.sponsor_compressed_pubkey
        if type(authenticated_sponsor_pubkey) is not str or authenticated_sponsor_pubkey != sponsor:
            raise MultiLegConsentReplayV2("issuer_not_sponsor")
        challenge = issue_multi_outpoint_admission_challenge_v2(
            verified, now=_timestamp(self._clock())
        )
        sha = _challenge_digest(challenge)
        params = {
            "challenge_sha256": sha,
            "proposal_schema": PROPOSAL_SCHEMA,
            "proposal_sha256": challenge.proposal_sha256,
            "nonce_hex": challenge.nonce_hex,
            "sponsor_compressed_pubkey": challenge.sponsor_compressed_pubkey,
            "child_compressed_pubkey": challenge.child_compressed_pubkey,
            "issuer_session_pubkey": authenticated_sponsor_pubkey,
            "issued_at": challenge.issued_at,
            "expires_at": challenge.expires_at,
        }
        try:
            result = self._session.execute(text(INSERT_SQL), params).scalar_one_or_none()
        except SQLAlchemyError:
            raise MultiLegConsentLedgerUnavailableV2("challenge_insert_failed") from None
        if result != sha:
            raise MultiLegConsentLedgerUnavailableV2("challenge_insert_unconfirmed")
        return PendingMultiLegChallengeV2(challenge, sha)

    def consume(
        self,
        proposal: CanonicalMultiOutpointAdmissionProposalV2,
        *,
        challenge_sha256: str,
        authenticated_child_pubkey: str,
        sponsor_signature: str,
        child_signature: str,
        rpc: object,
    ) -> PendingMultiLegConsumptionV2:
        """Lock DB-issued nonce, check two signatures and CAS NULL→consumed."""
        self._transaction()
        verified = _proposal(proposal)
        if not _digest(challenge_sha256):
            raise MultiLegConsentReplayV2("challenge_digest")
        child = verified.mirror.script_evidence.child_compressed_pubkey
        if type(authenticated_child_pubkey) is not str or authenticated_child_pubkey != child:
            raise MultiLegConsentReplayV2("consumer_not_child")
        try:
            row = self._session.execute(
                text(LOCK_SQL), {"challenge_sha256": challenge_sha256}
            ).mappings().one_or_none()
        except SQLAlchemyError:
            raise MultiLegConsentLedgerUnavailableV2("challenge_lock_failed") from None
        if row is None or row["consumed_at"] is not None or row["verification_sha256"] is not None:
            raise MultiLegConsentReplayV2("missing_or_already_consumed")
        if row["proposal_schema"] != PROPOSAL_SCHEMA:
            raise MultiLegConsentReplayV2("wrong_proposal_schema")
        try:
            challenge = CanonicalAdmissionConsentChallengeV2(
                CHALLENGE_SCHEMA,
                DOMAIN,
                NETWORK,
                row["proposal_sha256"],
                row["nonce_hex"],
                row["sponsor_compressed_pubkey"],
                row["child_compressed_pubkey"],
                row["issued_at"],
                row["expires_at"],
            )
        except Exception:
            raise MultiLegConsentLedgerUnavailableV2("stored_challenge_invalid") from None
        if (
            row["challenge_sha256"] != challenge_sha256
            or _challenge_digest(challenge) != challenge_sha256
            or row["issuer_session_pubkey"] != challenge.sponsor_compressed_pubkey
            or challenge.proposal_sha256 != canonical_multi_outpoint_admission_proposal_v2_sha256(verified)
        ):
            raise MultiLegConsentReplayV2("stored_proposal_or_issuer_binding")
        # This verifies all UTXOs via exact SHA commitment signed by BOTH keys.
        receipt = verify_multi_outpoint_admission_signatures_v2(
            verified,
            challenge,
            sponsor_signature=sponsor_signature,
            child_signature=child_signature,
            rpc=rpc,
            now=_timestamp(self._clock()),
        )
        verification_sha = _verification_digest(receipt)
        at = _timestamp(self._clock())
        if not challenge.issued_at <= at < challenge.expires_at:
            raise MultiLegConsentReplayV2("expired_before_consumption")
        params = {
            "challenge_sha256": challenge_sha256,
            "proposal_schema": PROPOSAL_SCHEMA,
            "proposal_sha256": challenge.proposal_sha256,
            "nonce_hex": challenge.nonce_hex,
            "sponsor_compressed_pubkey": challenge.sponsor_compressed_pubkey,
            "child_compressed_pubkey": challenge.child_compressed_pubkey,
            "consumed_at": at,
            "verification_sha256": verification_sha,
        }
        try:
            updated = self._session.execute(
                text(CONSUME_SQL), params
            ).scalar_one_or_none()
        except SQLAlchemyError:
            raise MultiLegConsentLedgerUnavailableV2("challenge_consume_failed") from None
        if updated != challenge_sha256:
            raise MultiLegConsentReplayV2("one_use_consumption_conflict")
        return PendingMultiLegConsumptionV2(
            challenge_sha256, verification_sha, receipt
        )
