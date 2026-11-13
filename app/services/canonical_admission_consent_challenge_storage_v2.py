"""Dormant PostgreSQL Canon V2 issued-challenge/one-use storage boundary.

No endpoints, grants, session authentication, or transaction commits are
installed. A trusted caller must explicitly begin and commit/rollback the
SQLAlchemy transaction. The caller still must verify active sponsor Full,
chain/reorg policy, authenticated sessions, and durable admission elsewhere.
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
    issue_canonical_admission_consent_challenge_v2,
    verify_canonical_admission_consent_signatures_v2,
)
from app.services.canonical_admission_proposal_v2 import (
    CanonicalAdmissionProposalV2,
    canonical_admission_proposal_v2_sha256,
    canonical_admission_proposal_v2_bytes,
)

RUNTIME_ENABLED = False
TABLE = "public.canonical_admission_consent_challenges_v2"

INSERT_SQL = """
INSERT INTO public.canonical_admission_consent_challenges_v2 (
    challenge_sha256, proposal_sha256, nonce_hex,
    sponsor_compressed_pubkey, child_compressed_pubkey,
    issuer_session_pubkey, issued_at, expires_at
) VALUES (
    :challenge_sha256, :proposal_sha256, :nonce_hex,
    :sponsor_compressed_pubkey, :child_compressed_pubkey,
    :issuer_session_pubkey, :issued_at, :expires_at
) RETURNING challenge_sha256
"""

LOCK_SQL = """
SELECT challenge_sha256, proposal_sha256, nonce_hex,
       sponsor_compressed_pubkey, child_compressed_pubkey,
       issuer_session_pubkey, issued_at, expires_at, consumed_at,
       verification_sha256
FROM public.canonical_admission_consent_challenges_v2
WHERE challenge_sha256 = :challenge_sha256
FOR UPDATE
"""

CONSUME_SQL = """
UPDATE public.canonical_admission_consent_challenges_v2
SET consumed_at = :consumed_at, verification_sha256 = :verification_sha256
WHERE challenge_sha256 = :challenge_sha256
  AND proposal_sha256 = :proposal_sha256
  AND nonce_hex = :nonce_hex
  AND issuer_session_pubkey = :issuer_session_pubkey
  AND sponsor_compressed_pubkey = :sponsor_compressed_pubkey
  AND child_compressed_pubkey = :child_compressed_pubkey
  AND issued_at <= :consumed_at
  AND expires_at > :consumed_at
  AND consumed_at IS NULL
  AND verification_sha256 IS NULL
RETURNING challenge_sha256
"""


class CanonicalAdmissionChallengeLedgerUnavailable(RuntimeError):
    """No authoritative transactionally verified issuance/consumption."""


class CanonicalAdmissionChallengeReplayV2(ValueError):
    """Challenge missing, already consumed, or invalid for the current request."""


@dataclass(frozen=True, slots=True)
class PendingIssuedChallengeV2:
    challenge: CanonicalAdmissionConsentChallengeV2
    challenge_sha256: str

    @property
    def durable(self) -> bool:
        """A caller-owned transaction still requires a successful commit."""
        return False

    @property
    def grants_full(self) -> bool:
        return False


@dataclass(frozen=True, slots=True)
class PendingConsumedChallengeV2:
    challenge_sha256: str
    verification_sha256: str
    verified: CanonicalAdmissionConsentVerificationV2

    @property
    def replay_protected(self) -> bool:
        """Only a caller-owned successful DB commit makes the update durable."""
        return False

    @property
    def grants_full(self) -> bool:
        return False


def _stamp(value: object) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise CanonicalAdmissionChallengeLedgerUnavailable("invalid_clock") from None
    value = value.astimezone(timezone.utc)
    if value.microsecond:
        raise CanonicalAdmissionChallengeLedgerUnavailable("clock_requires_seconds")
    return value


def _challenge_sha256(value: CanonicalAdmissionConsentChallengeV2) -> str:
    return hashlib.sha256(canonical_admission_consent_challenge_v2_bytes(value)).hexdigest()


def _verification_sha256(value: CanonicalAdmissionConsentVerificationV2) -> str:
    payload = {}
    for f in fields(CanonicalAdmissionConsentVerificationV2):
        item = getattr(value, f.name)
        payload[f.name] = item.isoformat().replace("+00:00", "Z") if f.name == "verified_at" else item
    data = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hashlib.sha256(data).hexdigest()


def _proposal(value: object) -> CanonicalAdmissionProposalV2:
    if type(value) is not CanonicalAdmissionProposalV2:
        raise CanonicalAdmissionChallengeReplayV2("proposal_type")
    try:
        canonical_admission_proposal_v2_bytes(value)
    except Exception:
        raise CanonicalAdmissionChallengeReplayV2("proposal_invalid") from None
    return value


class SqlAlchemyCanonicalAdmissionChallengeLedgerV2:
    """Owner-session-only, PostgreSQL-only proof boundary; NEVER commits.

    Reads the exact committed issued challenge under FOR UPDATE and
    calls the existing Bitcoin Core dual-signature verifier on those
    database-backed bytes, then atomically changes NULL -> consumed.
    A successful method return is only a *pending transaction effect*.
    """

    def __init__(self, session: Session, *, clock: Callable[[], datetime]) -> None:
        if not callable(clock):
            raise CanonicalAdmissionChallengeLedgerUnavailable("clock_required")
        if session is None or not callable(getattr(session, "execute", None)):
            raise CanonicalAdmissionChallengeLedgerUnavailable("session_required")
        self._session = session
        self._clock = clock

    def _transaction(self) -> None:
        try:
            if not self._session.in_transaction() or self._session.get_bind().dialect.name != "postgresql":
                raise CanonicalAdmissionChallengeLedgerUnavailable("postgres_transaction_required")
        except CanonicalAdmissionChallengeLedgerUnavailable:
            raise
        except Exception:
            raise CanonicalAdmissionChallengeLedgerUnavailable("postgres_transaction_required") from None

    def issue(
        self,
        proposal: CanonicalAdmissionProposalV2,
        *,
        authenticated_sponsor_pubkey: str,
    ) -> PendingIssuedChallengeV2:
        """A caller must independently authenticate the sponsor before calling.

        The key argument is NOT independently authenticated here. Persist
        inside the trusted caller's still-open transaction only.
        """
        self._transaction()
        proposal = _proposal(proposal)
        sponsor = proposal.script_evidence.sponsor_compressed_pubkey
        if type(authenticated_sponsor_pubkey) is not str or authenticated_sponsor_pubkey != sponsor:
            raise CanonicalAdmissionChallengeReplayV2("issuer_not_sponsor")
        challenge = issue_canonical_admission_consent_challenge_v2(proposal, now=_stamp(self._clock()))
        sha = _challenge_sha256(challenge)
        params = {
            "challenge_sha256": sha,
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
            raise CanonicalAdmissionChallengeLedgerUnavailable("challenge_insert_failed") from None
        if result != sha:
            raise CanonicalAdmissionChallengeLedgerUnavailable("challenge_insert_unconfirmed")
        return PendingIssuedChallengeV2(challenge, sha)

    def consume(
        self,
        proposal: CanonicalAdmissionProposalV2,
        *,
        challenge_sha256: str,
        authenticated_child_pubkey: str,
        sponsor_signature: str,
        child_signature: str,
        rpc: object,
    ) -> PendingConsumedChallengeV2:
        """Verify a DB-issued, unused challenge and reserve one consumption.

        Run in the caller's explicit SQLAlchemy transaction. A rejected
        attempt must result in caller rollback; no implicit commit or
        admission effect occurs.
        """
        self._transaction()
        proposal = _proposal(proposal)
        if (
            type(challenge_sha256) is not str
            or len(challenge_sha256) != 64
            or any(c not in "0123456789abcdef" for c in challenge_sha256)
        ):
            raise CanonicalAdmissionChallengeReplayV2("challenge_digest")
        child = proposal.script_evidence.child_compressed_pubkey
        if type(authenticated_child_pubkey) is not str or authenticated_child_pubkey != child:
            raise CanonicalAdmissionChallengeReplayV2("consumer_not_child")
        try:
            row = self._session.execute(text(LOCK_SQL), {"challenge_sha256": challenge_sha256}).mappings().one_or_none()
        except SQLAlchemyError:
            raise CanonicalAdmissionChallengeLedgerUnavailable("challenge_lock_failed") from None
        if row is None or row["consumed_at"] is not None or row["verification_sha256"] is not None:
            raise CanonicalAdmissionChallengeReplayV2("not_issued_or_already_consumed")
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
            raise CanonicalAdmissionChallengeLedgerUnavailable("stored_challenge_invalid") from None
        if (
            row["challenge_sha256"] != challenge_sha256
            or _challenge_sha256(challenge) != challenge_sha256
            or row["issuer_session_pubkey"] != challenge.sponsor_compressed_pubkey
            or challenge.proposal_sha256 != canonical_admission_proposal_v2_sha256(proposal)
        ):
            raise CanonicalAdmissionChallengeReplayV2("stored_challenge_binding")
        verification = verify_canonical_admission_consent_signatures_v2(
            proposal,
            challenge,
            sponsor_signature=sponsor_signature,
            child_signature=child_signature,
            rpc=rpc,
            now=_stamp(self._clock()),
        )
        verification_hash = _verification_sha256(verification)
        now = _stamp(self._clock())
        if not challenge.issued_at <= now < challenge.expires_at:
            raise CanonicalAdmissionChallengeReplayV2("expired_before_reservation")
        params = {
            "challenge_sha256": challenge_sha256,
            "proposal_sha256": challenge.proposal_sha256,
            "nonce_hex": challenge.nonce_hex,
            "issuer_session_pubkey": challenge.sponsor_compressed_pubkey,
            "sponsor_compressed_pubkey": challenge.sponsor_compressed_pubkey,
            "child_compressed_pubkey": challenge.child_compressed_pubkey,
            "consumed_at": now,
            "verification_sha256": verification_hash,
        }
        try:
            result = self._session.execute(text(CONSUME_SQL), params).scalar_one_or_none()
        except SQLAlchemyError:
            raise CanonicalAdmissionChallengeLedgerUnavailable("challenge_consumption_failed") from None
        if result != challenge_sha256:
            raise CanonicalAdmissionChallengeReplayV2("challenge_consumption_conflict")
        return PendingConsumedChallengeV2(challenge_sha256, verification_hash, verification)
