"""Read-only Bitcoin Signed Message consent proof for Canon V2 proposals.

The production browser login already uses Bitcoin Core verifymessage.
This module domain-separates sponsor and child intent over the *same*
immutable admission proposal, with an issued challenge nonce and expiry.

It does not issue or persist challenges, consume nonces, authenticate the
calling session, verify current sponsor Full, or confer admission rights.
A caller-constructed challenge is not proof of trustworthy issuance.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from app.services.canonical_admission_proposal_v2 import (
    CanonicalAdmissionProposalV2,
    canonical_admission_proposal_v2_sha256,
    canonical_admission_proposal_v2_bytes,
)
from app.utils import derive_legacy_address_from_pubkey

CHALLENGE_SCHEMA = "hodlxxi.canonical_admission_consent_challenge.v2"
VERIFICATION_SCHEMA = "hodlxxi.canonical_admission_consent_verification.v2"
DOMAIN = "HODLXXI/SponsoredAdmissionConsent/V2"
NETWORK = "bitcoin"
TTL_SECONDS = 300
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_KEY = re.compile(r"(?:02|03)[0-9a-f]{64}\Z")


class InvalidCanonicalAdmissionConsentV2(ValueError):
    """Invalid input, failed signer proof, or unusable challenge."""


class CanonicalAdmissionConsentVerifierUnavailable(RuntimeError):
    """A Bitcoin Core RPC verifier did not give an authoritative boolean."""


def _fail(reason: str) -> None:
    raise InvalidCanonicalAdmissionConsentV2(reason)


def _digest(value: object, name: str) -> None:
    if type(value) is not str or _HEX64.fullmatch(value) is None:
        _fail(name)


def _key(value: object, name: str) -> None:
    if type(value) is not str or _KEY.fullmatch(value) is None:
        _fail(name)


def _time(value: object, name: str) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        _fail(name)
    result = value.astimezone(timezone.utc)
    if result.microsecond != 0:
        _fail(name)
    return result


def _iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _proposal(value: object) -> CanonicalAdmissionProposalV2:
    if type(value) is not CanonicalAdmissionProposalV2:
        _fail("proposal_type")
    try:
        canonical_admission_proposal_v2_bytes(value)
    except Exception:
        _fail("proposal_invalid")
    return value


def _message_sig(value: object, field: str) -> str:
    """Accept only canonical standard-base64 65-byte compact BTC signatures."""
    if type(value) is not str or len(value) != 88:
        _fail(field)
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        _fail(field)
    if len(raw) != 65 or not 27 <= raw[0] <= 34 or base64.b64encode(raw).decode("ascii") != value:
        _fail(field)
    return value


@dataclass(frozen=True, slots=True)
class CanonicalAdmissionConsentChallengeV2:
    schema: str
    domain: str
    network: str
    proposal_sha256: str
    nonce_hex: str
    sponsor_compressed_pubkey: str
    child_compressed_pubkey: str
    issued_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        if self.schema != CHALLENGE_SCHEMA or self.domain != DOMAIN or self.network != NETWORK:
            _fail("challenge_domain_or_schema")
        _digest(self.proposal_sha256, "proposal_sha256")
        _digest(self.nonce_hex, "nonce_hex")
        _key(self.sponsor_compressed_pubkey, "sponsor_compressed_pubkey")
        _key(self.child_compressed_pubkey, "child_compressed_pubkey")
        if self.sponsor_compressed_pubkey == self.child_compressed_pubkey:
            _fail("same_participant")
        start = _time(self.issued_at, "issued_at")
        expiry = _time(self.expires_at, "expires_at")
        if not start < expiry <= start + timedelta(seconds=TTL_SECONDS):
            _fail("challenge_ttl")
        object.__setattr__(self, "issued_at", start)
        object.__setattr__(self, "expires_at", expiry)

    @property
    def is_trusted_issuance(self) -> bool:
        """No persistent issued-challenge authority is wired here."""
        return False


@dataclass(frozen=True, slots=True)
class CanonicalAdmissionConsentVerificationV2:
    schema: str
    proposal_sha256: str
    challenge_sha256: str
    sponsor_message_sha256: str
    child_message_sha256: str
    sponsor_signature_sha256: str
    child_signature_sha256: str
    verified_at: datetime

    def __post_init__(self) -> None:
        if self.schema != VERIFICATION_SCHEMA:
            _fail("verification_schema")
        for name in (
            "proposal_sha256",
            "challenge_sha256",
            "sponsor_message_sha256",
            "child_message_sha256",
            "sponsor_signature_sha256",
            "child_signature_sha256",
        ):
            _digest(getattr(self, name), name)
        object.__setattr__(self, "verified_at", _time(self.verified_at, "verified_at"))

    @property
    def grants_full(self) -> bool:
        return False

    @property
    def replay_protected(self) -> bool:
        """Must be backed by an atomically consumed server-issued nonce."""
        return False


def issue_canonical_admission_consent_challenge_v2(
    proposal: CanonicalAdmissionProposalV2, *, now: datetime
) -> CanonicalAdmissionConsentChallengeV2:
    """Generate a fresh 256-bit nonce, without persisting it or granting rights."""
    value = _proposal(proposal)
    timestamp = _time(now, "now")
    evidence = value.script_evidence
    return CanonicalAdmissionConsentChallengeV2(
        CHALLENGE_SCHEMA,
        DOMAIN,
        NETWORK,
        canonical_admission_proposal_v2_sha256(value),
        secrets.token_hex(32),
        evidence.sponsor_compressed_pubkey,
        evidence.child_compressed_pubkey,
        timestamp,
        timestamp + timedelta(seconds=TTL_SECONDS),
    )


def canonical_admission_consent_message_v2(
    challenge: CanonicalAdmissionConsentChallengeV2, *, role: str
) -> str:
    """The exact role-separated ASCII text to sign with Bitcoin signmessage."""
    if type(challenge) is not CanonicalAdmissionConsentChallengeV2:
        _fail("challenge_type")
    if role not in ("sponsor", "child") or type(role) is not str:
        _fail("role")
    signer = (
        challenge.sponsor_compressed_pubkey if role == "sponsor" else challenge.child_compressed_pubkey
    )
    counterparty = (
        challenge.child_compressed_pubkey if role == "sponsor" else challenge.sponsor_compressed_pubkey
    )
    return "\n".join(
        (
            DOMAIN,
            f"network={NETWORK}",
            f"proposal_sha256={challenge.proposal_sha256}",
            f"role={role}",
            f"signer_pubkey={signer}",
            f"counterparty_pubkey={counterparty}",
            f"nonce={challenge.nonce_hex}",
            f"issued_at={_iso(challenge.issued_at)}",
            f"expires_at={_iso(challenge.expires_at)}",
        )
    )


def canonical_admission_consent_challenge_v2_bytes(
    challenge: CanonicalAdmissionConsentChallengeV2,
) -> bytes:
    if type(challenge) is not CanonicalAdmissionConsentChallengeV2:
        _fail("challenge_type")
    value = CanonicalAdmissionConsentChallengeV2(
        challenge.schema,
        challenge.domain,
        challenge.network,
        challenge.proposal_sha256,
        challenge.nonce_hex,
        challenge.sponsor_compressed_pubkey,
        challenge.child_compressed_pubkey,
        challenge.issued_at,
        challenge.expires_at,
    )
    payload = {
        "schema": value.schema,
        "domain": value.domain,
        "network": value.network,
        "proposal_sha256": value.proposal_sha256,
        "nonce_hex": value.nonce_hex,
        "sponsor_compressed_pubkey": value.sponsor_compressed_pubkey,
        "child_compressed_pubkey": value.child_compressed_pubkey,
        "issued_at": _iso(value.issued_at),
        "expires_at": _iso(value.expires_at),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )


def verify_canonical_admission_consent_signatures_v2(
    proposal: CanonicalAdmissionProposalV2,
    challenge: CanonicalAdmissionConsentChallengeV2,
    *,
    sponsor_signature: str,
    child_signature: str,
    rpc: object,
    now: datetime,
) -> CanonicalAdmissionConsentVerificationV2:
    """Verify BOTH distinct Bitcoin Signed Message signatures through Bitcoin Core.

    The RPC result is authoritative ONLY for key possession of two
    challenge messages. It cannot establish that the nonce was genuinely
    issued by UBID, nor that the sponsor is Full, nor authorization to grant.
    """
    value = _proposal(proposal)
    if type(challenge) is not CanonicalAdmissionConsentChallengeV2:
        _fail("challenge_type")
    challenge = CanonicalAdmissionConsentChallengeV2(
        challenge.schema,
        challenge.domain,
        challenge.network,
        challenge.proposal_sha256,
        challenge.nonce_hex,
        challenge.sponsor_compressed_pubkey,
        challenge.child_compressed_pubkey,
        challenge.issued_at,
        challenge.expires_at,
    )
    current = _time(now, "now")
    evidence = value.script_evidence
    if (
        challenge.proposal_sha256 != canonical_admission_proposal_v2_sha256(value)
        or challenge.sponsor_compressed_pubkey != evidence.sponsor_compressed_pubkey
        or challenge.child_compressed_pubkey != evidence.child_compressed_pubkey
    ):
        _fail("challenge_proposal_or_identity_binding")
    if not challenge.issued_at <= current < challenge.expires_at:
        _fail("challenge_expired_or_not_issued")
    sponsor_signature = _message_sig(sponsor_signature, "sponsor_signature")
    child_signature = _message_sig(child_signature, "child_signature")
    if sponsor_signature == child_signature:
        _fail("indistinguishable_signatures")
    # Refuse the legacy utility's historical all-keys RIPEMD160 fallback.
    # A real Bitcoin P2PKH address requires functioning RIPEMD160.
    try:
        hashlib.new("ripemd160")
    except (ValueError, TypeError):
        raise CanonicalAdmissionConsentVerifierUnavailable("ripemd160_unavailable") from None
    method = getattr(rpc, "verifymessage", None)
    if not callable(method):
        raise CanonicalAdmissionConsentVerifierUnavailable("bitcoin_verifymessage_unavailable")
    sponsor_msg = canonical_admission_consent_message_v2(challenge, role="sponsor")
    child_msg = canonical_admission_consent_message_v2(challenge, role="child")
    checks = (
        (evidence.sponsor_compressed_pubkey, sponsor_signature, sponsor_msg, "sponsor_signature_invalid"),
        (evidence.child_compressed_pubkey, child_signature, child_msg, "child_signature_invalid"),
    )
    for pubkey, signature, message, reason in checks:
        try:
            # Bitcoin Core verifymessage requires the legacy P2PKH address
            # obtained from the same compressed key as the covenant script.
            address = derive_legacy_address_from_pubkey(pubkey)
            valid = method(address, signature, message)
        except Exception:
            raise CanonicalAdmissionConsentVerifierUnavailable("bitcoin_verifymessage_failed") from None
        if type(valid) is not bool:
            raise CanonicalAdmissionConsentVerifierUnavailable("bitcoin_verifymessage_not_boolean")
        if not valid:
            _fail(reason)
    return CanonicalAdmissionConsentVerificationV2(
        VERIFICATION_SCHEMA,
        challenge.proposal_sha256,
        hashlib.sha256(canonical_admission_consent_challenge_v2_bytes(challenge)).hexdigest(),
        hashlib.sha256(sponsor_msg.encode("ascii")).hexdigest(),
        hashlib.sha256(child_msg.encode("ascii")).hexdigest(),
        hashlib.sha256(sponsor_signature.encode("ascii")).hexdigest(),
        hashlib.sha256(child_signature.encode("ascii")).hexdigest(),
        current,
    )
