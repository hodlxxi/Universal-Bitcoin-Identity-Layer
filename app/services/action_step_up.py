"""Canonical, endpoint-independent action step-up proof contract."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Callable, Protocol

from coincurve import PublicKeyXOnly

from app.auth_api_core import canonical_xonly_pubkey
from app.services.action_authorization import ACTION_REQUIREMENTS, ActionName

CHALLENGE_SCHEMA = "hodlxxi.action-step-up.challenge.v1"
PROOF_SCHEMA = "hodlxxi.action-step-up.proof.v1"
VERIFICATION_SCHEMA = "hodlxxi.action-step-up.verification.v1"
SIGNATURE_DOMAIN = "HODLXXI_ACTION_STEP_UP_V1"
SIGNATURE_FORMAT = "bip340_schnorr_sha256"
EVIDENCE_SOURCE = "durable_single_use_bip340"

DEFAULT_CHALLENGE_LIFETIME_SECONDS = 300
MAX_CHALLENGE_LIFETIME_SECONDS = 600
MAX_CLOCK_SKEW_SECONDS = 60
MAX_CLIENT_ID_LENGTH = 256
MAX_TOKEN_JTI_LENGTH = 128
MAX_RESOURCE_ID_LENGTH = 256
NONCE_BYTES = 32

_LOWER_HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
_LOWER_HEX_128 = re.compile(r"[0-9a-f]{128}\Z")
_SAFE_ID = re.compile(r"[^\x00-\x1f\x7f]+\Z")


class StepUpReason(str, Enum):
    VERIFIED = "verified"
    INVALID_REQUEST = "invalid_request"
    INVALID_ACTOR = "invalid_actor"
    UNKNOWN_ACTION = "unknown_action"
    STEP_UP_NOT_REQUIRED = "step_up_not_required"
    CHALLENGE_NOT_FOUND = "challenge_not_found"
    CHALLENGE_EXPIRED = "challenge_expired"
    CHALLENGE_CONSUMED = "challenge_consumed"
    BINDING_MISMATCH = "binding_mismatch"
    INVALID_SIGNATURE = "invalid_signature"
    STORAGE_UNAVAILABLE = "storage_unavailable"


class StepUpError(ValueError):
    def __init__(self, reason: StepUpReason):
        super().__init__(reason.value)
        self.reason = reason


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone-aware datetime required")
    return value.astimezone(timezone.utc)


def _timestamp(value: datetime) -> str:
    return _utc(value).isoformat(timespec="seconds").replace("+00:00", "Z")


def _bounded_identifier(value: object, maximum: int, *, optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError("invalid identifier")
    if value.strip() != value or _SAFE_ID.fullmatch(value) is None:
        raise ValueError("invalid identifier")
    return value


def _canonical_actor(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("invalid actor")
    actor = canonical_xonly_pubkey(value)
    if value != actor or _LOWER_HEX_64.fullmatch(actor) is None:
        raise ValueError("noncanonical actor")
    # PublicKeyXOnly also rejects x coordinates that are not curve points.
    PublicKeyXOnly(bytes.fromhex(actor))
    return actor


def _canonical_challenge_id(value: object) -> str:
    if not isinstance(value, str) or len(value) != 32:
        raise ValueError("invalid challenge identifier")
    parsed = uuid.UUID(hex=value)
    if parsed.hex != value:
        raise ValueError("noncanonical challenge identifier")
    return value


def _action(value: object, *, require_step_up: bool) -> ActionName:
    try:
        action = ActionName(value)
    except (TypeError, ValueError) as exc:
        raise StepUpError(StepUpReason.UNKNOWN_ACTION) from exc
    if require_step_up and ACTION_REQUIREMENTS[action].step_up_required is not True:
        raise StepUpError(StepUpReason.STEP_UP_NOT_REQUIRED)
    return action


@dataclass(frozen=True)
class StepUpChallenge:
    schema: str
    challenge_id: str
    actor_pubkey: str
    oauth_client_id: str
    token_jti: str
    action: str
    resource_id: str | None
    request_sha256: str
    nonce: str
    issued_at: datetime
    expires_at: datetime
    signature_domain: str
    consumed_at: datetime | None = None

    def to_dict(self) -> dict[str, object]:
        """Return the bounded public challenge; consumption is repository state."""
        return {
            "schema": self.schema,
            "challenge_id": self.challenge_id,
            "actor_pubkey": self.actor_pubkey,
            "oauth_client_id": self.oauth_client_id,
            "token_jti": self.token_jti,
            "action": self.action,
            "resource_id": self.resource_id,
            "request_sha256": self.request_sha256,
            "nonce": self.nonce,
            "issued_at": _timestamp(self.issued_at),
            "expires_at": _timestamp(self.expires_at),
            "signature_domain": self.signature_domain,
        }


@dataclass(frozen=True)
class StepUpProof:
    schema: str
    challenge_id: str
    signature: str | bytes
    signature_format: str

    def to_dict(self) -> dict[str, str]:
        signature = self.signature.hex() if isinstance(self.signature, bytes) else self.signature
        return {
            "schema": self.schema,
            "challenge_id": self.challenge_id,
            "signature": signature,
            "signature_format": self.signature_format,
        }


@dataclass(frozen=True)
class VerifiedStepUp:
    verified: bool
    reason_code: StepUpReason
    challenge_id: str | None = None
    actor_pubkey: str | None = None
    oauth_client_id: str | None = None
    token_jti: str | None = None
    action: str | None = None
    resource_id: str | None = None
    request_sha256: str | None = None
    issued_at: datetime | None = None
    expires_at: datetime | None = None
    verified_at: datetime | None = None
    consumed_at: datetime | None = None
    verification_schema: str = VERIFICATION_SCHEMA
    evidence_source: str = EVIDENCE_SOURCE
    evidence_version: str = "v1"

    def to_dict(self) -> dict[str, object]:
        return {
            "verified": self.verified,
            "reason_code": self.reason_code.value,
            "verification_schema": self.verification_schema,
            "challenge_id": self.challenge_id,
            "actor_pubkey": self.actor_pubkey,
            "oauth_client_id": self.oauth_client_id,
            "token_jti": self.token_jti,
            "action": self.action,
            "resource_id": self.resource_id,
            "request_sha256": self.request_sha256,
            "issued_at": _timestamp(self.issued_at) if self.issued_at else None,
            "expires_at": _timestamp(self.expires_at) if self.expires_at else None,
            "verified_at": _timestamp(self.verified_at) if self.verified_at else None,
            "consumed_at": _timestamp(self.consumed_at) if self.consumed_at else None,
            "evidence_source": self.evidence_source,
            "evidence_version": self.evidence_version,
        }


class ChallengeRepository(Protocol):
    def create(self, challenge: StepUpChallenge) -> None: ...
    def get(self, challenge_id: str) -> StepUpChallenge | None: ...
    def consume(self, challenge: StepUpChallenge, consumed_at: datetime) -> bool: ...


def canonical_signed_bytes(challenge: StepUpChallenge) -> bytes:
    """Canonical domain-separated bytes whose SHA-256 digest is BIP-340 signed."""
    envelope = {"domain": SIGNATURE_DOMAIN, "challenge": challenge.to_dict()}
    return json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def parse_step_up_proof(payload: object) -> StepUpProof:
    """Parse an exact proof object with syntax ceilings before verification."""
    if not isinstance(payload, dict) or set(payload) != {"schema", "challenge_id", "signature", "signature_format"}:
        raise StepUpError(StepUpReason.INVALID_REQUEST)
    schema = payload.get("schema")
    challenge_id = payload.get("challenge_id")
    signature = payload.get("signature")
    signature_format = payload.get("signature_format")
    if schema != PROOF_SCHEMA or signature_format != SIGNATURE_FORMAT:
        raise StepUpError(StepUpReason.INVALID_REQUEST)
    try:
        _canonical_challenge_id(challenge_id)
    except (TypeError, ValueError) as exc:
        raise StepUpError(StepUpReason.INVALID_REQUEST) from exc
    if not isinstance(signature, str) or _LOWER_HEX_128.fullmatch(signature) is None:
        raise StepUpError(StepUpReason.INVALID_SIGNATURE)
    return StepUpProof(schema, challenge_id, signature, signature_format)


class ActionStepUpService:
    def __init__(self, repository: ChallengeRepository, *, clock: Callable[[], datetime] | None = None):
        self._repository = repository
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def issue_challenge(
        self,
        *,
        actor_pubkey: str,
        oauth_client_id: str,
        token_jti: str,
        action: ActionName | str,
        resource_id: str | None,
        request_sha256: str,
        lifetime_seconds: int = DEFAULT_CHALLENGE_LIFETIME_SECONDS,
    ) -> StepUpChallenge:
        try:
            actor = _canonical_actor(actor_pubkey)
        except (TypeError, ValueError) as exc:
            raise StepUpError(StepUpReason.INVALID_ACTOR) from exc
        known_action = _action(action, require_step_up=True)
        try:
            client = _bounded_identifier(oauth_client_id, MAX_CLIENT_ID_LENGTH)
            jti = _bounded_identifier(token_jti, MAX_TOKEN_JTI_LENGTH)
            resource = _bounded_identifier(resource_id, MAX_RESOURCE_ID_LENGTH, optional=True)
            if not isinstance(request_sha256, str) or _LOWER_HEX_64.fullmatch(request_sha256) is None:
                raise ValueError("invalid digest")
            if isinstance(lifetime_seconds, bool) or not isinstance(lifetime_seconds, int):
                raise ValueError("invalid lifetime")
            if not 1 <= lifetime_seconds <= MAX_CHALLENGE_LIFETIME_SECONDS:
                raise ValueError("invalid lifetime")
            now = _utc(self._clock()).replace(microsecond=0)
        except (TypeError, ValueError) as exc:
            raise StepUpError(StepUpReason.INVALID_REQUEST) from exc
        challenge = StepUpChallenge(
            CHALLENGE_SCHEMA,
            uuid.uuid4().hex,
            actor,
            client,
            jti,
            known_action.value,
            resource,
            request_sha256,
            secrets.token_hex(NONCE_BYTES),
            now,
            now + timedelta(seconds=lifetime_seconds),
            SIGNATURE_DOMAIN,
        )
        try:
            self._repository.create(challenge)
        except Exception as exc:
            raise StepUpError(StepUpReason.STORAGE_UNAVAILABLE) from exc
        return challenge

    def verify_and_consume(
        self,
        *,
        proof: StepUpProof,
        actor_pubkey: str,
        oauth_client_id: str,
        token_jti: str,
        action: ActionName | str,
        resource_id: str | None,
        request_sha256: str,
    ) -> VerifiedStepUp:
        try:
            now = _utc(self._clock()).replace(microsecond=0)
            if (
                type(proof) is not StepUpProof
                or proof.schema != PROOF_SCHEMA
                or proof.signature_format != SIGNATURE_FORMAT
            ):
                return VerifiedStepUp(False, StepUpReason.INVALID_REQUEST)
            try:
                _canonical_challenge_id(proof.challenge_id)
            except (TypeError, ValueError):
                return VerifiedStepUp(False, StepUpReason.INVALID_REQUEST)
            signature_hex = proof.signature.hex() if isinstance(proof.signature, bytes) else proof.signature
            if not isinstance(signature_hex, str) or _LOWER_HEX_128.fullmatch(signature_hex) is None:
                return VerifiedStepUp(False, StepUpReason.INVALID_SIGNATURE)
            try:
                expected = (
                    _canonical_actor(actor_pubkey),
                    _bounded_identifier(oauth_client_id, MAX_CLIENT_ID_LENGTH),
                    _bounded_identifier(token_jti, MAX_TOKEN_JTI_LENGTH),
                    _action(action, require_step_up=False).value,
                    _bounded_identifier(resource_id, MAX_RESOURCE_ID_LENGTH, optional=True),
                    request_sha256,
                )
                if _LOWER_HEX_64.fullmatch(request_sha256) is None:
                    raise ValueError("invalid digest")
            except StepUpError:
                return VerifiedStepUp(False, StepUpReason.BINDING_MISMATCH)
            except (TypeError, ValueError):
                return VerifiedStepUp(False, StepUpReason.BINDING_MISMATCH)
            try:
                challenge = self._repository.get(proof.challenge_id)
            except Exception:
                return VerifiedStepUp(False, StepUpReason.STORAGE_UNAVAILABLE)
            if challenge is None:
                return VerifiedStepUp(False, StepUpReason.CHALLENGE_NOT_FOUND)
            state_reason = self._validate_persisted(challenge, now)
            if state_reason:
                return VerifiedStepUp(False, state_reason, challenge_id=challenge.challenge_id)
            actual = (
                challenge.actor_pubkey,
                challenge.oauth_client_id,
                challenge.token_jti,
                challenge.action,
                challenge.resource_id,
                challenge.request_sha256,
            )
            if actual != expected:
                return VerifiedStepUp(False, StepUpReason.BINDING_MISMATCH, challenge_id=challenge.challenge_id)
            digest = hashlib.sha256(canonical_signed_bytes(challenge)).digest()
            try:
                valid = PublicKeyXOnly(bytes.fromhex(challenge.actor_pubkey)).verify(
                    bytes.fromhex(signature_hex), digest
                )
            except Exception:
                valid = False
            if not valid:
                return VerifiedStepUp(False, StepUpReason.INVALID_SIGNATURE, challenge_id=challenge.challenge_id)
            try:
                consumed = self._repository.consume(challenge, now)
                if not consumed:
                    current = self._repository.get(challenge.challenge_id)
                    reason = (
                        StepUpReason.CHALLENGE_EXPIRED
                        if current and current.expires_at <= now
                        else StepUpReason.CHALLENGE_CONSUMED
                    )
                    return VerifiedStepUp(False, reason, challenge_id=challenge.challenge_id)
            except Exception:
                return VerifiedStepUp(False, StepUpReason.STORAGE_UNAVAILABLE, challenge_id=challenge.challenge_id)
            return VerifiedStepUp(
                True,
                StepUpReason.VERIFIED,
                challenge.challenge_id,
                challenge.actor_pubkey,
                challenge.oauth_client_id,
                challenge.token_jti,
                challenge.action,
                challenge.resource_id,
                challenge.request_sha256,
                challenge.issued_at,
                challenge.expires_at,
                now,
                now,
            )
        except Exception:
            return VerifiedStepUp(False, StepUpReason.INVALID_REQUEST)

    @staticmethod
    def _validate_persisted(challenge: StepUpChallenge, now: datetime) -> StepUpReason | None:
        try:
            if type(challenge) is not StepUpChallenge:
                return StepUpReason.INVALID_REQUEST
            issued = _utc(challenge.issued_at)
            expires = _utc(challenge.expires_at)
            if challenge.schema != CHALLENGE_SCHEMA or challenge.signature_domain != SIGNATURE_DOMAIN:
                return StepUpReason.INVALID_REQUEST
            _canonical_challenge_id(challenge.challenge_id)
            _canonical_actor(challenge.actor_pubkey)
            _bounded_identifier(challenge.oauth_client_id, MAX_CLIENT_ID_LENGTH)
            _bounded_identifier(challenge.token_jti, MAX_TOKEN_JTI_LENGTH)
            _action(challenge.action, require_step_up=True)
            _bounded_identifier(challenge.resource_id, MAX_RESOURCE_ID_LENGTH, optional=True)
            if (
                not isinstance(challenge.request_sha256, str)
                or _LOWER_HEX_64.fullmatch(challenge.request_sha256) is None
            ):
                return StepUpReason.INVALID_REQUEST
            if not isinstance(challenge.nonce, str) or _LOWER_HEX_64.fullmatch(challenge.nonce) is None:
                return StepUpReason.INVALID_REQUEST
            if expires <= issued or expires - issued > timedelta(seconds=MAX_CHALLENGE_LIFETIME_SECONDS):
                return StepUpReason.INVALID_REQUEST
            if issued > now + timedelta(seconds=MAX_CLOCK_SKEW_SECONDS):
                return StepUpReason.INVALID_REQUEST
            if challenge.consumed_at is not None:
                consumed = _utc(challenge.consumed_at)
                if consumed < issued or consumed >= expires:
                    return StepUpReason.INVALID_REQUEST
                return StepUpReason.CHALLENGE_CONSUMED
            if expires <= now:
                return StepUpReason.CHALLENGE_EXPIRED
        except (KeyError, TypeError, ValueError, StepUpError):
            return StepUpReason.INVALID_REQUEST
        return None
