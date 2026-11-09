"""Trusted, short-lived intent contract for device-binding authorization.

Intent creation is a read-only admission step.  It derives the complete
participant claim from authenticated identity, trusted time, Current-Full,
and authoritative binding state.  The RS256 seal is a separate token domain;
it is neither participant authorization nor persisted evidence.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Mapping, Protocol, Sequence

import jwt
from jwt.algorithms import RSAAlgorithm

from app.services.action_step_up import _canonical_actor
from app.services.bearer_credentials import DEFAULT_MAX_BEARER_LENGTH, has_compact_jwt_shape
from app.services.current_full_entitlement_proof import TransactionBoundCurrentFullEntitlementVerifier
from app.services.full_recipient_directory_provider import validate_x25519_public_key
from app.services.social_messaging_device_binding_authorization import (
    ADOPTION_SCHEMA,
    AUTHORIZATION_SCHEMA,
    MAX_AUTHORIZATION_BYTES,
    MAX_AUTHORIZATION_WINDOW_SECONDS,
    MAX_STATE_RECORDS,
    SIGNATURE_FORMAT,
    STATE_SCHEMA,
    VERSION,
    AuthorizationReplayRecord,
    BindingAuthorizationEvidenceState,
    CurrentDeviceBindingState,
    CurrentPublicKeyBindingState,
    CurrentSubjectBindingState,
    DeviceBindingAdoptionClaim,
    DeviceBindingAuthorizationClaim,
    DeviceBindingAuthorizationUnavailable,
    IdentitySignedDeviceBindingAdoption,
    IdentitySignedDeviceBindingAuthorization,
    _binding_id_from_claim,
    _validated_binding_id_state,
    _validated_current_full,
    _validated_device_state,
    _validated_legacy_binding,
    _validated_public_key_state,
    _validated_subject_state,
    adoption_digest,
    adoption_event_id,
    authorization_digest,
    authorization_event_id,
    canonical_adoption_signed_bytes,
    canonical_adoption_unsigned_event,
    canonical_authorization_signed_bytes,
    canonical_authorization_unsigned_event,
    parse_and_verify_device_binding_adoption,
    parse_and_verify_device_binding_authorization,
)
from app.services.social_messaging_device_contract import (
    ALGORITHM,
    BINDING_RECORD_SCHEMA,
    BINDING_RECORD_VERSION,
    MAX_ACTIVE_DEVICES,
    MAX_BINDING_VERSION,
    MessagingDeviceBinding,
)

INTENT_SCHEMA = "hodlxxi.social_messaging_device_binding_authorization_intent.v1"
INTENT_TOKEN_TYPE = "hodlxxi-device-binding-intent+jwt"
INTENT_TOKEN_USE = "device_binding_authorization_intent"
INTENT_TOKEN_PURPOSE = "social_messaging_device_binding_authorization_intent_v1"
INTENT_TOKEN_AUDIENCE = "urn:hodlxxi:ubid:social-messaging-device-binding-authorization-submit:v1"
INTENT_TOKEN_ALGORITHM = "RS256"
MAX_INTENT_REQUEST_BYTES = 2_048
MAX_INTENT_TOKEN_BYTES = DEFAULT_MAX_BEARER_LENGTH

_HEX_64 = re.compile(r"[0-9a-f]{64}\Z").fullmatch
_LIFECYCLE_FIELDS = {"deviceId", "expectedBindingId", "operation", "publicKey", "requestId"}
_ADOPTION_FIELDS = {"bindingId", "operation", "requestId"}
_TOKEN_CLAIMS = {
    "action",
    "aud",
    "claimType",
    "digest",
    "eventId",
    "exp",
    "iat",
    "iss",
    "jti",
    "purpose",
    "signatureFormat",
    "sub",
    "tokenUse",
}
_TOKEN_HEADERS = {"alg", "kid", "typ"}
_RSA_PRIVATE_PARAMETERS = {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}


@dataclass(frozen=True)
class AuthorizationIntentProposal:
    operation: str
    request_id: str
    device_id: str | None = None
    public_key: str | None = None
    expected_binding_id: str | None = None
    selected_binding_id: str | None = None


@dataclass(frozen=True)
class TrustedAuthorizationIntent:
    claim_type: str
    claim: DeviceBindingAuthorizationClaim | DeviceBindingAdoptionClaim
    digest: str
    expected_pubkey: str
    unsigned_event: Mapping[str, object]


class IntentStateProvider(Protocol):
    def current_for_subject(self, subject: str, *, now: datetime, maximum: int) -> CurrentSubjectBindingState: ...

    def current_for_device(
        self, subject: str, device_id: str, *, now: datetime, maximum: int
    ) -> CurrentDeviceBindingState: ...

    def current_for_public_key(
        self, public_key: str, *, now: datetime, maximum: int
    ) -> CurrentPublicKeyBindingState: ...

    def authorization_for_binding(
        self, binding_id: str, *, now: datetime, maximum: int
    ) -> BindingAuthorizationEvidenceState: ...

    def get(self, request_id: str) -> AuthorizationReplayRecord | object | None: ...


class IntentBindingState(Protocol):
    def binding_for_id(self, binding_id: str, *, lock: bool = True) -> MessagingDeviceBinding | None: ...

    def has_device_history(self, subject: str, device_id: str) -> bool: ...

    def public_key_was_used(self, public_key: str) -> bool: ...


def _hex64(value: object) -> str:
    if type(value) is not str or _HEX_64(value) is None:
        raise ValueError
    return value


def _utc_second(value: object) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError
    normalized = value.astimezone(timezone.utc)
    if normalized.microsecond:
        raise ValueError
    return normalized


def _closed_json(payload: object) -> dict[str, object]:
    if type(payload) is not str or not payload or len(payload.encode("utf-8")) > MAX_INTENT_REQUEST_BYTES:
        raise ValueError
    if any(ord(character) < 0x20 or ord(character) > 0x7E for character in payload):
        raise ValueError

    def pairs(values):
        result = {}
        for key, item in values:
            if type(key) is not str or key in result:
                raise ValueError
            result[key] = item
        return result

    decoded = json.loads(payload, object_pairs_hook=pairs)
    if type(decoded) is not dict:
        raise ValueError
    canonical = json.dumps(decoded, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if canonical != payload:
        raise ValueError
    return decoded


def parse_authorization_intent_proposal(payload: object) -> AuthorizationIntentProposal:
    """Parse only the values a browser is permitted to propose."""

    try:
        data = _closed_json(payload)
        operation = data.get("operation")
        if type(operation) is not str:
            raise ValueError
        request_id = _hex64(data.get("requestId"))
        if operation == "adopt":
            if set(data) != _ADOPTION_FIELDS:
                raise ValueError
            return AuthorizationIntentProposal(
                operation="adopt",
                request_id=request_id,
                selected_binding_id=_hex64(data.get("bindingId")),
            )
        if set(data) != _LIFECYCLE_FIELDS or operation not in {"register", "rotate", "revoke"}:
            raise ValueError
        device_id = _hex64(data.get("deviceId"))
        expected = data.get("expectedBindingId")
        public_key = data.get("publicKey")
        if operation == "register":
            if expected is not None or type(public_key) is not str:
                raise ValueError
        else:
            expected = _hex64(expected)
        if operation == "revoke":
            if public_key is not None:
                raise ValueError
            normalized_key = None
        else:
            normalized_key = validate_x25519_public_key(public_key)
        return AuthorizationIntentProposal(
            operation=operation,
            request_id=request_id,
            device_id=device_id,
            public_key=normalized_key,
            expected_binding_id=expected,
        )
    except Exception:
        raise DeviceBindingAuthorizationUnavailable() from None


def _intent_values(intent: TrustedAuthorizationIntent) -> tuple[str, str, str, str, int, int]:
    if type(intent) is not TrustedAuthorizationIntent or intent.claim_type not in {"lifecycle", "adoption"}:
        raise ValueError
    if intent.claim_type == "lifecycle":
        claim = intent.claim
        if type(claim) is not DeviceBindingAuthorizationClaim:
            raise ValueError
        content = canonical_authorization_signed_bytes(claim)
        digest = authorization_digest(claim)
        event_id = authorization_event_id(claim)
        unsigned_event = canonical_authorization_unsigned_event(claim)
        subject = claim.subject
        request_id = claim.request_id
        action = claim.operation
        issued_at = int(claim.issued_at.timestamp())
    else:
        claim = intent.claim
        if type(claim) is not DeviceBindingAdoptionClaim:
            raise ValueError
        content = canonical_adoption_signed_bytes(claim)
        digest = adoption_digest(claim)
        event_id = adoption_event_id(claim)
        unsigned_event = canonical_adoption_unsigned_event(claim)
        subject = claim.binding.subject
        request_id = claim.request_id
        action = claim.action
        issued_at = int(claim.issued_at.timestamp())
    if (
        content.decode("ascii") != unsigned_event["content"]
        or intent.digest != digest
        or intent.expected_pubkey != subject
        or dict(intent.unsigned_event) != unsigned_event
    ):
        raise ValueError
    return subject, request_id, action, event_id, issued_at, int(claim.expires_at.timestamp())


def derive_trusted_authorization_intent(
    proposal: AuthorizationIntentProposal,
    *,
    authenticated_subject: object,
    state_provider: IntentStateProvider,
    binding_state: IntentBindingState,
    current_full: TransactionBoundCurrentFullEntitlementVerifier,
    now: datetime,
    binding_lifetime_seconds: int,
    signature_verifier,
) -> TrustedAuthorizationIntent:
    """Derive one complete claim from transaction-bound authoritative inputs."""

    try:
        if type(proposal) is not AuthorizationIntentProposal:
            raise ValueError
        subject = _canonical_actor(authenticated_subject)
        timestamp = _utc_second(now)
        if (
            type(binding_lifetime_seconds) is not int
            or binding_lifetime_seconds < 300
            or binding_lifetime_seconds > 31_536_000
            or not callable(getattr(current_full, "verify_in_transaction", None))
            or not callable(getattr(signature_verifier, "verify", None))
        ):
            raise ValueError
        _validated_current_full(
            current_full.verify_in_transaction(subject, now=timestamp),
            subject=subject,
            now=timestamp,
        )
        if state_provider.get(proposal.request_id) is not None:
            raise ValueError

        request_expires = timestamp + timedelta(seconds=MAX_AUTHORIZATION_WINDOW_SECONDS)
        if proposal.operation == "adopt":
            binding = binding_state.binding_for_id(proposal.selected_binding_id)
            if binding is None:
                raise ValueError
            binding = _validated_legacy_binding(binding)
            if (
                binding.subject != subject
                or binding.valid_from > timestamp
                or timestamp >= binding.expires_at
                or proposal.request_id == binding.request_id
            ):
                raise ValueError
            existing = _validated_binding_id_state(
                state_provider.authorization_for_binding(
                    binding.binding_id,
                    now=timestamp,
                    maximum=MAX_STATE_RECORDS,
                ),
                binding_id=binding.binding_id,
                signature_verifier=signature_verifier,
            )
            if existing:
                raise ValueError
            expires_at = min(request_expires, binding.expires_at)
            if expires_at <= timestamp:
                raise ValueError
            adoption_claim = DeviceBindingAdoptionClaim(
                ADOPTION_SCHEMA,
                VERSION,
                "adopt",
                proposal.request_id,
                binding,
                timestamp,
                expires_at,
            )
            return TrustedAuthorizationIntent(
                "adoption",
                adoption_claim,
                adoption_digest(adoption_claim),
                subject,
                canonical_adoption_unsigned_event(adoption_claim),
            )

        if proposal.device_id is None:
            raise ValueError
        device_records = _validated_device_state(
            state_provider.current_for_device(
                subject,
                proposal.device_id,
                now=timestamp,
                maximum=MAX_STATE_RECORDS,
            ),
            subject=subject,
            device_id=proposal.device_id,
            now=timestamp,
            signature_verifier=signature_verifier,
        )
        subject_records = _validated_subject_state(
            state_provider.current_for_subject(
                subject,
                now=timestamp,
                maximum=MAX_ACTIVE_DEVICES + 1,
            ),
            subject=subject,
            now=timestamp,
            signature_verifier=signature_verifier,
        )
        if proposal.operation == "register":
            if proposal.public_key is None:
                raise ValueError
            key_records = _validated_public_key_state(
                state_provider.current_for_public_key(
                    proposal.public_key,
                    now=timestamp,
                    maximum=MAX_STATE_RECORDS,
                ),
                public_key=proposal.public_key,
                now=timestamp,
                signature_verifier=signature_verifier,
            )
            if (
                device_records
                or key_records
                or len(subject_records) >= MAX_ACTIVE_DEVICES
                or binding_state.has_device_history(subject, proposal.device_id)
                or binding_state.public_key_was_used(proposal.public_key)
            ):
                raise ValueError
            public_key = proposal.public_key
            version = 1
            prior = None
            binding_expires = timestamp + timedelta(seconds=binding_lifetime_seconds)
        else:
            if len(device_records) != 1:
                raise ValueError
            current = device_records[0]
            binding = current.binding
            predecessor_key_records = _validated_public_key_state(
                state_provider.current_for_public_key(
                    binding.public_key,
                    now=timestamp,
                    maximum=MAX_STATE_RECORDS,
                ),
                public_key=binding.public_key,
                now=timestamp,
                signature_verifier=signature_verifier,
            )
            if (
                sum(item == current for item in subject_records) != 1
                or predecessor_key_records != (current,)
                or proposal.expected_binding_id != binding.binding_id
                or binding.binding_version >= MAX_BINDING_VERSION
            ):
                raise ValueError
            version = binding.binding_version + 1
            prior = binding.binding_id
            binding_expires = binding.expires_at
            if proposal.operation == "rotate":
                if (
                    proposal.public_key is None
                    or proposal.public_key == binding.public_key
                    or binding_state.public_key_was_used(proposal.public_key)
                ):
                    raise ValueError
                proposed_records = _validated_public_key_state(
                    state_provider.current_for_public_key(
                        proposal.public_key,
                        now=timestamp,
                        maximum=MAX_STATE_RECORDS,
                    ),
                    public_key=proposal.public_key,
                    now=timestamp,
                    signature_verifier=signature_verifier,
                )
                if proposed_records:
                    raise ValueError
                public_key = proposal.public_key
            else:
                public_key = binding.public_key

        if public_key == subject or binding_expires <= timestamp:
            raise ValueError
        lifecycle_claim = DeviceBindingAuthorizationClaim(
            AUTHORIZATION_SCHEMA,
            VERSION,
            BINDING_RECORD_SCHEMA,
            BINDING_RECORD_VERSION,
            proposal.operation,
            subject,
            proposal.device_id,
            ALGORITHM,
            public_key,
            version,
            timestamp,
            binding_expires,
            prior,
            proposal.request_id,
            timestamp,
            min(request_expires, binding_expires),
        )
        digest = authorization_digest(lifecycle_claim)
        candidate_binding_id = _binding_id_from_claim(lifecycle_claim)
        existing = _validated_binding_id_state(
            state_provider.authorization_for_binding(
                candidate_binding_id,
                now=timestamp,
                maximum=MAX_STATE_RECORDS,
            ),
            binding_id=candidate_binding_id,
            signature_verifier=signature_verifier,
        )
        if existing or candidate_binding_id == prior:
            raise ValueError
        return TrustedAuthorizationIntent(
            "lifecycle",
            lifecycle_claim,
            digest,
            subject,
            canonical_authorization_unsigned_event(lifecycle_claim),
        )
    except DeviceBindingAuthorizationUnavailable:
        raise
    except Exception:
        raise DeviceBindingAuthorizationUnavailable() from None


def _intent_claim_dict(intent: TrustedAuthorizationIntent) -> dict[str, object]:
    if intent.claim_type == "lifecycle":
        lifecycle_claim = intent.claim
        if type(lifecycle_claim) is not DeviceBindingAuthorizationClaim:
            raise ValueError
        envelope = json.loads(canonical_authorization_signed_bytes(lifecycle_claim))
        return envelope["authorization"]
    adoption_claim = intent.claim
    if type(adoption_claim) is not DeviceBindingAdoptionClaim:
        raise ValueError
    envelope = json.loads(canonical_adoption_signed_bytes(adoption_claim))
    return envelope["adoption"]


def _jwt_object_segment(encoded: str, index: int) -> dict[str, object]:
    segment = encoded.split(".")[index]
    raw = base64.b64decode(segment + "=" * (-len(segment) % 4), altchars=b"-_", validate=True)
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != segment:
        raise ValueError

    def pairs(values):
        result = {}
        for key, item in values:
            if type(key) is not str or key in result:
                raise ValueError
            result[key] = item
        return result

    decoded = json.loads(raw.decode("ascii"), object_pairs_hook=pairs)
    if type(decoded) is not dict:
        raise ValueError
    return decoded


def _select_intent_key(
    encoded: str,
    *,
    keys: Sequence[Mapping[str, object]],
    expected_kid: str,
):
    if (
        type(encoded) is not str
        or not encoded
        or len(encoded.encode("ascii")) > MAX_INTENT_TOKEN_BYTES
        or not has_compact_jwt_shape(encoded)
    ):
        raise ValueError
    header = _jwt_object_segment(encoded, 0)
    if (
        set(header) != _TOKEN_HEADERS
        or header.get("alg") != INTENT_TOKEN_ALGORITHM
        or header.get("typ") != INTENT_TOKEN_TYPE
        or header.get("kid") != expected_kid
    ):
        raise ValueError
    matches = [key for key in keys if isinstance(key, Mapping) and key.get("kid") == expected_kid]
    if len(matches) != 1:
        raise ValueError
    key = matches[0]
    if (
        key.get("kty") != "RSA"
        or key.get("use") != "sig"
        or key.get("alg") != INTENT_TOKEN_ALGORITHM
        or any(name in key for name in _RSA_PRIVATE_PARAMETERS)
    ):
        raise ValueError
    return RSAAlgorithm.from_jwk(json.dumps(dict(key)))


def seal_authorization_intent(
    intent: TrustedAuthorizationIntent,
    *,
    issuer: str,
    signing_key: object,
    signing_kid: str,
    verification_keys: Sequence[Mapping[str, object]],
) -> str:
    """Seal one intent and self-verify it against the configured public key."""

    try:
        if (
            type(issuer) is not str
            or not issuer
            or issuer.strip() != issuer
            or type(signing_kid) is not str
            or not signing_kid
            or signing_kid.strip() != signing_kid
        ):
            raise ValueError
        subject, request_id, action, event_id, issued_at, expires_at = _intent_values(intent)
        if expires_at <= issued_at or expires_at - issued_at > MAX_AUTHORIZATION_WINDOW_SECONDS:
            raise ValueError
        claims = {
            "iss": issuer,
            "sub": subject,
            "iat": issued_at,
            "exp": expires_at,
            "jti": request_id,
            "aud": INTENT_TOKEN_AUDIENCE,
            "tokenUse": INTENT_TOKEN_USE,
            "purpose": INTENT_TOKEN_PURPOSE,
            "claimType": intent.claim_type,
            "action": action,
            "digest": intent.digest,
            "eventId": event_id,
            "signatureFormat": SIGNATURE_FORMAT,
        }
        encoded = jwt.encode(
            claims,
            signing_key,
            algorithm=INTENT_TOKEN_ALGORITHM,
            headers={"kid": signing_kid, "typ": INTENT_TOKEN_TYPE},
        )
        key = _select_intent_key(
            encoded,
            keys=verification_keys,
            expected_kid=signing_kid,
        )
        encoded_claims = _jwt_object_segment(encoded, 1)
        verified = jwt.decode(
            encoded,
            key,
            algorithms=[INTENT_TOKEN_ALGORITHM],
            options={
                "verify_signature": True,
                "verify_aud": False,
                "verify_iss": False,
                "verify_exp": False,
                "verify_iat": False,
                "verify_nbf": False,
            },
        )
        if type(verified) is not dict or verified != claims or encoded_claims != claims:
            raise ValueError
        return encoded
    except Exception:
        raise DeviceBindingAuthorizationUnavailable() from None


def canonical_authorization_intent_bytes(
    intent: TrustedAuthorizationIntent,
    *,
    intent_token: str,
) -> bytes:
    """Return the closed canonical intent response sent to Social."""

    try:
        _intent_values(intent)
        if type(intent_token) is not str or not intent_token or len(intent_token) > MAX_INTENT_TOKEN_BYTES:
            raise ValueError
        encoded = json.dumps(
            {
                "schema": INTENT_SCHEMA,
                "version": VERSION,
                "claimType": intent.claim_type,
                "claim": _intent_claim_dict(intent),
                "digest": intent.digest,
                "signatureFormat": SIGNATURE_FORMAT,
                "expectedPubkey": intent.expected_pubkey,
                "unsignedEvent": dict(intent.unsigned_event),
                "intentToken": intent_token,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        if len(encoded) > MAX_AUTHORIZATION_BYTES + MAX_INTENT_TOKEN_BYTES:
            raise ValueError
        return encoded
    except DeviceBindingAuthorizationUnavailable:
        raise
    except Exception:
        raise DeviceBindingAuthorizationUnavailable() from None


def _signed_payload_identity(
    payload: object,
    *,
    authenticated_subject: str,
    signature_verifier,
) -> tuple[
    str,
    str,
    str,
    str,
    int,
    int,
    str,
    IdentitySignedDeviceBindingAuthorization | IdentitySignedDeviceBindingAdoption,
]:
    try:
        lifecycle = parse_and_verify_device_binding_authorization(
            payload,
            authenticated_subject=authenticated_subject,
            signature_verifier=signature_verifier,
        )
        return (
            "lifecycle",
            lifecycle.claim.operation,
            lifecycle.claim.request_id,
            lifecycle.digest,
            int(lifecycle.claim.issued_at.timestamp()),
            int(lifecycle.claim.expires_at.timestamp()),
            authorization_event_id(lifecycle.claim),
            lifecycle,
        )
    except DeviceBindingAuthorizationUnavailable:
        adoption = parse_and_verify_device_binding_adoption(
            payload,
            authenticated_subject=authenticated_subject,
            signature_verifier=signature_verifier,
        )
        return (
            "adoption",
            adoption.claim.action,
            adoption.claim.request_id,
            adoption.digest,
            int(adoption.claim.issued_at.timestamp()),
            int(adoption.claim.expires_at.timestamp()),
            adoption_event_id(adoption.claim),
            adoption,
        )


def _authenticated_authorization_intent_submission(
    intent_token: object,
    payload: object,
    *,
    authenticated_subject: object,
    issuer: str,
    expected_kid: str,
    verification_keys: Sequence[Mapping[str, object]],
    signature_verifier,
) -> tuple[
    IdentitySignedDeviceBindingAuthorization | IdentitySignedDeviceBindingAdoption,
    int,
    int,
]:
    """Authenticate the exact token, event, and signed candidate without freshness."""

    try:
        subject = _canonical_actor(authenticated_subject)
        (
            claim_type,
            action,
            request_id,
            digest,
            issued_at,
            expires_at,
            event_id,
            signed,
        ) = _signed_payload_identity(
            payload,
            authenticated_subject=subject,
            signature_verifier=signature_verifier,
        )
        if type(intent_token) is not str:
            raise ValueError
        key = _select_intent_key(
            intent_token,
            keys=verification_keys,
            expected_kid=expected_kid,
        )
        encoded_claims = _jwt_object_segment(intent_token, 1)
        claims = jwt.decode(
            intent_token,
            key,
            algorithms=[INTENT_TOKEN_ALGORITHM],
            options={
                "verify_signature": True,
                "verify_aud": False,
                "verify_iss": False,
                "verify_exp": False,
                "verify_iat": False,
                "verify_nbf": False,
            },
        )
        exp = claims.get("exp")
        iat = claims.get("iat")
        expected = {
            "iss": issuer,
            "sub": subject,
            "iat": issued_at,
            "exp": expires_at,
            "jti": request_id,
            "aud": INTENT_TOKEN_AUDIENCE,
            "tokenUse": INTENT_TOKEN_USE,
            "purpose": INTENT_TOKEN_PURPOSE,
            "claimType": claim_type,
            "action": action,
            "digest": digest,
            "eventId": event_id,
            "signatureFormat": SIGNATURE_FORMAT,
        }
        if (
            type(claims) is not dict
            or claims != encoded_claims
            or set(claims) != _TOKEN_CLAIMS
            or claims != expected
            or type(iat) is not int
            or type(exp) is not int
            or exp <= iat
            or exp - iat > MAX_AUTHORIZATION_WINDOW_SECONDS
        ):
            raise ValueError
        return signed, iat, exp
    except Exception:
        raise DeviceBindingAuthorizationUnavailable() from None


def authenticate_authorization_intent_submission(
    intent_token: object,
    payload: object,
    *,
    authenticated_subject: object,
    issuer: str,
    expected_kid: str,
    verification_keys: Sequence[Mapping[str, object]],
    signature_verifier,
) -> IdentitySignedDeviceBindingAuthorization | IdentitySignedDeviceBindingAdoption:
    """Authenticate exact replay material before consulting accepted state."""

    signed, _issued_at, _expires_at = _authenticated_authorization_intent_submission(
        intent_token,
        payload,
        authenticated_subject=authenticated_subject,
        issuer=issuer,
        expected_kid=expected_kid,
        verification_keys=verification_keys,
        signature_verifier=signature_verifier,
    )
    return signed


def verify_authorization_intent_submission(
    intent_token: object,
    payload: object,
    *,
    authenticated_subject: object,
    issuer: str,
    expected_kid: str,
    verification_keys: Sequence[Mapping[str, object]],
    signature_verifier,
    now: datetime,
) -> IdentitySignedDeviceBindingAuthorization | IdentitySignedDeviceBindingAdoption:
    """Authenticate exact intent material and require its normal fresh window."""

    try:
        timestamp = _utc_second(now)
        signed, issued_at, expires_at = _authenticated_authorization_intent_submission(
            intent_token,
            payload,
            authenticated_subject=authenticated_subject,
            issuer=issuer,
            expected_kid=expected_kid,
            verification_keys=verification_keys,
            signature_verifier=signature_verifier,
        )
        current = int(timestamp.timestamp())
        if issued_at > current or current >= expires_at:
            raise ValueError
        return signed
    except Exception:
        raise DeviceBindingAuthorizationUnavailable() from None


__all__ = [
    "AuthorizationIntentProposal",
    "INTENT_SCHEMA",
    "INTENT_TOKEN_ALGORITHM",
    "INTENT_TOKEN_AUDIENCE",
    "INTENT_TOKEN_PURPOSE",
    "INTENT_TOKEN_TYPE",
    "INTENT_TOKEN_USE",
    "MAX_INTENT_REQUEST_BYTES",
    "MAX_INTENT_TOKEN_BYTES",
    "TrustedAuthorizationIntent",
    "authenticate_authorization_intent_submission",
    "canonical_authorization_intent_bytes",
    "derive_trusted_authorization_intent",
    "parse_authorization_intent_proposal",
    "seal_authorization_intent",
    "verify_authorization_intent_submission",
]
