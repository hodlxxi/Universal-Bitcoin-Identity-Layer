"""Dormant identity-signed Social messaging device authorization contract.

The module is deliberately infrastructure-free.  It reconstructs exact
purpose-specific Nostr carriers, verifies their BIP-340 event-ID signatures,
coordinates injected complete-state and replay ports, and provides a verifier
compatible with the dormant recipient-routing gate.  It does not expose a
route or implement persistence.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Protocol

from coincurve import PublicKeyXOnly

from app.services.action_step_up import _canonical_actor
from app.services.current_full_entitlement_proof import (
    TransactionBoundCurrentFullEntitlementVerifier,
    VerifiedCurrentFullEntitlement,
    validate_verified_current_full_entitlement,
)
from app.services.full_recipient_directory_provider import validate_x25519_public_key
from app.services.social_messaging_device_contract import (
    ALGORITHM,
    BINDING_RECORD_SCHEMA,
    BINDING_RECORD_VERSION,
    MAX_ACTIVE_DEVICES,
    MAX_BINDING_VERSION,
    MessagingDeviceBinding,
    canonical_messaging_device_binding_record_bytes,
    messaging_device_binding_id,
)
from app.services.social_messaging_recipient_routing import VerifiedBindingAuthorization

AUTHORIZATION_SCHEMA = "hodlxxi.social_messaging_device_binding_authorization.v1"
ADOPTION_SCHEMA = "hodlxxi.social_messaging_device_binding_adoption.v1"
STATE_SCHEMA = "hodlxxi.social_messaging_device_binding_authorization_state.v1"
SIGNATURE_DOMAIN = "HODLXXI_SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_V1"
ADOPTION_SIGNATURE_DOMAIN = "HODLXXI_SOCIAL_MESSAGING_DEVICE_BINDING_ADOPTION_V1"
SIGNATURE_FORMAT = "nostr_event_id_bip340_v1"
NOSTR_EVENT_KIND = 27236
NOSTR_EVENT_PURPOSE = "hodlxxi-social-messaging-device-binding-authorization-v1"
PROOF_ID_PREFIX = "hodlxxi-binding-authorization-v1-sha256:"
VERSION = 1

MAX_AUTHORIZATION_BYTES = 8_192
MAX_AUTHORIZATION_WINDOW_SECONDS = 300
MAX_STATE_RECORDS = 2
UNAVAILABLE_MESSAGE = "social messaging device binding authorization unavailable"

_HEX_64 = re.compile(r"[0-9a-f]{64}\Z").fullmatch
_HEX_128 = re.compile(r"[0-9a-f]{128}\Z").fullmatch
_OPERATIONS = frozenset({"register", "rotate", "revoke"})
_CLAIM_FIELDS = {
    "algorithm",
    "bindingExpiresAt",
    "bindingRecordSchema",
    "bindingRecordVersion",
    "bindingValidFrom",
    "bindingVersion",
    "deviceId",
    "expiresAt",
    "issuedAt",
    "operation",
    "priorBindingId",
    "publicKey",
    "requestId",
    "schema",
    "subject",
    "version",
}
_AUTHORIZATION_FIELDS = _CLAIM_FIELDS | {"digest", "signature", "signatureFormat"}
_BINDING_RECORD_FIELDS = {
    "algorithm",
    "bindingVersion",
    "deviceId",
    "expiresAt",
    "operation",
    "priorBindingId",
    "publicKey",
    "requestId",
    "schema",
    "subject",
    "validFrom",
    "version",
}
_ADOPTION_CLAIM_FIELDS = {
    "action",
    "bindingId",
    "bindingRecord",
    "expiresAt",
    "issuedAt",
    "requestId",
    "schema",
    "version",
}
_ADOPTION_FIELDS = _ADOPTION_CLAIM_FIELDS | {"digest", "signature", "signatureFormat"}


class DeviceBindingAuthorizationUnavailable(RuntimeError):
    """The sole public error crossing this contract boundary."""

    def __init__(self) -> None:
        super().__init__(UNAVAILABLE_MESSAGE)


@dataclass(frozen=True)
class DeviceBindingAuthorizationClaim:
    schema: str
    version: int
    binding_record_schema: str
    binding_record_version: int
    operation: str
    subject: str
    device_id: str
    algorithm: str
    public_key: str
    binding_version: int
    binding_valid_from: datetime
    binding_expires_at: datetime
    prior_binding_id: str | None
    request_id: str
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True)
class IdentitySignedDeviceBindingAuthorization:
    claim: DeviceBindingAuthorizationClaim
    digest: str
    signature_format: str
    signature: str

    @property
    def binding_id(self) -> str:
        """The authoritative identifier of the exact canonical binding record."""

        return _binding_id_from_claim(self.claim)


@dataclass(frozen=True)
class AuthorizedDeviceBinding:
    authorization: IdentitySignedDeviceBindingAuthorization
    binding: MessagingDeviceBinding
    verification: VerifiedBindingAuthorization


@dataclass(frozen=True)
class DeviceBindingAdoptionClaim:
    schema: str
    version: int
    action: str
    request_id: str
    binding: MessagingDeviceBinding
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True)
class IdentitySignedDeviceBindingAdoption:
    claim: DeviceBindingAdoptionClaim
    digest: str
    signature_format: str
    signature: str

    @property
    def binding_id(self) -> str:
        return self.claim.binding.binding_id


@dataclass(frozen=True)
class AdoptedDeviceBindingAuthorization:
    adoption: IdentitySignedDeviceBindingAdoption
    binding: MessagingDeviceBinding
    verification: VerifiedBindingAuthorization


BindingAuthorizationEvidence = AuthorizedDeviceBinding | AdoptedDeviceBindingAuthorization


@dataclass(frozen=True)
class CurrentDeviceBindingState:
    schema: str
    version: int
    subject: str
    device_id: str
    complete: bool
    truncated: bool
    records: tuple[BindingAuthorizationEvidence, ...]


@dataclass(frozen=True)
class CurrentSubjectBindingState:
    schema: str
    version: int
    subject: str
    complete: bool
    truncated: bool
    records: tuple[BindingAuthorizationEvidence, ...]


@dataclass(frozen=True)
class CurrentPublicKeyBindingState:
    schema: str
    version: int
    public_key: str
    complete: bool
    truncated: bool
    records: tuple[BindingAuthorizationEvidence, ...]


@dataclass(frozen=True)
class BindingAuthorizationEvidenceState:
    schema: str
    version: int
    binding_id: str
    complete: bool
    truncated: bool
    records: tuple[BindingAuthorizationEvidence, ...]


@dataclass(frozen=True)
class CurrentLegacyDeviceBindingState:
    schema: str
    version: int
    subject: str
    binding_id: str
    complete: bool
    truncated: bool
    records: tuple[MessagingDeviceBinding, ...]


@dataclass(frozen=True)
class AuthorizationReplayRecord:
    request_id: str
    authorization_digest: str
    authorized_binding: AuthorizedDeviceBinding


@dataclass(frozen=True)
class AdoptionReplayRecord:
    request_id: str
    adoption_digest: str
    adopted_binding: AdoptedDeviceBindingAuthorization


class IdentitySignatureVerifier(Protocol):
    def verify(self, *, subject: str, signature: bytes, digest: bytes) -> bool: ...


class DeviceBindingAuthorizationStateProvider(Protocol):
    def current_for_subject(
        self,
        subject: str,
        *,
        now: datetime,
        maximum: int,
    ) -> CurrentSubjectBindingState: ...

    def current_for_device(
        self,
        subject: str,
        device_id: str,
        *,
        now: datetime,
        maximum: int,
    ) -> CurrentDeviceBindingState: ...

    def current_for_public_key(
        self,
        public_key: str,
        *,
        now: datetime,
        maximum: int,
    ) -> CurrentPublicKeyBindingState: ...

    def authorization_for_binding(
        self,
        binding_id: str,
        *,
        now: datetime,
        maximum: int,
    ) -> BindingAuthorizationEvidenceState: ...


class BindingAuthorizationEvidenceProvider(Protocol):
    def authorization_for_binding(
        self,
        binding_id: str,
        *,
        now: datetime,
        maximum: int,
    ) -> BindingAuthorizationEvidenceState: ...


class LegacyDeviceBindingAdoptionStateProvider(Protocol):
    def current_legacy_binding(
        self,
        subject: str,
        binding_id: str,
        *,
        now: datetime,
        maximum: int,
    ) -> CurrentLegacyDeviceBindingState: ...

    def authorization_for_binding(
        self,
        binding_id: str,
        *,
        now: datetime,
        maximum: int,
    ) -> BindingAuthorizationEvidenceState: ...


class AuthorizationReplayLedger(Protocol):
    """Future atomic, logically global lifecycle-and-adoption request ledger.

    ``get`` must fail instead of choosing among duplicate records. ``record``
    must atomically retain an absent request ID, return the exact existing
    record for an equal retry, and reject a different record type, digest, or
    result.
    """

    def get(self, request_id: str) -> AuthorizationReplayRecord | AdoptionReplayRecord | None: ...

    def record(
        self,
        record: AuthorizationReplayRecord | AdoptionReplayRecord,
    ) -> AuthorizationReplayRecord | AdoptionReplayRecord: ...


class Bip340IdentitySignatureVerifier:
    """UBID's established x-only secp256k1 identity-signature convention."""

    def verify(self, *, subject: str, signature: bytes, digest: bytes) -> bool:
        try:
            return PublicKeyXOnly(bytes.fromhex(subject)).verify(signature, digest) is True
        except Exception:
            return False


def _utc_second(value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError
    normalized = value.astimezone(timezone.utc)
    if normalized.microsecond:
        raise ValueError
    return normalized


def _trusted_utc_second(value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError
    return value.astimezone(timezone.utc).replace(microsecond=0)


def _timestamp(value: datetime) -> str:
    return _utc_second(value).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_timestamp(value: object) -> datetime:
    if type(value) is not str or not value.endswith("Z"):
        raise ValueError
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    if _timestamp(parsed) != value:
        raise ValueError
    return parsed


def _hex64(value: object) -> str:
    if type(value) is not str or _HEX_64(value) is None:
        raise ValueError
    return value


def _binding_record_values(claim: DeviceBindingAuthorizationClaim) -> dict[str, object]:
    return {
        "subject": claim.subject,
        "device_id": claim.device_id,
        "public_key": claim.public_key,
        "binding_version": claim.binding_version,
        "valid_from": claim.binding_valid_from,
        "expires_at": claim.binding_expires_at,
        "operation": claim.operation,
        "prior_binding_id": claim.prior_binding_id,
        "request_id": claim.request_id,
    }


def _binding_id_from_claim(claim: DeviceBindingAuthorizationClaim) -> str:
    validated = _validated_claim(claim)
    return messaging_device_binding_id(**_binding_record_values(validated))


def _claim_dict(value: DeviceBindingAuthorizationClaim) -> dict[str, object]:
    return {
        "schema": value.schema,
        "version": value.version,
        "bindingRecordSchema": value.binding_record_schema,
        "bindingRecordVersion": value.binding_record_version,
        "operation": value.operation,
        "subject": value.subject,
        "deviceId": value.device_id,
        "algorithm": value.algorithm,
        "publicKey": value.public_key,
        "bindingVersion": value.binding_version,
        "bindingValidFrom": _timestamp(value.binding_valid_from),
        "bindingExpiresAt": _timestamp(value.binding_expires_at),
        "priorBindingId": value.prior_binding_id,
        "requestId": value.request_id,
        "issuedAt": _timestamp(value.issued_at),
        "expiresAt": _timestamp(value.expires_at),
    }


def _validated_claim(value: object) -> DeviceBindingAuthorizationClaim:
    if type(value) is not DeviceBindingAuthorizationClaim:
        raise ValueError
    if (
        type(value.schema) is not str
        or value.schema != AUTHORIZATION_SCHEMA
        or type(value.version) is not int
        or value.version != VERSION
        or type(value.binding_record_schema) is not str
        or value.binding_record_schema != BINDING_RECORD_SCHEMA
        or type(value.binding_record_version) is not int
        or value.binding_record_version != BINDING_RECORD_VERSION
        or type(value.operation) is not str
        or value.operation not in _OPERATIONS
        or type(value.algorithm) is not str
        or value.algorithm != ALGORITHM
    ):
        raise ValueError
    subject = _canonical_actor(value.subject)
    device_id = _hex64(value.device_id)
    public_key = validate_x25519_public_key(value.public_key)
    if public_key != value.public_key or public_key == subject:
        raise ValueError
    binding_version = value.binding_version
    if type(binding_version) is not int or not 1 <= binding_version <= MAX_BINDING_VERSION:
        raise ValueError
    prior = value.prior_binding_id
    if value.operation == "register":
        if prior is not None or binding_version != 1:
            raise ValueError
    else:
        prior = _hex64(prior)
        if binding_version <= 1:
            raise ValueError
    request_id = _hex64(value.request_id)
    binding_valid_from = _utc_second(value.binding_valid_from)
    binding_expires_at = _utc_second(value.binding_expires_at)
    issued_at = _utc_second(value.issued_at)
    expires_at = _utc_second(value.expires_at)
    if (
        binding_valid_from >= binding_expires_at
        or issued_at >= expires_at
        or issued_at < binding_valid_from
        or expires_at > binding_expires_at
        or expires_at - issued_at > timedelta(seconds=MAX_AUTHORIZATION_WINDOW_SECONDS)
        or binding_valid_from != issued_at
    ):
        raise ValueError
    claim = DeviceBindingAuthorizationClaim(
        AUTHORIZATION_SCHEMA,
        VERSION,
        BINDING_RECORD_SCHEMA,
        BINDING_RECORD_VERSION,
        value.operation,
        subject,
        device_id,
        ALGORITHM,
        public_key,
        binding_version,
        binding_valid_from,
        binding_expires_at,
        prior,
        request_id,
        issued_at,
        expires_at,
    )
    canonical_messaging_device_binding_record_bytes(**_binding_record_values(claim))
    return claim


def canonical_authorization_signed_bytes(value: DeviceBindingAuthorizationClaim) -> bytes:
    """Return exact domain-separated bytes whose SHA-256 digest is signed."""

    try:
        claim = _validated_claim(value)
        envelope = {"authorization": _claim_dict(claim), "domain": SIGNATURE_DOMAIN}
        return json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    except Exception:
        raise DeviceBindingAuthorizationUnavailable() from None


def authorization_digest(value: DeviceBindingAuthorizationClaim) -> str:
    return hashlib.sha256(canonical_authorization_signed_bytes(value)).hexdigest()


def _carrier_unsigned_event(
    *,
    pubkey: str,
    issued_at: datetime,
    action: str,
    digest: str,
    request_id: str,
    content: bytes,
) -> dict[str, object]:
    subject = _canonical_actor(pubkey)
    semantic_digest = _hex64(digest)
    timestamp = _utc_second(issued_at)
    request = _hex64(request_id)
    if type(action) is not str or action not in _OPERATIONS | {"adopt"}:
        raise ValueError
    if type(content) is not bytes or hashlib.sha256(content).hexdigest() != semantic_digest:
        raise ValueError
    content_text = content.decode("ascii")
    return {
        "created_at": int(timestamp.timestamp()),
        "kind": NOSTR_EVENT_KIND,
        "tags": [
            ["purpose", NOSTR_EVENT_PURPOSE],
            ["semantic-digest", semantic_digest],
            ["request-id", request],
            ["action", action],
        ],
        "content": content_text,
        "pubkey": subject,
    }


def _carrier_serialization(event: object) -> bytes:
    if type(event) is not dict or set(event) != {"pubkey", "created_at", "kind", "tags", "content"}:
        raise ValueError
    pubkey = _canonical_actor(event["pubkey"])
    created_at = event["created_at"]
    kind = event["kind"]
    tags = event["tags"]
    content = event["content"]
    if (
        type(created_at) is not int
        or created_at < 0
        or type(kind) is not int
        or kind != NOSTR_EVENT_KIND
        or type(tags) is not list
        or len(tags) != 4
        or any(type(tag) is not list or len(tag) != 2 or any(type(item) is not str for item in tag) for tag in tags)
        or type(content) is not str
    ):
        raise ValueError
    encoded = json.dumps(
        [0, pubkey, created_at, kind, tags, content],
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii")
    if any(byte > 0x7F for byte in encoded):
        raise ValueError
    return encoded


def canonical_authorization_unsigned_event(
    value: DeviceBindingAuthorizationClaim,
) -> dict[str, object]:
    """Return the closed NIP-07/NIP-46 input without signer-owned fields."""

    try:
        claim = _validated_claim(value)
        digest = authorization_digest(claim)
        carrier = _carrier_unsigned_event(
            pubkey=claim.subject,
            issued_at=claim.issued_at,
            action=claim.operation,
            digest=digest,
            request_id=claim.request_id,
            content=canonical_authorization_signed_bytes(claim),
        )
        carrier.pop("pubkey")
        return carrier
    except Exception:
        raise DeviceBindingAuthorizationUnavailable() from None


def canonical_authorization_event_serialization(
    value: DeviceBindingAuthorizationClaim,
) -> bytes:
    """Return exact NIP-01 serialization bytes for one lifecycle carrier."""

    try:
        claim = _validated_claim(value)
        event = {"pubkey": claim.subject, **canonical_authorization_unsigned_event(claim)}
        return _carrier_serialization(event)
    except Exception:
        raise DeviceBindingAuthorizationUnavailable() from None


def authorization_event_id(value: DeviceBindingAuthorizationClaim) -> str:
    return hashlib.sha256(canonical_authorization_event_serialization(value)).hexdigest()


def _authorization_dict(value: IdentitySignedDeviceBindingAuthorization) -> dict[str, object]:
    return {
        **_claim_dict(value.claim),
        "digest": value.digest,
        "signatureFormat": value.signature_format,
        "signature": value.signature,
    }


def canonical_authorization_json(value: IdentitySignedDeviceBindingAuthorization) -> str:
    """Serialize an exact signed authorization for the external boundary."""

    try:
        authorization = _validated_signed_authorization(value, Bip340IdentitySignatureVerifier())
        encoded = json.dumps(
            _authorization_dict(authorization),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        if len(encoded.encode("ascii")) > MAX_AUTHORIZATION_BYTES:
            raise ValueError
        return encoded
    except Exception:
        raise DeviceBindingAuthorizationUnavailable() from None


def _validated_signed_authorization(
    value: object,
    signature_verifier: IdentitySignatureVerifier,
) -> IdentitySignedDeviceBindingAuthorization:
    if type(value) is not IdentitySignedDeviceBindingAuthorization:
        raise ValueError
    claim = _validated_claim(value.claim)
    digest = _hex64(value.digest)
    if (
        type(value.signature_format) is not str
        or value.signature_format != SIGNATURE_FORMAT
        or type(value.signature) is not str
        or _HEX_128(value.signature) is None
        or digest != authorization_digest(claim)
    ):
        raise ValueError
    verified = signature_verifier.verify(
        subject=claim.subject,
        signature=bytes.fromhex(value.signature),
        digest=bytes.fromhex(authorization_event_id(claim)),
    )
    if verified is not True:
        raise ValueError
    return IdentitySignedDeviceBindingAuthorization(claim, digest, SIGNATURE_FORMAT, value.signature)


def _closed_signed_object(
    payload: object,
    expected_fields: set[str],
) -> dict[str, object]:
    if type(payload) is not str or not payload or len(payload.encode("utf-8")) > MAX_AUTHORIZATION_BYTES:
        raise ValueError
    if any(ord(character) > 0x7F for character in payload):
        raise ValueError

    def pairs(values):
        result = {}
        for key, item in values:
            if type(key) is not str or key in result:
                raise ValueError
            result[key] = item
        return result

    decoded = json.loads(payload, object_pairs_hook=pairs)
    if type(decoded) is not dict or set(decoded) != expected_fields:
        raise ValueError
    canonical = json.dumps(decoded, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if payload != canonical:
        raise ValueError
    return decoded


def _closed_authorization_object(payload: object) -> dict[str, object]:
    return _closed_signed_object(payload, _AUTHORIZATION_FIELDS)


def parse_and_verify_device_binding_authorization(
    payload: object,
    *,
    authenticated_subject: object,
    signature_verifier: IdentitySignatureVerifier | None = None,
) -> IdentitySignedDeviceBindingAuthorization:
    """Parse canonical JSON and verify exact authenticated identity authority."""

    try:
        data = _closed_authorization_object(payload)
        subject = _canonical_actor(data["subject"])
        authenticated = _canonical_actor(authenticated_subject)
        if subject != authenticated:
            raise ValueError
        claim = DeviceBindingAuthorizationClaim(
            schema=data["schema"],
            version=data["version"],
            binding_record_schema=data["bindingRecordSchema"],
            binding_record_version=data["bindingRecordVersion"],
            operation=data["operation"],
            subject=subject,
            device_id=data["deviceId"],
            algorithm=data["algorithm"],
            public_key=data["publicKey"],
            binding_version=data["bindingVersion"],
            binding_valid_from=_parse_timestamp(data["bindingValidFrom"]),
            binding_expires_at=_parse_timestamp(data["bindingExpiresAt"]),
            prior_binding_id=data["priorBindingId"],
            request_id=data["requestId"],
            issued_at=_parse_timestamp(data["issuedAt"]),
            expires_at=_parse_timestamp(data["expiresAt"]),
        )
        result = IdentitySignedDeviceBindingAuthorization(
            claim=claim,
            digest=data["digest"],
            signature_format=data["signatureFormat"],
            signature=data["signature"],
        )
        return _validated_signed_authorization(
            result,
            signature_verifier or Bip340IdentitySignatureVerifier(),
        )
    except Exception:
        raise DeviceBindingAuthorizationUnavailable() from None


def _validated_legacy_binding(value: object) -> MessagingDeviceBinding:
    if type(value) is not MessagingDeviceBinding:
        raise ValueError
    if value.active is not True or value.operation not in {"register", "rotate"}:
        raise ValueError
    subject = _canonical_actor(value.subject)
    if value.public_key == subject:
        raise ValueError
    binding_id = _hex64(value.binding_id)
    expected = messaging_device_binding_id(
        subject=subject,
        device_id=value.device_id,
        public_key=value.public_key,
        binding_version=value.binding_version,
        valid_from=value.valid_from,
        expires_at=value.expires_at,
        operation=value.operation,
        prior_binding_id=value.prior_binding_id,
        request_id=value.request_id,
    )
    if binding_id != expected:
        raise ValueError
    return MessagingDeviceBinding(
        subject=subject,
        device_id=value.device_id,
        binding_id=binding_id,
        public_key=value.public_key,
        binding_version=value.binding_version,
        valid_from=_utc_second(value.valid_from),
        expires_at=_utc_second(value.expires_at),
        operation=value.operation,
        prior_binding_id=value.prior_binding_id,
        request_id=value.request_id,
        active=True,
    )


def _binding_record_dict(binding: MessagingDeviceBinding) -> dict[str, object]:
    return json.loads(
        canonical_messaging_device_binding_record_bytes(
            subject=binding.subject,
            device_id=binding.device_id,
            public_key=binding.public_key,
            binding_version=binding.binding_version,
            valid_from=binding.valid_from,
            expires_at=binding.expires_at,
            operation=binding.operation,
            prior_binding_id=binding.prior_binding_id,
            request_id=binding.request_id,
        )
    )


def _validated_adoption_claim(value: object) -> DeviceBindingAdoptionClaim:
    if (
        type(value) is not DeviceBindingAdoptionClaim
        or type(value.schema) is not str
        or value.schema != ADOPTION_SCHEMA
        or type(value.version) is not int
        or value.version != VERSION
        or type(value.action) is not str
        or value.action != "adopt"
    ):
        raise ValueError
    request_id = _hex64(value.request_id)
    binding = _validated_legacy_binding(value.binding)
    if request_id == binding.request_id:
        raise ValueError
    issued_at = _utc_second(value.issued_at)
    expires_at = _utc_second(value.expires_at)
    if (
        issued_at >= expires_at
        or expires_at - issued_at > timedelta(seconds=MAX_AUTHORIZATION_WINDOW_SECONDS)
        or issued_at < binding.valid_from
        or issued_at >= binding.expires_at
        or expires_at > binding.expires_at
    ):
        raise ValueError
    return DeviceBindingAdoptionClaim(
        ADOPTION_SCHEMA,
        VERSION,
        "adopt",
        request_id,
        binding,
        issued_at,
        expires_at,
    )


def _adoption_claim_dict(value: DeviceBindingAdoptionClaim) -> dict[str, object]:
    return {
        "schema": value.schema,
        "version": value.version,
        "action": value.action,
        "bindingId": value.binding.binding_id,
        "bindingRecord": _binding_record_dict(value.binding),
        "requestId": value.request_id,
        "issuedAt": _timestamp(value.issued_at),
        "expiresAt": _timestamp(value.expires_at),
    }


def canonical_adoption_signed_bytes(value: DeviceBindingAdoptionClaim) -> bytes:
    """Return the exact domain-separated bytes signed for legacy adoption."""

    try:
        claim = _validated_adoption_claim(value)
        envelope = {"adoption": _adoption_claim_dict(claim), "domain": ADOPTION_SIGNATURE_DOMAIN}
        return json.dumps(
            envelope,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    except Exception:
        raise DeviceBindingAuthorizationUnavailable() from None


def adoption_digest(value: DeviceBindingAdoptionClaim) -> str:
    return hashlib.sha256(canonical_adoption_signed_bytes(value)).hexdigest()


def canonical_adoption_unsigned_event(value: DeviceBindingAdoptionClaim) -> dict[str, object]:
    """Return the closed NIP-07/NIP-46 input for one adoption carrier."""

    try:
        claim = _validated_adoption_claim(value)
        digest = adoption_digest(claim)
        carrier = _carrier_unsigned_event(
            pubkey=claim.binding.subject,
            issued_at=claim.issued_at,
            action=claim.action,
            digest=digest,
            request_id=claim.request_id,
            content=canonical_adoption_signed_bytes(claim),
        )
        carrier.pop("pubkey")
        return carrier
    except Exception:
        raise DeviceBindingAuthorizationUnavailable() from None


def canonical_adoption_event_serialization(value: DeviceBindingAdoptionClaim) -> bytes:
    """Return exact NIP-01 serialization bytes for one adoption carrier."""

    try:
        claim = _validated_adoption_claim(value)
        event = {"pubkey": claim.binding.subject, **canonical_adoption_unsigned_event(claim)}
        return _carrier_serialization(event)
    except Exception:
        raise DeviceBindingAuthorizationUnavailable() from None


def adoption_event_id(value: DeviceBindingAdoptionClaim) -> str:
    return hashlib.sha256(canonical_adoption_event_serialization(value)).hexdigest()


def _validated_signed_adoption(
    value: object,
    signature_verifier: IdentitySignatureVerifier,
) -> IdentitySignedDeviceBindingAdoption:
    if type(value) is not IdentitySignedDeviceBindingAdoption:
        raise ValueError
    claim = _validated_adoption_claim(value.claim)
    digest = _hex64(value.digest)
    if (
        type(value.signature_format) is not str
        or value.signature_format != SIGNATURE_FORMAT
        or type(value.signature) is not str
        or _HEX_128(value.signature) is None
        or digest != adoption_digest(claim)
        or signature_verifier.verify(
            subject=claim.binding.subject,
            signature=bytes.fromhex(value.signature),
            digest=bytes.fromhex(adoption_event_id(claim)),
        )
        is not True
    ):
        raise ValueError
    return IdentitySignedDeviceBindingAdoption(claim, digest, SIGNATURE_FORMAT, value.signature)


def canonical_adoption_json(value: IdentitySignedDeviceBindingAdoption) -> str:
    """Serialize an exact identity-signed legacy-binding adoption."""

    try:
        adoption = _validated_signed_adoption(value, Bip340IdentitySignatureVerifier())
        encoded = json.dumps(
            {
                **_adoption_claim_dict(adoption.claim),
                "digest": adoption.digest,
                "signatureFormat": adoption.signature_format,
                "signature": adoption.signature,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        if len(encoded.encode("ascii")) > MAX_AUTHORIZATION_BYTES:
            raise ValueError
        return encoded
    except Exception:
        raise DeviceBindingAuthorizationUnavailable() from None


def _binding_from_record(value: object, binding_id: object) -> MessagingDeviceBinding:
    if type(value) is not dict or set(value) != _BINDING_RECORD_FIELDS:
        raise ValueError
    if (
        value["schema"] != BINDING_RECORD_SCHEMA
        or type(value["version"]) is not int
        or value["version"] != BINDING_RECORD_VERSION
        or value["algorithm"] != ALGORITHM
    ):
        raise ValueError
    binding = MessagingDeviceBinding(
        subject=value["subject"],
        device_id=value["deviceId"],
        binding_id=_hex64(binding_id),
        public_key=value["publicKey"],
        binding_version=value["bindingVersion"],
        valid_from=_parse_timestamp(value["validFrom"]),
        expires_at=_parse_timestamp(value["expiresAt"]),
        operation=value["operation"],
        prior_binding_id=value["priorBindingId"],
        request_id=value["requestId"],
        active=True,
    )
    validated = _validated_legacy_binding(binding)
    if _binding_record_dict(validated) != value:
        raise ValueError
    return validated


def parse_and_verify_device_binding_adoption(
    payload: object,
    *,
    authenticated_subject: object,
    signature_verifier: IdentitySignatureVerifier | None = None,
) -> IdentitySignedDeviceBindingAdoption:
    """Parse and verify one exact current legacy-binding attestation."""

    try:
        data = _closed_signed_object(payload, _ADOPTION_FIELDS)
        binding = _binding_from_record(data["bindingRecord"], data["bindingId"])
        if binding.subject != _canonical_actor(authenticated_subject):
            raise ValueError
        claim = DeviceBindingAdoptionClaim(
            schema=data["schema"],
            version=data["version"],
            action=data["action"],
            request_id=data["requestId"],
            binding=binding,
            issued_at=_parse_timestamp(data["issuedAt"]),
            expires_at=_parse_timestamp(data["expiresAt"]),
        )
        adoption = IdentitySignedDeviceBindingAdoption(
            claim,
            data["digest"],
            data["signatureFormat"],
            data["signature"],
        )
        return _validated_signed_adoption(
            adoption,
            signature_verifier or Bip340IdentitySignatureVerifier(),
        )
    except Exception:
        raise DeviceBindingAuthorizationUnavailable() from None


def _authorized_from(
    authorization: IdentitySignedDeviceBindingAuthorization,
) -> AuthorizedDeviceBinding:
    claim = authorization.claim
    active = claim.operation != "revoke"
    binding = MessagingDeviceBinding(
        subject=claim.subject,
        device_id=claim.device_id,
        binding_id=authorization.binding_id,
        public_key=claim.public_key,
        binding_version=claim.binding_version,
        valid_from=claim.binding_valid_from,
        expires_at=claim.binding_expires_at,
        operation=claim.operation,
        prior_binding_id=claim.prior_binding_id,
        request_id=claim.request_id,
        active=active,
    )
    verification = VerifiedBindingAuthorization(
        proof_id=PROOF_ID_PREFIX + authorization.digest,
        subject=claim.subject,
        device_id=claim.device_id,
        binding_id=authorization.binding_id,
        binding_version=claim.binding_version,
        public_key=claim.public_key,
        valid_from=claim.binding_valid_from,
        expires_at=claim.binding_expires_at,
        evidence_valid_from=claim.issued_at,
        evidence_expires_at=claim.binding_expires_at,
    )
    return AuthorizedDeviceBinding(authorization, binding, verification)


def _adopted_from(
    adoption: IdentitySignedDeviceBindingAdoption,
) -> AdoptedDeviceBindingAuthorization:
    binding = adoption.claim.binding
    verification = VerifiedBindingAuthorization(
        proof_id=PROOF_ID_PREFIX + adoption.digest,
        subject=binding.subject,
        device_id=binding.device_id,
        binding_id=binding.binding_id,
        binding_version=binding.binding_version,
        public_key=binding.public_key,
        valid_from=binding.valid_from,
        expires_at=binding.expires_at,
        evidence_valid_from=adoption.claim.issued_at,
        evidence_expires_at=binding.expires_at,
    )
    return AdoptedDeviceBindingAuthorization(adoption, binding, verification)


def _validated_authorized(
    value: object,
    signature_verifier: IdentitySignatureVerifier,
) -> AuthorizedDeviceBinding:
    if type(value) is not AuthorizedDeviceBinding:
        raise ValueError
    authorization = _validated_signed_authorization(value.authorization, signature_verifier)
    expected = _authorized_from(authorization)
    if value != expected:
        raise ValueError
    return expected


def _validated_adopted(
    value: object,
    signature_verifier: IdentitySignatureVerifier,
) -> AdoptedDeviceBindingAuthorization:
    if type(value) is not AdoptedDeviceBindingAuthorization:
        raise ValueError
    adoption = _validated_signed_adoption(value.adoption, signature_verifier)
    expected = _adopted_from(adoption)
    if value != expected:
        raise ValueError
    return expected


def _validated_evidence(
    value: object,
    signature_verifier: IdentitySignatureVerifier,
) -> BindingAuthorizationEvidence:
    if type(value) is AuthorizedDeviceBinding:
        return _validated_authorized(value, signature_verifier)
    if type(value) is AdoptedDeviceBindingAuthorization:
        return _validated_adopted(value, signature_verifier)
    raise ValueError


def _validated_device_state(
    value: object,
    *,
    subject: str,
    device_id: str,
    now: datetime,
    signature_verifier: IdentitySignatureVerifier,
) -> tuple[BindingAuthorizationEvidence, ...]:
    if (
        type(value) is not CurrentDeviceBindingState
        or value.schema != STATE_SCHEMA
        or type(value.schema) is not str
        or value.version != VERSION
        or type(value.version) is not int
        or value.subject != subject
        or value.device_id != device_id
        or value.complete is not True
        or value.truncated is not False
        or type(value.records) is not tuple
        or len(value.records) >= MAX_STATE_RECORDS
    ):
        raise ValueError
    records = tuple(_validated_evidence(item, signature_verifier) for item in value.records)
    if any(
        item.binding.subject != subject
        or item.binding.device_id != device_id
        or item.binding.active is not True
        or item.binding.operation not in {"register", "rotate"}
        or item.binding.valid_from > now
        or now >= item.binding.expires_at
        or item.verification.evidence_valid_from > now
        or now >= item.verification.evidence_expires_at
        for item in records
    ):
        raise ValueError
    if len({item.binding.binding_id for item in records}) != len(records):
        raise ValueError
    return records


def _validated_subject_state(
    value: object,
    *,
    subject: str,
    now: datetime,
    signature_verifier: IdentitySignatureVerifier,
) -> tuple[BindingAuthorizationEvidence, ...]:
    if (
        type(value) is not CurrentSubjectBindingState
        or value.schema != STATE_SCHEMA
        or type(value.schema) is not str
        or value.version != VERSION
        or type(value.version) is not int
        or value.subject != subject
        or type(value.subject) is not str
        or value.complete is not True
        or value.truncated is not False
        or type(value.records) is not tuple
        or len(value.records) > MAX_ACTIVE_DEVICES
    ):
        raise ValueError
    records = tuple(_validated_evidence(item, signature_verifier) for item in value.records)
    if any(
        item.binding.subject != subject
        or item.binding.active is not True
        or item.binding.operation not in {"register", "rotate"}
        or item.binding.valid_from > now
        or now >= item.binding.expires_at
        or item.verification.evidence_valid_from > now
        or now >= item.verification.evidence_expires_at
        for item in records
    ):
        raise ValueError
    for attribute in ("device_id", "binding_id", "public_key"):
        if len({getattr(item.binding, attribute) for item in records}) != len(records):
            raise ValueError
    return records


def _validated_public_key_state(
    value: object,
    *,
    public_key: str,
    now: datetime,
    signature_verifier: IdentitySignatureVerifier,
) -> tuple[BindingAuthorizationEvidence, ...]:
    if (
        type(value) is not CurrentPublicKeyBindingState
        or value.schema != STATE_SCHEMA
        or type(value.schema) is not str
        or value.version != VERSION
        or type(value.version) is not int
        or value.public_key != public_key
        or value.complete is not True
        or value.truncated is not False
        or type(value.records) is not tuple
        or len(value.records) >= MAX_STATE_RECORDS
    ):
        raise ValueError
    records = tuple(_validated_evidence(item, signature_verifier) for item in value.records)
    if any(
        item.binding.public_key != public_key
        or item.binding.active is not True
        or item.binding.operation not in {"register", "rotate"}
        or item.binding.valid_from > now
        or now >= item.binding.expires_at
        or item.verification.evidence_valid_from > now
        or now >= item.verification.evidence_expires_at
        for item in records
    ):
        raise ValueError
    if len({item.binding.binding_id for item in records}) != len(records):
        raise ValueError
    return records


def _validated_binding_id_state(
    value: object,
    *,
    binding_id: str,
    signature_verifier: IdentitySignatureVerifier,
) -> tuple[BindingAuthorizationEvidence, ...]:
    if (
        type(value) is not BindingAuthorizationEvidenceState
        or value.schema != STATE_SCHEMA
        or type(value.schema) is not str
        or value.version != VERSION
        or type(value.version) is not int
        or value.binding_id != binding_id
        or value.complete is not True
        or value.truncated is not False
        or type(value.records) is not tuple
        or len(value.records) >= MAX_STATE_RECORDS
    ):
        raise ValueError
    records = tuple(_validated_evidence(item, signature_verifier) for item in value.records)
    if any(item.binding.binding_id != binding_id for item in records):
        raise ValueError
    if len({item.verification.proof_id for item in records}) != len(records):
        raise ValueError
    return records


def _validated_replay(
    value: object,
    *,
    candidate: AuthorizedDeviceBinding,
    signature_verifier: IdentitySignatureVerifier,
) -> AuthorizationReplayRecord:
    if type(value) is not AuthorizationReplayRecord:
        raise ValueError
    request_id = _hex64(value.request_id)
    digest = _hex64(value.authorization_digest)
    authorized = _validated_authorized(value.authorized_binding, signature_verifier)
    if (
        request_id != candidate.authorization.claim.request_id
        or digest != candidate.authorization.digest
        or authorized != candidate
    ):
        raise ValueError
    return AuthorizationReplayRecord(request_id, digest, authorized)


def _validated_adoption_replay(
    value: object,
    *,
    candidate: AdoptedDeviceBindingAuthorization,
    signature_verifier: IdentitySignatureVerifier,
) -> AdoptionReplayRecord:
    if type(value) is not AdoptionReplayRecord:
        raise ValueError
    request_id = _hex64(value.request_id)
    digest = _hex64(value.adoption_digest)
    adopted = _validated_adopted(value.adopted_binding, signature_verifier)
    if request_id != candidate.adoption.claim.request_id or digest != candidate.adoption.digest or adopted != candidate:
        raise ValueError
    return AdoptionReplayRecord(request_id, digest, adopted)


class SocialMessagingDeviceBindingAuthorizationV1:
    """Authorize one exact lifecycle edge without applying or persisting it."""

    def __init__(
        self,
        *,
        state_provider: DeviceBindingAuthorizationStateProvider,
        replay_ledger: AuthorizationReplayLedger,
        signature_verifier: IdentitySignatureVerifier | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        signature_verifier = signature_verifier or Bip340IdentitySignatureVerifier()
        if (
            not callable(getattr(state_provider, "current_for_subject", None))
            or not callable(getattr(state_provider, "current_for_device", None))
            or not callable(getattr(state_provider, "current_for_public_key", None))
            or not callable(getattr(state_provider, "authorization_for_binding", None))
            or not callable(getattr(replay_ledger, "get", None))
            or not callable(getattr(replay_ledger, "record", None))
            or not callable(getattr(signature_verifier, "verify", None))
            or clock is not None
            and not callable(clock)
        ):
            raise ValueError("invalid device binding authorization dependency")
        self._state_provider = state_provider
        self._replay_ledger = replay_ledger
        self._signature_verifier = signature_verifier
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def authorize(
        self,
        payload: object,
        *,
        authenticated_subject: object,
    ) -> AuthorizedDeviceBinding:
        try:
            authorization = parse_and_verify_device_binding_authorization(
                payload,
                authenticated_subject=authenticated_subject,
                signature_verifier=self._signature_verifier,
            )
            claim = authorization.claim
            now = _trusted_utc_second(self._clock())
            if (
                claim.issued_at > now
                or now >= claim.expires_at
                or claim.binding_valid_from > now
                or now >= claim.binding_expires_at
            ):
                raise ValueError
            candidate = _authorized_from(authorization)

            replay = self._replay_ledger.get(claim.request_id)
            if replay is not None:
                return _validated_replay(
                    replay,
                    candidate=candidate,
                    signature_verifier=self._signature_verifier,
                ).authorized_binding

            binding_id_records = _validated_binding_id_state(
                self._state_provider.authorization_for_binding(
                    authorization.binding_id,
                    now=now,
                    maximum=MAX_STATE_RECORDS,
                ),
                binding_id=authorization.binding_id,
                signature_verifier=self._signature_verifier,
            )
            if binding_id_records or authorization.binding_id == claim.prior_binding_id:
                raise ValueError

            device_records = _validated_device_state(
                self._state_provider.current_for_device(
                    claim.subject,
                    claim.device_id,
                    now=now,
                    maximum=MAX_STATE_RECORDS,
                ),
                subject=claim.subject,
                device_id=claim.device_id,
                now=now,
                signature_verifier=self._signature_verifier,
            )
            subject_records = _validated_subject_state(
                self._state_provider.current_for_subject(
                    claim.subject,
                    now=now,
                    maximum=MAX_ACTIVE_DEVICES + 1,
                ),
                subject=claim.subject,
                now=now,
                signature_verifier=self._signature_verifier,
            )

            if claim.operation == "register":
                key_records = _validated_public_key_state(
                    self._state_provider.current_for_public_key(
                        claim.public_key,
                        now=now,
                        maximum=MAX_STATE_RECORDS,
                    ),
                    public_key=claim.public_key,
                    now=now,
                    signature_verifier=self._signature_verifier,
                )
                if (
                    len(subject_records) >= MAX_ACTIVE_DEVICES
                    or device_records
                    or key_records
                    or any(
                        item.binding.device_id == claim.device_id
                        or item.binding.public_key == claim.public_key
                        or item.binding.binding_id == authorization.binding_id
                        for item in subject_records
                    )
                ):
                    raise ValueError
            else:
                if len(device_records) != 1:
                    raise ValueError
                current = device_records[0]
                binding = current.binding
                predecessor_key_records = _validated_public_key_state(
                    self._state_provider.current_for_public_key(
                        binding.public_key,
                        now=now,
                        maximum=MAX_STATE_RECORDS,
                    ),
                    public_key=binding.public_key,
                    now=now,
                    signature_verifier=self._signature_verifier,
                )
                if (
                    sum(item == current for item in subject_records) != 1
                    or predecessor_key_records != (current,)
                    or binding.binding_id != claim.prior_binding_id
                    or binding.binding_version + 1 != claim.binding_version
                    or claim.binding_expires_at > binding.expires_at
                    or claim.binding_valid_from < binding.valid_from
                ):
                    raise ValueError
                if claim.operation == "rotate":
                    proposed_key_records = _validated_public_key_state(
                        self._state_provider.current_for_public_key(
                            claim.public_key,
                            now=now,
                            maximum=MAX_STATE_RECORDS,
                        ),
                        public_key=claim.public_key,
                        now=now,
                        signature_verifier=self._signature_verifier,
                    )
                    if claim.public_key == binding.public_key or proposed_key_records:
                        raise ValueError
                elif claim.public_key != binding.public_key or claim.binding_expires_at != binding.expires_at:
                    raise ValueError

            record = AuthorizationReplayRecord(
                request_id=claim.request_id,
                authorization_digest=authorization.digest,
                authorized_binding=candidate,
            )
            retained = self._replay_ledger.record(record)
            return _validated_replay(
                retained,
                candidate=candidate,
                signature_verifier=self._signature_verifier,
            ).authorized_binding
        except DeviceBindingAuthorizationUnavailable:
            raise
        except Exception:
            raise DeviceBindingAuthorizationUnavailable() from None


def _validated_current_full(
    value: object,
    *,
    subject: str,
    now: datetime,
) -> VerifiedCurrentFullEntitlement:
    return validate_verified_current_full_entitlement(
        value,
        subject=subject,
        now=now,
    )


def _validated_legacy_state(
    value: object,
    *,
    subject: str,
    binding_id: str,
    now: datetime,
) -> tuple[MessagingDeviceBinding, ...]:
    if (
        type(value) is not CurrentLegacyDeviceBindingState
        or type(value.schema) is not str
        or value.schema != STATE_SCHEMA
        or type(value.version) is not int
        or value.version != VERSION
        or value.subject != subject
        or value.binding_id != binding_id
        or value.complete is not True
        or value.truncated is not False
        or type(value.records) is not tuple
        or len(value.records) > MAX_STATE_RECORDS
    ):
        raise ValueError
    records = tuple(_validated_legacy_binding(item) for item in value.records)
    if any(
        item.subject != subject or item.binding_id != binding_id or item.valid_from > now or now >= item.expires_at
        for item in records
    ):
        raise ValueError
    return records


class SocialMessagingLegacyBindingAdoptionV1:
    """Attest to one exact existing binding without mutating its key or row."""

    def __init__(
        self,
        *,
        state_provider: LegacyDeviceBindingAdoptionStateProvider,
        current_full_prerequisite: TransactionBoundCurrentFullEntitlementVerifier,
        replay_ledger: AuthorizationReplayLedger,
        signature_verifier: IdentitySignatureVerifier | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        signature_verifier = signature_verifier or Bip340IdentitySignatureVerifier()
        if (
            not callable(getattr(state_provider, "current_legacy_binding", None))
            or not callable(getattr(state_provider, "authorization_for_binding", None))
            or not callable(getattr(current_full_prerequisite, "verify_in_transaction", None))
            or not callable(getattr(replay_ledger, "get", None))
            or not callable(getattr(replay_ledger, "record", None))
            or not callable(getattr(signature_verifier, "verify", None))
            or clock is not None
            and not callable(clock)
        ):
            raise ValueError("invalid legacy binding adoption dependency")
        self._state_provider = state_provider
        self._current_full_prerequisite = current_full_prerequisite
        self._replay_ledger = replay_ledger
        self._signature_verifier = signature_verifier
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def adopt(
        self,
        payload: object,
        *,
        authenticated_subject: object,
    ) -> AdoptedDeviceBindingAuthorization:
        try:
            adoption = parse_and_verify_device_binding_adoption(
                payload,
                authenticated_subject=authenticated_subject,
                signature_verifier=self._signature_verifier,
            )
            claim = adoption.claim
            binding = claim.binding
            now = _trusted_utc_second(self._clock())
            if (
                claim.issued_at > now
                or now >= claim.expires_at
                or binding.valid_from > now
                or now >= binding.expires_at
            ):
                raise ValueError
            candidate = _adopted_from(adoption)

            replay = self._replay_ledger.get(claim.request_id)
            if replay is not None:
                return _validated_adoption_replay(
                    replay,
                    candidate=candidate,
                    signature_verifier=self._signature_verifier,
                ).adopted_binding

            _validated_current_full(
                self._current_full_prerequisite.verify_in_transaction(binding.subject, now=now),
                subject=binding.subject,
                now=now,
            )
            current = _validated_legacy_state(
                self._state_provider.current_legacy_binding(
                    binding.subject,
                    binding.binding_id,
                    now=now,
                    maximum=MAX_STATE_RECORDS,
                ),
                subject=binding.subject,
                binding_id=binding.binding_id,
                now=now,
            )
            if current != (binding,):
                raise ValueError
            existing = _validated_binding_id_state(
                self._state_provider.authorization_for_binding(
                    binding.binding_id,
                    now=now,
                    maximum=MAX_STATE_RECORDS,
                ),
                binding_id=binding.binding_id,
                signature_verifier=self._signature_verifier,
            )
            if existing:
                raise ValueError
            record = AdoptionReplayRecord(
                request_id=claim.request_id,
                adoption_digest=adoption.digest,
                adopted_binding=candidate,
            )
            retained = self._replay_ledger.record(record)
            return _validated_adoption_replay(
                retained,
                candidate=candidate,
                signature_verifier=self._signature_verifier,
            ).adopted_binding
        except DeviceBindingAuthorizationUnavailable:
            raise
        except Exception:
            raise DeviceBindingAuthorizationUnavailable() from None


class IdentitySignedBindingAuthorizationVerifier:
    """Adapter implementing the recipient-routing authorization verifier port."""

    def __init__(
        self,
        evidence_provider: BindingAuthorizationEvidenceProvider,
        *,
        signature_verifier: IdentitySignatureVerifier | None = None,
    ) -> None:
        signature_verifier = signature_verifier or Bip340IdentitySignatureVerifier()
        if not callable(getattr(evidence_provider, "authorization_for_binding", None)) or not callable(
            getattr(signature_verifier, "verify", None)
        ):
            raise ValueError("invalid binding authorization verifier dependency")
        self._evidence_provider = evidence_provider
        self._signature_verifier = signature_verifier

    def verify(
        self,
        binding: MessagingDeviceBinding,
        *,
        now: datetime,
    ) -> VerifiedBindingAuthorization:
        try:
            if type(binding) is not MessagingDeviceBinding:
                raise ValueError
            normalized_now = _utc_second(now)
            binding_id = _hex64(binding.binding_id)
            state = self._evidence_provider.authorization_for_binding(
                binding_id,
                now=normalized_now,
                maximum=MAX_STATE_RECORDS,
            )
            if (
                type(state) is not BindingAuthorizationEvidenceState
                or state.schema != STATE_SCHEMA
                or type(state.schema) is not str
                or state.version != VERSION
                or type(state.version) is not int
                or state.binding_id != binding_id
                or state.complete is not True
                or state.truncated is not False
                or type(state.records) is not tuple
                or len(state.records) != 1
            ):
                raise ValueError
            authorized = _validated_evidence(state.records[0], self._signature_verifier)
            evidence_valid_from = _utc_second(authorized.verification.evidence_valid_from)
            evidence_expires_at = _utc_second(authorized.verification.evidence_expires_at)
            if (
                authorized.binding != binding
                or binding.active is not True
                or binding.operation not in {"register", "rotate"}
                or binding.valid_from > normalized_now
                or normalized_now >= binding.expires_at
                or evidence_valid_from > normalized_now
                or normalized_now >= evidence_expires_at
            ):
                raise ValueError
            return authorized.verification
        except Exception:
            raise DeviceBindingAuthorizationUnavailable() from None


__all__ = [
    "ADOPTION_SCHEMA",
    "ADOPTION_SIGNATURE_DOMAIN",
    "AUTHORIZATION_SCHEMA",
    "AdoptedDeviceBindingAuthorization",
    "AdoptionReplayRecord",
    "AuthorizationReplayLedger",
    "AuthorizationReplayRecord",
    "AuthorizedDeviceBinding",
    "BindingAuthorizationEvidence",
    "BindingAuthorizationEvidenceProvider",
    "BindingAuthorizationEvidenceState",
    "Bip340IdentitySignatureVerifier",
    "CurrentDeviceBindingState",
    "TransactionBoundCurrentFullEntitlementVerifier",
    "CurrentLegacyDeviceBindingState",
    "CurrentPublicKeyBindingState",
    "CurrentSubjectBindingState",
    "DeviceBindingAdoptionClaim",
    "DeviceBindingAuthorizationClaim",
    "DeviceBindingAuthorizationStateProvider",
    "DeviceBindingAuthorizationUnavailable",
    "IdentitySignatureVerifier",
    "IdentitySignedDeviceBindingAdoption",
    "IdentitySignedBindingAuthorizationVerifier",
    "IdentitySignedDeviceBindingAuthorization",
    "LegacyDeviceBindingAdoptionStateProvider",
    "MAX_AUTHORIZATION_BYTES",
    "MAX_AUTHORIZATION_WINDOW_SECONDS",
    "MAX_STATE_RECORDS",
    "NOSTR_EVENT_KIND",
    "NOSTR_EVENT_PURPOSE",
    "PROOF_ID_PREFIX",
    "SIGNATURE_DOMAIN",
    "SIGNATURE_FORMAT",
    "STATE_SCHEMA",
    "SocialMessagingLegacyBindingAdoptionV1",
    "SocialMessagingDeviceBindingAuthorizationV1",
    "UNAVAILABLE_MESSAGE",
    "VERSION",
    "adoption_digest",
    "adoption_event_id",
    "authorization_digest",
    "authorization_event_id",
    "canonical_adoption_event_serialization",
    "canonical_adoption_json",
    "canonical_adoption_signed_bytes",
    "canonical_adoption_unsigned_event",
    "canonical_authorization_event_serialization",
    "canonical_authorization_json",
    "canonical_authorization_signed_bytes",
    "canonical_authorization_unsigned_event",
    "parse_and_verify_device_binding_adoption",
    "parse_and_verify_device_binding_authorization",
]
