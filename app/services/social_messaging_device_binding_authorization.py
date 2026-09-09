"""Dormant identity-signed Social messaging device authorization contract.

The module is deliberately infrastructure-free.  It verifies exact BIP-340
identity signatures, coordinates injected complete-state and replay ports, and
provides a verifier compatible with the dormant recipient-routing gate.  It
does not expose a route or implement persistence.
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
from app.services.full_recipient_directory_provider import validate_x25519_public_key
from app.services.social_messaging_device_contract import (
    ALGORITHM,
    MAX_ACTIVE_DEVICES,
    MAX_BINDING_VERSION,
    MessagingDeviceBinding,
)
from app.services.social_messaging_recipient_routing import VerifiedBindingAuthorization

AUTHORIZATION_SCHEMA = "hodlxxi.social_messaging_device_binding_authorization.v1"
STATE_SCHEMA = "hodlxxi.social_messaging_device_binding_authorization_state.v1"
SIGNATURE_DOMAIN = "HODLXXI_SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_V1"
SIGNATURE_FORMAT = "bip340_schnorr_sha256"
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


class DeviceBindingAuthorizationUnavailable(RuntimeError):
    """The sole public error crossing this contract boundary."""

    def __init__(self) -> None:
        super().__init__(UNAVAILABLE_MESSAGE)


@dataclass(frozen=True)
class DeviceBindingAuthorizationClaim:
    schema: str
    version: int
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
        """The server-derived identifier for this exact signed lifecycle edge."""

        return self.digest


@dataclass(frozen=True)
class AuthorizedDeviceBinding:
    authorization: IdentitySignedDeviceBindingAuthorization
    binding: MessagingDeviceBinding
    verification: VerifiedBindingAuthorization


@dataclass(frozen=True)
class CurrentDeviceBindingState:
    schema: str
    version: int
    subject: str
    device_id: str
    complete: bool
    truncated: bool
    records: tuple[AuthorizedDeviceBinding, ...]


@dataclass(frozen=True)
class CurrentSubjectBindingState:
    schema: str
    version: int
    subject: str
    complete: bool
    truncated: bool
    records: tuple[AuthorizedDeviceBinding, ...]


@dataclass(frozen=True)
class CurrentPublicKeyBindingState:
    schema: str
    version: int
    public_key: str
    complete: bool
    truncated: bool
    records: tuple[AuthorizedDeviceBinding, ...]


@dataclass(frozen=True)
class BindingAuthorizationEvidenceState:
    schema: str
    version: int
    binding_id: str
    complete: bool
    truncated: bool
    records: tuple[AuthorizedDeviceBinding, ...]


@dataclass(frozen=True)
class AuthorizationReplayRecord:
    request_id: str
    authorization_digest: str
    authorized_binding: AuthorizedDeviceBinding


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


class AuthorizationReplayLedger(Protocol):
    """Future atomic request-ID ledger.

    ``get`` must fail instead of choosing among duplicate records. ``record``
    must atomically retain an absent request ID, return the exact existing
    record for an equal retry, and reject a different digest or result.
    """

    def get(self, request_id: str) -> AuthorizationReplayRecord | None: ...

    def record(self, record: AuthorizationReplayRecord) -> AuthorizationReplayRecord: ...


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


def _claim_dict(value: DeviceBindingAuthorizationClaim) -> dict[str, object]:
    return {
        "schema": value.schema,
        "version": value.version,
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
        or value.operation in {"register", "rotate"}
        and binding_valid_from != issued_at
    ):
        raise ValueError
    return DeviceBindingAuthorizationClaim(
        AUTHORIZATION_SCHEMA,
        VERSION,
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
        digest=bytes.fromhex(digest),
    )
    if verified is not True:
        raise ValueError
    return IdentitySignedDeviceBindingAuthorization(claim, digest, SIGNATURE_FORMAT, value.signature)


def _closed_authorization_object(payload: object) -> dict[str, object]:
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
    if type(decoded) is not dict or set(decoded) != _AUTHORIZATION_FIELDS:
        raise ValueError
    canonical = json.dumps(decoded, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if payload != canonical:
        raise ValueError
    return decoded


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


def _validated_device_state(
    value: object,
    *,
    subject: str,
    device_id: str,
    now: datetime,
    signature_verifier: IdentitySignatureVerifier,
) -> tuple[AuthorizedDeviceBinding, ...]:
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
    records = tuple(_validated_authorized(item, signature_verifier) for item in value.records)
    if any(
        item.binding.subject != subject
        or item.binding.device_id != device_id
        or item.binding.active is not True
        or item.binding.operation not in {"register", "rotate"}
        or item.binding.valid_from > now
        or now >= item.binding.expires_at
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
) -> tuple[AuthorizedDeviceBinding, ...]:
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
    records = tuple(_validated_authorized(item, signature_verifier) for item in value.records)
    if any(
        item.binding.subject != subject
        or item.binding.active is not True
        or item.binding.operation not in {"register", "rotate"}
        or item.binding.valid_from > now
        or now >= item.binding.expires_at
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
) -> tuple[AuthorizedDeviceBinding, ...]:
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
    records = tuple(_validated_authorized(item, signature_verifier) for item in value.records)
    if any(
        item.binding.public_key != public_key
        or item.binding.active is not True
        or item.binding.operation not in {"register", "rotate"}
        or item.binding.valid_from > now
        or now >= item.binding.expires_at
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
) -> tuple[AuthorizedDeviceBinding, ...]:
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
    records = tuple(_validated_authorized(item, signature_verifier) for item in value.records)
    if any(item.binding.binding_id != binding_id for item in records):
        raise ValueError
    if len({item.authorization.digest for item in records}) != len(records):
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
                elif (
                    claim.public_key != binding.public_key
                    or claim.binding_valid_from != binding.valid_from
                    or claim.binding_expires_at != binding.expires_at
                ):
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
            authorized = _validated_authorized(state.records[0], self._signature_verifier)
            if (
                authorized.binding != binding
                or binding.active is not True
                or binding.operation not in {"register", "rotate"}
                or binding.valid_from > normalized_now
                or normalized_now >= binding.expires_at
            ):
                raise ValueError
            return authorized.verification
        except Exception:
            raise DeviceBindingAuthorizationUnavailable() from None


__all__ = [
    "AUTHORIZATION_SCHEMA",
    "AuthorizationReplayLedger",
    "AuthorizationReplayRecord",
    "AuthorizedDeviceBinding",
    "BindingAuthorizationEvidenceProvider",
    "BindingAuthorizationEvidenceState",
    "Bip340IdentitySignatureVerifier",
    "CurrentDeviceBindingState",
    "CurrentPublicKeyBindingState",
    "CurrentSubjectBindingState",
    "DeviceBindingAuthorizationClaim",
    "DeviceBindingAuthorizationStateProvider",
    "DeviceBindingAuthorizationUnavailable",
    "IdentitySignatureVerifier",
    "IdentitySignedBindingAuthorizationVerifier",
    "IdentitySignedDeviceBindingAuthorization",
    "MAX_AUTHORIZATION_BYTES",
    "MAX_AUTHORIZATION_WINDOW_SECONDS",
    "MAX_STATE_RECORDS",
    "PROOF_ID_PREFIX",
    "SIGNATURE_DOMAIN",
    "SIGNATURE_FORMAT",
    "STATE_SCHEMA",
    "SocialMessagingDeviceBindingAuthorizationV1",
    "UNAVAILABLE_MESSAGE",
    "VERSION",
    "authorization_digest",
    "canonical_authorization_json",
    "canonical_authorization_signed_bytes",
    "parse_and_verify_device_binding_authorization",
]
