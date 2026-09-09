"""Dormant V1 contract for confidential Social recipient routing.

This module is deliberately infrastructure-free.  It defines the exact
validation, authority ports, immutable internal records, and fail-closed
decision logic needed before a future atomic repository and HTTP adapter can
be implemented.  Nothing in this module is wired into the application.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Protocol

from app.auth_api_core import canonical_xonly_pubkey
from app.services.current_full_entitlement_proof import (
    VerifiedCurrentFullEntitlement,
    validate_verified_current_full_entitlement,
)
from app.services.full_recipient_directory_provider import validate_x25519_public_key
from app.services.privacy_safe_full_directory import (
    MAX_ALIAS_SECRET_BYTES,
    MAX_ALIAS_VERSION,
    MIN_ALIAS_SECRET_BYTES,
    derive_privacy_directory_alias,
)
from app.services.social_messaging_device_contract import (
    ALGORITHM,
    MAX_ACTIVE_DEVICES,
    MAX_BINDING_VERSION,
    MessagingDeviceBinding,
)

REQUEST_SCHEMA = "hodlxxi.social_messaging_recipient_routing_request.v1"
SNAPSHOT_SCHEMA = "hodlxxi.social_messaging_recipient_routing_snapshot.v1"
DECISION_SCHEMA = "hodlxxi.social_messaging_recipient_routing_decision.v1"
RECIPIENT_PACKAGE_SCHEMA = "hodlxxi.social_messaging_recipient_package.v1"
SOURCE = "hodlxxi-ubid"
VERSION = 1

DEVICE_HANDLE_DOMAIN = b"HODLXXI_RECIPIENT_DEVICE_HANDLE_V1"
DEVICE_HANDLE_BYTES = 16
MAX_REQUEST_BYTES = 2_048
MAX_INTERNAL_SNAPSHOT_BYTES = 16_384
MAX_INTERNAL_DECISION_BYTES = 8_192
MAX_SNAPSHOT_VALIDITY_MS = 300_000
MAX_SAFE_INTEGER = 9_007_199_254_740_991
UNAVAILABLE_MESSAGE = "recipient messaging routing unavailable"

_HEX_64 = re.compile(r"[0-9a-f]{64}\Z").fullmatch
_DEVICE_HANDLE = re.compile(r"d_[A-Za-z0-9_-]{22}\Z").fullmatch
_ALIAS = re.compile(r"p_[A-Za-z0-9_-]{22}\Z").fullmatch
_SNAPSHOT_ID = re.compile(r"sha256:[0-9a-f]{64}\Z").fullmatch
_MESSAGE_ID = re.compile(r"m_[A-Za-z0-9_-]{43}\Z").fullmatch
_ENVELOPE_DIGEST = re.compile(r"hodlxxi-social-message-envelope-v1-sha256:[0-9a-f]{64}\Z").fullmatch
_BINDING_PROOF_ID = re.compile(r"hodlxxi-binding-authorization-v1-sha256:[0-9a-f]{64}\Z").fullmatch
_FULL_PROOF_ID = re.compile(r"hodlxxi-full-entitlement-v1-sha256:[0-9a-f]{64}\Z").fullmatch
_REQUEST_FIELDS = {
    "envelopeDigest",
    "messageId",
    "recipientDeviceHandles",
    "recipientPackageSnapshotId",
    "schema",
    "version",
}
_PACKAGE_FIELDS = {
    "schema",
    "version",
    "source",
    "snapshotId",
    "complete",
    "alias",
    "issuedAt",
    "expiresAt",
    "devices",
}
_PACKAGE_DEVICE_FIELDS = {
    "deviceHandle",
    "algorithm",
    "version",
    "publicKey",
    "validFrom",
    "expiresAt",
}


class RecipientMessagingRoutingUnavailable(RuntimeError):
    """The sole error crossing this dormant routing boundary."""

    def __init__(self) -> None:
        super().__init__(UNAVAILABLE_MESSAGE)


@dataclass(frozen=True)
class VerifiedBindingAuthorization:
    """Strict output of a future independent binding-authorization verifier."""

    proof_id: str
    subject: str
    device_id: str
    binding_id: str
    binding_version: int
    public_key: str
    valid_from: datetime
    expires_at: datetime
    evidence_valid_from: datetime
    evidence_expires_at: datetime


@dataclass(frozen=True)
class RecipientRoutingSnapshotRoute:
    device_handle: str
    device_id: str
    binding_id: str
    binding_version: int
    authorization_proof_id: str
    authorization_valid_from: int
    authorization_expires_at: int


@dataclass(frozen=True)
class RecipientRoutingSnapshot:
    schema: str
    version: int
    source: str
    viewer_subject: str
    recipient_subject: str
    alias_version: int
    recipient_package_snapshot_id: str
    issued_at: int
    expires_at: int
    complete: bool
    routes: tuple[RecipientRoutingSnapshotRoute, ...]


@dataclass(frozen=True)
class RecipientRoutingRequest:
    schema: str
    version: int
    message_id: str
    envelope_digest: str
    recipient_package_snapshot_id: str
    recipient_device_handles: tuple[str, ...]


@dataclass(frozen=True)
class RecipientRoutingDecisionRoute:
    device_handle: str
    device_id: str
    binding_id: str
    binding_version: int


@dataclass(frozen=True)
class RecipientRoutingDecision:
    schema: str
    version: int
    source: str
    message_id: str
    envelope_digest: str
    recipient_package_snapshot_id: str
    viewer_subject: str
    recipient_subject: str
    complete: bool
    expires_at: int
    routes: tuple[RecipientRoutingDecisionRoute, ...]


class BindingAuthorizationVerifier(Protocol):
    def verify(
        self,
        binding: MessagingDeviceBinding,
        *,
        now: datetime,
    ) -> VerifiedBindingAuthorization: ...


class CurrentFullEntitlementVerifier(Protocol):
    def verify(
        self,
        subject: str,
        *,
        now: datetime,
    ) -> VerifiedCurrentFullEntitlement: ...


class CurrentMessagingDeviceBindingProvider(Protocol):
    def current_for_subject(
        self,
        subject: str,
        *,
        now: datetime,
        maximum: int,
    ) -> list[MessagingDeviceBinding]: ...


class RecipientRoutingRepository(Protocol):
    """Future atomic confidential registry and message-id ledger boundary.

    ``retain_snapshot`` must enforce global, unambiguous handle ownership and
    idempotent exact snapshot retention. ``read_snapshot`` must fail rather
    than choose among duplicate rows. ``record_decision`` must atomically make
    equal message-id/digest retries idempotent and reject a changed digest.
    """

    def retain_snapshot(self, snapshot: RecipientRoutingSnapshot) -> RecipientRoutingSnapshot: ...

    def read_snapshot(self, snapshot_id: str) -> RecipientRoutingSnapshot | None: ...

    def record_decision(self, decision: RecipientRoutingDecision) -> RecipientRoutingDecision: ...


def _canonical_subject(value: object) -> str:
    if type(value) is not str:
        raise ValueError
    normalized = canonical_xonly_pubkey(value)
    if normalized != value:
        raise ValueError
    return normalized


def _hex64(value: object) -> str:
    if type(value) is not str or _HEX_64(value) is None:
        raise ValueError
    return value


def _utc_second(value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError
    normalized = value.astimezone(timezone.utc)
    if normalized.microsecond:
        raise ValueError
    return normalized


def _milliseconds(value: datetime) -> int:
    result = int(_utc_second(value).timestamp() * 1000)
    if not 0 <= result <= MAX_SAFE_INTEGER:
        raise ValueError
    return result


def _integer(value: object) -> int:
    if type(value) is not int or not 0 <= value <= MAX_SAFE_INTEGER:
        raise ValueError
    return value


def _canonical_token(value: object, *, prefix: str, characters: int, decoded: int) -> str:
    if type(value) is not str or not value.startswith(prefix):
        raise ValueError
    encoded = value[len(prefix) :]
    if len(encoded) != characters or re.fullmatch(r"[A-Za-z0-9_-]+", encoded) is None:
        raise ValueError
    raw = base64.urlsafe_b64decode(encoded + "=" * ((4 - len(encoded) % 4) % 4))
    if len(raw) != decoded:
        raise ValueError
    canonical = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    if canonical != encoded:
        raise ValueError
    return value


def derive_recipient_device_handle(
    *,
    viewer: object,
    target: object,
    binding_id: object,
    alias_secret: object,
    alias_version: object,
) -> str:
    """Derive the existing V1 pairwise handle, byte-for-byte unchanged."""

    try:
        normalized_viewer = _canonical_subject(viewer)
        normalized_target = _canonical_subject(target)
        normalized_binding = _hex64(binding_id)
        if (
            type(alias_secret) is not bytes
            or not MIN_ALIAS_SECRET_BYTES <= len(alias_secret) <= MAX_ALIAS_SECRET_BYTES
            or type(alias_version) is not int
            or not 1 <= alias_version <= MAX_ALIAS_VERSION
        ):
            raise ValueError
        message = b"\x00".join(
            (
                DEVICE_HANDLE_DOMAIN,
                str(VERSION).encode("ascii"),
                str(alias_version).encode("ascii"),
                normalized_viewer.encode("ascii"),
                normalized_target.encode("ascii"),
                normalized_binding.encode("ascii"),
            )
        )
        digest = hmac.new(alias_secret, message, hashlib.sha256).digest()[:DEVICE_HANDLE_BYTES]
        return "d_" + base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    except Exception:
        raise ValueError("invalid recipient device handle input") from None


def _request_dict(value: RecipientRoutingRequest) -> dict[str, object]:
    return {
        "schema": value.schema,
        "version": value.version,
        "messageId": value.message_id,
        "envelopeDigest": value.envelope_digest,
        "recipientPackageSnapshotId": value.recipient_package_snapshot_id,
        "recipientDeviceHandles": list(value.recipient_device_handles),
    }


def _validate_request_semantics(value: object) -> RecipientRoutingRequest:
    if type(value) is not RecipientRoutingRequest:
        raise ValueError
    if (
        type(value.schema) is not str
        or value.schema != REQUEST_SCHEMA
        or type(value.version) is not int
        or value.version != VERSION
        or type(value.recipient_device_handles) is not tuple
        or not 1 <= len(value.recipient_device_handles) <= MAX_ACTIVE_DEVICES
    ):
        raise ValueError
    _canonical_token(value.message_id, prefix="m_", characters=43, decoded=32)
    if (
        type(value.envelope_digest) is not str
        or _ENVELOPE_DIGEST(value.envelope_digest) is None
        or type(value.recipient_package_snapshot_id) is not str
        or _SNAPSHOT_ID(value.recipient_package_snapshot_id) is None
    ):
        raise ValueError
    handles = tuple(
        _canonical_token(item, prefix="d_", characters=22, decoded=16) for item in value.recipient_device_handles
    )
    if tuple(sorted(set(handles))) != handles:
        raise ValueError
    return value


def canonical_routing_request_bytes(value: RecipientRoutingRequest) -> bytes:
    try:
        value = _validate_request_semantics(value)
        encoded = json.dumps(_request_dict(value), ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode(
            "ascii"
        )
        if len(encoded) > MAX_REQUEST_BYTES:
            raise ValueError
        return encoded
    except Exception:
        raise RecipientMessagingRoutingUnavailable() from None


def parse_recipient_routing_request(payload: object) -> RecipientRoutingRequest:
    """Parse one closed canonical ASCII request and reject every ambiguity."""

    try:
        if type(payload) is not str or not 1 <= len(payload) <= MAX_REQUEST_BYTES:
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

        data = json.loads(payload, object_pairs_hook=pairs)
        if type(data) is not dict or set(data) != _REQUEST_FIELDS:
            raise ValueError
        handles = data["recipientDeviceHandles"]
        if (
            data["schema"] != REQUEST_SCHEMA
            or type(data["schema"]) is not str
            or data["version"] != VERSION
            or type(data["version"]) is not int
            or type(handles) is not list
            or not 1 <= len(handles) <= MAX_ACTIVE_DEVICES
        ):
            raise ValueError
        normalized_handles = tuple(_canonical_token(item, prefix="d_", characters=22, decoded=16) for item in handles)
        if tuple(sorted(set(normalized_handles))) != normalized_handles:
            raise ValueError
        message_id = _canonical_token(data["messageId"], prefix="m_", characters=43, decoded=32)
        digest = data["envelopeDigest"]
        snapshot_id = data["recipientPackageSnapshotId"]
        if (
            type(digest) is not str
            or _ENVELOPE_DIGEST(digest) is None
            or type(snapshot_id) is not str
            or _SNAPSHOT_ID(snapshot_id) is None
        ):
            raise ValueError
        result = RecipientRoutingRequest(
            schema=REQUEST_SCHEMA,
            version=VERSION,
            message_id=message_id,
            envelope_digest=digest,
            recipient_package_snapshot_id=snapshot_id,
            recipient_device_handles=normalized_handles,
        )
        _validate_request_semantics(result)
        if payload.encode("ascii") != canonical_routing_request_bytes(result):
            raise ValueError
        return result
    except RecipientMessagingRoutingUnavailable:
        raise
    except Exception:
        raise RecipientMessagingRoutingUnavailable() from None


def _snapshot_route_dict(value: RecipientRoutingSnapshotRoute) -> dict[str, object]:
    return {
        "deviceHandle": value.device_handle,
        "deviceId": value.device_id,
        "bindingId": value.binding_id,
        "bindingVersion": value.binding_version,
        "authorizationProofId": value.authorization_proof_id,
        "authorizationValidFrom": value.authorization_valid_from,
        "authorizationExpiresAt": value.authorization_expires_at,
    }


def canonical_routing_snapshot_bytes(value: RecipientRoutingSnapshot) -> bytes:
    try:
        value = _validate_snapshot_semantics(value)
        data = {
            "schema": value.schema,
            "version": value.version,
            "source": value.source,
            "viewerSubject": value.viewer_subject,
            "recipientSubject": value.recipient_subject,
            "aliasVersion": value.alias_version,
            "recipientPackageSnapshotId": value.recipient_package_snapshot_id,
            "issuedAt": value.issued_at,
            "expiresAt": value.expires_at,
            "complete": value.complete,
            "routes": [_snapshot_route_dict(item) for item in value.routes],
        }
        encoded = json.dumps(data, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
        if len(encoded) > MAX_INTERNAL_SNAPSHOT_BYTES:
            raise ValueError
        return encoded
    except Exception:
        raise RecipientMessagingRoutingUnavailable() from None


def canonical_routing_decision_bytes(value: RecipientRoutingDecision) -> bytes:
    try:
        value = _validate_decision_semantics(value)
        data = {
            "schema": value.schema,
            "version": value.version,
            "source": value.source,
            "messageId": value.message_id,
            "envelopeDigest": value.envelope_digest,
            "recipientPackageSnapshotId": value.recipient_package_snapshot_id,
            "viewerSubject": value.viewer_subject,
            "recipientSubject": value.recipient_subject,
            "complete": value.complete,
            "expiresAt": value.expires_at,
            "routes": [
                {
                    "deviceHandle": item.device_handle,
                    "deviceId": item.device_id,
                    "bindingId": item.binding_id,
                    "bindingVersion": item.binding_version,
                }
                for item in value.routes
            ],
        }
        encoded = json.dumps(data, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
        if len(encoded) > MAX_INTERNAL_DECISION_BYTES:
            raise ValueError
        return encoded
    except Exception:
        raise RecipientMessagingRoutingUnavailable() from None


def _verified_full(
    verifier: CurrentFullEntitlementVerifier,
    subject: str,
    *,
    now: datetime,
    issued_at: int,
    expires_at: int,
) -> VerifiedCurrentFullEntitlement:
    evidence = validate_verified_current_full_entitlement(
        verifier.verify(subject, now=now),
        subject=subject,
        now=now,
    )
    evidence_subject = _canonical_subject(evidence.subject)
    valid_from = _milliseconds(evidence.valid_from)
    evidence_expires_at = _milliseconds(evidence.expires_at)
    now_ms = _milliseconds(now)
    if (
        evidence_subject != subject
        or type(evidence.proof_id) is not str
        or _FULL_PROOF_ID(evidence.proof_id) is None
        or valid_from > now_ms
        or now_ms >= evidence_expires_at
        or valid_from > issued_at
        or expires_at > evidence_expires_at
    ):
        raise ValueError
    return evidence


def _verified_binding_route(
    binding: MessagingDeviceBinding,
    *,
    viewer_subject: str,
    recipient_subject: str,
    alias_secret: bytes,
    alias_version: int,
    verifier: BindingAuthorizationVerifier,
    now: datetime,
    issued_at: int,
    expires_at: int,
) -> tuple[RecipientRoutingSnapshotRoute, dict[str, object]]:
    if type(binding) is not MessagingDeviceBinding:
        raise ValueError
    subject = _canonical_subject(binding.subject)
    device_id = _hex64(binding.device_id)
    binding_id = _hex64(binding.binding_id)
    _hex64(binding.request_id)
    public_key = validate_x25519_public_key(binding.public_key)
    binding_version = binding.binding_version
    valid_from = _utc_second(binding.valid_from)
    binding_expires_at = _utc_second(binding.expires_at)
    now = _utc_second(now)
    operation = binding.operation
    if (
        subject != recipient_subject
        or public_key == subject
        or type(binding_version) is not int
        or not 1 <= binding_version <= MAX_BINDING_VERSION
        or type(operation) is not str
        or operation not in {"register", "rotate"}
        or binding.active is not True
        or valid_from > now
        or now >= binding_expires_at
        or _milliseconds(valid_from) > issued_at
        or expires_at > _milliseconds(binding_expires_at)
    ):
        raise ValueError
    if operation == "register":
        if binding_version != 1 or binding.prior_binding_id is not None:
            raise ValueError
    else:
        prior_binding_id = _hex64(binding.prior_binding_id)
        if binding_version < 2 or prior_binding_id == binding_id:
            raise ValueError
    evidence = verifier.verify(binding, now=now)
    if type(evidence) is not VerifiedBindingAuthorization:
        raise ValueError
    evidence_valid_from = _utc_second(evidence.evidence_valid_from)
    evidence_expires_at = _utc_second(evidence.evidence_expires_at)
    if (
        type(evidence.proof_id) is not str
        or _BINDING_PROOF_ID(evidence.proof_id) is None
        or _canonical_subject(evidence.subject) != subject
        or _hex64(evidence.device_id) != device_id
        or _hex64(evidence.binding_id) != binding_id
        or evidence.binding_version != binding_version
        or type(evidence.binding_version) is not int
        or validate_x25519_public_key(evidence.public_key) != public_key
        or _utc_second(evidence.valid_from) != valid_from
        or _utc_second(evidence.expires_at) != binding_expires_at
        or evidence_valid_from > now
        or now >= evidence_expires_at
        or _milliseconds(evidence_valid_from) > issued_at
        or expires_at > _milliseconds(evidence_expires_at)
    ):
        raise ValueError

    handle = derive_recipient_device_handle(
        viewer=viewer_subject,
        target=recipient_subject,
        binding_id=binding_id,
        alias_secret=alias_secret,
        alias_version=alias_version,
    )
    route = RecipientRoutingSnapshotRoute(
        device_handle=handle,
        device_id=device_id,
        binding_id=binding_id,
        binding_version=binding_version,
        authorization_proof_id=evidence.proof_id,
        authorization_valid_from=_milliseconds(evidence_valid_from),
        authorization_expires_at=_milliseconds(evidence_expires_at),
    )
    projected_device = {
        "deviceHandle": handle,
        "algorithm": ALGORITHM,
        "version": binding_version,
        "publicKey": public_key,
        "validFrom": _milliseconds(valid_from),
        "expiresAt": _milliseconds(binding_expires_at),
    }
    return route, projected_device


def _validated_package(
    value: object,
    *,
    viewer_subject: str,
    recipient_subject: str,
    alias_secret: bytes,
    alias_version: int,
    now_ms: int,
) -> dict[str, object]:
    if type(value) is not dict or set(value) != _PACKAGE_FIELDS:
        raise ValueError
    devices = value["devices"]
    if (
        value["schema"] != RECIPIENT_PACKAGE_SCHEMA
        or type(value["schema"]) is not str
        or value["version"] != VERSION
        or type(value["version"]) is not int
        or value["source"] != SOURCE
        or type(value["source"]) is not str
        or value["complete"] is not True
        or type(value["alias"]) is not str
        or _ALIAS(value["alias"]) is None
        or type(value["snapshotId"]) is not str
        or _SNAPSHOT_ID(value["snapshotId"]) is None
        or type(devices) is not list
        or not 1 <= len(devices) <= MAX_ACTIVE_DEVICES
    ):
        raise ValueError
    expected_alias = derive_privacy_directory_alias(
        viewer=viewer_subject,
        target=recipient_subject,
        alias_secret=alias_secret,
        alias_version=alias_version,
    )
    if not hmac.compare_digest(value["alias"], expected_alias):
        raise ValueError
    issued_at = _integer(value["issuedAt"])
    expires_at = _integer(value["expiresAt"])
    if (
        issued_at > now_ms
        or now_ms >= expires_at
        or issued_at >= expires_at
        or expires_at - issued_at > MAX_SNAPSHOT_VALIDITY_MS
    ):
        raise ValueError

    normalized_devices = []
    public_keys = set()
    previous = None
    for item in devices:
        if type(item) is not dict or set(item) != _PACKAGE_DEVICE_FIELDS:
            raise ValueError
        handle = _canonical_token(item["deviceHandle"], prefix="d_", characters=22, decoded=16)
        valid_from = _integer(item["validFrom"])
        device_expires_at = _integer(item["expiresAt"])
        if (
            previous is not None
            and handle <= previous
            or item["algorithm"] != ALGORITHM
            or type(item["algorithm"]) is not str
            or type(item["version"]) is not int
            or not 1 <= item["version"] <= MAX_BINDING_VERSION
            or valid_from > issued_at
            or device_expires_at < expires_at
        ):
            raise ValueError
        public_key = validate_x25519_public_key(item["publicKey"])
        if public_key != item["publicKey"] or public_key in public_keys:
            raise ValueError
        public_keys.add(public_key)
        previous = handle
        normalized_devices.append(
            {
                "deviceHandle": handle,
                "algorithm": ALGORITHM,
                "version": item["version"],
                "publicKey": public_key,
                "validFrom": valid_from,
                "expiresAt": device_expires_at,
            }
        )

    evidence = {
        "schema": RECIPIENT_PACKAGE_SCHEMA,
        "version": VERSION,
        "source": SOURCE,
        "alias": value["alias"],
        "complete": True,
        "issuedAt": issued_at,
        "expiresAt": expires_at,
        "devices": normalized_devices,
    }
    canonical = json.dumps(evidence, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
    expected_snapshot_id = "sha256:" + hashlib.sha256(canonical).hexdigest()
    if not hmac.compare_digest(value["snapshotId"], expected_snapshot_id):
        raise ValueError
    return {
        **evidence,
        "snapshotId": expected_snapshot_id,
    }


def _validate_snapshot_semantics(value: object) -> RecipientRoutingSnapshot:
    if type(value) is not RecipientRoutingSnapshot:
        raise ValueError
    if (
        type(value.schema) is not str
        or value.schema != SNAPSHOT_SCHEMA
        or type(value.version) is not int
        or value.version != VERSION
        or type(value.source) is not str
        or value.source != SOURCE
        or value.complete is not True
        or _canonical_subject(value.viewer_subject) != value.viewer_subject
        or _canonical_subject(value.recipient_subject) != value.recipient_subject
        or value.viewer_subject == value.recipient_subject
        or type(value.alias_version) is not int
        or not 1 <= value.alias_version <= MAX_ALIAS_VERSION
        or type(value.recipient_package_snapshot_id) is not str
        or _SNAPSHOT_ID(value.recipient_package_snapshot_id) is None
        or type(value.routes) is not tuple
        or not 1 <= len(value.routes) <= MAX_ACTIVE_DEVICES
    ):
        raise ValueError
    issued_at = _integer(value.issued_at)
    expires_at = _integer(value.expires_at)
    if issued_at >= expires_at or expires_at - issued_at > MAX_SNAPSHOT_VALIDITY_MS:
        raise ValueError
    handles = []
    device_ids = set()
    binding_ids = set()
    proof_ids = set()
    for route in value.routes:
        if type(route) is not RecipientRoutingSnapshotRoute:
            raise ValueError
        handle = _canonical_token(route.device_handle, prefix="d_", characters=22, decoded=16)
        device_id = _hex64(route.device_id)
        binding_id = _hex64(route.binding_id)
        if (
            type(route.binding_version) is not int
            or not 1 <= route.binding_version <= MAX_BINDING_VERSION
            or type(route.authorization_proof_id) is not str
            or _BINDING_PROOF_ID(route.authorization_proof_id) is None
            or _integer(route.authorization_valid_from) > issued_at
            or expires_at > _integer(route.authorization_expires_at)
            or device_id in device_ids
            or binding_id in binding_ids
            or route.authorization_proof_id in proof_ids
        ):
            raise ValueError
        handles.append(handle)
        device_ids.add(device_id)
        binding_ids.add(binding_id)
        proof_ids.add(route.authorization_proof_id)
    if tuple(sorted(set(handles))) != tuple(handles):
        raise ValueError
    return value


def _validated_snapshot(value: object) -> RecipientRoutingSnapshot:
    snapshot = _validate_snapshot_semantics(value)
    canonical_routing_snapshot_bytes(snapshot)
    return snapshot


def _validate_decision_semantics(value: object) -> RecipientRoutingDecision:
    if type(value) is not RecipientRoutingDecision:
        raise ValueError
    if (
        type(value.schema) is not str
        or value.schema != DECISION_SCHEMA
        or type(value.version) is not int
        or value.version != VERSION
        or type(value.source) is not str
        or value.source != SOURCE
        or _canonical_subject(value.viewer_subject) != value.viewer_subject
        or _canonical_subject(value.recipient_subject) != value.recipient_subject
        or value.viewer_subject == value.recipient_subject
        or value.complete is not True
        or type(value.recipient_package_snapshot_id) is not str
        or _SNAPSHOT_ID(value.recipient_package_snapshot_id) is None
        or type(value.envelope_digest) is not str
        or _ENVELOPE_DIGEST(value.envelope_digest) is None
        or type(value.routes) is not tuple
        or not 1 <= len(value.routes) <= MAX_ACTIVE_DEVICES
    ):
        raise ValueError
    _canonical_token(value.message_id, prefix="m_", characters=43, decoded=32)
    # Decisions carry no issued-at field; only a canonical, positive expiry can
    # be established from this contract without inventing unverifiable state.
    if _integer(value.expires_at) == 0:
        raise ValueError

    handles = []
    device_ids = set()
    binding_ids = set()
    for route in value.routes:
        if type(route) is not RecipientRoutingDecisionRoute:
            raise ValueError
        handle = _canonical_token(route.device_handle, prefix="d_", characters=22, decoded=16)
        device_id = _hex64(route.device_id)
        binding_id = _hex64(route.binding_id)
        if (
            type(route.binding_version) is not int
            or not 1 <= route.binding_version <= MAX_BINDING_VERSION
            or device_id in device_ids
            or binding_id in binding_ids
        ):
            raise ValueError
        handles.append(handle)
        device_ids.add(device_id)
        binding_ids.add(binding_id)
    if tuple(sorted(set(handles))) != tuple(handles):
        raise ValueError
    return value


class SocialMessagingRecipientRoutingGateV1:
    """Dormant fail-closed coordinator over injected authority ports."""

    def __init__(
        self,
        *,
        repository: RecipientRoutingRepository,
        binding_provider: CurrentMessagingDeviceBindingProvider,
        binding_authorization_verifier: BindingAuthorizationVerifier,
        full_entitlement_verifier: CurrentFullEntitlementVerifier,
        alias_secret: bytes,
        alias_version: int = 1,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if (
            not callable(getattr(repository, "retain_snapshot", None))
            or not callable(getattr(repository, "read_snapshot", None))
            or not callable(getattr(repository, "record_decision", None))
            or not callable(getattr(binding_provider, "current_for_subject", None))
            or not callable(getattr(binding_authorization_verifier, "verify", None))
            or not callable(getattr(full_entitlement_verifier, "verify", None))
            or type(alias_secret) is not bytes
            or not MIN_ALIAS_SECRET_BYTES <= len(alias_secret) <= MAX_ALIAS_SECRET_BYTES
            or type(alias_version) is not int
            or not 1 <= alias_version <= MAX_ALIAS_VERSION
            or clock is not None
            and not callable(clock)
        ):
            raise ValueError("invalid recipient routing dependency")
        self._repository = repository
        self._binding_provider = binding_provider
        self._binding_authorization_verifier = binding_authorization_verifier
        self._full_entitlement_verifier = full_entitlement_verifier
        self._alias_secret = alias_secret
        self._alias_version = alias_version
        self._clock = clock or (lambda: datetime.now(timezone.utc).replace(microsecond=0))

    def _now(self) -> datetime:
        return _utc_second(self._clock())

    def _current_bindings(self, recipient_subject: str, now: datetime) -> list[MessagingDeviceBinding]:
        bindings = self._binding_provider.current_for_subject(
            recipient_subject,
            now=now,
            maximum=MAX_ACTIVE_DEVICES,
        )
        if type(bindings) is not list or not 1 <= len(bindings) <= MAX_ACTIVE_DEVICES:
            raise ValueError
        return bindings

    def _routes(
        self,
        bindings: list[MessagingDeviceBinding],
        *,
        viewer_subject: str,
        recipient_subject: str,
        alias_version: int,
        now: datetime,
        issued_at: int,
        expires_at: int,
    ) -> tuple[tuple[RecipientRoutingSnapshotRoute, ...], tuple[dict[str, object], ...]]:
        pairs = [
            _verified_binding_route(
                item,
                viewer_subject=viewer_subject,
                recipient_subject=recipient_subject,
                alias_secret=self._alias_secret,
                alias_version=alias_version,
                verifier=self._binding_authorization_verifier,
                now=now,
                issued_at=issued_at,
                expires_at=expires_at,
            )
            for item in bindings
        ]
        pairs.sort(key=lambda item: item[0].device_handle)
        routes = tuple(item[0] for item in pairs)
        devices = tuple(item[1] for item in pairs)
        public_keys = tuple(item["publicKey"] for item in devices)
        if (
            len({item.device_handle for item in routes}) != len(routes)
            or len({item.device_id for item in routes}) != len(routes)
            or len({item.binding_id for item in routes}) != len(routes)
            or len({item.authorization_proof_id for item in routes}) != len(routes)
            or len(set(public_keys)) != len(public_keys)
        ):
            raise ValueError
        return routes, devices

    def retain_recipient_package(
        self,
        *,
        viewer_subject: object,
        recipient_subject: object,
        recipient_package: object,
    ) -> RecipientRoutingSnapshot:
        """Validate and confidentially retain one exact outward package mapping."""

        try:
            viewer = _canonical_subject(viewer_subject)
            recipient = _canonical_subject(recipient_subject)
            if viewer == recipient:
                raise ValueError
            now = self._now()
            now_ms = _milliseconds(now)
            package = _validated_package(
                recipient_package,
                viewer_subject=viewer,
                recipient_subject=recipient,
                alias_secret=self._alias_secret,
                alias_version=self._alias_version,
                now_ms=now_ms,
            )
            issued_at = package["issuedAt"]
            expires_at = package["expiresAt"]
            _verified_full(
                self._full_entitlement_verifier,
                viewer,
                now=now,
                issued_at=issued_at,
                expires_at=expires_at,
            )
            _verified_full(
                self._full_entitlement_verifier,
                recipient,
                now=now,
                issued_at=issued_at,
                expires_at=expires_at,
            )
            routes, projected_devices = self._routes(
                self._current_bindings(recipient, now),
                viewer_subject=viewer,
                recipient_subject=recipient,
                alias_version=self._alias_version,
                now=now,
                issued_at=issued_at,
                expires_at=expires_at,
            )
            if list(projected_devices) != package["devices"]:
                raise ValueError
            snapshot = RecipientRoutingSnapshot(
                schema=SNAPSHOT_SCHEMA,
                version=VERSION,
                source=SOURCE,
                viewer_subject=viewer,
                recipient_subject=recipient,
                alias_version=self._alias_version,
                recipient_package_snapshot_id=package["snapshotId"],
                issued_at=issued_at,
                expires_at=expires_at,
                complete=True,
                routes=routes,
            )
            _validated_snapshot(snapshot)
            retained = self._repository.retain_snapshot(snapshot)
            if type(retained) is not RecipientRoutingSnapshot or retained != snapshot:
                raise ValueError
            return retained
        except RecipientMessagingRoutingUnavailable:
            raise
        except Exception:
            raise RecipientMessagingRoutingUnavailable() from None

    def resolve(
        self,
        payload: object,
        *,
        authenticated_viewer_subject: object,
    ) -> RecipientRoutingDecision:
        """Resolve an exact complete request while rechecking current authority."""

        try:
            request = parse_recipient_routing_request(payload)
            viewer = _canonical_subject(authenticated_viewer_subject)
            snapshot = _validated_snapshot(self._repository.read_snapshot(request.recipient_package_snapshot_id))
            now = self._now()
            now_ms = _milliseconds(now)
            if (
                viewer != snapshot.viewer_subject
                or request.recipient_package_snapshot_id != snapshot.recipient_package_snapshot_id
                or request.recipient_device_handles != tuple(item.device_handle for item in snapshot.routes)
                or now_ms < snapshot.issued_at
                or now_ms >= snapshot.expires_at
            ):
                raise ValueError
            _verified_full(
                self._full_entitlement_verifier,
                snapshot.viewer_subject,
                now=now,
                issued_at=snapshot.issued_at,
                expires_at=snapshot.expires_at,
            )
            _verified_full(
                self._full_entitlement_verifier,
                snapshot.recipient_subject,
                now=now,
                issued_at=snapshot.issued_at,
                expires_at=snapshot.expires_at,
            )
            current_routes, _ = self._routes(
                self._current_bindings(snapshot.recipient_subject, now),
                viewer_subject=snapshot.viewer_subject,
                recipient_subject=snapshot.recipient_subject,
                alias_version=snapshot.alias_version,
                now=now,
                issued_at=snapshot.issued_at,
                expires_at=snapshot.expires_at,
            )
            if current_routes != snapshot.routes:
                raise ValueError
            decision = RecipientRoutingDecision(
                schema=DECISION_SCHEMA,
                version=VERSION,
                source=SOURCE,
                message_id=request.message_id,
                envelope_digest=request.envelope_digest,
                recipient_package_snapshot_id=request.recipient_package_snapshot_id,
                viewer_subject=snapshot.viewer_subject,
                recipient_subject=snapshot.recipient_subject,
                complete=True,
                expires_at=snapshot.expires_at,
                routes=tuple(
                    RecipientRoutingDecisionRoute(
                        device_handle=item.device_handle,
                        device_id=item.device_id,
                        binding_id=item.binding_id,
                        binding_version=item.binding_version,
                    )
                    for item in snapshot.routes
                ),
            )
            canonical_routing_decision_bytes(decision)
            recorded = self._repository.record_decision(decision)
            if type(recorded) is not RecipientRoutingDecision or recorded != decision:
                raise ValueError
            return recorded
        except RecipientMessagingRoutingUnavailable:
            raise
        except Exception:
            raise RecipientMessagingRoutingUnavailable() from None


__all__ = [
    "BindingAuthorizationVerifier",
    "CurrentFullEntitlementVerifier",
    "CurrentMessagingDeviceBindingProvider",
    "DECISION_SCHEMA",
    "DEVICE_HANDLE_BYTES",
    "DEVICE_HANDLE_DOMAIN",
    "MAX_REQUEST_BYTES",
    "RECIPIENT_PACKAGE_SCHEMA",
    "REQUEST_SCHEMA",
    "RecipientMessagingRoutingUnavailable",
    "RecipientRoutingDecision",
    "RecipientRoutingDecisionRoute",
    "RecipientRoutingRepository",
    "RecipientRoutingRequest",
    "RecipientRoutingSnapshot",
    "RecipientRoutingSnapshotRoute",
    "SNAPSHOT_SCHEMA",
    "SOURCE",
    "SocialMessagingRecipientRoutingGateV1",
    "UNAVAILABLE_MESSAGE",
    "VERSION",
    "VerifiedBindingAuthorization",
    "VerifiedCurrentFullEntitlement",
    "canonical_routing_decision_bytes",
    "canonical_routing_request_bytes",
    "canonical_routing_snapshot_bytes",
    "derive_recipient_device_handle",
    "parse_recipient_routing_request",
]
