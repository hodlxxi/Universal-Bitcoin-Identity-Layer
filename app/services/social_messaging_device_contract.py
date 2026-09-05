"""Pure contract for Social multi-device X25519 authority.

This module owns only request parsing and response projection. It does not
register HTTP routes, access the database, validate OAuth tokens, or decide
whether a subject is currently Full.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Protocol

from app.auth_api_core import canonical_xonly_pubkey
from app.services.full_recipient_directory_provider import validate_x25519_public_key

COMMAND_SCHEMA = "hodlxxi.social_messaging_device_binding_command.v1"
RESULT_SCHEMA = "hodlxxi.social_messaging_device_binding_result.v1"
SNAPSHOT_SCHEMA = "hodlxxi.social_messaging_device_binding_snapshot.v1"
SOURCE = "hodlxxi-ubid"
ALGORITHM = "x25519-v1"

MAX_COMMAND_BYTES = 8192
MAX_ACTIVE_DEVICES = 16
MAX_BINDING_VERSION = 1024
SNAPSHOT_LIFETIME_SECONDS = 300
UNAVAILABLE_MESSAGE = "social messaging device authority unavailable"
REQUEST_INVALID_MESSAGE = "social messaging device request invalid"

_HEX_64 = re.compile(r"[0-9a-f]{64}\Z").fullmatch
_OPERATIONS = frozenset({"register", "rotate", "revoke"})
_COMMAND_FIELDS = {
    "schema",
    "version",
    "operation",
    "deviceId",
    "algorithm",
    "publicKey",
    "expectedBindingId",
    "requestId",
}


class MessagingDeviceAuthorityUnavailable(RuntimeError):
    def __init__(self) -> None:
        super().__init__(UNAVAILABLE_MESSAGE)


class MessagingDeviceRequestInvalid(ValueError):
    def __init__(self) -> None:
        super().__init__(REQUEST_INVALID_MESSAGE)


@dataclass(frozen=True)
class MessagingDeviceCommand:
    operation: str
    device_id: str
    public_key: str | None
    expected_binding_id: str | None
    request_id: str


@dataclass(frozen=True)
class MessagingDeviceBinding:
    subject: str
    device_id: str
    binding_id: str
    public_key: str
    binding_version: int
    valid_from: datetime
    expires_at: datetime
    operation: str
    prior_binding_id: str | None
    request_id: str
    active: bool


class MessagingDeviceRepository(Protocol):
    def apply(
        self,
        command: MessagingDeviceCommand,
        *,
        subject: str,
        now: datetime,
    ) -> MessagingDeviceBinding: ...

    def current_for_subject(
        self,
        subject: str,
        *,
        now: datetime,
        maximum: int,
    ) -> list[MessagingDeviceBinding]: ...


def _canonical_subject(value: object) -> str:
    try:
        if type(value) is not str:
            raise ValueError
        subject = canonical_xonly_pubkey(value)
        if value != subject:
            raise ValueError
        return subject
    except Exception:
        raise MessagingDeviceAuthorityUnavailable() from None


def _hex64(value: object) -> str:
    if type(value) is not str or _HEX_64(value) is None:
        raise MessagingDeviceAuthorityUnavailable()
    return value


def _utc_second(value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise MessagingDeviceAuthorityUnavailable()
    normalized = value.astimezone(timezone.utc)
    if normalized.microsecond:
        raise MessagingDeviceAuthorityUnavailable()
    return normalized


def _timestamp(value: datetime) -> str:
    return _utc_second(value).isoformat(timespec="seconds").replace("+00:00", "Z")


def _closed_json_object(source: object) -> dict[str, object]:
    try:
        if type(source) is not str or not 1 <= len(source) <= MAX_COMMAND_BYTES:
            raise ValueError
        if any(ord(char) < 0x20 or ord(char) > 0x7E for char in source):
            raise ValueError

        def pairs(values):
            result = {}
            for key, item in values:
                if type(key) is not str or key in result:
                    raise ValueError
                result[key] = item
            return result

        decoded = json.loads(source, object_pairs_hook=pairs)
        if type(decoded) is not dict:
            raise ValueError
        return decoded
    except Exception:
        raise MessagingDeviceRequestInvalid() from None


def parse_messaging_device_command(
    payload: object,
    *,
    authenticated_subject: object,
) -> tuple[str, MessagingDeviceCommand]:
    """Parse one browser command while deriving authority from server auth."""

    subject = _canonical_subject(authenticated_subject)
    try:
        data = _closed_json_object(payload)
        if set(data) != _COMMAND_FIELDS:
            raise ValueError
        if (
            data["schema"] != COMMAND_SCHEMA
            or type(data["version"]) is not int
            or data["version"] != 1
            or data["operation"] not in _OPERATIONS
            or data["algorithm"] != ALGORITHM
        ):
            raise ValueError

        operation = data["operation"]
        device_id = _hex64(data["deviceId"])
        request_id = _hex64(data["requestId"])
        expected = data["expectedBindingId"]
        public_key = data["publicKey"]

        if operation == "register":
            if expected is not None:
                raise ValueError
        else:
            expected = _hex64(expected)

        if operation == "revoke":
            if public_key is not None:
                raise ValueError
            normalized_key = None
        else:
            if type(public_key) is not str:
                raise ValueError
            normalized_key = validate_x25519_public_key(public_key)
            if normalized_key == subject:
                raise ValueError

        return subject, MessagingDeviceCommand(
            operation=operation,
            device_id=device_id,
            public_key=normalized_key,
            expected_binding_id=expected,
            request_id=request_id,
        )
    except MessagingDeviceRequestInvalid:
        raise
    except Exception:
        raise MessagingDeviceRequestInvalid() from None


def _validated_binding(
    value: object,
    *,
    expected_subject: str,
    now: datetime,
    require_active: bool | None = None,
) -> MessagingDeviceBinding:
    try:
        if type(value) is not MessagingDeviceBinding:
            raise ValueError
        subject = _canonical_subject(value.subject)
        if subject != expected_subject:
            raise ValueError
        device_id = _hex64(value.device_id)
        binding_id = _hex64(value.binding_id)
        request_id = _hex64(value.request_id)
        public_key = validate_x25519_public_key(value.public_key)
        if public_key == subject:
            raise ValueError
        version = value.binding_version
        if type(version) is not int or not 1 <= version <= MAX_BINDING_VERSION:
            raise ValueError
        valid_from = _utc_second(value.valid_from)
        expires_at = _utc_second(value.expires_at)
        timestamp = _utc_second(now)
        if valid_from > timestamp or expires_at <= timestamp or valid_from >= expires_at:
            raise ValueError
        operation = value.operation
        if operation not in _OPERATIONS or type(value.active) is not bool:
            raise ValueError

        prior_binding_id = value.prior_binding_id
        if operation == "register":
            if prior_binding_id is not None or version != 1:
                raise ValueError
        else:
            prior_binding_id = _hex64(prior_binding_id)
            if version <= 1 or prior_binding_id == binding_id:
                raise ValueError

        if operation == "revoke":
            if value.active is not False:
                raise ValueError
        elif value.active is not True:
            raise ValueError
        if require_active is not None and value.active is not require_active:
            raise ValueError

        return MessagingDeviceBinding(
            subject,
            device_id,
            binding_id,
            public_key,
            version,
            valid_from,
            expires_at,
            operation,
            prior_binding_id,
            request_id,
            value.active,
        )
    except MessagingDeviceAuthorityUnavailable:
        raise
    except Exception:
        raise MessagingDeviceAuthorityUnavailable() from None


def _device_result(binding: MessagingDeviceBinding) -> dict[str, object]:
    return {
        "deviceId": binding.device_id,
        "bindingId": binding.binding_id,
        "algorithm": ALGORITHM,
        "version": binding.binding_version,
        "publicKey": binding.public_key,
        "validFrom": _timestamp(binding.valid_from),
        "expiresAt": _timestamp(binding.expires_at),
    }


class SocialMessagingDeviceAuthority:
    """Join a server-derived subject to an injected multi-device repository."""

    def __init__(
        self,
        repository: MessagingDeviceRepository,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not callable(getattr(repository, "apply", None)) or not callable(
            getattr(repository, "current_for_subject", None)
        ):
            raise ValueError("invalid messaging device repository")
        self._repository = repository
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def apply(
        self,
        payload: object,
        *,
        authenticated_subject: object,
    ) -> dict[str, object]:
        try:
            subject, command = parse_messaging_device_command(
                payload,
                authenticated_subject=authenticated_subject,
            )
            now = _utc_second(self._clock())
            raw = self._repository.apply(command, subject=subject, now=now)
            binding = _validated_binding(raw, expected_subject=subject, now=now)
            if (
                binding.device_id != command.device_id
                or binding.operation != command.operation
                or binding.request_id != command.request_id
                or binding.prior_binding_id != command.expected_binding_id
                or (command.public_key is not None and binding.public_key != command.public_key)
                or (command.operation == "register" and binding.binding_version != 1)
                or (command.operation != "register" and binding.binding_version <= 1)
            ):
                raise ValueError
            return {
                "schema": RESULT_SCHEMA,
                "version": 1,
                "operation": command.operation,
                "device": _device_result(binding),
            }
        except MessagingDeviceRequestInvalid:
            raise
        except MessagingDeviceAuthorityUnavailable:
            raise
        except Exception:
            raise MessagingDeviceAuthorityUnavailable() from None

    def current(
        self,
        *,
        authenticated_subject: object,
    ) -> dict[str, object]:
        try:
            subject = _canonical_subject(authenticated_subject)
            now = _utc_second(self._clock())
            raw = self._repository.current_for_subject(
                subject,
                now=now,
                maximum=MAX_ACTIVE_DEVICES,
            )
            if type(raw) is not list or len(raw) > MAX_ACTIVE_DEVICES:
                raise ValueError

            bindings = [
                _validated_binding(
                    item,
                    expected_subject=subject,
                    now=now,
                    require_active=True,
                )
                for item in raw
            ]
            if any(item.operation not in {"register", "rotate"} for item in bindings):
                raise ValueError

            bindings.sort(key=lambda item: item.device_id)
            if len({item.device_id for item in bindings}) != len(bindings):
                raise ValueError
            if len({item.binding_id for item in bindings}) != len(bindings):
                raise ValueError
            if len({item.public_key for item in bindings}) != len(bindings):
                raise ValueError

            issued_at = int(now.timestamp() * 1000)
            expires_at = int(
                min(
                    now + timedelta(seconds=SNAPSHOT_LIFETIME_SECONDS),
                    *(item.expires_at for item in bindings),
                ).timestamp()
                * 1000
            )
            public_devices = [
                {
                    "deviceId": item.device_id,
                    "bindingId": item.binding_id,
                    "algorithm": ALGORITHM,
                    "version": item.binding_version,
                    "publicKey": item.public_key,
                    "validFrom": int(item.valid_from.timestamp() * 1000),
                    "expiresAt": int(item.expires_at.timestamp() * 1000),
                    "revoked": False,
                }
                for item in bindings
            ]
            evidence = {
                "subject": subject,
                "complete": True,
                "issuedAt": issued_at,
                "expiresAt": expires_at,
                "activeDevices": public_devices,
            }
            canonical = json.dumps(
                evidence,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("ascii")
            snapshot_id = "sha256:" + hashlib.sha256(canonical).hexdigest()

            return {
                "schema": SNAPSHOT_SCHEMA,
                "version": 1,
                "source": SOURCE,
                "snapshotId": snapshot_id,
                "complete": True,
                "issuedAt": issued_at,
                "expiresAt": expires_at,
                "activeDevices": [{"snapshotId": snapshot_id, **device} for device in public_devices],
            }
        except MessagingDeviceAuthorityUnavailable:
            raise
        except Exception:
            raise MessagingDeviceAuthorityUnavailable() from None


__all__ = [
    "ALGORITHM",
    "COMMAND_SCHEMA",
    "MAX_ACTIVE_DEVICES",
    "MessagingDeviceAuthorityUnavailable",
    "MessagingDeviceRequestInvalid",
    "MessagingDeviceBinding",
    "MessagingDeviceCommand",
    "MessagingDeviceRepository",
    "RESULT_SCHEMA",
    "SNAPSHOT_SCHEMA",
    "SOURCE",
    "SocialMessagingDeviceAuthority",
    "parse_messaging_device_command",
]
