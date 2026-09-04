"""Identity-authorized multi-device public X25519 bindings for Social messaging."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Protocol

from coincurve import PublicKeyXOnly

from app.services.action_step_up import _canonical_actor
from app.services.full_recipient_directory_provider import validate_x25519_public_key


STATEMENT_SCHEMA = "hodlxxi.social_messaging_device_binding_statement.v1"
SNAPSHOT_SCHEMA = "hodlxxi.social_messaging_device_binding_snapshot.v1"

SIGNATURE_DOMAIN = "HODLXXI_SOCIAL_MESSAGING_DEVICE_BINDING_V1"
SIGNATURE_FORMAT = "bip340_schnorr_sha256"

ALGORITHM = "x25519-v1"
SOURCE = "hodlxxi-ubid"

MAX_BINDING_VERSION = 1024
MAX_ACTIVE_DEVICES = 16
SNAPSHOT_LIFETIME_SECONDS = 300

UNAVAILABLE_MESSAGE = "social messaging device binding registry unavailable"

_HEX64 = re.compile(r"[0-9a-f]{64}\Z").fullmatch
_HEX128 = re.compile(r"[0-9a-f]{128}\Z").fullmatch

_OPERATIONS = frozenset({"register", "rotate", "revoke"})

_FIELDS = {
    "schema",
    "version",
    "subject",
    "deviceId",
    "algorithm",
    "publicKey",
    "bindingVersion",
    "validFrom",
    "expiresAt",
    "operation",
    "priorBindingId",
    "nonce",
    "digest",
    "signatureFormat",
    "signature",
}


class DeviceBindingRegistryUnavailable(RuntimeError):
    def __init__(self) -> None:
        super().__init__(UNAVAILABLE_MESSAGE)


@dataclass(frozen=True)
class DeviceBindingStatement:
    schema: str
    subject: str
    device_id: str
    algorithm: str
    public_key: str
    binding_version: int
    valid_from: datetime
    expires_at: datetime
    operation: str
    prior_binding_id: str | None
    nonce: str
    digest: str
    signature_format: str
    signature: str

    @property
    def binding_id(self) -> str:
        return self.digest

    def public_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "version": 1,
            "subject": self.subject,
            "deviceId": self.device_id,
            "algorithm": self.algorithm,
            "publicKey": self.public_key,
            "bindingVersion": self.binding_version,
            "validFrom": _timestamp(self.valid_from),
            "expiresAt": _timestamp(self.expires_at),
            "operation": self.operation,
            "priorBindingId": self.prior_binding_id,
            "nonce": self.nonce,
            "digest": self.digest,
            "signatureFormat": self.signature_format,
            "signature": self.signature,
        }


class DeviceBindingRepository(Protocol):
    def apply(
        self,
        statement: DeviceBindingStatement,
        now: datetime,
    ) -> DeviceBindingStatement:
        ...

    def current_for_subject(
        self,
        subject: str,
        now: datetime,
        maximum: int,
    ) -> list[DeviceBindingStatement]:
        ...


def _utc(value: object) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise ValueError

    normalized = value.astimezone(timezone.utc)

    if normalized.microsecond:
        raise ValueError

    return normalized


def _trusted_utc_second(value: object) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise ValueError

    return value.astimezone(timezone.utc).replace(microsecond=0)


def _timestamp(value: datetime) -> str:
    return (
        _utc(value)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _parse_timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError

    parsed = datetime.fromisoformat(value[:-1] + "+00:00")

    if _timestamp(parsed) != value:
        raise ValueError

    return parsed


def _core_dict(
    *,
    subject: str,
    device_id: str,
    public_key: str,
    binding_version: int,
    valid_from: datetime,
    expires_at: datetime,
    operation: str,
    prior_binding_id: str | None,
    nonce: str,
) -> dict[str, object]:
    return {
        "schema": STATEMENT_SCHEMA,
        "version": 1,
        "subject": subject,
        "deviceId": device_id,
        "algorithm": ALGORITHM,
        "publicKey": public_key,
        "bindingVersion": binding_version,
        "validFrom": _timestamp(valid_from),
        "expiresAt": _timestamp(expires_at),
        "operation": operation,
        "priorBindingId": prior_binding_id,
        "nonce": nonce,
    }


def canonical_statement_bytes(core: dict[str, object]) -> bytes:
    envelope = {
        "domain": SIGNATURE_DOMAIN,
        "statement": core,
    }

    return json.dumps(
        envelope,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def statement_digest(core: dict[str, object]) -> str:
    return hashlib.sha256(canonical_statement_bytes(core)).hexdigest()


def _closed_json_object(value: object) -> dict[str, object]:
    if not isinstance(value, str):
        raise ValueError

    def pairs(values):
        result = {}

        for key, item in values:
            if not isinstance(key, str) or key in result:
                raise ValueError

            result[key] = item

        return result

    decoded = json.loads(value, object_pairs_hook=pairs)

    if type(decoded) is not dict:
        raise ValueError

    canonical = json.dumps(
        decoded,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )

    if canonical != value:
        raise ValueError

    return decoded


def _parse_and_verify_dict(
    payload: object,
    *,
    authenticated_subject: object,
) -> DeviceBindingStatement:
    try:
        if (
            type(payload) is not dict
            or not all(type(key) is str for key in payload)
            or set(payload) != _FIELDS
        ):
            raise ValueError

        if type(payload["version"]) is not int or payload["version"] != 1:
            raise ValueError

        subject = _canonical_actor(payload["subject"])
        actor = _canonical_actor(authenticated_subject)

        if subject != actor:
            raise ValueError

        device_id = payload["deviceId"]

        if (
            not isinstance(device_id, str)
            or _HEX64(device_id) is None
            or device_id == "00" * 32
        ):
            raise ValueError

        public_key = validate_x25519_public_key(payload["publicKey"])

        if device_id in {subject, public_key}:
            raise ValueError

        binding_version = payload["bindingVersion"]

        if (
            type(binding_version) is not int
            or not 1 <= binding_version <= MAX_BINDING_VERSION
        ):
            raise ValueError

        valid_from = _parse_timestamp(payload["validFrom"])
        expires_at = _parse_timestamp(payload["expiresAt"])

        if valid_from >= expires_at:
            raise ValueError

        operation = payload["operation"]

        if type(operation) is not str or operation not in _OPERATIONS:
            raise ValueError

        prior = payload["priorBindingId"]

        if operation == "register":
            if prior is not None or binding_version != 1:
                raise ValueError
        elif (
            not isinstance(prior, str)
            or _HEX64(prior) is None
            or binding_version < 2
        ):
            raise ValueError

        nonce = payload["nonce"]
        digest = payload["digest"]
        signature = payload["signature"]

        if (
            payload["schema"] != STATEMENT_SCHEMA
            or payload["algorithm"] != ALGORITHM
            or payload["signatureFormat"] != SIGNATURE_FORMAT
            or not isinstance(nonce, str)
            or _HEX64(nonce) is None
            or not isinstance(digest, str)
            or _HEX64(digest) is None
            or not isinstance(signature, str)
            or _HEX128(signature) is None
        ):
            raise ValueError

        core = _core_dict(
            subject=subject,
            device_id=device_id,
            public_key=public_key,
            binding_version=binding_version,
            valid_from=valid_from,
            expires_at=expires_at,
            operation=operation,
            prior_binding_id=prior,
            nonce=nonce,
        )

        expected = statement_digest(core)

        if digest != expected:
            raise ValueError

        verifier = PublicKeyXOnly(bytes.fromhex(subject))

        if not verifier.verify(
            bytes.fromhex(signature),
            bytes.fromhex(expected),
        ):
            raise ValueError

        if public_key == subject:
            raise ValueError

        return DeviceBindingStatement(
            STATEMENT_SCHEMA,
            subject,
            device_id,
            ALGORITHM,
            public_key,
            binding_version,
            valid_from,
            expires_at,
            operation,
            prior,
            nonce,
            digest,
            SIGNATURE_FORMAT,
            signature,
        )

    except Exception:
        raise DeviceBindingRegistryUnavailable() from None


def parse_and_verify_statement(
    payload: object,
    *,
    authenticated_subject: object,
) -> DeviceBindingStatement:
    try:
        decoded = _closed_json_object(payload)

        return _parse_and_verify_dict(
            decoded,
            authenticated_subject=authenticated_subject,
        )

    except Exception:
        raise DeviceBindingRegistryUnavailable() from None


class SocialMessagingDeviceBindingRegistry:
    def __init__(
        self,
        repository: DeviceBindingRepository,
        *,
        clock: Callable[[], datetime] | None = None,
    ):
        self._repository = repository
        self._clock = clock or (
            lambda: datetime.now(timezone.utc)
        )

    def apply(
        self,
        payload: object,
        *,
        authenticated_subject: object,
    ) -> dict[str, object]:
        try:
            now = _trusted_utc_second(self._clock())

            statement = parse_and_verify_statement(
                payload,
                authenticated_subject=authenticated_subject,
            )

            stored = self._repository.apply(statement, now)

            if stored != statement:
                raise ValueError

            return stored.public_dict()

        except Exception:
            raise DeviceBindingRegistryUnavailable() from None

    def current_for_subject(
        self,
        subject: object,
        *,
        maximum: object = MAX_ACTIVE_DEVICES,
    ) -> dict[str, object]:
        try:
            canonical_subject = _canonical_actor(subject)

            if (
                type(maximum) is not int
                or not 0 <= maximum <= MAX_ACTIVE_DEVICES
            ):
                raise ValueError

            now = _trusted_utc_second(self._clock())

            records = self._repository.current_for_subject(
                canonical_subject,
                now,
                maximum,
            )

            if type(records) is not list or len(records) > maximum:
                raise ValueError

            devices = []
            public_keys = set()
            previous_device = None
            deadlines = []

            for record in records:
                if type(record) is not DeviceBindingStatement:
                    raise ValueError

                verified = _parse_and_verify_dict(
                    record.public_dict(),
                    authenticated_subject=canonical_subject,
                )

                if (
                    verified != record
                    or record.subject != canonical_subject
                    or record.operation not in {"register", "rotate"}
                    or record.valid_from > now
                    or record.expires_at <= now
                    or (
                        previous_device is not None
                        and record.device_id <= previous_device
                    )
                    or record.public_key in public_keys
                ):
                    raise ValueError

                previous_device = record.device_id
                public_keys.add(record.public_key)
                deadlines.append(record.expires_at)

                devices.append(
                    {
                        "deviceId": record.device_id,
                        "bindingId": record.binding_id,
                        "algorithm": ALGORITHM,
                        "version": record.binding_version,
                        "publicKey": record.public_key,
                        "validFrom": int(
                            record.valid_from.timestamp() * 1000
                        ),
                        "expiresAt": int(
                            record.expires_at.timestamp() * 1000
                        ),
                        "revoked": False,
                    }
                )

            expires_at = (
                int(
                    min(
                        now.timestamp() + SNAPSHOT_LIFETIME_SECONDS,
                        *(
                            deadline.timestamp()
                            for deadline in deadlines
                        ),
                    )
                    * 1000
                )
                if deadlines
                else int(
                    (
                        now.timestamp()
                        + SNAPSHOT_LIFETIME_SECONDS
                    )
                    * 1000
                )
            )

            issued_at = int(now.timestamp() * 1000)

            evidence = {
                "activeDevices": devices,
                "complete": True,
                "expiresAt": expires_at,
                "issuedAt": issued_at,
            }

            canonical = json.dumps(
                evidence,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            )

            snapshot_id = (
                "sha256:"
                + hashlib.sha256(
                    canonical.encode("ascii")
                ).hexdigest()
            )

            return {
                "schema": SNAPSHOT_SCHEMA,
                "version": 1,
                "source": SOURCE,
                "snapshotId": snapshot_id,
                "complete": True,
                "issuedAt": issued_at,
                "expiresAt": expires_at,
                "activeDevices": [
                    {
                        "snapshotId": snapshot_id,
                        **device,
                    }
                    for device in devices
                ],
            }

        except Exception:
            raise DeviceBindingRegistryUnavailable() from None


__all__ = [
    "ALGORITHM",
    "DeviceBindingRegistryUnavailable",
    "DeviceBindingRepository",
    "DeviceBindingStatement",
    "MAX_ACTIVE_DEVICES",
    "MAX_BINDING_VERSION",
    "SIGNATURE_DOMAIN",
    "SIGNATURE_FORMAT",
    "SNAPSHOT_SCHEMA",
    "SocialMessagingDeviceBindingRegistry",
    "STATEMENT_SCHEMA",
    "canonical_statement_bytes",
    "parse_and_verify_statement",
    "statement_digest",
]
