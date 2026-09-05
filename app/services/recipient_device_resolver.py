"""Viewer-private resolver for current Full recipient messaging devices.

This module resolves one viewer-private ``p_`` alias to the target's current
multi-device X25519 bindings without returning the canonical target subject,
raw device IDs, or raw binding IDs.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from datetime import datetime, timezone
from typing import Callable

from app.services.privacy_safe_full_directory import (
    MAX_ALIAS_SECRET_BYTES,
    MAX_ALIAS_VERSION,
    MIN_ALIAS_SECRET_BYTES,
    PrivacySafeFullDirectoryDenied,
    PrivacySafeFullDirectoryUnavailable,
    PrivacySafeFullDirectoryV1,
    derive_privacy_directory_alias,
)
from app.services.social_messaging_device_contract import (
    MAX_ACTIVE_DEVICES,
    MessagingDeviceAuthorityUnavailable,
    SocialMessagingDeviceAuthority,
)

PACKAGE_SCHEMA = "hodlxxi.social_messaging_recipient_package.v1"
SOURCE = "hodlxxi-ubid"
VERSION = 1
DEVICE_HANDLE_DOMAIN = b"HODLXXI_RECIPIENT_DEVICE_HANDLE_V1"
DEVICE_HANDLE_BYTES = 16
_ALIAS = re.compile(r"p_[A-Za-z0-9_-]{22}\Z").fullmatch
_UNAVAILABLE_MESSAGE = "recipient messaging devices unavailable"
_DENIED_MESSAGE = "recipient messaging device resolution denied"
_INVALID_MESSAGE = "recipient alias invalid"


class RecipientDeviceResolverUnavailable(RuntimeError):
    def __init__(self) -> None:
        super().__init__(_UNAVAILABLE_MESSAGE)


class RecipientDeviceResolverDenied(ValueError):
    def __init__(self) -> None:
        super().__init__(_DENIED_MESSAGE)


class RecipientAliasInvalid(ValueError):
    def __init__(self) -> None:
        super().__init__(_INVALID_MESSAGE)


def _utc_second(value: object) -> datetime:
    try:
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            raise ValueError
        normalized = value.astimezone(timezone.utc)
        if normalized.microsecond:
            raise ValueError
        return normalized
    except Exception:
        raise RecipientDeviceResolverUnavailable() from None


def _device_handle(
    *,
    viewer: str,
    target: str,
    binding_id: str,
    alias_secret: bytes,
    alias_version: int,
) -> str:
    message = b"\x00".join(
        (
            DEVICE_HANDLE_DOMAIN,
            str(VERSION).encode("ascii"),
            str(alias_version).encode("ascii"),
            viewer.encode("ascii"),
            target.encode("ascii"),
            binding_id.encode("ascii"),
        )
    )
    digest = hmac.new(alias_secret, message, hashlib.sha256).digest()[:DEVICE_HANDLE_BYTES]
    return "d_" + base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


class RecipientDeviceResolverV1:
    """Resolve a viewer-private Full alias to a privacy-minimized device package."""

    def __init__(
        self,
        *,
        current_entitlement_resolver: Callable[[str], object],
        full_population_provider: Callable[[], object],
        device_repository: object,
        alias_secret: bytes,
        alias_version: int = 1,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if (
            not callable(current_entitlement_resolver)
            or not callable(full_population_provider)
            or not callable(getattr(device_repository, "current_for_subject", None))
            or type(alias_secret) is not bytes
            or not MIN_ALIAS_SECRET_BYTES <= len(alias_secret) <= MAX_ALIAS_SECRET_BYTES
            or type(alias_version) is not int
            or not 1 <= alias_version <= MAX_ALIAS_VERSION
            or clock is not None
            and not callable(clock)
        ):
            raise ValueError("invalid recipient device resolver dependency")
        self._current_entitlement_resolver = current_entitlement_resolver
        self._full_population_provider = full_population_provider
        self._device_repository = device_repository
        self._alias_secret = alias_secret
        self._alias_version = alias_version
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def resolve(self, *, viewer_subject: object, recipient_alias: object) -> dict[str, object]:
        if type(recipient_alias) is not str or _ALIAS(recipient_alias) is None:
            raise RecipientAliasInvalid()

        now = _utc_second(self._clock())
        captured: list[object] = []

        def capture_population() -> object:
            value = self._full_population_provider()
            captured.append(value)
            return value

        try:
            directory = PrivacySafeFullDirectoryV1(
                viewer_subject=viewer_subject,
                current_entitlement_resolver=self._current_entitlement_resolver,
                full_population_provider=capture_population,
                alias_secret=self._alias_secret,
                alias_version=self._alias_version,
                clock=lambda: now,
            ).current_directory()
        except PrivacySafeFullDirectoryDenied:
            raise RecipientDeviceResolverDenied() from None
        except PrivacySafeFullDirectoryUnavailable:
            raise RecipientDeviceResolverUnavailable() from None
        except Exception:
            raise RecipientDeviceResolverUnavailable() from None

        try:
            if len(captured) != 1:
                raise ValueError
            population = captured[0]
            if type(population) is not dict or type(population.get("entitlements")) is not list:
                raise ValueError
            aliases = {
                entry["alias"]
                for entry in directory["participants"]
                if type(entry) is dict and type(entry.get("alias")) is str
            }
            if recipient_alias not in aliases:
                raise RecipientDeviceResolverUnavailable()

            viewer = viewer_subject
            matches = []
            for entitlement in population["entitlements"]:
                if type(entitlement) is not dict:
                    raise ValueError
                target = entitlement.get("subject")
                if target == viewer:
                    continue
                alias = derive_privacy_directory_alias(
                    viewer=viewer,
                    target=target,
                    alias_secret=self._alias_secret,
                    alias_version=self._alias_version,
                )
                if hmac.compare_digest(alias, recipient_alias):
                    matches.append(target)
            if len(matches) != 1:
                raise RecipientDeviceResolverUnavailable()
            target = matches[0]

            device_snapshot = SocialMessagingDeviceAuthority(
                self._device_repository,
                clock=lambda: now,
            ).current(authenticated_subject=target)
            raw_devices = device_snapshot["activeDevices"]
            if type(raw_devices) is not list or not 1 <= len(raw_devices) <= MAX_ACTIVE_DEVICES:
                raise RecipientDeviceResolverUnavailable()

            devices = []
            handles = set()
            for raw in raw_devices:
                if type(raw) is not dict:
                    raise ValueError
                handle = _device_handle(
                    viewer=viewer,
                    target=target,
                    binding_id=raw["bindingId"],
                    alias_secret=self._alias_secret,
                    alias_version=self._alias_version,
                )
                if handle in handles:
                    raise ValueError
                handles.add(handle)
                devices.append(
                    {
                        "deviceHandle": handle,
                        "algorithm": raw["algorithm"],
                        "version": raw["version"],
                        "publicKey": raw["publicKey"],
                        "validFrom": raw["validFrom"],
                        "expiresAt": raw["expiresAt"],
                    }
                )
            devices.sort(key=lambda item: item["deviceHandle"])

            issued_at = max(population["issuedAt"], device_snapshot["issuedAt"])
            expires_at = min(population["expiresAt"], device_snapshot["expiresAt"])
            now_ms = int(now.timestamp() * 1000)
            if (
                type(issued_at) is not int
                or type(expires_at) is not int
                or issued_at > now_ms
                or now_ms >= expires_at
                or issued_at >= expires_at
            ):
                raise ValueError

            evidence = {
                "schema": PACKAGE_SCHEMA,
                "version": VERSION,
                "source": SOURCE,
                "alias": recipient_alias,
                "complete": True,
                "issuedAt": issued_at,
                "expiresAt": expires_at,
                "devices": devices,
            }
            canonical = json.dumps(
                evidence,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
            snapshot_id = "sha256:" + hashlib.sha256(canonical).hexdigest()
            return {
                "schema": PACKAGE_SCHEMA,
                "version": VERSION,
                "source": SOURCE,
                "snapshotId": snapshot_id,
                "complete": True,
                "alias": recipient_alias,
                "issuedAt": issued_at,
                "expiresAt": expires_at,
                "devices": devices,
            }
        except RecipientDeviceResolverUnavailable:
            raise
        except MessagingDeviceAuthorityUnavailable:
            raise RecipientDeviceResolverUnavailable() from None
        except Exception:
            raise RecipientDeviceResolverUnavailable() from None


__all__ = [
    "PACKAGE_SCHEMA",
    "RecipientAliasInvalid",
    "RecipientDeviceResolverDenied",
    "RecipientDeviceResolverUnavailable",
    "RecipientDeviceResolverV1",
    "SOURCE",
    "VERSION",
]
