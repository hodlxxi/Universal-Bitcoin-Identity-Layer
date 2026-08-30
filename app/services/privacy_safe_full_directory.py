"""Viewer-private directory over one complete current-Full snapshot."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from collections.abc import Callable
from datetime import datetime, timezone

from app.auth_api_core import canonical_xonly_pubkey
from app.services.action_authorization import IdentityClass
from app.services.current_entitlement import EntitlementDecision, EntitlementDenied, EntitlementUnavailable

DIRECTORY_SCHEMA = "hodlxxi.privacy_safe_full_directory.v1"
FULL_ENTITLEMENT_SNAPSHOT_SCHEMA = "hodlxxi.full_entitlement_snapshot.v1"
SOURCE = "hodlxxi-crt"
VERSION = 1
DEFAULT_ALIAS_VERSION = 1
ALIAS_DOMAIN = b"HODLXXI_PRIVACY_DIRECTORY_ALIAS_V1"
ALIAS_BYTES = 16
MIN_ALIAS_SECRET_BYTES = 32
MAX_ALIAS_SECRET_BYTES = 4096
MAX_ALIAS_VERSION = 2_147_483_647
MAX_PARTICIPANTS = 4096
MAX_SNAPSHOT_VALIDITY_MS = 300_000
MAX_SAFE_INTEGER = 9_007_199_254_740_991

_SNAPSHOT_ID = re.compile(r"sha256:[0-9a-f]{64}").fullmatch
_DENIED_MESSAGE = "privacy-safe full directory denied"
_UNAVAILABLE_MESSAGE = "privacy-safe full directory unavailable"

CurrentEntitlementResolver = Callable[[str], EntitlementDecision]
FullPopulationProvider = Callable[[], object]


class PrivacySafeFullDirectoryDenied(ValueError):
    """The viewer is not authorized to receive any directory data."""

    def __init__(self) -> None:
        super().__init__(_DENIED_MESSAGE)


class PrivacySafeFullDirectoryUnavailable(RuntimeError):
    """The complete privacy-safe directory cannot be constructed."""

    def __init__(self) -> None:
        super().__init__(_UNAVAILABLE_MESSAGE)


class _InvalidPopulation(ValueError):
    pass


def _exact_dict(value: object, fields: set[str]) -> dict:
    if type(value) is not dict or not all(type(key) is str for key in value) or set(value) != fields:
        raise _InvalidPopulation
    return value


def _integer(value: object) -> int:
    if type(value) is not int or not 0 <= value <= MAX_SAFE_INTEGER:
        raise _InvalidPopulation
    return value


def _subject(value: object) -> str:
    if type(value) is not str:
        raise _InvalidPopulation
    try:
        canonical = canonical_xonly_pubkey(value)
    except (TypeError, ValueError):
        raise _InvalidPopulation from None
    if value != canonical:
        raise _InvalidPopulation
    return canonical


def _current_time_ms(clock: Callable[[], datetime]) -> int:
    try:
        now = clock()
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
            raise ValueError
        return int(now.astimezone(timezone.utc).timestamp() * 1000)
    except Exception:
        raise PrivacySafeFullDirectoryUnavailable() from None


def _snapshot_subjects(value: object, *, now: int, viewer: str) -> tuple[str, ...]:
    snapshot = _exact_dict(
        value,
        {"schema", "version", "source", "snapshotId", "complete", "issuedAt", "expiresAt", "entitlements"},
    )
    if (
        snapshot["schema"] != FULL_ENTITLEMENT_SNAPSHOT_SCHEMA
        or type(snapshot["schema"]) is not str
        or snapshot["version"] != VERSION
        or type(snapshot["version"]) is not int
        or snapshot["source"] != SOURCE
        or type(snapshot["source"]) is not str
        or snapshot["complete"] is not True
        or type(snapshot["snapshotId"]) is not str
        or _SNAPSHOT_ID(snapshot["snapshotId"]) is None
        or type(snapshot["entitlements"]) is not list
        or len(snapshot["entitlements"]) > MAX_PARTICIPANTS
    ):
        raise _InvalidPopulation

    issued_at = _integer(snapshot["issuedAt"])
    expires_at = _integer(snapshot["expiresAt"])
    if (
        issued_at > now
        or now >= expires_at
        or issued_at >= expires_at
        or expires_at - issued_at > MAX_SNAPSHOT_VALIDITY_MS
    ):
        raise _InvalidPopulation

    subjects = []
    digest_entitlements = []
    previous = None
    fields = {"snapshotId", "subject", "status", "validFrom", "expiresAt", "revoked"}
    for value in snapshot["entitlements"]:
        entitlement = _exact_dict(value, fields)
        subject = _subject(entitlement["subject"])
        valid_from = _integer(entitlement["validFrom"])
        record_expires_at = _integer(entitlement["expiresAt"])
        if (
            entitlement["snapshotId"] != snapshot["snapshotId"]
            or type(entitlement["snapshotId"]) is not str
            or entitlement["status"] != "full"
            or type(entitlement["status"]) is not str
            or entitlement["revoked"] is not False
            or valid_from > issued_at
            or record_expires_at < expires_at
            or previous is not None
            and subject <= previous
        ):
            raise _InvalidPopulation
        previous = subject
        subjects.append(subject)
        digest_entitlements.append(
            {
                "subject": subject,
                "status": "full",
                "validFrom": valid_from,
                "expiresAt": record_expires_at,
                "revoked": False,
            }
        )

    digest_evidence = {
        "complete": True,
        "entitlements": digest_entitlements,
        "expiresAt": expires_at,
        "issuedAt": issued_at,
    }
    canonical = json.dumps(digest_evidence, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    expected_snapshot_id = "sha256:" + hashlib.sha256(canonical.encode("ascii")).hexdigest()
    if not hmac.compare_digest(snapshot["snapshotId"], expected_snapshot_id) or viewer not in subjects:
        raise _InvalidPopulation
    return tuple(subjects)


class PrivacySafeFullDirectoryV1:
    """Authorize one viewer and build a viewer-bound alias directory."""

    def __init__(
        self,
        *,
        viewer_subject: str,
        current_entitlement_resolver: CurrentEntitlementResolver,
        full_population_provider: FullPopulationProvider,
        alias_secret: bytes,
        alias_version: int = DEFAULT_ALIAS_VERSION,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not callable(current_entitlement_resolver) or not callable(full_population_provider):
            raise ValueError("invalid privacy directory dependency")
        if type(alias_secret) is not bytes or not MIN_ALIAS_SECRET_BYTES <= len(alias_secret) <= MAX_ALIAS_SECRET_BYTES:
            raise ValueError("invalid pairwise alias secret")
        if type(alias_version) is not int or not 1 <= alias_version <= MAX_ALIAS_VERSION:
            raise ValueError("invalid pairwise alias version")
        if clock is not None and not callable(clock):
            raise ValueError("invalid privacy directory clock")
        self._viewer_subject = viewer_subject
        self._current_entitlement_resolver = current_entitlement_resolver
        self._full_population_provider = full_population_provider
        self._alias_secret = alias_secret
        self._alias_version = alias_version
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def _authorized_viewer(self) -> str:
        try:
            viewer = canonical_xonly_pubkey(self._viewer_subject)
            if self._viewer_subject != viewer:
                raise ValueError
        except (TypeError, ValueError):
            raise PrivacySafeFullDirectoryDenied() from None

        try:
            entitlement = self._current_entitlement_resolver(viewer)
        except EntitlementDenied:
            raise PrivacySafeFullDirectoryDenied() from None
        except EntitlementUnavailable:
            raise PrivacySafeFullDirectoryUnavailable() from None
        except Exception:
            raise PrivacySafeFullDirectoryUnavailable() from None

        try:
            if type(entitlement) is not EntitlementDecision or entitlement.subject != viewer:
                raise ValueError
            if type(entitlement.identity_class) is not IdentityClass:
                raise ValueError
            if type(entitlement.current_full_relation_satisfied) is not bool:
                raise ValueError
        except Exception:
            raise PrivacySafeFullDirectoryUnavailable() from None

        if (
            entitlement.identity_class is not IdentityClass.FULL
            or entitlement.current_full_relation_satisfied is not True
        ):
            raise PrivacySafeFullDirectoryDenied() from None

        try:
            if (
                type(entitlement.evidence_source) is not str
                or not entitlement.evidence_source
                or entitlement.evidence_source.strip() != entitlement.evidence_source
                or type(entitlement.observed_at) is not str
                or not entitlement.observed_at
            ):
                raise ValueError
            observed_at = datetime.fromisoformat(entitlement.observed_at)
            if observed_at.tzinfo is None or observed_at.utcoffset() is None:
                raise ValueError
        except Exception:
            raise PrivacySafeFullDirectoryUnavailable() from None
        return viewer

    def _alias(self, viewer: str, target: str) -> str:
        message = b"\x00".join(
            (
                ALIAS_DOMAIN,
                str(VERSION).encode("ascii"),
                str(self._alias_version).encode("ascii"),
                viewer.encode("ascii"),
                target.encode("ascii"),
            )
        )
        digest = hmac.new(self._alias_secret, message, hashlib.sha256).digest()[:ALIAS_BYTES]
        encoded = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        return "p_" + encoded

    def current_directory(self) -> dict[str, object]:
        """Return only opaque entries, or fail without returning partial data."""

        viewer = self._authorized_viewer()
        try:
            snapshot = self._full_population_provider()
        except Exception:
            raise PrivacySafeFullDirectoryUnavailable() from None

        try:
            subjects = _snapshot_subjects(snapshot, now=_current_time_ms(self._clock), viewer=viewer)
            entries = []
            aliases = set()
            for target in subjects:
                if target == viewer:
                    continue
                alias = self._alias(viewer, target)
                if alias in aliases:
                    raise _InvalidPopulation
                aliases.add(alias)
                entries.append(
                    {
                        "alias": alias,
                        "identity_class": "full",
                        "current_full_relation_satisfied": True,
                    }
                )
            entries.sort(key=lambda entry: entry["alias"])
            return {"schema": DIRECTORY_SCHEMA, "version": VERSION, "participants": entries}
        except PrivacySafeFullDirectoryUnavailable:
            raise
        except Exception:
            raise PrivacySafeFullDirectoryUnavailable() from None
