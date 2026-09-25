"""Dormant offline-signed alias namespace command contract.

Verification is evidence for a future transaction owner, never permission to
write a registry row by itself. No signer, private key, database, environment,
HTTP route, clock source, or runtime composition is provided here.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import NoReturn

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SCHEMA = "hodlxxi.social_active_alias_namespace_lifecycle_command.v1"
AUDIENCE = "hodlxxi.ubid.alias_namespace_lifecycle.v1"
ALGORITHM = "Ed25519"
COMMAND_ID_DOMAIN = b"HODLXXI_SOCIAL_ACTIVE_ALIAS_LIFECYCLE_COMMAND_ID_V1"
SIGNATURE_DOMAIN = b"HODLXXI_SOCIAL_ACTIVE_ALIAS_LIFECYCLE_SIGNATURE_V1"
COMMAND_ID_PREFIX = "hodlxxi-social-active-alias-lifecycle-command-v1-sha256:"
COMMITMENT_PREFIX = "hodlxxi-social-active-alias-namespace-v1-sha256:"
MAX_COMMAND_BYTES = 2048
MAX_COMMAND_LIFETIME_MS = 86_400_000
MAX_ALIAS_VERSION = 2_147_483_647
MAX_SAFE_INTEGER = 9_007_199_254_740_991

_COMMITMENT = re.compile(re.escape(COMMITMENT_PREFIX) + r"[0-9a-f]{64}\Z").fullmatch
_COMMAND_ID = re.compile(re.escape(COMMAND_ID_PREFIX) + r"[0-9a-f]{64}\Z").fullmatch
_KEY_ID = re.compile(r"[a-z0-9][a-z0-9._:-]{0,63}\Z").fullmatch
_NONCE = re.compile(r"[A-Za-z0-9_-]{43}\Z").fullmatch
_SIGNATURE = re.compile(r"[A-Za-z0-9_-]{86}\Z").fullmatch
_FIELDS = frozenset(
    (
        "action", "algorithm", "audience", "commandId", "expectedCommitment",
        "expectedVersion", "expiresAtMs", "issuedAtMs", "keyId", "nonce",
        "schema", "successorCommitment", "successorVersion", "version",
    )
)
_VERIFIED_TOKEN = object()


class AliasLifecycleCommandUnavailable(ValueError):
    """One non-sensitive outcome for invalid or untrusted lifecycle commands."""

    def __init__(self) -> None:
        super().__init__("social messaging alias lifecycle unavailable")


def _deny() -> NoReturn:
    raise AliasLifecycleCommandUnavailable()


def _canonical(value: dict[str, object]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _decoded(value: object, pattern: Callable[[str], re.Match[str] | None], length: int) -> bytes:
    if type(value) is not str or pattern(value) is None:
        _deny()
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if len(raw) != length or base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != value:
        _deny()
    return raw


def _command_id(command_without_id: dict[str, object]) -> str:
    return COMMAND_ID_PREFIX + hashlib.sha256(
        COMMAND_ID_DOMAIN + b"\x00" + _canonical(command_without_id)
    ).hexdigest()


def _validated(command: object) -> dict[str, object]:
    if type(command) is not dict or set(command) != _FIELDS or any(
        type(key) is not str for key in command
    ):
        _deny()
    value = dict(command)
    if (
        value["schema"] != SCHEMA
        or type(value["schema"]) is not str
        or value["version"] != 1
        or type(value["version"]) is not int
        or value["algorithm"] != ALGORITHM
        or type(value["algorithm"]) is not str
        or value["audience"] != AUDIENCE
        or type(value["audience"]) is not str
        or type(value["keyId"]) is not str
        or _KEY_ID(value["keyId"]) is None
        or type(value["action"]) is not str
        or value["action"] not in ("provision", "rotate")
        or type(value["commandId"]) is not str
        or _COMMAND_ID(value["commandId"]) is None
        or type(value["successorCommitment"]) is not str
        or _COMMITMENT(value["successorCommitment"]) is None
    ):
        _deny()
    _decoded(value["nonce"], _NONCE, 32)
    for field in ("issuedAtMs", "expiresAtMs"):
        if type(value[field]) is not int or not 0 <= value[field] <= MAX_SAFE_INTEGER:
            _deny()
    if not 0 < value["expiresAtMs"] - value["issuedAtMs"] <= MAX_COMMAND_LIFETIME_MS:
        _deny()
    if (
        type(value["successorVersion"]) is not int
        or not 1 <= value["successorVersion"] <= MAX_ALIAS_VERSION
    ):
        _deny()
    if value["action"] == "provision":
        if (
            value["expectedVersion"] is not None
            or value["expectedCommitment"] is not None
            or value["successorVersion"] != 1
        ):
            _deny()
    elif (
        type(value["expectedVersion"]) is not int
        or not 1 <= value["expectedVersion"] < MAX_ALIAS_VERSION
        or value["successorVersion"] != value["expectedVersion"] + 1
        or type(value["expectedCommitment"]) is not str
        or _COMMITMENT(value["expectedCommitment"]) is None
        or hmac.compare_digest(value["expectedCommitment"], value["successorCommitment"])
    ):
        _deny()
    if not hmac.compare_digest(
        value["commandId"], _command_id({key: item for key, item in value.items() if key != "commandId"})
    ):
        _deny()
    return value


def canonical_alias_lifecycle_command_v1(fields: object) -> bytes:
    """Build unsigned exact bytes; generating a nonce/signature is external."""

    try:
        if type(fields) is not dict or set(fields) != _FIELDS - {"commandId"}:
            _deny()
        value = dict(fields)
        value["commandId"] = _command_id(value)
        _validated(value)
        wire = _canonical(value)
        if len(wire) > MAX_COMMAND_BYTES:
            _deny()
        return wire
    except Exception:
        _deny()


def parse_canonical_alias_lifecycle_command_v1(wire: object) -> dict[str, object]:
    """Parse without granting lifecycle authority or accepting JSON aliases."""

    try:
        if type(wire) is not bytes or not 1 <= len(wire) <= MAX_COMMAND_BYTES:
            _deny()
        source = wire.decode("ascii")
        if any(ord(character) < 0x20 or ord(character) > 0x7E for character in source):
            _deny()

        def unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
            if len(pairs) != len(set(key for key, _ in pairs)):
                _deny()
            return dict(pairs)

        command = _validated(json.loads(source, object_pairs_hook=unique_pairs))
        if _canonical(command) != wire:
            _deny()
        return command
    except Exception:
        _deny()


@dataclass(frozen=True, slots=True)
class InspectedAliasLifecycleCommandV1:
    """Canonical values only. This is NOT authenticated authority."""

    command_id: str
    action: str
    expected_version: int | None
    expected_commitment: str | None
    successor_version: int
    successor_commitment: str
    expires_at_ms: int
    key_id: str


class VerifiedAliasLifecycleCommandV1:
    """Signature evidence; a future writer must verify inside its own entry."""

    __slots__ = ("_inspected", "_command_wire", "_signature")

    def __new__(cls, token: object, *_args: object):
        if cls is not VerifiedAliasLifecycleCommandV1 or token is not _VERIFIED_TOKEN:
            _deny()
        return super().__new__(cls)

    def __init__(self, token: object, inspected: InspectedAliasLifecycleCommandV1,
                 command_wire: bytes, signature: str) -> None:
        object.__setattr__(self, "_inspected", inspected)
        object.__setattr__(self, "_command_wire", command_wire)
        object.__setattr__(self, "_signature", signature)

    def __setattr__(self, _name: str, _value: object) -> None:
        _deny()

    def __init_subclass__(cls, **_kwargs: object) -> None:
        _deny()

    @property
    def inspected(self) -> InspectedAliasLifecycleCommandV1:
        return self._inspected

    @property
    def command_wire(self) -> bytes:
        return self._command_wire

    @property
    def signature(self) -> str:
        return self._signature


class PinnedOfflineAliasLifecycleVerifierV1:
    """Trust comes only from an explicitly injected, pinned public key/ID."""

    __slots__ = ("_public_key", "_key_id")

    def __init__(self, *, public_key: bytes, key_id: str) -> None:
        try:
            if type(public_key) is not bytes or len(public_key) != 32 or (
                type(key_id) is not str or _KEY_ID(key_id) is None
            ):
                _deny()
            self._public_key = Ed25519PublicKey.from_public_bytes(public_key)
            self._key_id = key_id
        except Exception:
            _deny()

    def verify(self, command_wire: bytes, signature: str, *, now_ms: int) -> VerifiedAliasLifecycleCommandV1:
        try:
            command = parse_canonical_alias_lifecycle_command_v1(command_wire)
            if (
                command["keyId"] != self._key_id
                or type(now_ms) is not int
                or not 0 <= now_ms <= MAX_SAFE_INTEGER
                or not command["issuedAtMs"] <= now_ms < command["expiresAtMs"]
            ):
                _deny()
            self._public_key.verify(
                _decoded(signature, _SIGNATURE, 64),
                SIGNATURE_DOMAIN + b"\x00" + command_wire,
            )
            inspected = InspectedAliasLifecycleCommandV1(
                command_id=command["commandId"],
                action=command["action"],
                expected_version=command["expectedVersion"],
                expected_commitment=command["expectedCommitment"],
                successor_version=command["successorVersion"],
                successor_commitment=command["successorCommitment"],
                expires_at_ms=command["expiresAtMs"],
                key_id=command["keyId"],
            )
            return VerifiedAliasLifecycleCommandV1(_VERIFIED_TOKEN, inspected, command_wire, signature)
        except Exception:
            _deny()


RUNTIME_ENABLED = False
NAMESPACE_PROVISIONING = "not_implemented"
NAMESPACE_ROTATION = "not_implemented"
