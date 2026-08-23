"""Pure builder for a complete, injected Full recipient directory snapshot."""

from __future__ import annotations

import hashlib
import json
import re

DIRECTORY_SCHEMA = "hodlxxi.full_recipient_directory.v1"
ENTITLEMENT_SNAPSHOT_SCHEMA = "hodlxxi.full_entitlement_snapshot.v1"
BINDING_SNAPSHOT_SCHEMA = "hodlxxi.recipient_key_binding_snapshot.v1"
SOURCE = "hodlxxi-crt"
VERSION = 1
MAX_RECIPIENTS = 4096
MAX_VALIDITY_MS = 300_000
MAX_SAFE_INTEGER = 9_007_199_254_740_991
X25519_FIELD_PRIME = 2**255 - 19

_HEX_64 = re.compile(r"[0-9a-f]{64}").fullmatch
_SNAPSHOT_ID = re.compile(r"[A-Za-z0-9._:-]{1,128}").fullmatch
_UNAVAILABLE_MESSAGE = "full recipient directory unavailable"

# Little-endian encodings rejected by the X25519 contributory-behaviour checks
# used by established implementations. The separate high-bit check prevents
# accepting aliases that an X25519 implementation might silently mask.
_PROHIBITED_X25519 = frozenset(
    {
        "00" * 32,
        "01" + "00" * 31,
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224e8dcf54e900",
        "ec" + "ff" * 30 + "7f",
        "ed" + "ff" * 30 + "7f",
        "ee" + "ff" * 30 + "7f",
    }
)


class FullRecipientDirectoryUnavailable(RuntimeError):
    """The complete directory cannot be safely constructed."""

    def __init__(self) -> None:
        super().__init__(_UNAVAILABLE_MESSAGE)


class _InvalidSource(ValueError):
    pass


def _exact_dict(value: object, fields: set[str]) -> dict:
    if type(value) is not dict or not all(type(key) is str for key in value) or set(value) != fields:
        raise _InvalidSource
    return value


def _exact_list(value: object) -> list:
    if type(value) is not list:
        raise _InvalidSource
    return value


def _integer(value: object, *, positive: bool = False) -> int:
    if type(value) is not int or abs(value) > MAX_SAFE_INTEGER or (positive and value <= 0):
        raise _InvalidSource
    return value


def _subject(value: object) -> str:
    if type(value) is not str or _HEX_64(value) is None:
        raise _InvalidSource
    return value


def _snapshot_id(value: object) -> str:
    if type(value) is not str or _SNAPSHOT_ID(value) is None:
        raise _InvalidSource
    return value


def _interval(issued_at: object, expires_at: object, now: int) -> tuple[int, int]:
    issued = _integer(issued_at)
    expires = _integer(expires_at)
    if issued > now or now >= expires or issued >= expires:
        raise _InvalidSource
    return issued, expires


def _snapshot(value: object, *, schema: str, records_field: str, now: int) -> tuple[dict, list]:
    data = _exact_dict(
        value,
        {"schema", "version", "source", "snapshotId", "complete", "issuedAt", "expiresAt", records_field},
    )
    if (
        type(data["schema"]) is not str
        or data["schema"] != schema
        or type(data["version"]) is not int
        or data["version"] != VERSION
        or type(data["source"]) is not str
        or data["source"] != SOURCE
        or data["complete"] is not True
    ):
        raise _InvalidSource
    snapshot_id = _snapshot_id(data["snapshotId"])
    issued, expires = _interval(data["issuedAt"], data["expiresAt"], now)
    records = _exact_list(data[records_field])
    if len(records) > MAX_RECIPIENTS:
        raise _InvalidSource
    return {
        "schema": schema,
        "version": VERSION,
        "source": SOURCE,
        "snapshotId": snapshot_id,
        "complete": True,
        "issuedAt": issued,
        "expiresAt": expires,
        records_field: [],
    }, records


def _entitlements(snapshot: dict, records: list, now: int) -> dict[str, dict]:
    fields = {"snapshotId", "subject", "status", "validFrom", "expiresAt", "revoked"}
    normalized = []
    previous = None
    for value in records:
        record = _exact_dict(value, fields)
        subject = _subject(record["subject"])
        valid_from = _integer(record["validFrom"])
        expires_at = _integer(record["expiresAt"])
        if (
            _snapshot_id(record["snapshotId"]) != snapshot["snapshotId"]
            or type(record["status"]) is not str
            or record["status"] != "full"
            or record["revoked"] is not False
            or valid_from > now
            or now >= expires_at
            or valid_from > snapshot["issuedAt"]
            or expires_at < snapshot["expiresAt"]
            or previous is not None
            and subject <= previous
        ):
            raise _InvalidSource
        previous = subject
        normalized.append(
            {
                "snapshotId": snapshot["snapshotId"],
                "subject": subject,
                "status": "full",
                "validFrom": valid_from,
                "expiresAt": expires_at,
                "revoked": False,
            }
        )
    snapshot["entitlements"] = normalized
    return {record["subject"]: record for record in normalized}


def _x25519_public_key(value: object) -> str:
    key = _subject(value)
    key_bytes = bytes.fromhex(key)
    if key in _PROHIBITED_X25519 or key_bytes[31] & 0x80 or int.from_bytes(key_bytes, "little") >= X25519_FIELD_PRIME:
        raise _InvalidSource
    return key


def _bindings(snapshot: dict, records: list, now: int) -> dict[str, dict]:
    fields = {"snapshotId", "subject", "algorithm", "version", "publicKey", "validFrom", "expiresAt", "revoked"}
    normalized = []
    previous = None
    public_keys = set()
    for value in records:
        record = _exact_dict(value, fields)
        subject = _subject(record["subject"])
        public_key = _x25519_public_key(record["publicKey"])
        version = _integer(record["version"], positive=True)
        valid_from = _integer(record["validFrom"])
        expires_at = _integer(record["expiresAt"])
        if (
            _snapshot_id(record["snapshotId"]) != snapshot["snapshotId"]
            or type(record["algorithm"]) is not str
            or record["algorithm"] != "x25519-v1"
            or record["revoked"] is not False
            or public_key == subject
            or public_key in public_keys
            or valid_from > now
            or now >= expires_at
            or previous is not None
            and subject <= previous
        ):
            raise _InvalidSource
        previous = subject
        public_keys.add(public_key)
        normalized.append(
            {
                "snapshotId": snapshot["snapshotId"],
                "subject": subject,
                "algorithm": "x25519-v1",
                "version": version,
                "publicKey": public_key,
                "validFrom": valid_from,
                "expiresAt": expires_at,
                "revoked": False,
            }
        )
    snapshot["bindings"] = normalized
    return {record["subject"]: record for record in normalized}


def _digest(entitlements: dict, bindings: dict, issued_at: int, expires_at: int) -> str:
    evidence = {
        "bindings": bindings,
        "directoryInterval": {"issuedAt": issued_at, "expiresAt": expires_at},
        "entitlements": entitlements,
    }
    canonical = json.dumps(evidence, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    return "sha256:" + hashlib.sha256(canonical.encode("ascii")).hexdigest()


def build_full_recipient_directory(entitlement_snapshot: object, binding_snapshot: object, *, now: object) -> dict:
    """Build a complete directory or raise one generic unavailable error."""

    try:
        normalized_now = _integer(now)
        entitlement_source, entitlement_records = _snapshot(
            entitlement_snapshot,
            schema=ENTITLEMENT_SNAPSHOT_SCHEMA,
            records_field="entitlements",
            now=normalized_now,
        )
        binding_source, binding_records = _snapshot(
            binding_snapshot,
            schema=BINDING_SNAPSHOT_SCHEMA,
            records_field="bindings",
            now=normalized_now,
        )
        entitlements = _entitlements(entitlement_source, entitlement_records, normalized_now)
        bindings = _bindings(binding_source, binding_records, normalized_now)
        if entitlements.keys() != bindings.keys():
            raise _InvalidSource

        issued_at = max(entitlement_source["issuedAt"], binding_source["issuedAt"])
        expires_at = min(entitlement_source["expiresAt"], binding_source["expiresAt"], issued_at + MAX_VALIDITY_MS)
        if issued_at > normalized_now or normalized_now >= expires_at or issued_at >= expires_at:
            raise _InvalidSource
        if any(binding["validFrom"] < issued_at or binding["expiresAt"] > expires_at for binding in bindings.values()):
            raise _InvalidSource

        snapshot_id = _digest(entitlement_source, binding_source, issued_at, expires_at)
        recipients = []
        for subject in entitlements:
            binding = bindings[subject]
            recipients.append(
                {
                    "snapshotId": snapshot_id,
                    "subject": subject,
                    "encryptionKey": {
                        "algorithm": "x25519-v1",
                        "version": binding["version"],
                        "publicKey": binding["publicKey"],
                        "validFrom": binding["validFrom"],
                        "expiresAt": binding["expiresAt"],
                        "revoked": False,
                    },
                    "authority": {
                        "source": SOURCE,
                        "version": VERSION,
                        "snapshotId": snapshot_id,
                        "subject": subject,
                        "status": "full",
                        "expiresAt": expires_at,
                    },
                }
            )
        return {
            "schema": DIRECTORY_SCHEMA,
            "version": VERSION,
            "source": SOURCE,
            "snapshotId": snapshot_id,
            "complete": True,
            "issuedAt": issued_at,
            "expiresAt": expires_at,
            "recipients": recipients,
        }
    except (KeyError, TypeError, ValueError, OverflowError):
        raise FullRecipientDirectoryUnavailable() from None
