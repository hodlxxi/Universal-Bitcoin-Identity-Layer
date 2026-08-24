"""Identity-authorized, public-only X25519 binding lifecycle contract."""

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

STATEMENT_SCHEMA = "hodlxxi.x25519_identity_binding_statement.v1"
SNAPSHOT_SCHEMA = "hodlxxi.recipient_key_binding_snapshot.v1"
SIGNATURE_DOMAIN = "HODLXXI_X25519_IDENTITY_BINDING_V1"
SIGNATURE_FORMAT = "bip340_schnorr_sha256"
ALGORITHM = "x25519-v1"
SOURCE = "hodlxxi-crt"
MAX_SAFE_INTEGER = 9_007_199_254_740_991
MAX_BINDINGS = 4096
SNAPSHOT_LIFETIME_SECONDS = 300
UNAVAILABLE_MESSAGE = "x25519 identity binding registry unavailable"

_HEX_64 = re.compile(r"[0-9a-f]{64}\Z").fullmatch
_HEX_128 = re.compile(r"[0-9a-f]{128}\Z").fullmatch
_OPERATIONS = frozenset({"register", "rotate", "revoke"})
_FIELDS = {
    "schema",
    "version",
    "subject",
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


class BindingRegistryUnavailable(RuntimeError):
    def __init__(self) -> None:
        super().__init__(UNAVAILABLE_MESSAGE)


@dataclass(frozen=True)
class BindingStatement:
    schema: str
    subject: str
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


@dataclass(frozen=True)
class SnapshotBinding:
    statement: BindingStatement
    chain_expires_at: datetime


class BindingRepository(Protocol):
    def apply(self, statement: BindingStatement, now: datetime) -> BindingStatement: ...

    def current_snapshot(self, now: datetime, maximum: int) -> list[SnapshotBinding]: ...


def _utc(value: object) -> datetime:
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
    return _utc(value).isoformat(timespec="seconds").replace("+00:00", "Z")


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
    envelope = {"domain": SIGNATURE_DOMAIN, "statement": core}
    return json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def statement_digest(core: dict[str, object]) -> str:
    return hashlib.sha256(canonical_statement_bytes(core)).hexdigest()


def _parse_and_verify_dict(payload: object, *, authenticated_subject: object) -> BindingStatement:
    try:
        if type(payload) is not dict or not all(type(key) is str for key in payload) or set(payload) != _FIELDS:
            raise ValueError
        subject = _canonical_actor(payload["subject"])
        actor = _canonical_actor(authenticated_subject)
        if subject != actor:
            raise ValueError
        public_key = validate_x25519_public_key(payload["publicKey"])
        version = payload["bindingVersion"]
        if type(version) is not int or not 1 <= version <= MAX_SAFE_INTEGER:
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
            if prior is not None or version != 1:
                raise ValueError
        elif not isinstance(prior, str) or _HEX_64(prior) is None:
            raise ValueError
        nonce = payload["nonce"]
        digest = payload["digest"]
        signature = payload["signature"]
        if (
            payload["schema"] != STATEMENT_SCHEMA
            or payload["version"] != 1
            or type(payload["version"]) is not int
            or payload["algorithm"] != ALGORITHM
            or payload["signatureFormat"] != SIGNATURE_FORMAT
            or not isinstance(nonce, str)
            or _HEX_64(nonce) is None
            or not isinstance(digest, str)
            or _HEX_64(digest) is None
            or not isinstance(signature, str)
            or _HEX_128(signature) is None
        ):
            raise ValueError
        core = _core_dict(
            subject=subject,
            public_key=public_key,
            binding_version=version,
            valid_from=valid_from,
            expires_at=expires_at,
            operation=operation,
            prior_binding_id=prior,
            nonce=nonce,
        )
        expected = statement_digest(core)
        if digest != expected or not PublicKeyXOnly(bytes.fromhex(subject)).verify(
            bytes.fromhex(signature), bytes.fromhex(expected)
        ):
            raise ValueError
        return BindingStatement(
            STATEMENT_SCHEMA,
            subject,
            ALGORITHM,
            public_key,
            version,
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
        raise BindingRegistryUnavailable() from None


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
    canonical = json.dumps(decoded, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if value != canonical:
        raise ValueError
    return decoded


def parse_and_verify_statement(payload: object, *, authenticated_subject: object) -> BindingStatement:
    """Parse canonical JSON without key collapse and verify identity authority."""
    try:
        decoded = _closed_json_object(payload)
        return _parse_and_verify_dict(decoded, authenticated_subject=authenticated_subject)
    except Exception:
        raise BindingRegistryUnavailable() from None


class X25519IdentityBindingRegistry:
    def __init__(self, repository: BindingRepository, *, clock: Callable[[], datetime] | None = None):
        self._repository = repository
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def apply(self, payload: object, *, authenticated_subject: object) -> dict[str, object]:
        try:
            now = _trusted_utc_second(self._clock())
            statement = parse_and_verify_statement(payload, authenticated_subject=authenticated_subject)
            stored = self._repository.apply(statement, now)
            if stored != statement:
                raise ValueError
            return stored.public_dict()
        except Exception:
            raise BindingRegistryUnavailable() from None

    def current_snapshot(self, *, maximum: object = MAX_BINDINGS) -> dict[str, object]:
        try:
            if type(maximum) is not int or not 0 <= maximum <= MAX_BINDINGS:
                raise ValueError
            now = _trusted_utc_second(self._clock())
            records = self._repository.current_snapshot(now, maximum)
            if type(records) is not list or len(records) > maximum:
                raise ValueError
            bindings = []
            deadlines = []
            previous = None
            keys = set()
            for item in records:
                if type(item) is not SnapshotBinding or type(item.statement) is not BindingStatement:
                    raise ValueError
                record = item.statement
                chain_expires_at = _utc(item.chain_expires_at)
                verified = _parse_and_verify_dict(record.public_dict(), authenticated_subject=record.subject)
                if (
                    verified != record
                    or record.operation not in {"register", "rotate"}
                    or record.valid_from > now
                    or record.expires_at <= now
                    or chain_expires_at <= now
                    or chain_expires_at > record.expires_at
                    or previous is not None
                    and record.subject <= previous
                    or record.public_key in keys
                ):
                    raise ValueError
                validate_x25519_public_key(record.public_key)
                previous = record.subject
                keys.add(record.public_key)
                bindings.append(
                    {
                        "subject": record.subject,
                        "algorithm": ALGORITHM,
                        "version": record.binding_version,
                        "publicKey": record.public_key,
                        "validFrom": int(record.valid_from.timestamp() * 1000),
                        "expiresAt": int(record.expires_at.timestamp() * 1000),
                        "revoked": False,
                    }
                )
                deadlines.extend((record.expires_at, chain_expires_at))
            expires_at = (
                int(
                    min(
                        now.timestamp() + SNAPSHOT_LIFETIME_SECONDS,
                        *(deadline.timestamp() for deadline in deadlines),
                    )
                    * 1000
                )
                if records
                else int((now.timestamp() + SNAPSHOT_LIFETIME_SECONDS) * 1000)
            )
            issued_at = int(now.timestamp() * 1000)
            evidence = {"bindings": bindings, "complete": True, "expiresAt": expires_at, "issuedAt": issued_at}
            canonical = json.dumps(evidence, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            snapshot_id = "sha256:" + hashlib.sha256(canonical.encode("ascii")).hexdigest()
            return {
                "schema": SNAPSHOT_SCHEMA,
                "version": 1,
                "source": SOURCE,
                "snapshotId": snapshot_id,
                "complete": True,
                "issuedAt": issued_at,
                "expiresAt": expires_at,
                "bindings": [{"snapshotId": snapshot_id, **binding} for binding in bindings],
            }
        except Exception:
            raise BindingRegistryUnavailable() from None
