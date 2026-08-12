"""Dormant canonical allowlist of registration-bound covenant funding outpoints."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import re
import uuid

from app.services.covenant_relation import MAX_BITCOIN_SATS, MAX_VOUT, CovenantDirection
from app.services.trusted_covenant_registration import (
    TrustedCovenantRegistration,
    TrustedCovenantRegistrationLifecycle,
    canonical_trusted_registration_bytes,
    trusted_registration_sha256,
)

FUNDING_SET_SCHEMA = "hodlxxi.canonical_recognized_covenant_funding_set.v1"
FUNDING_SET_VERSION = "hodlxxi.canonical_recognized_covenant_funding_set_service.v1"
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class InvalidCanonicalCovenantFundingSet(ValueError):
    pass


class CovenantFundingSetLifecycle(Enum):
    PROPOSED = "proposed"
    EFFECTIVE = "effective"
    DISPUTED = "disputed"
    SUPERSEDED = "superseded"
    REVOKED = "revoked"


def _fail(message):
    raise InvalidCanonicalCovenantFundingSet(message)


def _digest(value, field):
    if type(value) is not str or _HEX64.fullmatch(value) is None:
        _fail(f"{field} must be canonical lowercase 64-hex")


def _id(value, field):
    if type(value) is not str:
        _fail(f"{field} must be a canonical lowercase UUID")
    try:
        canonical = str(uuid.UUID(value))
    except (ValueError, TypeError, AttributeError):
        _fail(f"{field} must be a canonical lowercase UUID")
    if canonical != value:
        _fail(f"{field} must be a canonical lowercase UUID")


def _utc(value, field):
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        _fail(f"{field} must be an exact timezone-aware datetime")
    return value.astimezone(timezone.utc)


@dataclass(frozen=True, slots=True)
class RecognizedCovenantFundingOutpoint:
    direction: CovenantDirection
    txid: str
    vout: int
    amount_sats: int
    witness_script_sha256: str
    descriptor_sha256: str | None = None

    def __post_init__(self):
        if type(self.direction) is not CovenantDirection:
            _fail("direction must be an exact CovenantDirection")
        _digest(self.txid, "txid")
        if type(self.vout) is not int or not 0 <= self.vout <= MAX_VOUT:
            _fail("vout must be an exact int in range")
        if type(self.amount_sats) is not int or not 1 <= self.amount_sats <= MAX_BITCOIN_SATS:
            _fail("amount_sats must be a positive exact int in range")
        _digest(self.witness_script_sha256, "witness_script_sha256")
        if self.descriptor_sha256 is not None:
            _digest(self.descriptor_sha256, "descriptor_sha256")


def _outpoint(value):
    if type(value) is not RecognizedCovenantFundingOutpoint:
        _fail("recognized_outpoints require exact RecognizedCovenantFundingOutpoint values")
    return RecognizedCovenantFundingOutpoint(
        value.direction, value.txid, value.vout, value.amount_sats,
        value.witness_script_sha256, value.descriptor_sha256,
    )


def _sort_key(value):
    return (0 if value.direction is CovenantDirection.INCOMING else 1, value.txid, value.vout)


@dataclass(frozen=True, slots=True)
class CanonicalCovenantFundingSet:
    schema: str
    funding_set_version: str
    funding_set_id: str
    trusted_registration_id: str
    trusted_registration_sha256: str
    pair_sha256: str
    subject_xonly_pubkey: str
    counterparty_xonly_pubkey: str
    lifecycle_state: CovenantFundingSetLifecycle
    created_at: datetime
    lifecycle_changed_at: datetime
    effective_at: datetime | None
    superseded_by_funding_set_id: str | None
    recognized_outpoints: tuple[RecognizedCovenantFundingOutpoint, ...]

    def __post_init__(self):
        if type(self.schema) is not str or self.schema != FUNDING_SET_SCHEMA:
            _fail("invalid funding set schema")
        if type(self.funding_set_version) is not str or self.funding_set_version != FUNDING_SET_VERSION:
            _fail("invalid funding set version")
        _id(self.funding_set_id, "funding_set_id")
        _id(self.trusted_registration_id, "trusted_registration_id")
        for name in ("trusted_registration_sha256", "pair_sha256", "subject_xonly_pubkey", "counterparty_xonly_pubkey"):
            _digest(getattr(self, name), name)
        if type(self.lifecycle_state) is not CovenantFundingSetLifecycle:
            _fail("invalid lifecycle state")
        created = _utc(self.created_at, "created_at")
        changed = _utc(self.lifecycle_changed_at, "lifecycle_changed_at")
        effective = None if self.effective_at is None else _utc(self.effective_at, "effective_at")
        if changed < created:
            _fail("lifecycle_changed_at must not precede created_at")
        if self.lifecycle_state is CovenantFundingSetLifecycle.PROPOSED:
            if effective is not None or self.superseded_by_funding_set_id is not None:
                _fail("proposed lifecycle is inconsistent")
        elif self.lifecycle_state is CovenantFundingSetLifecycle.EFFECTIVE:
            if effective is None or effective < created or changed < effective or self.superseded_by_funding_set_id is not None:
                _fail("effective lifecycle is inconsistent")
        elif self.lifecycle_state is CovenantFundingSetLifecycle.SUPERSEDED:
            if effective is None or effective < created or changed < effective or self.superseded_by_funding_set_id is None:
                _fail("superseded lifecycle is inconsistent")
        else:
            if self.superseded_by_funding_set_id is not None:
                _fail("successor is forbidden for this lifecycle")
            if effective is not None and (effective < created or changed < effective):
                _fail("disputed or revoked effective_at is outside lifecycle bounds")
        if self.superseded_by_funding_set_id is not None:
            _id(self.superseded_by_funding_set_id, "superseded_by_funding_set_id")
            if self.superseded_by_funding_set_id == self.funding_set_id:
                _fail("funding set cannot supersede itself")
        if type(self.recognized_outpoints) is not tuple:
            _fail("recognized_outpoints must be an exact tuple")
        items = tuple(_outpoint(item) for item in self.recognized_outpoints)
        if len({(item.txid, item.vout) for item in items}) != len(items):
            _fail("duplicate recognized outpoint")
        items = tuple(sorted(items, key=_sort_key))
        if self.lifecycle_state is CovenantFundingSetLifecycle.EFFECTIVE and {
            item.direction for item in items
        } != {CovenantDirection.INCOMING, CovenantDirection.OUTGOING}:
            _fail("effective funding set requires both directions")
        object.__setattr__(self, "created_at", created)
        object.__setattr__(self, "lifecycle_changed_at", changed)
        object.__setattr__(self, "effective_at", effective)
        object.__setattr__(self, "recognized_outpoints", items)


def create_canonical_covenant_funding_set(*, funding_set_id, trusted_registration,
        lifecycle_state, created_at, lifecycle_changed_at, effective_at=None,
        superseded_by_funding_set_id=None, recognized_outpoints=()):
    registration = _registration(trusted_registration)
    value = CanonicalCovenantFundingSet(
        FUNDING_SET_SCHEMA, FUNDING_SET_VERSION, funding_set_id,
        registration.registration_id, trusted_registration_sha256(registration),
        registration.pair_sha256, registration.subject_xonly_pubkey,
        registration.counterparty_xonly_pubkey, lifecycle_state, created_at,
        lifecycle_changed_at, effective_at, superseded_by_funding_set_id,
        recognized_outpoints,
    )
    return validate_funding_set_registration(value, registration)


def _registration(value):
    if type(value) is not TrustedCovenantRegistration:
        _fail("trusted_registration must have exact TrustedCovenantRegistration type")
    try:
        canonical_trusted_registration_bytes(value)
        return TrustedCovenantRegistration(
            *(getattr(value, field) for field in TrustedCovenantRegistration.__dataclass_fields__)
        )
    except Exception:
        _fail("trusted registration failed canonical revalidation")


def validate_funding_set_registration(value, trusted_registration):
    value = _validated(value)
    registration = _registration(trusted_registration)
    if value.lifecycle_state is not CovenantFundingSetLifecycle.EFFECTIVE:
        return value
    expected = (
        value.trusted_registration_id == registration.registration_id,
        value.trusted_registration_sha256 == trusted_registration_sha256(registration),
        registration.lifecycle_state is TrustedCovenantRegistrationLifecycle.ACTIVE,
        value.pair_sha256 == registration.pair_sha256,
        value.subject_xonly_pubkey == registration.subject_xonly_pubkey,
        value.counterparty_xonly_pubkey == registration.counterparty_xonly_pubkey,
    )
    if not all(expected):
        _fail("effective funding set does not match active registration authority")
    scripts = {
        CovenantDirection.INCOMING: registration.mirrored_pair.incoming_leg_script_sha256,
        CovenantDirection.OUTGOING: registration.mirrored_pair.outgoing_leg_script_sha256,
    }
    if any(item.witness_script_sha256 != scripts[item.direction] for item in value.recognized_outpoints):
        _fail("recognized outpoint script does not match authoritative pair")
    recognized = {(x.direction, x.txid, x.vout, x.amount_sats, x.witness_script_sha256, x.descriptor_sha256) for x in value.recognized_outpoints}
    anchors = {(x.direction, x.txid, x.vout, x.amount_sats, x.witness_script_sha256, x.descriptor_sha256) for x in registration.outpoints}
    if not anchors <= recognized:
        _fail("registration anchors are not present exactly")
    return value


def _validated(value):
    if type(value) is not CanonicalCovenantFundingSet:
        _fail("funding set must have exact CanonicalCovenantFundingSet type")
    return CanonicalCovenantFundingSet(*(getattr(value, f) for f in CanonicalCovenantFundingSet.__dataclass_fields__))


def _iso(value):
    return None if value is None else value.isoformat().replace("+00:00", "Z")


def canonical_covenant_funding_set_bytes(value):
    value = _validated(value)
    payload = {name: getattr(value, name) for name in CanonicalCovenantFundingSet.__dataclass_fields__}
    payload["lifecycle_state"] = value.lifecycle_state.value
    for name in ("created_at", "lifecycle_changed_at", "effective_at"):
        payload[name] = _iso(getattr(value, name))
    payload["recognized_outpoints"] = [
        {"direction": x.direction.value, "txid": x.txid, "vout": x.vout,
         "amount_sats": x.amount_sats, "witness_script_sha256": x.witness_script_sha256,
         "descriptor_sha256": x.descriptor_sha256} for x in value.recognized_outpoints
    ]
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def canonical_covenant_funding_set_sha256(value):
    return hashlib.sha256(canonical_covenant_funding_set_bytes(value)).hexdigest()


def _parse_time(value, field):
    if value is None:
        return None
    if type(value) is not str or not value.endswith("Z"):
        _fail(f"{field} must be canonical UTC text")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        _fail(f"{field} must be canonical UTC text")
    if _iso(parsed) != value:
        _fail(f"{field} must be canonical UTC text")
    return parsed


def parse_canonical_covenant_funding_set(raw):
    if type(raw) not in (str, bytes):
        _fail("canonical funding set JSON must be exact str or bytes")
    try:
        data = json.loads(raw)
        if type(data) is not dict or set(data) != set(CanonicalCovenantFundingSet.__dataclass_fields__):
            _fail("canonical funding set JSON has invalid fields")
        if type(data["recognized_outpoints"]) is not list:
            _fail("recognized_outpoints must be a JSON list")
        outpoints = []
        fields = set(RecognizedCovenantFundingOutpoint.__dataclass_fields__)
        for item in data["recognized_outpoints"]:
            if type(item) is not dict or set(item) != fields:
                _fail("recognized outpoint JSON has invalid fields")
            outpoints.append(RecognizedCovenantFundingOutpoint(
                CovenantDirection(item["direction"]), item["txid"], item["vout"],
                item["amount_sats"], item["witness_script_sha256"], item["descriptor_sha256"]
            ))
        value = CanonicalCovenantFundingSet(
            data["schema"], data["funding_set_version"], data["funding_set_id"],
            data["trusted_registration_id"], data["trusted_registration_sha256"],
            data["pair_sha256"], data["subject_xonly_pubkey"], data["counterparty_xonly_pubkey"],
            CovenantFundingSetLifecycle(data["lifecycle_state"]), _parse_time(data["created_at"], "created_at"),
            _parse_time(data["lifecycle_changed_at"], "lifecycle_changed_at"),
            _parse_time(data["effective_at"], "effective_at"), data["superseded_by_funding_set_id"], tuple(outpoints),
        )
        if canonical_covenant_funding_set_bytes(value) != (raw.encode("ascii") if type(raw) is str else raw):
            _fail("funding set JSON is not canonical")
        return value
    except InvalidCanonicalCovenantFundingSet:
        raise
    except Exception:
        _fail("invalid canonical funding set JSON")
