"""Dormant, exact registration of validated covenant pairs to Bitcoin outpoints."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import re
import uuid

from app.services.covenant_relation import MAX_BITCOIN_SATS, MAX_VOUT, CovenantDirection
from app.services.mirrored_covenant_pair import (
    NETWORK as PAIR_NETWORK,
    CovenantDeltaProfile,
    CovenantTemplateFamily,
    ValidatedMirroredCovenantPair,
    mirrored_covenant_pair_sha256,
)
from app.services.trusted_covenant_observation import TRUSTED_OUTPOINT_SCHEMA, TrustedCovenantOutpoint

REGISTRATION_SCHEMA = "hodlxxi.trusted_covenant_registration.v1"
REGISTRATION_VERSION = "hodlxxi.trusted_covenant_registration_service.v1"
NETWORK = "bitcoin"

_LOWER_HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
_LOWER_HEX_66 = re.compile(r"(?:02|03)[0-9a-f]{64}\Z")


class InvalidTrustedCovenantRegistration(ValueError):
    """A trusted registration violates the stable, strict domain contract."""


class TrustedCovenantRegistrationLifecycle(Enum):
    ACTIVE = "active"
    REVOKED = "revoked"
    SUPERSEDED = "superseded"
    DISPUTED = "disputed"


def _fail(message: str) -> None:
    raise InvalidTrustedCovenantRegistration(message)


def _digest(value: object, field: str) -> None:
    if type(value) is not str or _LOWER_HEX_64.fullmatch(value) is None:
        _fail(f"{field} must be canonical lowercase 64-hex")


def _compressed_key(value: object, field: str) -> None:
    if type(value) is not str or _LOWER_HEX_66.fullmatch(value) is None:
        _fail(f"{field} must be a canonical compressed lowercase 66-hex pubkey")


def _exact_int(value: object, field: str, minimum: int, maximum: int) -> None:
    if type(value) is not int:
        _fail(f"{field} must be an exact int")
    if not minimum <= value <= maximum:
        _fail(f"{field} is outside its permitted range")


def _uuid(value: object, field: str) -> None:
    if type(value) is not str:
        _fail(f"{field} must be a canonical lowercase UUID")
    try:
        canonical = str(uuid.UUID(value))
    except (ValueError, AttributeError, TypeError):
        _fail(f"{field} must be a canonical lowercase UUID")
    if value != canonical:
        _fail(f"{field} must be a canonical lowercase UUID")


def _utc(value: object, field: str) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        _fail(f"{field} must be an exact timezone-aware datetime")
    return value.astimezone(timezone.utc)


@dataclass(frozen=True, slots=True)
class RegisteredCovenantOutpoint:
    direction: CovenantDirection
    txid: str
    vout: int
    amount_sats: int
    witness_script_sha256: str
    descriptor_sha256: str | None = None

    def __post_init__(self) -> None:
        if type(self.direction) is not CovenantDirection:
            _fail("direction must be an exact CovenantDirection")
        _digest(self.txid, "txid")
        _exact_int(self.vout, "vout", 0, MAX_VOUT)
        _exact_int(self.amount_sats, "amount_sats", 1, MAX_BITCOIN_SATS)
        _digest(self.witness_script_sha256, "witness_script_sha256")
        if self.descriptor_sha256 is not None:
            _digest(self.descriptor_sha256, "descriptor_sha256")


def _binding(value: object) -> RegisteredCovenantOutpoint:
    if type(value) is not RegisteredCovenantOutpoint:
        _fail("bindings must have exact RegisteredCovenantOutpoint type")
    return RegisteredCovenantOutpoint(
        *(getattr(value, field) for field in RegisteredCovenantOutpoint.__dataclass_fields__)
    )


def _pair(value: object) -> ValidatedMirroredCovenantPair:
    if type(value) is not ValidatedMirroredCovenantPair:
        _fail("mirrored_pair must have exact ValidatedMirroredCovenantPair type")
    try:
        return ValidatedMirroredCovenantPair(
            *(getattr(value, field) for field in ValidatedMirroredCovenantPair.__dataclass_fields__)
        )
    except Exception:
        raise InvalidTrustedCovenantRegistration("mirrored_pair failed authoritative revalidation") from None


@dataclass(frozen=True, slots=True)
class TrustedCovenantRegistration:
    schema: str
    registration_version: str
    registration_id: str
    network: str
    pair_sha256: str
    validator_version: str
    subject_pubkey: str
    subject_xonly_pubkey: str
    counterparty_pubkey: str
    counterparty_xonly_pubkey: str
    template_family: CovenantTemplateFamily
    delta_profile: CovenantDeltaProfile
    delta_blocks: int
    lifecycle_state: TrustedCovenantRegistrationLifecycle
    registered_at: datetime
    lifecycle_changed_at: datetime
    superseded_by_registration_id: str | None
    outpoints: tuple[RegisteredCovenantOutpoint, ...]
    mirrored_pair: ValidatedMirroredCovenantPair

    def __post_init__(self) -> None:
        if type(self.schema) is not str or self.schema != REGISTRATION_SCHEMA:
            _fail("invalid registration schema")
        if type(self.registration_version) is not str or self.registration_version != REGISTRATION_VERSION:
            _fail("invalid registration version")
        _uuid(self.registration_id, "registration_id")
        if type(self.network) is not str or self.network != NETWORK or self.network != PAIR_NETWORK:
            _fail("invalid registration network")
        _digest(self.pair_sha256, "pair_sha256")
        _compressed_key(self.subject_pubkey, "subject_pubkey")
        _digest(self.subject_xonly_pubkey, "subject_xonly_pubkey")
        _compressed_key(self.counterparty_pubkey, "counterparty_pubkey")
        _digest(self.counterparty_xonly_pubkey, "counterparty_xonly_pubkey")
        if type(self.validator_version) is not str:
            _fail("validator_version must be an exact str")
        if type(self.template_family) is not CovenantTemplateFamily:
            _fail("template_family must be an exact CovenantTemplateFamily")
        if type(self.delta_profile) is not CovenantDeltaProfile:
            _fail("delta_profile must be an exact CovenantDeltaProfile")
        _exact_int(self.delta_blocks, "delta_blocks", 1, 499_999_999)
        if type(self.lifecycle_state) is not TrustedCovenantRegistrationLifecycle:
            _fail("lifecycle_state must be an exact lifecycle enum")

        registered_at = _utc(self.registered_at, "registered_at")
        changed_at = _utc(self.lifecycle_changed_at, "lifecycle_changed_at")
        if changed_at < registered_at:
            _fail("lifecycle_changed_at must not precede registered_at")
        object.__setattr__(self, "registered_at", registered_at)
        object.__setattr__(self, "lifecycle_changed_at", changed_at)

        if self.lifecycle_state is TrustedCovenantRegistrationLifecycle.SUPERSEDED:
            if self.superseded_by_registration_id is None:
                _fail("superseded registrations require superseded_by_registration_id")
            _uuid(self.superseded_by_registration_id, "superseded_by_registration_id")
            if self.superseded_by_registration_id == self.registration_id:
                _fail("a registration cannot supersede itself")
        elif self.superseded_by_registration_id is not None:
            _fail("superseded_by_registration_id is forbidden outside superseded state")

        pair = _pair(self.mirrored_pair)
        authoritative = {
            "pair_sha256": mirrored_covenant_pair_sha256(pair),
            "validator_version": pair.validator_version,
            "network": pair.network,
            "subject_pubkey": pair.subject_pubkey,
            "subject_xonly_pubkey": pair.subject_xonly_pubkey,
            "counterparty_pubkey": pair.counterparty_pubkey,
            "counterparty_xonly_pubkey": pair.counterparty_xonly_pubkey,
            "template_family": pair.template_family,
            "delta_profile": pair.delta_profile,
            "delta_blocks": pair.delta_blocks,
        }
        if any(type(getattr(self, name)) is not type(value) or getattr(self, name) != value for name, value in authoritative.items()):
            _fail("registration fields do not exactly match the authoritative mirrored pair")

        if type(self.outpoints) is not tuple or len(self.outpoints) != 2:
            _fail("outpoints must be an exact tuple of exactly two bindings")
        bindings = tuple(_binding(item) for item in self.outpoints)
        if {item.direction for item in bindings} != {CovenantDirection.INCOMING, CovenantDirection.OUTGOING}:
            _fail("registration requires exactly one incoming and one outgoing binding")
        if len({(item.txid, item.vout) for item in bindings}) != 2:
            _fail("registered outpoints must be distinct")
        by_direction = {item.direction: item for item in bindings}
        if by_direction[CovenantDirection.INCOMING].witness_script_sha256 != pair.incoming_leg_script_sha256:
            _fail("incoming binding script does not match the authoritative pair")
        if by_direction[CovenantDirection.OUTGOING].witness_script_sha256 != pair.outgoing_leg_script_sha256:
            _fail("outgoing binding script does not match the authoritative pair")
        object.__setattr__(
            self,
            "outpoints",
            (by_direction[CovenantDirection.INCOMING], by_direction[CovenantDirection.OUTGOING]),
        )
        object.__setattr__(self, "mirrored_pair", pair)


def create_trusted_covenant_registration(
    mirrored_pair: ValidatedMirroredCovenantPair,
    outpoints: tuple[RegisteredCovenantOutpoint, ...],
    *,
    registration_id: str,
    lifecycle_state: TrustedCovenantRegistrationLifecycle,
    registered_at: datetime,
    lifecycle_changed_at: datetime,
    superseded_by_registration_id: str | None = None,
) -> TrustedCovenantRegistration:
    """Bind one exact validated pair to two exact outpoints."""
    pair = _pair(mirrored_pair)
    return TrustedCovenantRegistration(
        REGISTRATION_SCHEMA,
        REGISTRATION_VERSION,
        registration_id,
        NETWORK,
        mirrored_covenant_pair_sha256(pair),
        pair.validator_version,
        pair.subject_pubkey,
        pair.subject_xonly_pubkey,
        pair.counterparty_pubkey,
        pair.counterparty_xonly_pubkey,
        pair.template_family,
        pair.delta_profile,
        pair.delta_blocks,
        lifecycle_state,
        registered_at,
        lifecycle_changed_at,
        superseded_by_registration_id,
        outpoints,
        pair,
    )


def _validated(registration: object) -> TrustedCovenantRegistration:
    if type(registration) is not TrustedCovenantRegistration:
        _fail("registration must have exact TrustedCovenantRegistration type")
    return TrustedCovenantRegistration(
        *(getattr(registration, field) for field in TrustedCovenantRegistration.__dataclass_fields__)
    )


def canonical_trusted_registration_bytes(registration: TrustedCovenantRegistration) -> bytes:
    """Return deterministic ASCII-safe canonical JSON after complete revalidation."""
    registration = _validated(registration)
    payload = {
        "schema": registration.schema,
        "registration_version": registration.registration_version,
        "registration_id": registration.registration_id,
        "network": registration.network,
        "pair_sha256": registration.pair_sha256,
        "validator_version": registration.validator_version,
        "subject_pubkey": registration.subject_pubkey,
        "subject_xonly_pubkey": registration.subject_xonly_pubkey,
        "counterparty_pubkey": registration.counterparty_pubkey,
        "counterparty_xonly_pubkey": registration.counterparty_xonly_pubkey,
        "template_family": registration.template_family.value,
        "delta_profile": registration.delta_profile.value,
        "delta_blocks": registration.delta_blocks,
        "lifecycle_state": registration.lifecycle_state.value,
        "registered_at": registration.registered_at.isoformat().replace("+00:00", "Z"),
        "lifecycle_changed_at": registration.lifecycle_changed_at.isoformat().replace("+00:00", "Z"),
        "superseded_by_registration_id": registration.superseded_by_registration_id,
        "outpoints": [
            {
                "direction": item.direction.value,
                "txid": item.txid,
                "vout": item.vout,
                "amount_sats": item.amount_sats,
                "witness_script_sha256": item.witness_script_sha256,
                "descriptor_sha256": item.descriptor_sha256,
            }
            for item in registration.outpoints
        ],
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def trusted_registration_sha256(registration: TrustedCovenantRegistration) -> str:
    return hashlib.sha256(canonical_trusted_registration_bytes(registration)).hexdigest()


def p2wsh_script_pubkey_sha256(witness_script_sha256: str) -> str:
    """Hash the exact serialized native-P2WSH scriptPubKey for a witness-script digest."""
    _digest(witness_script_sha256, "witness_script_sha256")
    return hashlib.sha256(bytes.fromhex("0020" + witness_script_sha256)).hexdigest()


def trusted_outpoints_from_registration(
    registration: TrustedCovenantRegistration,
) -> tuple[TrustedCovenantOutpoint, ...]:
    registration = _validated(registration)
    if registration.lifecycle_state is not TrustedCovenantRegistrationLifecycle.ACTIVE:
        _fail("only an active registration may materialize trusted outpoints")
    return tuple(
        TrustedCovenantOutpoint(
            TRUSTED_OUTPOINT_SCHEMA,
            registration.subject_xonly_pubkey,
            registration.counterparty_xonly_pubkey,
            item.direction,
            item.txid,
            item.vout,
            item.amount_sats,
            p2wsh_script_pubkey_sha256(item.witness_script_sha256),
            item.descriptor_sha256,
        )
        for item in registration.outpoints
    )
