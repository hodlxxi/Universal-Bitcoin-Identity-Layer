"""Dormant canonical root-to-trusted-registration selection contract."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256
import json
import re
import uuid

from app.services.canonical_genesis_record import (
    CanonicalGenesisEvaluation,
    CanonicalGenesisEvaluationState,
)
from app.services.trusted_covenant_registration import (
    TrustedCovenantRegistration,
    TrustedCovenantRegistrationLifecycle,
    trusted_registration_sha256,
)

BINDING_SCHEMA = "hodlxxi.canonical_root_registration_binding.v1"
BINDING_VERSION = "hodlxxi.canonical_root_registration_binding_service.v1"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class InvalidCanonicalRootRegistrationBinding(ValueError):
    """The supplied root registration binding is not canonical."""


class RootRegistrationBindingLifecycle(Enum):
    PROPOSED = "proposed"
    EFFECTIVE = "effective"
    DISPUTED = "disputed"
    SUPERSEDED = "superseded"
    REVOKED = "revoked"


def _fail(name: str) -> None:
    raise InvalidCanonicalRootRegistrationBinding(name)


def _uuid(value: object, name: str) -> str:
    if type(value) is not str:
        _fail(name)
    try:
        canonical = str(uuid.UUID(value))
    except (ValueError, TypeError, AttributeError):
        _fail(name)
    if canonical != value:
        _fail(name)
    return value


def _text(value: object, name: str, maximum: int = 64) -> str:
    if type(value) is not str or not value or value != value.strip() or len(value.encode()) > maximum:
        _fail(name)
    return value


def _digest(value: object, name: str) -> str:
    if type(value) is not str or _HEX64.fullmatch(value) is None:
        _fail(name)
    return value


def _time(value: object, name: str, optional: bool = False) -> datetime | None:
    if value is None and optional:
        return None
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        _fail(name)
    if value.utcoffset().total_seconds() != 0 or value.microsecond:
        _fail(name)
    return value


def _timestamp(value: datetime | None) -> str | None:
    return None if value is None else value.isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_time(value: object, name: str, optional: bool = False) -> datetime | None:
    if value is None and optional:
        return None
    if type(value) is not str or not value.endswith("Z"):
        _fail(name)
    try:
        result = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        _fail(name)
    if _timestamp(result) != value:
        _fail(name)
    return result


@dataclass(frozen=True, slots=True)
class CanonicalRootRegistrationBinding:
    schema: str
    binding_version: str
    binding_id: str
    graph_or_protocol_id: str
    root_x_only_public_key: str
    trusted_registration_id: str
    trusted_registration_sha256: str
    lifecycle_state: RootRegistrationBindingLifecycle
    created_at: datetime
    lifecycle_changed_at: datetime
    effective_at: datetime | None
    superseded_by_binding_id: str | None

    def __post_init__(self) -> None:
        if type(self) is not CanonicalRootRegistrationBinding:
            _fail("binding type")
        if (
            type(self.schema) is not str
            or self.schema != BINDING_SCHEMA
            or type(self.binding_version) is not str
            or self.binding_version != BINDING_VERSION
        ):
            _fail("fixed contract")
        _uuid(self.binding_id, "binding_id")
        _text(self.graph_or_protocol_id, "graph_or_protocol_id")
        _digest(self.root_x_only_public_key, "root_x_only_public_key")
        _uuid(self.trusted_registration_id, "trusted_registration_id")
        _digest(self.trusted_registration_sha256, "trusted_registration_sha256")
        if type(self.lifecycle_state) is not RootRegistrationBindingLifecycle:
            _fail("lifecycle_state")
        created = _time(self.created_at, "created_at")
        changed = _time(self.lifecycle_changed_at, "lifecycle_changed_at")
        effective = _time(self.effective_at, "effective_at", True)
        if changed < created:
            _fail("lifecycle time")
        if self.superseded_by_binding_id is not None:
            _uuid(self.superseded_by_binding_id, "superseded_by_binding_id")
            if self.superseded_by_binding_id == self.binding_id:
                _fail("superseded_by_binding_id")
        state = self.lifecycle_state
        valid = (
            (
                state is RootRegistrationBindingLifecycle.PROPOSED
                and effective is None
                and self.superseded_by_binding_id is None
            )
            or (
                state is RootRegistrationBindingLifecycle.EFFECTIVE
                and effective is not None
                and effective >= created
                and changed >= effective
                and self.superseded_by_binding_id is None
            )
            or (
                state is RootRegistrationBindingLifecycle.SUPERSEDED
                and effective is not None
                and effective >= created
                and changed >= effective
                and self.superseded_by_binding_id is not None
            )
            or (
                state in (RootRegistrationBindingLifecycle.DISPUTED, RootRegistrationBindingLifecycle.REVOKED)
                and self.superseded_by_binding_id is None
                and (effective is None or (effective >= created and changed >= effective))
            )
        )
        if not valid:
            _fail("lifecycle consistency")


def canonical_root_registration_binding_dict(value: CanonicalRootRegistrationBinding) -> dict:
    if type(value) is not CanonicalRootRegistrationBinding:
        _fail("binding type")
    value = CanonicalRootRegistrationBinding(
        *(getattr(value, field) for field in CanonicalRootRegistrationBinding.__dataclass_fields__)
    )
    return {
        "binding_id": value.binding_id,
        "binding_version": value.binding_version,
        "created_at": _timestamp(value.created_at),
        "effective_at": _timestamp(value.effective_at),
        "graph_or_protocol_id": value.graph_or_protocol_id,
        "lifecycle_changed_at": _timestamp(value.lifecycle_changed_at),
        "lifecycle_state": value.lifecycle_state.value,
        "root_x_only_public_key": value.root_x_only_public_key,
        "schema": value.schema,
        "superseded_by_binding_id": value.superseded_by_binding_id,
        "trusted_registration_id": value.trusted_registration_id,
        "trusted_registration_sha256": value.trusted_registration_sha256,
    }


def canonical_root_registration_binding_bytes(value: CanonicalRootRegistrationBinding) -> bytes:
    return json.dumps(
        canonical_root_registration_binding_dict(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def canonical_root_registration_binding_sha256(value: CanonicalRootRegistrationBinding) -> str:
    return sha256(canonical_root_registration_binding_bytes(value)).hexdigest()


def parse_canonical_root_registration_binding(value: bytes | str | dict) -> CanonicalRootRegistrationBinding:
    serialized = None
    if type(value) is bytes:
        try:
            value = value.decode("ascii")
        except UnicodeDecodeError:
            _fail("JSON")
    if type(value) is str:
        serialized = value
        try:

            def pairs(items):
                result = {}
                for key, item in items:
                    if key in result:
                        raise ValueError()
                    result[key] = item
                return result

            def reject(_):
                raise ValueError()

            value = json.loads(value, object_pairs_hook=pairs, parse_float=reject, parse_constant=reject)
        except (ValueError, json.JSONDecodeError):
            _fail("JSON")
    if type(value) is not dict or set(value) != set(CanonicalRootRegistrationBinding.__dataclass_fields__):
        _fail("binding fields")
    try:
        result = CanonicalRootRegistrationBinding(
            **{
                **value,
                "lifecycle_state": RootRegistrationBindingLifecycle(value["lifecycle_state"]),
                "created_at": _parse_time(value["created_at"], "created_at"),
                "lifecycle_changed_at": _parse_time(value["lifecycle_changed_at"], "lifecycle_changed_at"),
                "effective_at": _parse_time(value["effective_at"], "effective_at", True),
            }
        )
        if serialized is not None and canonical_root_registration_binding_bytes(result).decode("ascii") != serialized:
            _fail("noncanonical JSON")
        return result
    except (TypeError, ValueError):
        _fail("binding value")


def validate_binding_sources(
    binding: CanonicalRootRegistrationBinding,
    *,
    genesis_evaluation: CanonicalGenesisEvaluation,
    trusted_registration: TrustedCovenantRegistration,
    require_active: bool = True,
    require_digest: bool = True,
) -> tuple[CanonicalRootRegistrationBinding, TrustedCovenantRegistration]:
    if type(require_active) is not bool or type(require_digest) is not bool:
        _fail("source requirements")
    binding = parse_canonical_root_registration_binding(canonical_root_registration_binding_bytes(binding))
    if type(genesis_evaluation) is not CanonicalGenesisEvaluation:
        _fail("genesis source")
    try:
        genesis_evaluation = CanonicalGenesisEvaluation(
            *(getattr(genesis_evaluation, field) for field in CanonicalGenesisEvaluation.__dataclass_fields__)
        )
    except Exception:
        _fail("genesis source")
    if (
        genesis_evaluation.state is not CanonicalGenesisEvaluationState.GENESIS_ACTIVE
        or genesis_evaluation.graph_or_protocol_id != binding.graph_or_protocol_id
        or genesis_evaluation.x_only_public_key != binding.root_x_only_public_key
    ):
        _fail("genesis source")
    if type(trusted_registration) is not TrustedCovenantRegistration:
        _fail("trusted registration")
    try:
        trusted_registration = TrustedCovenantRegistration(
            *(getattr(trusted_registration, field) for field in TrustedCovenantRegistration.__dataclass_fields__)
        )
    except Exception:
        _fail("trusted registration")
    if (
        trusted_registration.registration_id != binding.trusted_registration_id
        or (require_digest and trusted_registration_sha256(trusted_registration) != binding.trusted_registration_sha256)
        or trusted_registration.subject_xonly_pubkey != binding.root_x_only_public_key
        or (require_active and trusted_registration.lifecycle_state is not TrustedCovenantRegistrationLifecycle.ACTIVE)
    ):
        _fail("trusted registration")
    return binding, trusted_registration


def validate_root_registration_binding_transition(
    previous: CanonicalRootRegistrationBinding,
    successor: CanonicalRootRegistrationBinding,
) -> None:
    previous = parse_canonical_root_registration_binding(canonical_root_registration_binding_bytes(previous))
    successor = parse_canonical_root_registration_binding(canonical_root_registration_binding_bytes(successor))
    if (
        previous.binding_id != successor.binding_id
        or previous.graph_or_protocol_id != successor.graph_or_protocol_id
        or previous.root_x_only_public_key != successor.root_x_only_public_key
        or previous.created_at != successor.created_at
        or previous.trusted_registration_id != successor.trusted_registration_id
        or previous.trusted_registration_sha256 != successor.trusted_registration_sha256
        or successor.lifecycle_changed_at < previous.lifecycle_changed_at
    ):
        _fail("transition identity")
    allowed = {
        RootRegistrationBindingLifecycle.PROPOSED: {
            RootRegistrationBindingLifecycle.EFFECTIVE,
            RootRegistrationBindingLifecycle.DISPUTED,
            RootRegistrationBindingLifecycle.REVOKED,
        },
        RootRegistrationBindingLifecycle.EFFECTIVE: {
            RootRegistrationBindingLifecycle.DISPUTED,
            RootRegistrationBindingLifecycle.SUPERSEDED,
            RootRegistrationBindingLifecycle.REVOKED,
        },
        RootRegistrationBindingLifecycle.DISPUTED: {
            RootRegistrationBindingLifecycle.EFFECTIVE,
            RootRegistrationBindingLifecycle.SUPERSEDED,
            RootRegistrationBindingLifecycle.REVOKED,
        },
        RootRegistrationBindingLifecycle.SUPERSEDED: set(),
        RootRegistrationBindingLifecycle.REVOKED: set(),
    }
    if successor.lifecycle_state not in allowed[previous.lifecycle_state]:
        _fail("lifecycle transition")
    if successor.lifecycle_state is RootRegistrationBindingLifecycle.EFFECTIVE:
        if previous.effective_at is not None and successor.effective_at != previous.effective_at:
            _fail("effective_at transition")
    elif successor.effective_at != previous.effective_at:
        _fail("effective_at transition")
    if (
        previous.lifecycle_state is RootRegistrationBindingLifecycle.EFFECTIVE
        and successor.lifecycle_state is RootRegistrationBindingLifecycle.SUPERSEDED
    ):
        if successor.binding_id != previous.binding_id or successor.superseded_by_binding_id is None:
            _fail("supersession transition")
