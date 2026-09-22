"""Dormant pure Ed25519 association lifecycle for one Social device.

Events and enrollment wires are candidate evidence only. A future storage owner
must authenticate enrollment and load the event sequence from locked, durable
state before using a current-authority comparison. This module performs no I/O.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace
from typing import NoReturn, cast

from app.services.social_messaging_device_admission_contract import (
    VerificationContextV1,
    parse_verification_context_v1,
)
from app.services.social_messaging_device_proof_profile import (
    MAX_SAFE_INTEGER,
    enrollment_v2_digest,
    parse_enrollment_v2,
)

CREATION_SCHEMA = "hodlxxi.social_messaging_device_ed25519_association_creation.v1"
EVENT_SCHEMA = "hodlxxi.social_messaging_device_ed25519_association_event.v1"
ASSOCIATION_ID_DOMAIN = "HODLXXI_SOCIAL_MESSAGING_DEVICE_ED25519_ASSOCIATION_ID_V1"
VERSION = 1
MAX_EVENT_BYTES = 4096
UNAVAILABLE_MESSAGE = "social messaging device association lifecycle unavailable"

CREATION_KINDS = frozenset(("initial", "rotate", "reenroll"))
EVENT_KINDS = CREATION_KINDS | frozenset(("invalidate", "revoke"))
TERMINAL_STATES = frozenset(("rotated", "revoked"))
_HEX64 = re.compile(r"[0-9a-f]{64}\Z").fullmatch
_EVENT_FIELDS = frozenset(
    (
        "associationId",
        "associationVersion",
        "authorityEpoch",
        "enrollmentWire",
        "kind",
        "predecessorAssociationId",
        "schema",
        "version",
    )
)


class SocialMessagingDeviceAssociationLifecycleUnavailable(ValueError):
    def __init__(self) -> None:
        super().__init__(UNAVAILABLE_MESSAGE)


@dataclass(frozen=True, slots=True)
class AssociationEventV1:
    kind: str
    association_id: str
    association_version: int
    predecessor_association_id: str | None
    authority_epoch: int
    enrollment_wire: str | None


@dataclass(frozen=True, slots=True)
class AssociationLifecycleV1:
    events: tuple[AssociationEventV1, ...] = ()


@dataclass(frozen=True, slots=True)
class AssociationGenerationV1:
    association_id: str
    subject: str
    device_id: str
    ed25519_public_key: str
    association_version: int
    predecessor_association_id: str | None
    enrollment_wire: str
    state: str


@dataclass(frozen=True, slots=True)
class AssociationSnapshotV1:
    history: tuple[AssociationGenerationV1, ...]
    authority_epoch: int

    @property
    def current(self) -> AssociationGenerationV1 | None:
        return self.history[-1] if self.history and self.history[-1].state == "active" else None


def _deny() -> NoReturn:
    raise SocialMessagingDeviceAssociationLifecycleUnavailable()


def _hex64(value: object) -> str:
    if type(value) is not str or _HEX64(value) is None:
        _deny()
    return cast(str, value)


def _positive_integer(value: object) -> int:
    if type(value) is not int or not 1 <= value <= MAX_SAFE_INTEGER:
        _deny()
    return cast(int, value)


def _canonical(value: dict[str, object]) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")


def canonical_association_creation_v1_bytes(
    enrollment_wire: object, association_version: object, predecessor_association_id: object
) -> bytes:
    """Bind an association generation to an exact canonical Enrollment V2 wire."""
    try:
        enrollment = parse_enrollment_v2(enrollment_wire)
        version = _positive_integer(association_version)
        predecessor = None if predecessor_association_id is None else _hex64(predecessor_association_id)
        if (version == 1) != (predecessor is None):
            raise ValueError
        return _canonical(
            {
                "associationVersion": version,
                "deviceId": enrollment.device_id,
                "ed25519PublicKey": enrollment.ed25519_public_key,
                "enrollmentDigest": enrollment_v2_digest(cast(str, enrollment_wire)),
                "predecessorAssociationId": predecessor,
                "schema": CREATION_SCHEMA,
                "subject": enrollment.subject,
                "version": VERSION,
            }
        )
    except Exception:
        _deny()


def association_id_v1(
    enrollment_wire: object, association_version: object, predecessor_association_id: object
) -> str:
    preimage = canonical_association_creation_v1_bytes(
        enrollment_wire, association_version, predecessor_association_id
    )
    return hashlib.sha256(ASSOCIATION_ID_DOMAIN.encode("ascii") + b"\0" + preimage).hexdigest()


def _valid_event(event: object) -> AssociationEventV1:
    if type(event) is not AssociationEventV1:
        _deny()
    event = cast(AssociationEventV1, event)
    if type(event.kind) is not str or event.kind not in EVENT_KINDS:
        _deny()
    _hex64(event.association_id)
    _positive_integer(event.association_version)
    _positive_integer(event.authority_epoch)
    if event.predecessor_association_id is not None:
        _hex64(event.predecessor_association_id)
    if event.kind in CREATION_KINDS:
        if type(event.enrollment_wire) is not str:
            _deny()
        if association_id_v1(
            event.enrollment_wire, event.association_version, event.predecessor_association_id
        ) != event.association_id:
            _deny()
    elif event.enrollment_wire is not None:
        _deny()
    return event


def canonical_association_event_v1_bytes(event: object) -> bytes:
    event = _valid_event(event)
    wire = _canonical(
        {
            "associationId": event.association_id,
            "associationVersion": event.association_version,
            "authorityEpoch": event.authority_epoch,
            "enrollmentWire": event.enrollment_wire,
            "kind": event.kind,
            "predecessorAssociationId": event.predecessor_association_id,
            "schema": EVENT_SCHEMA,
            "version": VERSION,
        }
    )
    if len(wire) > MAX_EVENT_BYTES:
        _deny()
    return wire


def parse_association_event_v1(source: object) -> AssociationEventV1:
    try:
        if type(source) is not str or not 1 <= len(source) <= MAX_EVENT_BYTES or not source.isascii():
            raise ValueError
        if any(ord(character) < 0x20 or ord(character) > 0x7E for character in source):
            raise ValueError

        def unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError
                result[key] = value
            return result

        value = json.loads(source, object_pairs_hook=unique_pairs)
        if (
            type(value) is not dict
            or set(value) != _EVENT_FIELDS
            or value["schema"] != EVENT_SCHEMA
            or type(value["version"]) is not int
            or value["version"] != VERSION
        ):
            raise ValueError
        event = AssociationEventV1(
            kind=value["kind"],
            association_id=value["associationId"],
            association_version=value["associationVersion"],
            predecessor_association_id=value["predecessorAssociationId"],
            authority_epoch=value["authorityEpoch"],
            enrollment_wire=value["enrollmentWire"],
        )
        if canonical_association_event_v1_bytes(event).decode("ascii") != source:
            raise ValueError
        return event
    except Exception:
        _deny()


def association_snapshot_v1(lifecycle: object) -> AssociationSnapshotV1:
    """Replay every event; a malformed, forked or reopened history fails closed."""
    try:
        if type(lifecycle) is not AssociationLifecycleV1 or type(lifecycle.events) is not tuple:
            raise ValueError
        history: tuple[AssociationGenerationV1, ...] = ()
        epoch = 0
        used_challenges: set[str] = set()
        for candidate in lifecycle.events:
            event = _valid_event(candidate)
            if event.authority_epoch != epoch + 1:
                raise ValueError
            if event.kind in CREATION_KINDS:
                enrollment = parse_enrollment_v2(event.enrollment_wire)
                if enrollment.enrollment_challenge_id in used_challenges:
                    raise ValueError
                used_challenges.add(enrollment.enrollment_challenge_id)
                if event.kind == "initial":
                    if history or event.association_version != 1 or event.predecessor_association_id is not None:
                        raise ValueError
                else:
                    if not history or history[-1].state != ("active" if event.kind == "rotate" else "revoked"):
                        raise ValueError
                    previous = history[-1]
                    if (
                        enrollment.subject != previous.subject
                        or enrollment.device_id != previous.device_id
                        or event.association_version != previous.association_version + 1
                        or event.predecessor_association_id != previous.association_id
                    ):
                        raise ValueError
                    history = history[:-1] + (
                        replace(previous, state="rotated") if event.kind == "rotate" else previous,
                    )
                if (
                    any(
                        item.association_id == event.association_id
                        or item.ed25519_public_key == enrollment.ed25519_public_key
                        for item in history
                    )
                    or event.association_id
                    in (enrollment.device_id, enrollment.ed25519_public_key, enrollment.x25519_binding_id)
                ):
                    raise ValueError
                history += (
                    AssociationGenerationV1(
                        association_id=event.association_id,
                        subject=enrollment.subject,
                        device_id=enrollment.device_id,
                        ed25519_public_key=enrollment.ed25519_public_key,
                        association_version=event.association_version,
                        predecessor_association_id=event.predecessor_association_id,
                        enrollment_wire=cast(str, event.enrollment_wire),
                        state="active",
                    ),
                )
            else:
                if not history or history[-1].state != "active":
                    raise ValueError
                current = history[-1]
                if (
                    event.association_id != current.association_id
                    or event.association_version != current.association_version
                    or event.predecessor_association_id != current.predecessor_association_id
                ):
                    raise ValueError
                if event.kind == "revoke":
                    history = history[:-1] + (replace(current, state="revoked"),)
            epoch = event.authority_epoch
        return AssociationSnapshotV1(history=history, authority_epoch=epoch)
    except Exception:
        _deny()


def _append(lifecycle: AssociationLifecycleV1, event: AssociationEventV1) -> AssociationLifecycleV1:
    result = AssociationLifecycleV1(lifecycle.events + (event,))
    association_snapshot_v1(result)
    return result


def initial_association_v1(lifecycle: AssociationLifecycleV1, enrollment_wire: str) -> AssociationLifecycleV1:
    snapshot = association_snapshot_v1(lifecycle)
    if snapshot.history:
        _deny()
    event = AssociationEventV1("initial", association_id_v1(enrollment_wire, 1, None), 1, None, 1, enrollment_wire)
    return _append(lifecycle, event)


def _current_expected(
    lifecycle: AssociationLifecycleV1, expected_association_id: object, expected_authority_epoch: object
) -> AssociationSnapshotV1:
    snapshot = association_snapshot_v1(lifecycle)
    if (
        snapshot.current is None
        or _hex64(expected_association_id) != snapshot.current.association_id
        or _positive_integer(expected_authority_epoch) != snapshot.authority_epoch
        or snapshot.authority_epoch == MAX_SAFE_INTEGER
    ):
        _deny()
    return snapshot


def rotate_association_v1(
    lifecycle: AssociationLifecycleV1,
    enrollment_wire: str,
    *,
    expected_predecessor_association_id: str,
    expected_authority_epoch: int,
) -> AssociationLifecycleV1:
    snapshot = _current_expected(lifecycle, expected_predecessor_association_id, expected_authority_epoch)
    current = cast(AssociationGenerationV1, snapshot.current)
    version = current.association_version + 1
    event = AssociationEventV1(
        "rotate",
        association_id_v1(enrollment_wire, version, current.association_id),
        version,
        current.association_id,
        snapshot.authority_epoch + 1,
        enrollment_wire,
    )
    return _append(lifecycle, event)


def invalidate_association_authority_v1(
    lifecycle: AssociationLifecycleV1, *, expected_association_id: str, expected_authority_epoch: int
) -> AssociationLifecycleV1:
    snapshot = _current_expected(lifecycle, expected_association_id, expected_authority_epoch)
    current = cast(AssociationGenerationV1, snapshot.current)
    return _append(
        lifecycle,
        AssociationEventV1(
            "invalidate",
            current.association_id,
            current.association_version,
            current.predecessor_association_id,
            snapshot.authority_epoch + 1,
            None,
        ),
    )


def revoke_association_v1(
    lifecycle: AssociationLifecycleV1, *, expected_association_id: str, expected_authority_epoch: int
) -> AssociationLifecycleV1:
    snapshot = _current_expected(lifecycle, expected_association_id, expected_authority_epoch)
    current = cast(AssociationGenerationV1, snapshot.current)
    return _append(
        lifecycle,
        AssociationEventV1(
            "revoke",
            current.association_id,
            current.association_version,
            current.predecessor_association_id,
            snapshot.authority_epoch + 1,
            None,
        ),
    )


def reenroll_association_v1(
    lifecycle: AssociationLifecycleV1,
    enrollment_wire: str,
    *,
    expected_predecessor_association_id: str,
    expected_authority_epoch: int,
) -> AssociationLifecycleV1:
    snapshot = association_snapshot_v1(lifecycle)
    if (
        not snapshot.history
        or snapshot.history[-1].state != "revoked"
        or _hex64(expected_predecessor_association_id) != snapshot.history[-1].association_id
        or _positive_integer(expected_authority_epoch) != snapshot.authority_epoch
        or snapshot.authority_epoch == MAX_SAFE_INTEGER
    ):
        _deny()
    previous = snapshot.history[-1]
    version = previous.association_version + 1
    event = AssociationEventV1(
        "reenroll",
        association_id_v1(enrollment_wire, version, previous.association_id),
        version,
        previous.association_id,
        snapshot.authority_epoch + 1,
        enrollment_wire,
    )
    return _append(lifecycle, event)


def current_association_matches_v1(lifecycle: object, context: object) -> bool:
    """Compare persisted lifecycle evidence with a frozen context, never mint authority from it."""
    try:
        snapshot = association_snapshot_v1(lifecycle)
        if type(context) is not VerificationContextV1 or parse_verification_context_v1(context.wire) != context:
            return False
        current = snapshot.current
        return bool(
            current is not None
            and current.subject == context.subject
            and current.device_id == context.device_id
            and current.ed25519_public_key == context.ed25519_public_key
            and current.association_id == context.association_id
            and current.association_version == context.association_version
            and snapshot.authority_epoch == context.authority_epoch
            and (
                context.challenge_kind == "device-request-v1"
                or current.predecessor_association_id == context.predecessor_association_id
            )
        )
    except Exception:
        return False
