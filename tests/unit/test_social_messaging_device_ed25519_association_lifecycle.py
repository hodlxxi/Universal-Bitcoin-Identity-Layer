from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from app.services import social_messaging_device_ed25519_association_lifecycle as lifecycle
from app.services.social_messaging_device_admission_contract import parse_verification_context_v1
from app.services.social_messaging_device_proof_profile import enrollment_v2_digest, parse_enrollment_v2

FIXTURES = Path(__file__).parents[1] / "fixtures"
VECTORS = json.loads((FIXTURES / "social_messaging_device_ed25519_association_lifecycle_v1.json").read_bytes())
ERROR = "^social messaging device association lifecycle unavailable$"


def canonical(value: dict[str, object]) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def event(name: str) -> lifecycle.AssociationEventV1:
    return lifecycle.parse_association_event_v1(VECTORS["eventWires"][name])


def replay(*names: str) -> lifecycle.AssociationLifecycleV1:
    return lifecycle.AssociationLifecycleV1(tuple(event(name) for name in names))


def changed_context(context, **changes):
    return parse_verification_context_v1(canonical({**json.loads(context.wire), **changes}))


def test_existing_fixture_bytes_and_creation_preimages_are_fixed():
    for name, expected in VECTORS["sourceFixtureSha256"].items():
        if name == "admission":
            filename = "social_device_admission_v1.json"
        else:
            filename = "social_messaging_device_proof_profile_v1.json"
        assert hashlib.sha256((FIXTURES / filename).read_bytes()).hexdigest() == expected

    for name, vector in VECTORS["creationVectors"].items():
        wire = VECTORS["enrollmentWires"][vector["enrollment"]]
        enrollment = parse_enrollment_v2(wire)
        expected_preimage = canonical(
            {
                "associationVersion": vector["associationVersion"],
                "deviceId": enrollment.device_id,
                "ed25519PublicKey": enrollment.ed25519_public_key,
                "enrollmentDigest": enrollment_v2_digest(wire),
                "predecessorAssociationId": vector["predecessorAssociationId"],
                "schema": lifecycle.CREATION_SCHEMA,
                "subject": enrollment.subject,
                "version": 1,
            }
        )
        assert vector["preimage"] == expected_preimage
        assert lifecycle.canonical_association_creation_v1_bytes(
            wire, vector["associationVersion"], vector["predecessorAssociationId"]
        ) == expected_preimage.encode("ascii")
        independent_id = hashlib.sha256(
            lifecycle.ASSOCIATION_ID_DOMAIN.encode("ascii") + b"\0" + expected_preimage.encode("ascii")
        ).hexdigest()
        assert lifecycle.association_id_v1(wire, vector["associationVersion"], vector["predecessorAssociationId"]) == (
            vector["associationId"]
        )
        assert independent_id == vector["associationId"]
        assert hashlib.sha256(expected_preimage.encode("ascii")).hexdigest() != independent_id
        assert hashlib.sha256(b"OTHER_DOMAIN\0" + expected_preimage.encode("ascii")).hexdigest() != independent_id
        assert independent_id not in (
            enrollment.device_id,
            enrollment.ed25519_public_key,
            enrollment.x25519_binding_id,
        )
        assert name in ("initial", "firstRotation", "secondRotation", "reenrollment")


def test_canonical_event_wires_round_trip_byte_for_byte():
    for name, wire in VECTORS["eventWires"].items():
        parsed = lifecycle.parse_association_event_v1(wire)
        assert lifecycle.canonical_association_event_v1_bytes(parsed) == wire.encode("ascii")
        assert parsed.authority_epoch == VECTORS["lifecycleOrder"].index(name) + 1


def test_initial_rotation_invalidation_revocation_and_reenrollment_chain():
    wire = VECTORS["enrollmentWires"]
    identifiers = VECTORS["creationVectors"]
    state = lifecycle.initial_association_v1(lifecycle.AssociationLifecycleV1(), wire["initial"])
    assert state.events == (event("initial"),)
    assert lifecycle.association_snapshot_v1(state).authority_epoch == 1
    assert lifecycle.association_snapshot_v1(state).current.association_version == 1

    first_id = identifiers["initial"]["associationId"]
    state = lifecycle.rotate_association_v1(
        state, wire["firstRotation"], expected_predecessor_association_id=first_id, expected_authority_epoch=1
    )
    assert state.events[-1] == event("firstRotation")
    assert lifecycle.association_snapshot_v1(state).history[0].state == "rotated"
    second_id = identifiers["firstRotation"]["associationId"]
    for epoch, name in ((2, "firstInvalidation"), (3, "secondInvalidation")):
        state = lifecycle.invalidate_association_authority_v1(
            state, expected_association_id=second_id, expected_authority_epoch=epoch
        )
        assert state.events[-1] == event(name)
        snapshot = lifecycle.association_snapshot_v1(state)
        assert snapshot.current.association_version == 2
        assert snapshot.authority_epoch == epoch + 1

    assert lifecycle.association_snapshot_v1(state).authority_epoch == 4
    state = lifecycle.rotate_association_v1(
        state, wire["secondRotation"], expected_predecessor_association_id=second_id, expected_authority_epoch=4
    )
    assert state.events[-1] == event("secondRotation")
    third_id = identifiers["secondRotation"]["associationId"]
    state = lifecycle.revoke_association_v1(state, expected_association_id=third_id, expected_authority_epoch=5)
    assert state.events[-1] == event("revocation")
    revoked = lifecycle.association_snapshot_v1(state)
    assert revoked.authority_epoch == 6
    assert revoked.current is None
    assert revoked.history[-1].state == "revoked"
    with pytest.raises(lifecycle.SocialMessagingDeviceAssociationLifecycleUnavailable, match=ERROR):
        lifecycle.rotate_association_v1(
            state, wire["fork"], expected_predecessor_association_id=third_id, expected_authority_epoch=6
        )

    state = lifecycle.reenroll_association_v1(
        state, wire["reenrollment"], expected_predecessor_association_id=third_id, expected_authority_epoch=6
    )
    assert state.events[-1] == event("reenrollment")
    snapshot = lifecycle.association_snapshot_v1(state)
    assert snapshot.authority_epoch == 7
    assert snapshot.current.association_version == 4
    assert snapshot.current.predecessor_association_id == third_id
    assert [generation.state for generation in snapshot.history] == ["rotated", "rotated", "revoked", "active"]
    assert [generation.association_id for generation in snapshot.history] == [
        identifiers[name]["associationId"] for name in ("initial", "firstRotation", "secondRotation", "reenrollment")
    ]


@pytest.mark.parametrize("name", sorted(VECTORS["rejectionVectors"]))
def test_fixed_replay_rejections(name: str):
    vector = VECTORS["rejectionVectors"][name]
    prior = replay(*vector["priorEvents"])
    candidate = lifecycle.parse_association_event_v1(vector["candidateEventWire"])
    with pytest.raises(lifecycle.SocialMessagingDeviceAssociationLifecycleUnavailable, match=ERROR):
        lifecycle.association_snapshot_v1(lifecycle.AssociationLifecycleV1(prior.events + (candidate,)))


def test_stale_compare_and_swap_reuse_and_reopening_are_denied():
    initial = replay("initial")
    first = replay("initial", "firstRotation")
    initial_id = VECTORS["creationVectors"]["initial"]["associationId"]
    first_id = VECTORS["creationVectors"]["firstRotation"]["associationId"]
    with pytest.raises(lifecycle.SocialMessagingDeviceAssociationLifecycleUnavailable, match=ERROR):
        lifecycle.rotate_association_v1(
            first,
            VECTORS["enrollmentWires"]["secondRotation"],
            expected_predecessor_association_id=initial_id,
            expected_authority_epoch=1,
        )
    with pytest.raises(lifecycle.SocialMessagingDeviceAssociationLifecycleUnavailable, match=ERROR):
        lifecycle.revoke_association_v1(first, expected_association_id=first_id, expected_authority_epoch=1)
    with pytest.raises(lifecycle.SocialMessagingDeviceAssociationLifecycleUnavailable, match=ERROR):
        lifecycle.initial_association_v1(first, VECTORS["enrollmentWires"]["initial"])
    with pytest.raises(lifecycle.SocialMessagingDeviceAssociationLifecycleUnavailable, match=ERROR):
        lifecycle.rotate_association_v1(
            initial,
            VECTORS["enrollmentWires"]["initial"],
            expected_predecessor_association_id=initial_id,
            expected_authority_epoch=1,
        )
    reused_challenge = canonical(
        {
            **json.loads(VECTORS["enrollmentWires"]["firstRotation"]),
            "enrollmentChallengeId": json.loads(VECTORS["enrollmentWires"]["initial"])["enrollmentChallengeId"],
        }
    )
    with pytest.raises(lifecycle.SocialMessagingDeviceAssociationLifecycleUnavailable, match=ERROR):
        lifecycle.rotate_association_v1(
            initial,
            reused_challenge,
            expected_predecessor_association_id=initial_id,
            expected_authority_epoch=1,
        )
    revoked = replay(*VECTORS["lifecycleOrder"][:-1])
    with pytest.raises(lifecycle.SocialMessagingDeviceAssociationLifecycleUnavailable, match=ERROR):
        lifecycle.reenroll_association_v1(
            revoked,
            VECTORS["enrollmentWires"]["resurrection"],
            expected_predecessor_association_id=VECTORS["creationVectors"]["secondRotation"]["associationId"],
            expected_authority_epoch=6,
        )


def test_current_association_matches_frozen_context_with_request_predecessor_null():
    contexts = {name: parse_verification_context_v1(wire) for name, wire in VECTORS["contextWires"].items()}
    initial = replay("initial")
    assert lifecycle.current_association_matches_v1(initial, contexts["initialEnrollment"])
    first_epoch_four = replay("initial", "firstRotation", "firstInvalidation", "secondInvalidation")
    successor = contexts["successorEnrollmentVersion2Epoch4"]
    request = contexts["requestVersion2Epoch4"]
    assert successor.association_version == 2 and successor.authority_epoch == 4
    assert successor.predecessor_association_id == VECTORS["creationVectors"]["initial"]["associationId"]
    assert request.predecessor_association_id is None
    assert lifecycle.association_snapshot_v1(first_epoch_four).current.predecessor_association_id is not None
    assert lifecycle.current_association_matches_v1(first_epoch_four, successor)
    assert lifecycle.current_association_matches_v1(first_epoch_four, request)
    assert not lifecycle.current_association_matches_v1(first_epoch_four, changed_context(request, authorityEpoch=3))
    assert not lifecycle.current_association_matches_v1(
        first_epoch_four, changed_context(successor, associationVersion=3)
    )
    assert not lifecycle.current_association_matches_v1(first_epoch_four, contexts["initialEnrollment"])
    assert not lifecycle.current_association_matches_v1(first_epoch_four, changed_context(successor, subject="41" * 32))
    assert not lifecycle.current_association_matches_v1(
        first_epoch_four, changed_context(successor, deviceId="42" * 32)
    )
    assert not lifecycle.current_association_matches_v1(
        first_epoch_four, changed_context(successor, predecessorAssociationId="ff" * 32)
    )
    assert not lifecycle.current_association_matches_v1(first_epoch_four, replace(successor, authority_epoch=3))
    revoked = replay(*VECTORS["lifecycleOrder"][:-1])
    assert not lifecycle.current_association_matches_v1(revoked, successor)
    assert not lifecycle.current_association_matches_v1(first_epoch_four, object())


def test_event_parser_rejects_noncanonical_and_ambiguous_wires():
    wire = VECTORS["eventWires"]["firstRotation"]
    candidates = (
        wire[:-1] + ',"kind":"rotate"}',
        canonical({**json.loads(wire), "unknown": None}),
        wire.replace('"kind":"rotate"', '"kind": "rotate"'),
        wire.replace("rotate", "rótate", 1),
    )
    for candidate in candidates:
        with pytest.raises(lifecycle.SocialMessagingDeviceAssociationLifecycleUnavailable, match=ERROR):
            lifecycle.parse_association_event_v1(candidate)
    with pytest.raises(lifecycle.SocialMessagingDeviceAssociationLifecycleUnavailable, match=ERROR):
        lifecycle.association_snapshot_v1(
            lifecycle.AssociationLifecycleV1((replace(event("initial"), authority_epoch=2),))
        )
