from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from app.services.social_messaging_device_proof_profile import (
    ATOMIC_CHALLENGE_OWNER,
    AUTH_KEY_ROTATION_INVALIDATES_OUTSTANDING_CHALLENGES,
    AUTH_KEY_ROTATION_INVALIDATES_PREDECESSOR,
    DEVICE_PROOF_PROFILE,
    DEVICE_PROOF_RUNTIME_ENABLED,
    ENROLLMENT_V2_EXISTING_DEVICES_REQUIRE_REENROLLMENT,
    ENROLLMENT_V2_RUNTIME_ENABLED,
    FINAL_ADMISSION_OWNER,
    FINAL_AUTHORITY_MODEL,
    SocialMessagingDeviceProofUnavailable,
    canonical_device_proof_signing_preimage_v1,
    canonical_device_proof_v1_bytes,
    canonical_enrollment_proof_signing_preimage_v2,
    canonical_enrollment_proof_v2_bytes,
    canonical_enrollment_v2_bytes,
    enrollment_approval_unsigned_event_v2,
    enrollment_v2_digest,
    inspect_device_proof_shape_v1,
    parse_device_proof_v1,
    parse_enrollment_proof_v2,
    parse_enrollment_v2,
    x25519_public_key_commitment_v1,
)

FIXTURE_PATH = Path(__file__).parents[1] / "fixtures/social_messaging_device_proof_profile_v1.json"
FIXTURE_BYTES = FIXTURE_PATH.read_bytes()
VECTORS = json.loads(FIXTURE_BYTES)
PROOF = VECTORS["proofVector"]
ENROLLMENT = VECTORS["enrollmentVector"]
PROOF_VALUE = json.loads(PROOF["proofWire"])
ENROLLMENT_VALUE = json.loads(ENROLLMENT["wire"])
ENROLLMENT_PROOF = json.loads(ENROLLMENT["phoneProofWire"])


def canonical(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def change(source, **changes):
    return canonical({**json.loads(source), **changes})


def inspect(**changes):
    values = {
        "stored_challenge_wire": PROOF["storedChallengeWire"],
        "actual_request_wire": PROOF["actualRequestWire"],
        "proof_wire": PROOF["proofWire"],
        "expected_public_key": PROOF["publicKey"],
        "now": PROOF["now"],
    }
    values.update(changes)
    return inspect_device_proof_shape_v1(**values)


def enrollment_values(**changes):
    values = {
        "audience": ENROLLMENT_VALUE["audience"],
        "device_id": ENROLLMENT_VALUE["deviceId"],
        "ed25519_public_key": ENROLLMENT_VALUE["ed25519PublicKey"],
        "enrollment_challenge_id": ENROLLMENT_VALUE["enrollmentChallengeId"],
        "expires_at": ENROLLMENT_VALUE["expiresAt"],
        "issued_at": ENROLLMENT_VALUE["issuedAt"],
        "subject": ENROLLMENT_VALUE["subject"],
        "x25519_binding_id": ENROLLMENT_VALUE["x25519BindingId"],
        "x25519_binding_version": ENROLLMENT_VALUE["x25519BindingVersion"],
        "x25519_public_key_commitment": ENROLLMENT_VALUE["x25519PublicKeyCommitment"],
    }
    values.update(changes)
    return values


def test_shared_independent_vectors_and_canonical_bytes_are_frozen():
    assert hashlib.sha256(FIXTURE_BYTES).hexdigest() == (
        "f616cee3db22d906d309953ae74b5626109a643884edd27b00fba68325508477"
    )
    assert DEVICE_PROOF_PROFILE == "hodlxxi.social_messaging_device_proof.ed25519_webcrypto.v1"
    assert (
        canonical_device_proof_signing_preimage_v1(PROOF["storedChallengeWire"], PROOF["publicKey"]).decode("ascii")
        == PROOF["signingPreimage"]
    )
    assert parse_device_proof_v1(PROOF["proofWire"]) == PROOF_VALUE
    assert (
        canonical_device_proof_v1_bytes(
            challenge_id=PROOF_VALUE["challengeId"],
            public_key=PROOF_VALUE["publicKey"],
            signature=PROOF_VALUE["signature"],
        ).decode("ascii")
        == PROOF["proofWire"]
    )

    assert x25519_public_key_commitment_v1(ENROLLMENT["x25519PublicKey"]) == (ENROLLMENT["x25519PublicKeyCommitment"])
    assert canonical_enrollment_v2_bytes(**enrollment_values()).decode("ascii") == ENROLLMENT["wire"]
    parsed = parse_enrollment_v2(ENROLLMENT["wire"])
    assert parsed.subject == ENROLLMENT_VALUE["subject"]
    assert parsed.ed25519_public_key == ENROLLMENT_VALUE["ed25519PublicKey"]
    assert enrollment_v2_digest(ENROLLMENT["wire"]) == ENROLLMENT["digest"]
    assert canonical_enrollment_proof_signing_preimage_v2(ENROLLMENT["wire"]).decode("ascii") == (
        ENROLLMENT["phoneProofSigningPreimage"]
    )
    phone_proof = parse_enrollment_proof_v2(ENROLLMENT["phoneProofWire"])
    assert phone_proof.signature == ENROLLMENT_PROOF["signature"]
    assert (
        canonical_enrollment_proof_v2_bytes(
            enrollment_challenge_id=ENROLLMENT_PROOF["enrollmentChallengeId"],
            enrollment_digest=ENROLLMENT_PROOF["enrollmentDigest"],
            public_key=ENROLLMENT_PROOF["publicKey"],
            signature=ENROLLMENT_PROOF["signature"],
        ).decode("ascii")
        == ENROLLMENT["phoneProofWire"]
    )
    assert enrollment_approval_unsigned_event_v2(ENROLLMENT["wire"]) == (ENROLLMENT["approvalUnsignedEvent"])
    approval_event = ENROLLMENT["approvalEvent"]
    assert set(approval_event) == {"content", "created_at", "id", "kind", "pubkey", "sig", "tags"}
    assert approval_event["pubkey"] == ENROLLMENT_VALUE["subject"]
    assert {
        "content": approval_event["content"],
        "created_at": approval_event["created_at"],
        "kind": approval_event["kind"],
        "tags": approval_event["tags"],
    } == ENROLLMENT["approvalUnsignedEvent"]
    assert not {"privateKey", "private_key", "secret", "seed"} & set(approval_event)
    alternate_signer = ENROLLMENT["alternateSignerApproval"]
    assert set(alternate_signer) == {"id", "pubkey", "sig"}
    assert alternate_signer["pubkey"] != ENROLLMENT_VALUE["subject"]


@pytest.mark.parametrize("case", VECTORS["audienceCorpus"]["cases"], ids=lambda case: case["id"])
def test_shared_canonical_audience_corpus_through_real_contract_paths(case):
    audience = case["audience"]
    assert json.loads(case["audienceJson"]) == audience
    enrollment_wire = change(ENROLLMENT["wire"], audience=audience)
    escaped_enrollment = ENROLLMENT["wire"].replace(canonical(ENROLLMENT_VALUE["audience"]), case["audienceJson"])
    literal_enrollment = json.dumps(
        {**ENROLLMENT_VALUE, "audience": audience}, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    )

    def constructor():
        return canonical_enrollment_v2_bytes(**enrollment_values(audience=audience))

    if case["accepted"]:
        assert constructor().decode("ascii") == enrollment_wire
        for wire in (enrollment_wire, escaped_enrollment, literal_enrollment):
            assert parse_enrollment_v2(wire).audience == audience
    else:
        with pytest.raises(SocialMessagingDeviceProofUnavailable, match="^social messaging device proof unavailable$"):
            constructor()
        for wire in (enrollment_wire, escaped_enrollment, literal_enrollment):
            with pytest.raises(
                SocialMessagingDeviceProofUnavailable, match="^social messaging device proof unavailable$"
            ):
                parse_enrollment_v2(wire)
    request = json.loads(PROOF["actualRequestWire"])
    challenge = json.loads(PROOF["storedChallengeWire"])
    request_wire = change(PROOF["actualRequestWire"], audience=audience)
    escaped_request = PROOF["actualRequestWire"].replace(canonical(request["audience"]), case["audienceJson"])
    literal_request = json.dumps(
        {**request, "audience": audience}, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    )
    for wire in (request_wire, escaped_request, literal_request):
        challenge_wire = canonical({**challenge, "request": wire})
        if case["accepted"]:
            result = inspect(actual_request_wire=wire, stored_challenge_wire=challenge_wire)
            assert result.canonical_structure_validity == "valid"
            assert result.final_admission == "denied"
            assert canonical_device_proof_signing_preimage_v1(challenge_wire, PROOF["publicKey"]).decode("ascii") == (
                PROOF["signingPreimage"].replace(canonical(PROOF["storedChallengeWire"]), canonical(challenge_wire))
            )
        else:
            # Exercise both the actual-request parser and embedded stored request.
            for stored in (PROOF["storedChallengeWire"], challenge_wire):
                with pytest.raises(
                    SocialMessagingDeviceProofUnavailable, match="^social messaging device proof unavailable$"
                ):
                    inspect(actual_request_wire=wire, stored_challenge_wire=stored)
            with pytest.raises(
                SocialMessagingDeviceProofUnavailable, match="^social messaging device proof unavailable$"
            ):
                canonical_device_proof_signing_preimage_v1(challenge_wire, PROOF["publicKey"])


def test_ubid_returns_shape_only_and_never_claims_cryptographic_or_final_authority():
    result = inspect()
    assert result.canonical_structure_validity == "valid"
    assert result.strict_ed25519_cryptographic_validity == "not_evaluated_by_ubid"
    assert result.current_device_key_association_validity == "not_evaluated"
    assert result.atomic_challenge_consumption == "not_implemented"
    assert result.final_admission == "denied"
    assert result.proof_profile == DEVICE_PROOF_PROFILE

    # A same-shape signature mutation remains shape-valid here by design. The
    # current strict primitive in Social will reject it, but that result is not
    # an atomic final-admission decision.
    signature = PROOF_VALUE["signature"]
    mutated = signature[:-1] + ("1" if signature[-1] == "0" else "0")
    result = inspect(proof_wire=change(PROOF["proofWire"], signature=mutated))
    assert result.strict_ed25519_cryptographic_validity == "not_evaluated_by_ubid"
    assert result.final_admission == "denied"


@pytest.mark.parametrize("assertion", (True, "valid"))
def test_unauthenticated_social_assertion_cannot_be_final_authority(assertion):
    with pytest.raises(TypeError):
        inspect(social_verified=assertion)
    assert inspect().final_admission == "denied"


@pytest.mark.parametrize(
    "candidate",
    (
        PROOF["proofWire"] + "\n",
        " " + PROOF["proofWire"],
        change(PROOF["proofWire"], publicKey=PROOF["publicKey"].upper()),
        change(PROOF["proofWire"], publicKey="0x" + PROOF["publicKey"]),
        change(PROOF["proofWire"], signature=PROOF_VALUE["signature"].upper()),
        change(PROOF["proofWire"], algorithm="ed25519"),
        change(PROOF["proofWire"], profile=DEVICE_PROOF_PROFILE + ".other"),
        change(PROOF["proofWire"], unknown=None),
        change(PROOF["proofWire"], version=True),
        change(PROOF["proofWire"], version=1.0),
        PROOF["proofWire"].replace('"version":1', '"version":1,"version":1'),
    ),
)
def test_proof_shape_rejects_alternate_encodings_and_unknown_or_duplicate_members(candidate):
    with pytest.raises(SocialMessagingDeviceProofUnavailable):
        parse_device_proof_v1(candidate)


@pytest.mark.parametrize(
    "replacement",
    (
        {"subject": "aa" * 32},
        {"sessionBinding": "bb" * 32},
        {"deviceId": "cc" * 32},
        {"bindingId": "dd" * 32},
        {"bindingVersion": 2},
        {"operation": "recipient-self-read", "recipientHandle": "d_CAgICAgICAgICAgICAgICA"},
        {"method": "GET"},
        {"path": "/auth/messaging/v1/other"},
        {"bodyDigest": "hodlxxi-social-device-request-body-v1-sha256:" + "ee" * 32},
        {"audience": "https://other.example"},
    ),
)
def test_request_substitution_fails_shape_comparison(replacement):
    request = {**json.loads(PROOF["actualRequestWire"]), **replacement}
    with pytest.raises(SocialMessagingDeviceProofUnavailable):
        inspect(actual_request_wire=canonical(request))


def test_challenge_freshness_is_exclusive_and_lifetime_is_capped():
    challenge = json.loads(PROOF["storedChallengeWire"])
    assert inspect(now=challenge["issuedAt"]).final_admission == "denied"
    assert inspect(now=challenge["expiresAt"] - 1).final_admission == "denied"
    with pytest.raises(SocialMessagingDeviceProofUnavailable):
        inspect(now=challenge["issuedAt"] - 1)
    with pytest.raises(SocialMessagingDeviceProofUnavailable):
        inspect(now=challenge["expiresAt"])
    with pytest.raises(SocialMessagingDeviceProofUnavailable):
        inspect(stored_challenge_wire=canonical({**challenge, "expiresAt": challenge["issuedAt"] + 60_001}))


def test_audience_and_version_encoding_match_the_social_contract_exactly():
    request = json.loads(PROOF["actualRequestWire"])
    challenge = json.loads(PROOF["storedChallengeWire"])
    for version in (True, 1.0):
        changed_request = canonical({**request, "version": version})
        with pytest.raises(SocialMessagingDeviceProofUnavailable):
            inspect(actual_request_wire=changed_request)
        with pytest.raises(SocialMessagingDeviceProofUnavailable):
            inspect(stored_challenge_wire=canonical({**challenge, "version": version}))
    with pytest.raises(SocialMessagingDeviceProofUnavailable):
        inspect(actual_request_wire=canonical({**request, "audience": "https://social.example:443"}))
    ipv6 = canonical({**request, "audience": "https://[2001:db8::1]"})
    changed_challenge = canonical({**challenge, "request": ipv6})
    assert (
        inspect(
            actual_request_wire=ipv6,
            stored_challenge_wire=changed_challenge,
        ).canonical_structure_validity
        == "valid"
    )


@pytest.mark.parametrize(
    "replacement",
    (
        {"subject": "aa" * 32},
        {"deviceId": "bb" * 32},
        {"x25519BindingId": "cc" * 32},
        {"x25519BindingVersion": 2},
        {"x25519PublicKeyCommitment": "hodlxxi-social-messaging-x25519-public-key-v1-sha256:" + "dd" * 32},
        {"ed25519PublicKey": VECTORS["rfc8032Vector1"]["publicKey"]},
        {"enrollmentChallengeId": "ee" * 32},
        {"profile": DEVICE_PROOF_PROFILE + ".other"},
        {"audience": "https://other.example"},
    ),
)
def test_enrollment_v2_substitutions_change_or_invalidate_exact_bytes(replacement):
    source = change(ENROLLMENT["wire"], **replacement)
    if "profile" in replacement:
        with pytest.raises(SocialMessagingDeviceProofUnavailable):
            parse_enrollment_v2(source)
    else:
        assert source != ENROLLMENT["wire"]
        parsed = parse_enrollment_v2(source)
        assert parsed != parse_enrollment_v2(ENROLLMENT["wire"])
        assert enrollment_v2_digest(source) != ENROLLMENT["digest"]


def test_enrollment_v2_rejects_future_expired_and_overlong_intervals_at_consumption_seam():
    issued = ENROLLMENT_VALUE["issuedAt"]
    expires = ENROLLMENT_VALUE["expiresAt"]
    assert issued <= ENROLLMENT["now"] < expires
    with pytest.raises(SocialMessagingDeviceProofUnavailable):
        parse_enrollment_v2(change(ENROLLMENT["wire"], expiresAt=issued + 60_001))
    with pytest.raises(SocialMessagingDeviceProofUnavailable):
        parse_enrollment_v2(change(ENROLLMENT["wire"], expiresAt=issued))
    for version in (True, 2.0):
        with pytest.raises(SocialMessagingDeviceProofUnavailable):
            parse_enrollment_v2(change(ENROLLMENT["wire"], version=version))
        with pytest.raises(SocialMessagingDeviceProofUnavailable):
            parse_enrollment_proof_v2(change(ENROLLMENT["phoneProofWire"], version=version))
    with pytest.raises(SocialMessagingDeviceProofUnavailable):
        parse_enrollment_v2(change(ENROLLMENT["wire"], audience="https://social.example:443"))


def test_default_off_rotation_and_reenrollment_invariants_are_explicit():
    assert DEVICE_PROOF_RUNTIME_ENABLED is False
    assert ENROLLMENT_V2_RUNTIME_ENABLED is False
    assert ENROLLMENT_V2_EXISTING_DEVICES_REQUIRE_REENROLLMENT is True
    assert AUTH_KEY_ROTATION_INVALIDATES_PREDECESSOR is True
    assert AUTH_KEY_ROTATION_INVALIDATES_OUTSTANDING_CHALLENGES is True
    assert FINAL_AUTHORITY_MODEL == "ATOMIC_OWNER_PENDING"
    assert ATOMIC_CHALLENGE_OWNER == "PENDING"
    assert FINAL_ADMISSION_OWNER == "PENDING"


def test_phase2_and_phase3_fixtures_remain_byte_identical():
    fixtures = {
        "social_mobile_device_authorization_v1.json": "26f335b718a771d08aacc7ebbe63895d395e2e2376d12484fb19ab30c0db7356",
        "social_messaging_phase3_routing_v1.json": "90f7c3726a9dfcfa655630626d53d65b410e5e330456d5114d04982a53da2f1c",
    }
    for name, expected in fixtures.items():
        source = Path(__file__).parents[1] / "fixtures" / name
        assert hashlib.sha256(source.read_bytes()).hexdigest() == expected


def test_module_is_absent_from_factory_and_runtime_configuration():
    root = Path(__file__).parents[2]
    for name in ("app/factory.py", "app/config.py"):
        assert "social_messaging_device_proof_profile" not in (root / name).read_text()
