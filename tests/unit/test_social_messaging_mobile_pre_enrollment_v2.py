from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest
from coincurve import PublicKeyXOnly
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from app.services import social_messaging_mobile_pre_enrollment_v2 as contract
from app.services.social_messaging_device_admission_contract import canonical_verification_context_v1_bytes
from app.services.social_messaging_device_ed25519_association_lifecycle import (
    association_id_v1,
    canonical_association_creation_v1_bytes,
)
from app.services.social_messaging_device_proof_profile import (
    DEVICE_PROOF_PROFILE,
    canonical_enrollment_proof_signing_preimage_v2,
    canonical_enrollment_proof_v2_bytes,
    canonical_enrollment_v2_bytes,
    enrollment_v2_digest,
    parse_enrollment_proof_v2,
    parse_enrollment_v2,
    x25519_public_key_commitment_v1,
)
from app.services.social_messaging_mobile_authorization import inspect_claim
from app.services.social_messaging_mobile_authorization import parse_json as parse_v1_json

ROOT = Path(__file__).parents[2]
FIXTURE_PATH = ROOT / "tests/fixtures/social_preacceptance_ed25519_handoff_v2.json"
FIXTURE_BYTES = FIXTURE_PATH.read_bytes()
FIXTURE = json.loads(FIXTURE_BYTES)
VECTOR = FIXTURE["vector"]
PRE_VALUE = json.loads(VECTOR["preEnrollmentWire"])
OUTER_VALUE = json.loads(VECTOR["authorizationWire"])
EVENT_VALUE = json.loads(VECTOR["approvalEventWire"])
ACCEPTANCE_VALUE = json.loads(VECTOR["acceptanceWire"])
ENROLLMENT_VALUE = json.loads(VECTOR["enrollmentWire"])
PROOF_VALUE = json.loads(VECTOR["enrollmentPhoneProofWire"])

PAIRING_SECRET = "77" * 32
EXCHANGE_VERIFIER = "88" * 32
ACCEPTED_AT = PRE_VALUE["issuedAt"]
ENROLLMENT_NOW = ENROLLMENT_VALUE["issuedAt"]
X25519_DEADLINE = contract.epoch_milliseconds_from_utc_second("2026-10-08T22:29:59Z")
FULL_PROOF = "hodlxxi-full-entitlement-v1-sha256:" + "ab" * 32
APPROVER_FULL_PROOF = "hodlxxi-full-entitlement-v1-sha256:" + "ac" * 32


def canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def changed(source: str, **changes: object) -> str:
    return canonical({**json.loads(source), **changes})


def pre_kwargs(value: dict[str, object] | None = None) -> dict[str, object]:
    source = PRE_VALUE if value is None else value
    return {
        "binding_authorization_digest": source["bindingAuthorizationDigest"],
        "device_id": source["deviceId"],
        "ed25519_public_key": source["ed25519PublicKey"],
        "expires_at": source["expiresAt"],
        "issued_at": source["issuedAt"],
        "pairing_id": source["pairingId"],
        "pre_effect_association_id": source["preEffectAssociationId"],
        "pre_effect_association_state": source["preEffectAssociationState"],
        "pre_effect_association_version": source["preEffectAssociationVersion"],
        "pre_effect_authority_epoch": source["preEffectAuthorityEpoch"],
        "proposed_association_version": source["proposedAssociationVersion"],
        "proposed_authority_epoch": source["proposedAuthorityEpoch"],
        "proposed_predecessor_association_id": source["proposedPredecessorAssociationId"],
        "request_id": source["requestId"],
        "subject": source["subject"],
        "transition_kind": source["transitionKind"],
        "x25519_binding_id": source["x25519BindingId"],
        "x25519_binding_version": source["x25519BindingVersion"],
        "x25519_public_key_commitment": source["x25519PublicKeyCommitment"],
    }


def enrollment_kwargs(value: dict[str, object] | None = None) -> dict[str, object]:
    source = ENROLLMENT_VALUE if value is None else value
    return {
        "audience": source["audience"],
        "device_id": source["deviceId"],
        "ed25519_public_key": source["ed25519PublicKey"],
        "enrollment_challenge_id": source["enrollmentChallengeId"],
        "expires_at": source["expiresAt"],
        "issued_at": source["issuedAt"],
        "subject": source["subject"],
        "x25519_binding_id": source["x25519BindingId"],
        "x25519_binding_version": source["x25519BindingVersion"],
        "x25519_public_key_commitment": source["x25519PublicKeyCommitment"],
    }


def context_wire(**changes: object) -> str:
    values = {
        "challenge_kind": "enrollment-v2",
        "challenge_id": ENROLLMENT_VALUE["enrollmentChallengeId"],
        "attempt_id": "cc" * 32,
        "audience": ENROLLMENT_VALUE["audience"],
        "subject": PRE_VALUE["subject"],
        "device_id": PRE_VALUE["deviceId"],
        "binding_id": PRE_VALUE["x25519BindingId"],
        "binding_version": PRE_VALUE["x25519BindingVersion"],
        "x25519_public_key_commitment": PRE_VALUE["x25519PublicKeyCommitment"],
        "profile": DEVICE_PROOF_PROFILE,
        "ed25519_public_key": PRE_VALUE["ed25519PublicKey"],
        "association_id": VECTOR["associationId"],
        "association_version": 1,
        "predecessor_association_id": None,
        "authority_epoch": 1,
        "session_binding": "44" * 32,
        "approver_session_binding": "aa" * 32,
        "full_proof_id": FULL_PROOF,
        "approver_full_proof_id": APPROVER_FULL_PROOF,
    }
    values.update(changes)
    return canonical_verification_context_v1_bytes(**values).decode("ascii")


def verification_input_wire(**changes: object) -> str:
    values = {
        "approval_event_wire": VECTOR["approvalEventWire"],
        "context_wire": context_wire(),
        "enrollment_wire": VECTOR["enrollmentWire"],
        "phone_proof_wire": VECTOR["enrollmentPhoneProofWire"],
    }
    values.update(changes)
    return contract.canonical_preaccepted_enrollment_verification_input_v2_bytes(**values).decode("ascii")


def time_kwargs(**changes: object) -> dict[str, int]:
    values = {
        "now_ms": ENROLLMENT_NOW,
        "phone_session_expires_at_ms": ENROLLMENT_VALUE["expiresAt"],
        "approver_session_expires_at_ms": ENROLLMENT_VALUE["expiresAt"],
        "full_expires_at_ms": ENROLLMENT_VALUE["expiresAt"],
        "x25519_binding_expires_at_ms": X25519_DEADLINE,
    }
    values.update(changes)
    return values


def assert_denied(callable_value) -> None:
    with pytest.raises(
        contract.SocialMessagingMobilePreEnrollmentV2Unavailable,
        match="^social messaging mobile pre-enrollment unavailable$",
    ):
        callable_value()


def test_reviewed_public_fixture_and_existing_v1_fixture_bytes_are_frozen():
    assert len(FIXTURE_BYTES) == 32_998
    assert hashlib.sha256(FIXTURE_BYTES).hexdigest() == (
        "4f79dd0f24fd8ded4c2e4e3e644811dd42ca620d8c0e09aea177237dd5d199dc"
    )
    expected_hashes = {
        "social_mobile_device_authorization_v1.json": (
            "26f335b718a771d08aacc7ebbe63895d395e2e2376d12484fb19ab30c0db7356"
        ),
        "social_messaging_device_proof_profile_v1.json": (
            "f616cee3db22d906d309953ae74b5626109a643884edd27b00fba68325508477"
        ),
        "social_device_admission_v1.json": ("09722ca9ab230a7bbc73b2228dfed5e80cdd2c2bb44a32e8571bdcf246ca4324"),
    }
    for name, expected in expected_hashes.items():
        assert hashlib.sha256((ROOT / "tests/fixtures" / name).read_bytes()).hexdigest() == expected

    fixture_text = FIXTURE_BYTES.decode("ascii")
    for forbidden in ("privateKey", "private_key", "seed"):
        assert forbidden not in fixture_text


def test_pre_enrollment_outer_event_and_acceptance_reconstruct_byte_for_byte():
    assert contract.canonical_pre_enrollment_v2_bytes(**pre_kwargs()).decode("ascii") == (VECTOR["preEnrollmentWire"])
    assert contract.pre_enrollment_v2_digest(VECTOR["preEnrollmentWire"]) == VECTOR["preEnrollmentDigest"]
    context = canonical(OUTER_VALUE["context"])
    assert (
        contract.canonical_authorization_envelope_v2_bytes(
            content=OUTER_VALUE["content"],
            context_wire=context,
            pre_enrollment_wire=VECTOR["preEnrollmentWire"],
        ).decode("ascii")
        == VECTOR["authorizationWire"]
    )
    envelope = contract.parse_authorization_envelope_v2(VECTOR["authorizationWire"])
    assert envelope.semantic.operation == "register"
    assert envelope.semantic.binding_id == PRE_VALUE["x25519BindingId"]
    assert envelope.pre_enrollment.issued_at == envelope.semantic.issued_at * 1000
    assert contract.authorization_v2_digest(envelope.wire) == VECTOR["authorizationDigest"]
    assert contract.canonical_approval_event_id_input_v2(envelope.wire).decode("ascii") == (
        VECTOR["approvalEventIdInput"]
    )
    assert contract.approval_event_id_v2(envelope.wire) == VECTOR["approvalEventId"]
    assert (
        contract.canonical_approval_event_v2_bytes(envelope.wire, signature=VECTOR["approvalEventSignature"]).decode(
            "ascii"
        )
        == VECTOR["approvalEventWire"]
    )
    approval = contract.parse_approval_event_v2(VECTOR["approvalEventWire"])
    assert approval.event_id == VECTOR["approvalEventId"]
    assert (
        PublicKeyXOnly(bytes.fromhex(EVENT_VALUE["pubkey"])).verify(
            bytes.fromhex(EVENT_VALUE["sig"]), bytes.fromhex(EVENT_VALUE["id"])
        )
        is True
    )
    assert contract.canonical_acceptance_id_preimage_v2_bytes(approval.wire).decode("ascii") == (
        VECTOR["acceptanceIdPreimage"]
    )
    assert contract.acceptance_id_v2(approval.wire) == VECTOR["acceptanceId"]
    assert contract.canonical_acceptance_v2_bytes(approval.wire, now_ms=ACCEPTED_AT).decode("ascii") == (
        VECTOR["acceptanceWire"]
    )
    acceptance = contract.parse_acceptance_v2(VECTOR["acceptanceWire"], approval_event_wire=approval.wire)
    assert acceptance.acceptance_id == VECTOR["acceptanceId"]
    assert set(ACCEPTANCE_VALUE) == contract._ACCEPTANCE_FIELDS


def test_pairing_possession_derivations_and_all_acceptance_deadlines():
    assert contract.pairing_secret_commitment_v2(PAIRING_SECRET) == OUTER_VALUE["context"]["secretCommitment"]
    assert contract.phone_exchange_commitment_v2(EXCHANGE_VERIFIER) == OUTER_VALUE["context"]["exchangeCommitment"]
    assert contract.pairing_possession_proof_v2(PAIRING_SECRET, VECTOR["authorizationDigest"]) == (
        VECTOR["pairingPossessionProof"]
    )
    verified = contract.verify_pairing_possession_v2(
        VECTOR["authorizationWire"],
        secret=PAIRING_SECRET,
        possession_proof=VECTOR["pairingPossessionProof"],
        now_ms=ACCEPTED_AT,
    )
    assert verified.pre_enrollment.pairing_id == PRE_VALUE["pairingId"]
    assert_denied(
        lambda: contract.verify_pairing_possession_v2(
            VECTOR["authorizationWire"],
            secret="76" * 32,
            possession_proof=VECTOR["pairingPossessionProof"],
            now_ms=ACCEPTED_AT,
        )
    )
    assert_denied(
        lambda: contract.verify_pairing_possession_v2(
            VECTOR["authorizationWire"],
            secret=PAIRING_SECRET,
            possession_proof="00" * 32,
            now_ms=ACCEPTED_AT,
        )
    )
    assert_denied(lambda: contract.validate_acceptance_time_v2(VECTOR["authorizationWire"], now_ms=ACCEPTED_AT - 1))
    pairing_expires = contract.epoch_milliseconds_from_utc_second(OUTER_VALUE["context"]["expiresAt"])
    assert_denied(lambda: contract.validate_acceptance_time_v2(VECTOR["authorizationWire"], now_ms=pairing_expires))


def test_offer_may_precede_the_whole_second_phone_proposal():
    content_value = json.loads(OUTER_VALUE["content"])
    authorization = content_value["authorization"]
    authorization["bindingValidFrom"] = "2026-09-08T22:30:00Z"
    authorization["issuedAt"] = "2026-09-08T22:30:00Z"
    content = canonical(content_value)
    semantic = inspect_claim(content, PRE_VALUE["subject"])
    pre_value = {
        **PRE_VALUE,
        "bindingAuthorizationDigest": hashlib.sha256(content.encode("ascii")).hexdigest(),
        "issuedAt": 1_788_906_600_000,
        "x25519BindingId": semantic.binding_id,
    }
    pre_wire = contract.canonical_pre_enrollment_v2_bytes(**pre_kwargs(pre_value)).decode("ascii")
    outer = contract.canonical_authorization_envelope_v2_bytes(
        content=content,
        context_wire=canonical(OUTER_VALUE["context"]),
        pre_enrollment_wire=pre_wire,
    ).decode("ascii")
    parsed = contract.parse_authorization_envelope_v2(outer)
    assert parsed.context.created_at < parsed.semantic.issued_at
    assert parsed.semantic.expires_at <= parsed.context.expires_at


def test_existing_enrollment_v2_and_association_bytes_remain_unchanged():
    assert canonical_enrollment_v2_bytes(**enrollment_kwargs()).decode("ascii") == VECTOR["enrollmentWire"]
    enrollment = parse_enrollment_v2(VECTOR["enrollmentWire"])
    assert enrollment_v2_digest(VECTOR["enrollmentWire"]) == VECTOR["enrollmentDigest"]
    assert canonical_enrollment_proof_signing_preimage_v2(VECTOR["enrollmentWire"]).decode("ascii") == (
        VECTOR["enrollmentPhoneProofSigningPreimage"]
    )
    proof = parse_enrollment_proof_v2(VECTOR["enrollmentPhoneProofWire"])
    signed_pre_enrollment_key = contract.parse_approval_event_v2(
        VECTOR["approvalEventWire"]
    ).envelope.pre_enrollment.ed25519_public_key
    assert (
        VECTOR["preProposalPhonePublicKey"]
        == signed_pre_enrollment_key
        == enrollment.ed25519_public_key
        == proof.public_key
    )
    assert (
        canonical_enrollment_proof_v2_bytes(
            enrollment_challenge_id=proof.enrollment_challenge_id,
            enrollment_digest=proof.enrollment_digest,
            public_key=proof.public_key,
            signature=proof.signature,
        ).decode("ascii")
        == VECTOR["enrollmentPhoneProofWire"]
    )
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(enrollment.ed25519_public_key)).verify(
        bytes.fromhex(proof.signature),
        VECTOR["enrollmentPhoneProofSigningPreimage"].encode("ascii"),
    )
    with pytest.raises(InvalidSignature):
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(enrollment.ed25519_public_key)).verify(
            bytes.fromhex("00" + proof.signature[2:]),
            VECTOR["enrollmentPhoneProofSigningPreimage"].encode("ascii"),
        )
    assert canonical_association_creation_v1_bytes(VECTOR["enrollmentWire"], 1, None).decode("ascii") == (
        VECTOR["associationCreationPreimage"]
    )
    assert association_id_v1(VECTOR["enrollmentWire"], 1, None) == VECTOR["associationId"]


def test_preaccepted_input_digest_deadlines_and_link_are_exact_and_derived():
    reconstructed_context = context_wire()
    assert reconstructed_context == VECTOR["verificationContextWire"]
    input_wire = verification_input_wire(context_wire=reconstructed_context)
    assert input_wire == VECTOR["preacceptedEnrollmentVerificationInputWire"]
    parsed = contract.parse_preaccepted_enrollment_verification_input_v2(input_wire)
    expected_digest = (
        "hodlxxi-social-preaccepted-enrollment-verification-input-v2-sha256:"
        + hashlib.sha256(
            b"HODLXXI_SOCIAL_PREACCEPTED_ENROLLMENT_VERIFICATION_INPUT_V2\0"
            + VECTOR["preacceptedEnrollmentVerificationInputWire"].encode("ascii")
        ).hexdigest()
    )
    assert expected_digest == VECTOR["preacceptedEnrollmentVerificationInputDigest"]
    assert contract.preaccepted_enrollment_verification_input_v2_digest(input_wire) == (
        VECTOR["preacceptedEnrollmentVerificationInputDigest"]
    )
    assert parsed.acceptance_id == VECTOR["acceptanceId"]
    assert parsed.association_id == VECTOR["associationId"]
    assert parsed.context.association_version == 1
    assert parsed.context.authority_epoch == 1
    assert parsed.context.predecessor_association_id is None
    assert contract.association_creation_preimage_v1_bytes(input_wire).decode("ascii") == (
        VECTOR["associationCreationPreimage"]
    )
    assert contract.validate_preaccepted_enrollment_time_v2(input_wire, **time_kwargs()) == parsed
    link = contract.canonical_association_link_v2_bytes(input_wire, **time_kwargs()).decode("ascii")
    assert link == VECTOR["associationLinkWire"]
    parsed_link = contract.parse_association_link_v2(link, verification_input_wire=input_wire)
    assert parsed_link.acceptance_id == VECTOR["acceptanceId"]
    assert parsed_link.association_id == VECTOR["associationId"]


def test_independently_shortened_pre_enrollment_expiry_is_exclusive():
    shortened_expiry = ACCEPTED_AT + 30_000
    assert shortened_expiry < PRE_VALUE["expiresAt"]
    pre_wire = contract.canonical_pre_enrollment_v2_bytes(
        **pre_kwargs({**PRE_VALUE, "expiresAt": shortened_expiry})
    ).decode("ascii")
    envelope_wire = contract.canonical_authorization_envelope_v2_bytes(
        content=OUTER_VALUE["content"],
        context_wire=canonical(OUTER_VALUE["context"]),
        pre_enrollment_wire=pre_wire,
    ).decode("ascii")
    assert (
        contract.validate_acceptance_time_v2(envelope_wire, now_ms=shortened_expiry - 1).pre_enrollment.expires_at
        == shortened_expiry
    )
    assert_denied(lambda: contract.validate_acceptance_time_v2(envelope_wire, now_ms=shortened_expiry))


def test_parsed_verification_records_and_forged_cached_fields_are_never_accepted():
    parsed = contract.parse_preaccepted_enrollment_verification_input_v2(
        VECTOR["preacceptedEnrollmentVerificationInputWire"]
    )
    assert_denied(lambda: contract.validate_preaccepted_enrollment_time_v2(parsed, **time_kwargs()))
    assert_denied(lambda: contract.canonical_association_link_v2_bytes(parsed, **time_kwargs()))
    forged_records = (
        replace(parsed, acceptance_id="00" * 32),
        replace(parsed, association_id="00" * 32),
        replace(
            parsed,
            enrollment=replace(parsed.enrollment, enrollment_challenge_id="ed" * 32),
        ),
        replace(
            parsed,
            enrollment_wire=changed(parsed.enrollment_wire, expiresAt=parsed.enrollment.expires_at - 1),
        ),
        replace(parsed, approval=replace(parsed.approval, event_id="00" * 32)),
        replace(
            parsed,
            context=replace(parsed.context, association_id="00" * 32),
        ),
        replace(
            parsed,
            enrollment=replace(parsed.enrollment, ed25519_public_key="85" * 32),
        ),
        replace(
            parsed,
            phone_proof=replace(parsed.phone_proof, public_key="85" * 32),
        ),
    )
    for forged in forged_records:
        assert_denied(lambda forged=forged: contract.validate_preaccepted_enrollment_time_v2(forged, **time_kwargs()))
        emitted: list[bytes] = []
        assert_denied(
            lambda forged=forged: emitted.append(contract.canonical_association_link_v2_bytes(forged, **time_kwargs()))
        )
        assert emitted == []


def test_preaccepted_input_rejects_mutated_top_level_acceptance_id():
    input_value = json.loads(VECTOR["preacceptedEnrollmentVerificationInputWire"])
    assert_denied(
        lambda: contract.parse_preaccepted_enrollment_verification_input_v2(
            canonical({**input_value, "acceptanceId": "00" * 32})
        )
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("enrollmentChallengeId", "ed" * 32),
        (
            "enrollmentDigest",
            "hodlxxi-social-messaging-device-enrollment-v2-sha256:" + "00" * 32,
        ),
        ("publicKey", "85" * 32),
    ],
)
def test_preaccepted_input_rejects_each_independent_phone_proof_attachment_mutation(field, value):
    input_value = json.loads(VECTOR["preacceptedEnrollmentVerificationInputWire"])
    proof_wire = changed(VECTOR["enrollmentPhoneProofWire"], **{field: value})
    assert_denied(
        lambda: contract.parse_preaccepted_enrollment_verification_input_v2(
            canonical({**input_value, "phoneProof": proof_wire})
        )
    )


@pytest.mark.parametrize(
    "call",
    [
        lambda: contract.canonical_pre_enrollment_v2_bytes(**pre_kwargs({**PRE_VALUE, "deviceId": object()})),
        lambda: contract.canonical_authorization_envelope_v2_bytes(
            content=object(),
            context_wire=canonical(OUTER_VALUE["context"]),
            pre_enrollment_wire=VECTOR["preEnrollmentWire"],
        ),
        lambda: contract.canonical_preaccepted_enrollment_verification_input_v2_bytes(
            approval_event_wire=object(),
            context_wire=VECTOR["verificationContextWire"],
            enrollment_wire=VECTOR["enrollmentWire"],
            phone_proof_wire=VECTOR["enrollmentPhoneProofWire"],
        ),
        lambda: contract.canonical_association_link_v2_bytes(object(), **time_kwargs()),
    ],
)
def test_public_constructors_convert_nonserializable_values_to_one_failure(call):
    with pytest.raises(contract.SocialMessagingMobilePreEnrollmentV2Unavailable) as denied:
        call()
    assert str(denied.value) == "social messaging mobile pre-enrollment unavailable"
    assert denied.value.__suppress_context__ is True


def test_pre_enrollment_constructor_converts_circular_values_to_one_failure():
    circular: list[object] = []
    circular.append(circular)
    with pytest.raises(contract.SocialMessagingMobilePreEnrollmentV2Unavailable) as denied:
        contract.canonical_pre_enrollment_v2_bytes(**pre_kwargs({**PRE_VALUE, "deviceId": circular}))
    assert str(denied.value) == "social messaging mobile pre-enrollment unavailable"
    assert denied.value.__suppress_context__ is True


@pytest.mark.parametrize(
    "field,value",
    [
        ("transitionKind", "rotate"),
        ("transitionKind", "reenroll"),
        ("preEffectAssociationState", "active"),
        ("preEffectAssociationState", "revoked"),
        ("preEffectAssociationId", "11" * 32),
        ("preEffectAssociationVersion", 1),
        ("preEffectAuthorityEpoch", 1),
        ("proposedAssociationVersion", 2),
        ("proposedAuthorityEpoch", 2),
        ("proposedPredecessorAssociationId", "11" * 32),
    ],
)
def test_every_non_initial_transition_shape_is_rejected(field, value):
    assert_denied(lambda: contract.parse_pre_enrollment_v2(changed(VECTOR["preEnrollmentWire"], **{field: value})))


@pytest.mark.parametrize("operation", ["rotate", "revoke", "adopt"])
def test_every_non_register_x25519_action_is_rejected(operation):
    legacy = json.loads((ROOT / "tests/fixtures/social_mobile_device_authorization_v1.json").read_bytes())
    entry = next(item for item in legacy["entries"] if item["operation"] == operation)
    content = entry["content"]
    semantic = inspect_claim(content, legacy["subject"])
    record = parse_v1_json(semantic.binding_record)
    binding_deadline = contract.epoch_milliseconds_from_utc_second(record["expiresAt"])
    pre_value = {
        **PRE_VALUE,
        "bindingAuthorizationDigest": hashlib.sha256(content.encode("ascii")).hexdigest(),
        "deviceId": record["deviceId"],
        "expiresAt": min(semantic.issued_at * 1000 + 600_000, binding_deadline),
        "issuedAt": semantic.issued_at * 1000,
        "requestId": semantic.request_id,
        "subject": semantic.subject,
        "x25519BindingId": semantic.binding_id,
        "x25519BindingVersion": record["bindingVersion"],
        "x25519PublicKeyCommitment": x25519_public_key_commitment_v1(record["publicKey"]),
    }

    def construct_and_parse():
        pre_wire = contract.canonical_pre_enrollment_v2_bytes(**pre_kwargs(pre_value)).decode("ascii")
        source = canonical(
            {
                **OUTER_VALUE,
                "content": content,
                "preEnrollment": pre_wire,
            }
        )
        return contract.parse_authorization_envelope_v2(source)

    assert_denied(construct_and_parse)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: {key: item for key, item in value.items() if key != "pairingId"},
        lambda value: {**value, "unknown": None},
        lambda value: {**value, "version": True},
        lambda value: {**value, "version": 3},
        lambda value: {**value, "issuedAt": 9_007_199_254_740_992},
        lambda value: {**value, "subject": str(value["subject"]).upper()},
        lambda value: {**value, "subject": "0" * 63},
        lambda value: {**value, "domain": "HODLXXI_SOCIAL_MESSAGING_DEVICE_PRE_ENROLLMENT_V1"},
        lambda value: {**value, "schema": "hodlxxi.social_messaging_device_pre_enrollment.v1"},
        lambda value: {**value, "profile": "other"},
        lambda value: {**value, "expiresAt": value["issuedAt"]},
        lambda value: {**value, "expiresAt": int(value["issuedAt"]) + 600_001},
    ],
)
def test_pre_enrollment_rejects_closed_shape_canonical_hex_and_time_mutations(mutation):
    assert_denied(lambda: contract.parse_pre_enrollment_v2(canonical(mutation(dict(PRE_VALUE)))))


@pytest.mark.parametrize(
    "source",
    [
        " " + VECTOR["preEnrollmentWire"],
        VECTOR["preEnrollmentWire"] + " ",
        VECTOR["preEnrollmentWire"].replace('"initial"', '"\\u0069nitial"'),
        VECTOR["preEnrollmentWire"][:-1] + ',"version":2}',
        VECTOR["preEnrollmentWire"] + "é",
    ],
)
def test_pre_enrollment_rejects_noncanonical_duplicate_escape_whitespace_and_non_ascii(source):
    assert_denied(lambda: contract.parse_pre_enrollment_v2(source))


@pytest.mark.parametrize(
    "field,value",
    [
        ("bindingAuthorizationDigest", "00" * 32),
        ("deviceId", "21" * 32),
        ("requestId", "31" * 32),
        ("subject", "11" * 32),
        ("pairingId", "98" * 32),
        ("issuedAt", PRE_VALUE["issuedAt"] + 1_000),
        ("x25519BindingId", "66" * 32),
        ("x25519BindingVersion", 2),
        ("x25519PublicKeyCommitment", "hodlxxi-social-messaging-x25519-public-key-v1-sha256:" + "00" * 32),
    ],
)
def test_outer_contract_rejects_binding_request_subject_pairing_and_time_substitution(field, value):
    altered_pre = changed(VECTOR["preEnrollmentWire"], **{field: value})
    source = canonical({**OUTER_VALUE, "preEnrollment": altered_pre})
    assert_denied(lambda: contract.parse_authorization_envelope_v2(source))


def test_outer_contract_rejects_wrong_method_schema_domain_and_nested_time_order():
    for field, value in (
        ("method", "qr_desktop_v1"),
        ("schema", "hodlxxi.social_messaging_device_authorization_method.v1"),
        ("domain", "HODLXXI_SOCIAL_MESSAGING_DEVICE_AUTHORIZATION_METHOD_V1"),
        ("version", 1),
    ):
        assert_denied(
            lambda field=field, value=value: contract.parse_authorization_envelope_v2(
                canonical({**OUTER_VALUE, field: value})
            )
        )
    context = {**OUTER_VALUE["context"], "createdAt": "2026-09-08T22:30:00Z"}
    assert_denied(lambda: contract.parse_authorization_envelope_v2(canonical({**OUTER_VALUE, "context": context})))
    too_late = changed(VECTOR["preEnrollmentWire"], expiresAt=X25519_DEADLINE + 1)
    assert_denied(
        lambda: contract.parse_authorization_envelope_v2(canonical({**OUTER_VALUE, "preEnrollment": too_late}))
    )


@pytest.mark.parametrize("field", ["content", "created_at", "id", "kind", "pubkey", "sig", "tags"])
def test_approval_event_rejects_every_mutated_field(field):
    value = dict(EVENT_VALUE)
    replacements = {
        "content": VECTOR["authorizationWire"] + " ",
        "created_at": EVENT_VALUE["created_at"] + 1,
        "id": "00" * 32,
        "kind": 27235,
        "pubkey": "11" * 32,
        "sig": "00" * 64,
        "tags": list(reversed(EVENT_VALUE["tags"])),
    }
    value[field] = replacements[field]
    assert_denied(lambda: contract.parse_approval_event_v2(canonical(value)))


@pytest.mark.parametrize(
    "context_change",
    [
        {"subject": "11" * 32},
        {"device_id": "21" * 32},
        {"binding_id": "66" * 32},
        {"binding_version": 2},
        {"x25519_public_key_commitment": "hodlxxi-social-messaging-x25519-public-key-v1-sha256:" + "00" * 32},
        {"ed25519_public_key": "86" * 32},
        {"challenge_id": "ed" * 32},
        {"audience": "https://other.example"},
        {"association_id": "9a" * 32},
        {"association_version": 2, "predecessor_association_id": "11" * 32},
        {"authority_epoch": 2},
    ],
)
def test_preaccepted_input_rejects_context_key_binding_subject_challenge_and_transition_substitution(
    context_change,
):
    if context_change == {"authority_epoch": 2}:
        mutated_context = changed(context_wire(), authorityEpoch=2)
    else:
        mutated_context = context_wire(**context_change)
    assert_denied(lambda: verification_input_wire(context_wire=mutated_context))


@pytest.mark.parametrize(
    "field,value",
    [
        ("subject", "11" * 32),
        ("deviceId", "21" * 32),
        ("ed25519PublicKey", "86" * 32),
        ("enrollmentChallengeId", "ed" * 32),
        ("x25519BindingId", "66" * 32),
        ("x25519BindingVersion", 2),
        ("x25519PublicKeyCommitment", "hodlxxi-social-messaging-x25519-public-key-v1-sha256:" + "00" * 32),
        ("issuedAt", PRE_VALUE["issuedAt"] - 1),
        ("expiresAt", PRE_VALUE["expiresAt"] + 1),
    ],
)
def test_preaccepted_input_rejects_enrollment_key_binding_subject_challenge_and_time_substitution(field, value):
    enrollment = changed(VECTOR["enrollmentWire"], **{field: value})
    assert_denied(lambda: verification_input_wire(enrollment_wire=enrollment))


def test_phone_signature_bytes_are_preserved_but_not_treated_as_ubid_cryptographic_authority():
    proof_value = {**PROOF_VALUE, "signature": "00" * 64}
    proof_wire = canonical(proof_value)
    input_wire = verification_input_wire(phone_proof_wire=proof_wire)
    parsed = contract.parse_preaccepted_enrollment_verification_input_v2(input_wire)
    assert parsed.phone_proof.signature == "00" * 64
    assert contract.preaccepted_enrollment_verification_input_v2_digest(input_wire) != (
        contract.preaccepted_enrollment_verification_input_v2_digest(verification_input_wire())
    )


def test_every_new_outer_wire_rejects_missing_unknown_duplicate_and_whitespace_forms():
    input_wire = verification_input_wire()
    link_wire = VECTOR["associationLinkWire"]
    cases = (
        (
            VECTOR["authorizationWire"],
            lambda source: contract.parse_authorization_envelope_v2(source),
        ),
        (
            VECTOR["approvalEventWire"],
            lambda source: contract.parse_approval_event_v2(source),
        ),
        (
            VECTOR["acceptanceWire"],
            lambda source: contract.parse_acceptance_v2(source, approval_event_wire=VECTOR["approvalEventWire"]),
        ),
        (
            input_wire,
            lambda source: contract.parse_preaccepted_enrollment_verification_input_v2(source),
        ),
        (
            link_wire,
            lambda source: contract.parse_association_link_v2(source, verification_input_wire=input_wire),
        ),
    )
    for source, parser in cases:
        value = json.loads(source)
        first = next(iter(value))
        missing = canonical({key: item for key, item in value.items() if key != first})
        unknown = canonical({**value, "unknown": None})
        duplicate = source[:-1] + f',"{first}":{canonical(value[first])}' + "}"
        for malformed in (missing, unknown, duplicate, " " + source, source + " "):
            assert_denied(lambda malformed=malformed, parser=parser: parser(malformed))


@pytest.mark.parametrize(
    "deadline_field",
    [
        "phone_session_expires_at_ms",
        "approver_session_expires_at_ms",
        "full_expires_at_ms",
    ],
)
def test_enrollment_is_capped_by_each_current_session_and_full_deadline(deadline_field):
    input_wire = verification_input_wire()
    assert_denied(
        lambda: contract.validate_preaccepted_enrollment_time_v2(
            input_wire,
            **time_kwargs(**{deadline_field: ENROLLMENT_VALUE["expiresAt"] - 1}),
        )
    )


def test_enrollment_and_link_reject_expiry_and_x25519_deadline_substitution():
    input_wire = verification_input_wire()
    assert_denied(
        lambda: contract.validate_preaccepted_enrollment_time_v2(
            input_wire, **time_kwargs(now_ms=ENROLLMENT_VALUE["expiresAt"])
        )
    )
    assert_denied(
        lambda: contract.validate_preaccepted_enrollment_time_v2(
            input_wire,
            **time_kwargs(x25519_binding_expires_at_ms=X25519_DEADLINE - 1),
        )
    )
    link_value = json.loads(VECTOR["associationLinkWire"])
    for field, value in (
        ("acceptanceId", "00" * 32),
        ("preEnrollmentDigest", contract.PRE_ENROLLMENT_DIGEST_PREFIX + "00" * 32),
        ("enrollmentDigest", "hodlxxi-social-messaging-device-enrollment-v2-sha256:" + "00" * 32),
        ("enrollmentChallengeId", "ed" * 32),
        ("associationId", "00" * 32),
        ("associationVersion", 2),
        ("authorityEpoch", 2),
    ):
        assert_denied(
            lambda field=field, value=value: contract.parse_association_link_v2(
                canonical({**link_value, field: value}), verification_input_wire=input_wire
            )
        )


def test_module_is_dormant_and_unimported_by_runtime_entrypoints():
    module_name = "social_messaging_mobile_pre_enrollment_v2"
    for relative in ("app/services/__init__.py", "app/app.py", "app/factory.py"):
        assert module_name not in (ROOT / relative).read_text()
