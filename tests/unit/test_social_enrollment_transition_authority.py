from __future__ import annotations

import ast
import hashlib
import json
from dataclasses import fields
from pathlib import Path

import pytest

from app.services import social_enrollment_transition_authority as contract
from app.services import social_messaging_device_admission_contract as admission
from app.services import social_messaging_device_ed25519_association_lifecycle as lifecycle
from app.services.social_device_verification_statement import AuthenticatedSocialDeviceVerificationStatementV1

ROOT = Path(__file__).parents[2]
FIXTURES = ROOT / "tests/fixtures"
SOURCE = ROOT / "app/services/social_enrollment_transition_authority.py"
VECTORS = json.loads((FIXTURES / "social_enrollment_transition_authority_effect_identity_v1.json").read_bytes())
LIFECYCLE = json.loads((FIXTURES / "social_messaging_device_ed25519_association_lifecycle_v1.json").read_bytes())
ERROR = "^social enrollment transition authority unavailable$"

EXPECTED_SOURCE_HASHES = {
    "social_admission_session_binding_v1.json": ("da98cfc67294a39fd45ed0a3488d6c21bf8f3ca755111a61b1fb92d5fe46ed09"),
    "social_device_admission_v1.json": ("09722ca9ab230a7bbc73b2228dfed5e80cdd2c2bb44a32e8571bdcf246ca4324"),
    "social_messaging_device_ed25519_association_lifecycle_v1.json": (
        "4851690baa82ffef85d6badd7469e43ae5468d7d3eeec93bf67999be6f2def23"
    ),
    "social_messaging_device_proof_profile_v1.json": (
        "f616cee3db22d906d309953ae74b5626109a643884edd27b00fba68325508477"
    ),
    "social_messaging_phase3_routing_v1.json": ("90f7c3726a9dfcfa655630626d53d65b410e5e330456d5114d04982a53da2f1c"),
    "social_mobile_authorization_ingress_v1.json": ("d8f40ccc552c18c1beadb5ddb9d6a12b4b42c48dbe1eaf82c96f97233eca2e7d"),
    "social_mobile_device_authorization_v1.json": ("26f335b718a771d08aacc7ebbe63895d395e2e2376d12484fb19ab30c0db7356"),
    "social_session_issuance_v1.json": ("474bdfa4d3c300da0e78e5cde9a2b8dd263ee1e68227bb3a5000687d2ce230f3"),
}

EXPECTED_EFFECTS = {
    "initial": (
        "355267872e7533429602db60647a54262e35b214f429944c0a5e7cdd006fb431",
        "ce25fef36043e33c61d19b88102a2b4165761da8d2187ddea6a49b2612d34fe1",
    ),
    "rotation": (
        "342b37a1ff4d11167fd9293c0cbf68d1e9870cb69285f5d283e0734971b74e5d",
        "67b55483dc7196eb77be3e03308ae510d3aebdddab96c46fa76433dd7eb31348",
    ),
    "reenrollment": (
        "c9005ac33214431296cf884c61d25c1559857a3efbbbd7da68defde0eefa5a44",
        "8be56b1be1b57d4bb4201bb570b3a6d59f53bf01d69bfcb21ff4c69c6838840d",
    ),
}


def _lifecycle(names: list[str]) -> lifecycle.AssociationLifecycleV1:
    return lifecycle.AssociationLifecycleV1(
        tuple(lifecycle.parse_association_event_v1(LIFECYCLE["eventWires"][name]) for name in names)
    )


def _statement(facts: dict[str, object]) -> AuthenticatedSocialDeviceVerificationStatementV1:
    value = object.__new__(AuthenticatedSocialDeviceVerificationStatementV1)
    for name, item in facts.items():
        object.__setattr__(value, name, item)
    return value


def _authorize(name: str) -> contract.EnrollmentTransitionAuthorityV1:
    vector = VECTORS["vectors"][name]
    value = admission.parse_verification_input_v1(vector["inputWire"])
    return contract.authorize_enrollment_transition_v1(
        value,
        _statement(vector["statementFacts"]),
        _lifecycle(vector["priorEvents"]),
        observed_at=vector["observedAt"],
        locked_deadline_ms=vector["lockedDeadlineMs"],
        full_proof_id=value.context.full_proof_id,
        approver_full_proof_id=value.context.approver_full_proof_id,
    )


def _denied(callable_) -> None:
    with pytest.raises(contract.SocialEnrollmentTransitionAuthorityUnavailable, match=ERROR):
        try:
            callable_()
        except contract.SocialEnrollmentTransitionAuthorityUnavailable as error:
            assert error.__cause__ is None
            assert error.__context__ is None
            raise


def test_fixture_and_existing_frozen_fixture_bytes_are_exact():
    assert VECTORS["schema"] == ("hodlxxi.social_enrollment_transition_authority_effect_identity_vectors.v1")
    assert VECTORS["version"] == 1
    assert VECTORS["sourceFixtureSha256"] == EXPECTED_SOURCE_HASHES
    for name, expected in EXPECTED_SOURCE_HASHES.items():
        assert hashlib.sha256((FIXTURES / name).read_bytes()).hexdigest() == expected


@pytest.mark.parametrize(
    ("name", "kind", "pre_state", "pre_version", "pre_epoch", "version", "epoch"),
    (
        ("initial", "initial", "absent", None, 0, 1, 1),
        ("rotation", "rotate", "active", 2, 4, 3, 5),
        ("reenrollment", "reenroll", "revoked", 3, 6, 4, 7),
    ),
)
def test_exact_initial_rotation_and_reenrollment_pre_effect_authority(
    name, kind, pre_state, pre_version, pre_epoch, version, epoch
):
    vector = VECTORS["vectors"][name]
    authority = _authorize(name)
    assert authority.wire == vector["authorityWire"]
    assert contract.validate_enrollment_transition_authority_v1_bytes(vector["authorityWire"]) == vector[
        "authorityWire"
    ].encode("ascii")
    assert authority.transition_kind == kind
    assert authority.pre_effect_association_state == pre_state
    assert authority.pre_effect_association_version == pre_version
    assert authority.pre_effect_authority_epoch == pre_epoch
    assert authority.proposed_association_version == version
    assert authority.proposed_authority_epoch == epoch
    assert authority.proposed_predecessor_association_id == authority.pre_effect_association_id
    assert authority.operation == "enrollment-activate"
    assert authority.challenge_kind == "enrollment-v2"


@pytest.mark.parametrize("name", ("initial", "rotation", "reenrollment"))
def test_effect_identity_and_transition_digest_fixed_vectors(name):
    vector = VECTORS["vectors"][name]
    authority = _authorize(name)
    expected_id, expected_digest = EXPECTED_EFFECTS[name]
    assert vector["effectId"] == expected_id
    assert vector["effectDigest"] == expected_digest
    assert (
        contract.canonical_enrollment_effect_id_preimage_v1_bytes(authority).decode("ascii")
        == vector["effectIdPreimage"]
    )
    assert (
        contract.canonical_enrollment_effect_transition_v1_bytes(authority).decode("ascii")
        == vector["effectTransitionPreimage"]
    )
    assert contract.enrollment_effect_id_v1(authority) == expected_id
    assert contract.enrollment_effect_digest_v1(authority) == expected_digest
    prepared = contract.prepared_enrollment_effect_v1(authority)
    assert prepared == admission.PreparedAdmissionEffectV1(
        operation="enrollment-activate",
        effect_id=expected_id,
        effect_digest=expected_digest,
    )
    assert prepared.effect_id != prepared.effect_digest


@pytest.mark.parametrize("kind", ("effectId", "effectDigest"))
def test_one_field_mutation_vectors_change_the_appropriate_identity(kind):
    if kind == "effectId":
        base = VECTORS["vectors"]["initial"]["effectId"]
        domain = contract.EFFECT_ID_DOMAIN
        result_name = "effectId"
    else:
        base = VECTORS["vectors"]["initial"]["effectDigest"]
        domain = contract.EFFECT_DIGEST_DOMAIN
        result_name = "effectDigest"
    for mutation in VECTORS["mutationVectors"][kind].values():
        calculated = hashlib.sha256(domain.encode("ascii") + b"\0" + mutation["preimage"].encode("ascii")).hexdigest()
        assert calculated == mutation[result_name]
        assert calculated != base


def test_id_and_digest_domain_separation_is_explicit():
    authority = _authorize("initial")
    id_preimage = contract.canonical_enrollment_effect_id_preimage_v1_bytes(authority)
    transition_preimage = contract.canonical_enrollment_effect_transition_v1_bytes(authority)
    assert contract.EFFECT_ID_DOMAIN != contract.EFFECT_DIGEST_DOMAIN
    assert hashlib.sha256(
        contract.EFFECT_DIGEST_DOMAIN.encode("ascii") + b"\0" + id_preimage
    ).hexdigest() != contract.enrollment_effect_id_v1(authority)
    assert hashlib.sha256(
        contract.EFFECT_ID_DOMAIN.encode("ascii") + b"\0" + transition_preimage
    ).hexdigest() != contract.enrollment_effect_digest_v1(authority)


@pytest.mark.parametrize("wire", VECTORS["rejectionAuthorityWires"].values())
def test_malformed_noncanonical_and_out_of_matrix_authority_is_denied(wire):
    _denied(lambda: contract.validate_enrollment_transition_authority_v1_bytes(wire))


def test_typed_authority_cannot_be_publicly_constructed_or_subclassed():
    _denied(lambda: contract.EnrollmentTransitionAuthorityV1())
    _denied(lambda: type("ForgedAuthority", (contract.EnrollmentTransitionAuthorityV1,), {}))


def test_exact_authenticated_statement_type_is_required():
    vector = VECTORS["vectors"]["initial"]
    value = admission.parse_verification_input_v1(vector["inputWire"])
    fabricated = type("FabricatedStatement", (), dict(vector["statementFacts"]))()
    _denied(
        lambda: contract.authorize_enrollment_transition_v1(
            value,
            fabricated,
            lifecycle.AssociationLifecycleV1(),
            observed_at=vector["observedAt"],
            locked_deadline_ms=vector["lockedDeadlineMs"],
            full_proof_id=value.context.full_proof_id,
            approver_full_proof_id=value.context.approver_full_proof_id,
        )
    )


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("challenge_id", "01" * 32),
        ("attempt_id", "02" * 32),
        ("context_digest", admission.CONTEXT_DIGEST_PREFIX + "03" * 32),
        ("input_digest", admission.INPUT_DIGEST_PREFIX + "04" * 32),
        ("issuer", "https://wrong.example"),
        ("token_id", "not-hex"),
        ("key_fingerprint", "not-a-fingerprint"),
    ),
)
def test_statement_input_and_context_binding_is_exact(field, replacement):
    vector = VECTORS["vectors"]["initial"]
    value = admission.parse_verification_input_v1(vector["inputWire"])
    facts = dict(vector["statementFacts"])
    facts[field] = replacement
    _denied(
        lambda: contract.authorize_enrollment_transition_v1(
            value,
            _statement(facts),
            lifecycle.AssociationLifecycleV1(),
            observed_at=vector["observedAt"],
            locked_deadline_ms=vector["lockedDeadlineMs"],
            full_proof_id=value.context.full_proof_id,
            approver_full_proof_id=value.context.approver_full_proof_id,
        )
    )


def test_stale_lifecycle_wrong_proof_and_expired_locked_authority_are_denied():
    vector = VECTORS["vectors"]["initial"]
    value = admission.parse_verification_input_v1(vector["inputWire"])
    statement = _statement(vector["statementFacts"])
    kwargs = {
        "observed_at": vector["observedAt"],
        "locked_deadline_ms": vector["lockedDeadlineMs"],
        "full_proof_id": value.context.full_proof_id,
        "approver_full_proof_id": value.context.approver_full_proof_id,
    }
    _denied(lambda: contract.authorize_enrollment_transition_v1(value, statement, _lifecycle(["initial"]), **kwargs))
    _denied(
        lambda: contract.authorize_enrollment_transition_v1(
            value,
            statement,
            lifecycle.AssociationLifecycleV1(),
            **{**kwargs, "full_proof_id": "hodlxxi-full-entitlement-v1-sha256:" + "00" * 32},
        )
    )
    _denied(
        lambda: contract.authorize_enrollment_transition_v1(
            value,
            statement,
            lifecycle.AssociationLifecycleV1(),
            **{**kwargs, "observed_at": vector["lockedDeadlineMs"]},
        )
    )


def test_current_authority_semantics_are_not_redefined():
    assert [item.name for item in fields(admission.CurrentAdmissionAuthorityV1)] == [
        "context_digest",
        "authority_epoch",
        "locked_deadline_ms",
        "full_proof_id",
        "approver_full_proof_id",
    ]
    assert [item.name for item in fields(contract.EnrollmentTransitionAuthorityV1)] == [
        "wire",
        "transition_kind",
        "challenge_id",
        "subject",
        "device_id",
        "context_digest",
        "input_digest",
        "enrollment_digest",
        "statement_token_id",
        "observed_at",
        "locked_deadline_ms",
        "full_proof_id",
        "approver_full_proof_id",
        "pre_effect_association_state",
        "pre_effect_association_id",
        "pre_effect_association_version",
        "pre_effect_authority_epoch",
        "proposed_ed25519_public_key",
        "proposed_association_id",
        "proposed_association_version",
        "proposed_predecessor_association_id",
        "proposed_authority_epoch",
        "operation",
        "challenge_kind",
    ]


def test_contract_is_pure_dormant_and_claims_no_execution_or_admission():
    source = SOURCE.read_text(encoding="ascii")
    ast.parse(source)
    assert contract.RUNTIME_ENABLED is False
    assert contract.EFFECT_EXECUTION == "not_implemented"
    assert contract.CHALLENGE_CONSUMPTION == "not_implemented"
    assert contract.RECEIPT_ISSUANCE == "not_implemented"
    assert contract.FINAL_ADMISSION == "denied"
    for forbidden in (
        "sqlalchemy",
        "DATABASE_URL",
        "create_engine(",
        "sessionmaker(",
        ".commit(",
        ".rollback(",
        "redis",
        "datetime.now(",
        "time.time(",
        "uuid4(",
        "AdmissionReceiptV1(",
    ):
        assert forbidden not in source
