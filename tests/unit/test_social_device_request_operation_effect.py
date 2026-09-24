from __future__ import annotations

import ast
import hashlib
import json
from dataclasses import FrozenInstanceError, fields
from pathlib import Path

import pytest

from app.services import social_device_request_operation_effect as contract
from app.services import social_enrollment_transition_authority as enrollment
from app.services import social_messaging_device_admission_contract as admission
from app.services.social_device_verification_statement import AuthenticatedSocialDeviceVerificationStatementV1

ROOT = Path(__file__).parents[2]
FIXTURES = ROOT / "tests/fixtures"
SOURCE = ROOT / "app/services/social_device_request_operation_effect.py"
VECTORS = json.loads((FIXTURES / "social_device_request_operation_effect_v1.json").read_bytes())
ADMISSION = json.loads((FIXTURES / "social_device_admission_v1.json").read_bytes())
ROUTING = json.loads((FIXTURES / "social_messaging_phase3_routing_v1.json").read_bytes())
ERROR = "^social device request operation effect unavailable$"


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def _statement(name: str, **changes: object) -> AuthenticatedSocialDeviceVerificationStatementV1:
    facts = dict(VECTORS["vectors"][name]["statementFacts"])
    facts.update(changes)
    value = object.__new__(AuthenticatedSocialDeviceVerificationStatementV1)
    for field_name, item in facts.items():
        object.__setattr__(value, field_name, item)
    return value


def _authority(name: str, **changes: object) -> admission.CurrentAdmissionAuthorityV1:
    facts = dict(VECTORS["vectors"][name]["currentAuthority"])
    facts.update(changes)
    return admission.CurrentAdmissionAuthorityV1(
        context_digest=facts["contextDigest"],
        authority_epoch=facts["authorityEpoch"],
        locked_deadline_ms=facts["lockedDeadlineMs"],
        full_proof_id=facts["fullProofId"],
        approver_full_proof_id=facts["approverFullProofId"],
    )


def _input(name: str, wire: str | None = None) -> admission.VerificationInputV1:
    source_name = VECTORS["vectors"][name]["sourceVector"]
    return admission.parse_verification_input_v1(
        ADMISSION["vectors"][source_name]["inputWire"] if wire is None else wire
    )


def _prepare(
    name: str,
    *,
    input_value: object | None = None,
    authority: object | None = None,
    statement: object | None = None,
    observed_at: object | None = None,
) -> contract.PreparedDeviceRequestOperationEffectV1:
    vector = VECTORS["vectors"][name]
    return contract.prepare_device_request_operation_effect_v1(
        _input(name) if input_value is None else input_value,
        _authority(name) if authority is None else authority,
        _statement(name) if statement is None else statement,
        observed_at=vector["observedAt"] if observed_at is None else observed_at,
    )


def _denied(callable_) -> None:
    with pytest.raises(contract.SocialDeviceRequestOperationEffectUnavailable, match=ERROR):
        try:
            callable_()
        except contract.SocialDeviceRequestOperationEffectUnavailable as error:
            assert error.__cause__ is None
            assert error.__context__ is None
            raise


def _replace_request(
    name: str,
    *,
    actual_updates: dict[str, object] | None = None,
    actual_wire: str | None = None,
    routing_updates: dict[str, object] | None = None,
    routing_wire: str | None | object = ...,
) -> str:
    source_name = VECTORS["vectors"][name]["sourceVector"]
    outer = json.loads(ADMISSION["vectors"][source_name]["inputWire"])
    if actual_wire is None:
        request = json.loads(outer["actualRequest"])
        request.update(actual_updates or {})
        actual_wire = _canonical(request)
    outer["actualRequest"] = actual_wire
    challenge = json.loads(outer["challenge"])
    challenge["request"] = actual_wire
    outer["challenge"] = _canonical(challenge)
    if routing_wire is not ...:
        outer["routingRequest"] = routing_wire
    elif routing_updates is not None:
        routing = json.loads(outer["routingRequest"])
        routing.update(routing_updates)
        outer["routingRequest"] = _canonical(routing)
    return _canonical(outer)


def test_fixture_domains_schemas_and_protected_source_hashes_are_exact():
    assert VECTORS["schema"] == "hodlxxi.social_device_request_operation_effect_identity_vectors.v1"
    assert VECTORS["version"] == 1
    assert VECTORS["effectIdDomain"] == contract.EFFECT_ID_DOMAIN
    assert VECTORS["effectDigestDomain"] == contract.EFFECT_DIGEST_DOMAIN
    assert VECTORS["receiptIdDomain"] == contract.RECEIPT_ID_DOMAIN
    assert VECTORS["effectIdPreimageSchema"] == contract.EFFECT_ID_PREIMAGE_SCHEMA
    assert VECTORS["ciphertextSubmitEffectSchema"] == contract.CIPHERTEXT_SUBMIT_EFFECT_SCHEMA
    assert VECTORS["recipientSelfReadEffectSchema"] == contract.RECIPIENT_SELF_READ_EFFECT_SCHEMA
    assert VECTORS["receiptIdPreimageSchema"] == contract.RECEIPT_ID_PREIMAGE_SCHEMA
    assert VECTORS["preparedEffectSchema"] == contract.PREPARED_EFFECT_SCHEMA
    assert (
        hashlib.sha256((FIXTURES / "social_device_admission_v1.json").read_bytes()).hexdigest()
        == VECTORS["sourceFixtureSha256"]
    )
    assert (
        hashlib.sha256((FIXTURES / "social_messaging_phase3_routing_v1.json").read_bytes()).hexdigest()
        == VECTORS["sourceRoutingFixtureSha256"]
    )


@pytest.mark.parametrize("name", ("ciphertextSubmit", "recipientSelfRead"))
def test_exact_effect_and_receipt_identity_fixed_vectors(name):
    vector = VECTORS["vectors"][name]
    prepared = _prepare(name)
    assert (
        contract.canonical_request_effect_id_preimage_v1_bytes(prepared).decode("ascii") == vector["effectIdPreimage"]
    )
    assert (
        contract.canonical_request_effect_digest_preimage_v1_bytes(prepared).decode("ascii")
        == vector["effectDigestPreimage"]
    )
    assert (
        contract.canonical_request_receipt_id_preimage_v1_bytes(prepared).decode("ascii") == vector["receiptIdPreimage"]
    )
    assert contract.request_effect_id_v1(prepared) == prepared.effect_id == vector["effectId"]
    assert contract.request_effect_digest_v1(prepared) == prepared.effect_digest == vector["effectDigest"]
    assert contract.request_receipt_id_v1(prepared) == prepared.receipt_id == vector["receiptId"]
    projection = contract.canonical_prepared_request_operation_effect_v1_bytes(prepared).decode("ascii")
    assert projection == vector["preparedProjectionWire"]
    assert json.loads(projection) == vector["preparedProjection"]
    assert prepared.effect_id != prepared.effect_digest != prepared.receipt_id


def test_submit_projection_binds_exact_frozen_request_and_routing_identity():
    prepared = _prepare("ciphertextSubmit")
    promised = prepared.promised_effect
    assert type(promised) is contract.CiphertextSubmitPromisedEffectV1
    source = ADMISSION["vectors"]["ciphertextSubmit"]
    assert promised.actual_request_wire == source["actualRequestWire"]
    assert promised.routing_request_wire == source["routingRequestWire"] == ROUTING["routingRequest"]
    parsed = admission._parse_routing_request(promised.routing_request_wire)
    assert promised.message_id == parsed["messageId"]
    assert promised.envelope_digest == parsed["envelopeDigest"] == ROUTING["envelopeDigest"]
    assert promised.recipient_package_snapshot_id == parsed["recipientPackageSnapshotId"]
    assert promised.recipient_device_handles == tuple(parsed["recipientDeviceHandles"])
    assert json.loads(promised.actual_request_wire)["recipientHandle"] is None


def test_self_read_projection_binds_handle_without_resolution_or_results():
    prepared = _prepare("recipientSelfRead")
    promised = prepared.promised_effect
    assert type(promised) is contract.RecipientSelfReadPromisedEffectV1
    source = ADMISSION["vectors"]["recipientSelfRead"]
    assert promised.actual_request_wire == source["actualRequestWire"]
    assert promised.recipient_handle == json.loads(source["actualRequestWire"])["recipientHandle"]
    assert not hasattr(promised, "routing_request_wire")
    projection = json.loads(contract.canonical_prepared_request_operation_effect_v1_bytes(prepared))
    serialized = _canonical(projection)
    for invented in ("cursor", "inbox", "items", "messages", "selectedMessage", "routingDecision"):
        assert invented not in serialized


@pytest.mark.parametrize("name", ("ciphertextSubmit", "recipientSelfRead"))
def test_generic_prepared_effect_is_projection_only(name):
    prepared = _prepare(name)
    assert contract.prepared_admission_effect_v1(prepared) == admission.PreparedAdmissionEffectV1(
        operation=prepared.operation,
        effect_id=prepared.effect_id,
        effect_digest=prepared.effect_digest,
    )


@pytest.mark.parametrize(
    ("group", "domain", "preimage_key", "identity_key"),
    (
        ("effectId", contract.EFFECT_ID_DOMAIN, "effectIdPreimage", "effectId"),
        ("effectDigest", contract.EFFECT_DIGEST_DOMAIN, "effectDigestPreimage", "effectDigest"),
        ("receiptId", contract.RECEIPT_ID_DOMAIN, "receiptIdPreimage", "receiptId"),
    ),
)
def test_adversarial_mutation_vectors_change_the_appropriate_identity(group, domain, preimage_key, identity_key):
    for mutation in VECTORS["identityMutations"][group].values():
        vector = VECTORS["vectors"][mutation["vector"]]
        preimage = json.loads(vector[preimage_key])
        assert preimage[mutation["field"]] != mutation["replacement"]
        preimage[mutation["field"]] = mutation["replacement"]
        wire = _canonical(preimage).encode("ascii")
        calculated = hashlib.sha256(domain.encode("ascii") + b"\0" + wire).hexdigest()
        assert calculated == mutation["identity"]
        assert calculated != vector[identity_key]


def test_domains_are_independent_and_do_not_reuse_enrollment_domains_or_input_digest():
    assert len({contract.EFFECT_ID_DOMAIN, contract.EFFECT_DIGEST_DOMAIN, contract.RECEIPT_ID_DOMAIN}) == 3
    assert contract.EFFECT_ID_DOMAIN != enrollment.EFFECT_ID_DOMAIN
    assert contract.EFFECT_DIGEST_DOMAIN != enrollment.EFFECT_DIGEST_DOMAIN
    assert contract.RECEIPT_ID_DOMAIN != "HODLXXI_SOCIAL_ENROLLMENT_RECEIPT_ID_V1"
    prepared = _prepare("ciphertextSubmit")
    input_digest_hex = prepared.input_digest.removeprefix(admission.INPUT_DIGEST_PREFIX)
    assert prepared.effect_id not in {
        input_digest_hex,
        prepared.challenge_id,
        prepared.statement_token_id,
        prepared.effect_digest,
        prepared.receipt_id,
    }
    assert (
        hashlib.sha256(
            contract.EFFECT_DIGEST_DOMAIN.encode("ascii")
            + b"\0"
            + contract.canonical_request_effect_id_preimage_v1_bytes(prepared)
        ).hexdigest()
        != prepared.effect_id
    )


def test_receipt_identity_excludes_decision_and_observation_time():
    vector = VECTORS["vectors"]["ciphertextSubmit"]
    first = _prepare("ciphertextSubmit")
    second = _prepare("ciphertextSubmit", observed_at=vector["observedAt"] + 1)
    assert first == second
    receipt_preimage = contract.canonical_request_receipt_id_preimage_v1_bytes(first).decode("ascii")
    effect_id_preimage = contract.canonical_request_effect_id_preimage_v1_bytes(first).decode("ascii")
    assert "decidedAt" not in receipt_preimage
    assert "observedAt" not in receipt_preimage
    assert "observedAt" not in effect_id_preimage


def test_exact_current_authority_fields_are_bound_without_mutation_or_successor():
    base = _prepare("ciphertextSubmit")
    changed = _prepare(
        "ciphertextSubmit",
        authority=_authority(
            "ciphertextSubmit",
            lockedDeadlineMs=VECTORS["vectors"]["ciphertextSubmit"]["currentAuthority"]["lockedDeadlineMs"] - 1,
        ),
    )
    assert changed.authority_epoch == base.authority_epoch
    assert changed.locked_deadline_ms == base.locked_deadline_ms - 1
    assert changed.effect_id != base.effect_id
    assert changed.effect_digest != base.effect_digest
    assert changed.receipt_id != base.receipt_id
    assert not hasattr(changed, "proposed_authority_epoch")
    assert not hasattr(changed, "successor")


def test_cross_jti_changes_operation_identity_but_not_promised_effect_semantics():
    base = _prepare("ciphertextSubmit")
    changed = _prepare("ciphertextSubmit", statement=_statement("ciphertextSubmit", token_id="dd" * 32))
    assert changed.effect_id != base.effect_id
    assert changed.effect_digest == base.effect_digest
    assert changed.receipt_id != base.receipt_id


def test_actual_request_change_requires_a_new_authenticated_input_identity():
    changed_wire = _replace_request(
        "ciphertextSubmit",
        actual_updates={"bodyDigest": "hodlxxi-social-device-request-body-v1-sha256:" + "ef" * 32},
    )
    changed_input = admission.parse_verification_input_v1(changed_wire)
    _denied(lambda: _prepare("ciphertextSubmit", input_value=changed_input))
    changed_statement = _statement(
        "ciphertextSubmit",
        input_digest=admission.verification_input_digest_v1(changed_input.wire),
    )
    changed = _prepare("ciphertextSubmit", input_value=changed_input, statement=changed_statement)
    base = _prepare("ciphertextSubmit")
    assert changed.effect_id != base.effect_id
    assert changed.effect_digest != base.effect_digest
    assert changed.receipt_id != base.receipt_id


@pytest.mark.parametrize(
    "name",
    (
        "missingRoutingRequestOnSubmit",
        "unexpectedRoutingRequestOnSelfRead",
        "operationPathMismatch",
        "duplicateRecipientDeviceHandles",
        "reversedRecipientDeviceHandles",
        "noncanonicalRecipientDeviceHandle",
    ),
)
def test_operation_shape_rejection_vectors_fail_in_frozen_admission_parser(name):
    vector = VECTORS["rejectionVectors"][name]
    if name == "missingRoutingRequestOnSubmit":
        wire = _replace_request(vector["base"], routing_wire=None)
    elif name == "unexpectedRoutingRequestOnSelfRead":
        submit = ADMISSION["vectors"][vector["routingRequestFrom"]]
        wire = _replace_request(vector["base"], routing_wire=submit["routingRequestWire"])
    elif name == "operationPathMismatch":
        wire = _replace_request(vector["base"], actual_updates={"operation": vector["operation"]})
    else:
        wire = _replace_request(
            vector["base"],
            routing_updates={"recipientDeviceHandles": vector["recipientDeviceHandles"]},
        )
    with pytest.raises(admission.SocialMessagingDeviceAdmissionUnavailable):
        admission.parse_verification_input_v1(wire)


def test_cross_operation_substitution_is_bound_to_the_authenticated_attempt():
    vector = VECTORS["rejectionVectors"]["crossOperationSubstitution"]
    other = ADMISSION["vectors"][vector["actualRequestFrom"]]
    wire = _replace_request(
        vector["base"],
        actual_wire=other["actualRequestWire"],
        routing_wire=vector["routingRequest"],
    )
    substituted = admission.parse_verification_input_v1(wire)
    assert substituted.operation == contract.RECIPIENT_SELF_READ
    _denied(lambda: _prepare("ciphertextSubmit", input_value=substituted))


@pytest.mark.parametrize(
    ("field_name", "replacement"),
    (
        ("challenge_id", "01" * 32),
        ("attempt_id", "02" * 32),
        ("context_digest", admission.CONTEXT_DIGEST_PREFIX + "03" * 32),
        ("input_digest", admission.INPUT_DIGEST_PREFIX + "04" * 32),
        ("token_id", "not-hex"),
        ("issuer", "https://wrong.example"),
        ("key_fingerprint", "not-a-fingerprint"),
    ),
)
def test_authenticated_statement_binding_is_exact(field_name, replacement):
    _denied(
        lambda: _prepare(
            "ciphertextSubmit",
            statement=_statement("ciphertextSubmit", **{field_name: replacement}),
        )
    )


def test_shape_inspection_and_generic_placeholder_cannot_be_promoted_to_authority():
    vector = ADMISSION["vectors"]["ciphertextSubmit"]
    inspected = admission.inspect_verification_statement_shape_v1(
        vector["compactJws"],
        expected_kid=ADMISSION["configuration"]["kid"],
        expected_issuer=ADMISSION["configuration"]["issuer"],
        expected_audience=ADMISSION["configuration"]["audience"],
        expected_client_id=ADMISSION["configuration"]["clientId"],
        expected_service_principal=ADMISSION["configuration"]["servicePrincipal"],
        expected_context_wire=vector["contextWire"],
        expected_input_wire=vector["inputWire"],
        now=vector["now"],
        challenge_expires_at=vector["challengeExpiresAt"],
        session_expires_at=vector["sessionExpiresAt"],
    )
    placeholder = admission.AuthenticatedVerificationStatementV1(
        claims=inspected.claims,
        statement_digest="00" * 32,
        trust_registration_id="test",
    )
    _denied(lambda: _prepare("ciphertextSubmit", statement=inspected))
    _denied(lambda: _prepare("ciphertextSubmit", statement=placeholder))
    _denied(lambda: _prepare("ciphertextSubmit", statement=True))


@pytest.mark.parametrize(
    "authority",
    (
        admission.CurrentAdmissionAuthorityV1(
            admission.CONTEXT_DIGEST_PREFIX + "00" * 32,
            2,
            1788906659000,
            "hodlxxi-full-entitlement-v1-sha256:" + "ab" * 32,
            None,
        ),
        admission.CurrentAdmissionAuthorityV1(
            VECTORS["vectors"]["ciphertextSubmit"]["currentAuthority"]["contextDigest"],
            3,
            1788906659000,
            "hodlxxi-full-entitlement-v1-sha256:" + "ab" * 32,
            None,
        ),
        admission.CurrentAdmissionAuthorityV1(
            VECTORS["vectors"]["ciphertextSubmit"]["currentAuthority"]["contextDigest"],
            2,
            VECTORS["vectors"]["ciphertextSubmit"]["observedAt"],
            "hodlxxi-full-entitlement-v1-sha256:" + "ab" * 32,
            None,
        ),
        admission.CurrentAdmissionAuthorityV1(
            VECTORS["vectors"]["ciphertextSubmit"]["currentAuthority"]["contextDigest"],
            2,
            1788906659000,
            "hodlxxi-full-entitlement-v1-sha256:" + "cd" * 32,
            None,
        ),
        admission.CurrentAdmissionAuthorityV1(
            VECTORS["vectors"]["ciphertextSubmit"]["currentAuthority"]["contextDigest"],
            2,
            1788906659000,
            "hodlxxi-full-entitlement-v1-sha256:" + "ab" * 32,
            "hodlxxi-full-entitlement-v1-sha256:" + "cd" * 32,
        ),
    ),
)
def test_current_authority_mismatch_and_staleness_are_denied(authority):
    _denied(lambda: _prepare("ciphertextSubmit", authority=authority))


def test_wrong_input_types_enrollment_and_expired_times_are_denied():
    _denied(lambda: _prepare("ciphertextSubmit", input_value={}))
    _denied(lambda: _prepare("ciphertextSubmit", authority={}))
    _denied(lambda: _prepare("ciphertextSubmit", observed_at=True))
    _denied(
        lambda: _prepare(
            "ciphertextSubmit",
            observed_at=ADMISSION["vectors"]["ciphertextSubmit"]["challengeExpiresAt"],
        )
    )
    enrollment_input = admission.parse_verification_input_v1(ADMISSION["vectors"]["enrollmentV2"]["inputWire"])
    _denied(lambda: _prepare("ciphertextSubmit", input_value=enrollment_input))


def test_prepared_types_are_frozen_closed_and_operation_specific():
    submit = _prepare("ciphertextSubmit")
    self_read = _prepare("recipientSelfRead")
    with pytest.raises(FrozenInstanceError):
        submit.effect_id = "00" * 32
    _denied(lambda: contract.PreparedDeviceRequestOperationEffectV1())
    _denied(lambda: contract.CiphertextSubmitPromisedEffectV1())
    _denied(lambda: contract.RecipientSelfReadPromisedEffectV1())
    _denied(lambda: type("ForgedPrepared", (contract.PreparedDeviceRequestOperationEffectV1,), {}))
    assert type(submit.promised_effect) is contract.CiphertextSubmitPromisedEffectV1
    assert type(self_read.promised_effect) is contract.RecipientSelfReadPromisedEffectV1
    assert submit.effect_id != self_read.effect_id
    assert submit.effect_digest != self_read.effect_digest
    assert submit.receipt_id != self_read.receipt_id


def test_prepared_representation_freezes_current_authority_and_statement_identity_fields():
    assert [item.name for item in fields(contract.PreparedDeviceRequestOperationEffectV1)] == [
        "challenge_kind",
        "challenge_id",
        "operation",
        "subject",
        "device_id",
        "binding_id",
        "binding_version",
        "association_id",
        "association_version",
        "context_digest",
        "input_digest",
        "authority_epoch",
        "locked_deadline_ms",
        "full_proof_id",
        "approver_full_proof_id",
        "statement_token_id",
        "statement_attempt_id",
        "promised_effect",
        "effect_id",
        "effect_digest",
        "receipt_id",
    ]


def test_contract_is_pure_dormant_and_claims_no_commit_or_admission():
    source = SOURCE.read_text(encoding="ascii")
    tree = ast.parse(source)
    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert imported.isdisjoint({"flask", "os", "redis", "requests", "socket", "sqlalchemy", "time", "uuid"})
    assert contract.RUNTIME_ENABLED is False
    assert contract.EFFECT_EXECUTION == "not_implemented"
    assert contract.CHALLENGE_CONSUMPTION == "not_implemented"
    assert contract.RECEIPT_STORAGE == "not_implemented"
    assert contract.ROUTING_DECISION == "not_implemented"
    assert contract.RECIPIENT_RESOLUTION == "not_implemented"
    assert contract.FINAL_ADMISSION == "denied"
    for forbidden in (
        "AdmissionReceiptV1(",
        "create_engine(",
        "sessionmaker(",
        ".commit(",
        ".rollback(",
        "datetime.now(",
        "time.time(",
        "uuid4(",
    ):
        assert forbidden not in source
