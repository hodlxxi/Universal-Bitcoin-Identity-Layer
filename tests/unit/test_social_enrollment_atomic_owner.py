"""Narrow composition tests for the dormant enrollment atomic owner."""

from __future__ import annotations

import ast
import json
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.services import social_device_challenge_store as challenge_storage
from app.services import social_device_ed25519_association_storage as association_storage
from app.services import social_enrollment_atomic_owner as owner
from app.services import social_enrollment_receipt_storage as receipt_storage
from app.services import social_enrollment_transition_authority as transition
from app.services import social_messaging_device_admission_contract as admission
from app.services.social_device_verification_statement import AuthenticatedSocialDeviceVerificationStatementV1
from tests.unit.test_social_enrollment_transition_authority import VECTORS, _authorize

ROOT = Path(__file__).parents[2]
SOURCE = ROOT / "app/services/social_enrollment_atomic_owner.py"
ERROR = "^social enrollment atomic owner unavailable$"


def _evidence(name: str):
    vector = VECTORS["vectors"][name]
    authority = _authorize(name)
    value = admission.parse_verification_input_v1(vector["inputWire"])
    statement = object.__new__(AuthenticatedSocialDeviceVerificationStatementV1)
    for field, item in vector["statementFacts"].items():
        object.__setattr__(statement, field, item)
    association = association_storage.CurrentEd25519AssociationV1(
        subject=authority.subject,
        device_id=authority.device_id,
        ed25519_public_key=authority.proposed_ed25519_public_key,
        association_id=authority.proposed_association_id,
        association_version=authority.proposed_association_version,
        predecessor_association_id=authority.proposed_predecessor_association_id,
        authority_epoch=authority.proposed_authority_epoch,
        state="active",
    )
    effect = transition.prepared_enrollment_effect_v1(authority)
    decided_at = authority.observed_at + 1
    receipt_id = receipt_storage.enrollment_receipt_id_v1(authority)
    receipt = receipt_storage.StoredEnrollmentAdmissionReceiptV1(
        receipt=admission.AdmissionReceiptV1(
            receipt_id=receipt_id,
            challenge_id=authority.challenge_id,
            operation=effect.operation,
            decided_at=decided_at,
        ),
        receipt_wire=admission.canonical_admission_receipt_v1_bytes(
            receipt_id=receipt_id,
            challenge_id=authority.challenge_id,
            operation=effect.operation,
            decided_at=decided_at,
        ).decode("ascii"),
        effect_id=effect.effect_id,
        effect_digest=effect.effect_digest,
        proposed_association_id=authority.proposed_association_id,
    )
    challenge = challenge_storage.parse_stored_device_challenge_v1(
        {
            "challenge_id": authority.challenge_id,
            "context_wire": value.context.wire,
            "challenge_wire": value.challenge_wire,
            "routing_request_wire": None,
            "state": "consumed",
        }
    )
    return authority, value, statement, association, receipt, challenge, decided_at


def _install_fakes(monkeypatch, evidence):
    authority, _value, _statement, association, receipt, challenge, _decided_at = evidence
    calls = []

    class Authority:
        def __init__(self, session, **selectors):
            calls.append(("authority-init", session, selectors))

        def lock_transition_authority(self, value, statement, *, observed_at):
            calls.append(("authority", value, statement, observed_at))
            return authority

    class Associations:
        def __init__(self, session):
            calls.append(("association-init", session))

        def establish_initial(self, **kwargs):
            calls.append(("initial", kwargs))
            return association

        def rotate(self, **kwargs):
            calls.append(("rotate", kwargs))
            return association

        def reenroll(self, **kwargs):
            calls.append(("reenroll", kwargs))
            return association

    class Receipts:
        def __init__(self, session):
            calls.append(("receipt-init", session))

        def store_committed(self, supplied_authority, **kwargs):
            calls.append(("receipt", supplied_authority, kwargs))
            return receipt

    class Challenges:
        def __init__(self, session):
            calls.append(("challenge-init", session))

        def record_enrollment_consumed(self, supplied_authority, **kwargs):
            calls.append(("consume", supplied_authority, kwargs))
            return challenge

    monkeypatch.setattr(owner, "SqlAlchemyTransactionBoundEnrollmentTransitionAuthority", Authority)
    monkeypatch.setattr(owner, "SqlAlchemyEd25519AssociationStore", Associations)
    monkeypatch.setattr(owner, "SqlAlchemyEnrollmentAdmissionReceiptStore", Receipts)
    monkeypatch.setattr(owner, "SqlAlchemyDeviceChallengeStore", Challenges)
    return calls


def _owner(session=object()):
    return owner.SqlAlchemyTransactionBoundEnrollmentAtomicOwner(
        session,
        device_issuance_id="device-issuance",
        device_client_id="device-client",
        oauth_issuer="https://identity.example",
        approver_oauth_session_id="approver-session",
        approver_client_id="approver-client",
    )


@pytest.mark.parametrize(
    ("name", "method"),
    (("initial", "initial"), ("rotation", "rotate"), ("reenrollment", "reenroll")),
)
def test_exact_transition_effect_receipt_and_consumption_order_is_one_shot(monkeypatch, name, method):
    evidence = _evidence(name)
    authority, value, statement, association, receipt, challenge, decided_at = evidence
    session = object()
    calls = _install_fakes(monkeypatch, evidence)
    atomic_owner = _owner(session)

    result = atomic_owner.execute_enrollment_activate(
        value,
        statement,
        observed_at=authority.observed_at,
        decided_at=decided_at,
    )

    operations = [call[0] for call in calls if not call[0].endswith("-init")]
    assert operations == ["authority", method, "receipt", "consume"]
    effect_call = next(call for call in calls if call[0] == method)[1]
    assert effect_call["input_wire"] == value.wire
    assert effect_call["statement"] is statement
    assert effect_call["now"] == decided_at
    if method != "initial":
        assert effect_call["expected_predecessor"] == authority.pre_effect_association_id
        assert effect_call["expected_epoch"] == authority.pre_effect_authority_epoch
    assert type(result) is owner.ProvisionalEnrollmentActivationV1
    assert result.authority is authority
    assert result.effect == transition.prepared_enrollment_effect_v1(authority)
    assert result.association is association
    assert result.receipt is receipt
    assert result.consumed_challenge is challenge
    assert result.publication_status == "provisional_until_caller_commit"
    assert result.bearer_authority == result.reexecution_authority == "none"
    assert result.final_admission == "denied"
    with pytest.raises(FrozenInstanceError):
        result.publication_status = "committed"
    with pytest.raises(owner.SocialEnrollmentAtomicOwnerUnavailable, match=ERROR):
        atomic_owner.execute_enrollment_activate(
            value,
            statement,
            observed_at=authority.observed_at,
            decided_at=decided_at,
        )


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("subject", "01" * 32),
        ("device_id", "02" * 32),
        ("ed25519_public_key", "03" * 32),
        ("association_id", "04" * 32),
        ("association_version", 99),
        ("predecessor_association_id", "05" * 32),
        ("authority_epoch", 99),
        ("state", "revoked"),
    ),
)
def test_every_returned_association_field_must_match_frozen_proposal(field, replacement):
    authority, _value, _statement, association, *_rest = _evidence("rotation")
    with pytest.raises(owner.SocialEnrollmentAtomicOwnerUnavailable, match=ERROR):
        owner._exact_association(replace(association, **{field: replacement}), authority)


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("effect_id", "06" * 32),
        ("effect_digest", "07" * 32),
        ("proposed_association_id", "08" * 32),
    ),
)
def test_returned_receipt_effect_mismatch_is_denied(field, replacement):
    authority, _value, _statement, _association, receipt, _challenge, decided_at = _evidence("initial")
    effect = transition.prepared_enrollment_effect_v1(authority)
    with pytest.raises(owner.SocialEnrollmentAtomicOwnerUnavailable, match=ERROR):
        owner._exact_receipt(
            replace(receipt, **{field: replacement}),
            authority,
            effect,
            decided_at=decided_at,
        )


def test_failed_owner_is_poisoned_and_never_reaches_consumption(monkeypatch):
    evidence = list(_evidence("initial"))
    evidence[3] = replace(evidence[3], association_id="09" * 32)
    evidence = tuple(evidence)
    authority, value, statement, *_rest, decided_at = evidence
    calls = _install_fakes(monkeypatch, evidence)
    atomic_owner = _owner()
    for _attempt in range(2):
        with pytest.raises(owner.SocialEnrollmentAtomicOwnerUnavailable, match=ERROR):
            atomic_owner.execute_enrollment_activate(
                value,
                statement,
                observed_at=authority.observed_at,
                decided_at=decided_at,
            )
    assert [call[0] for call in calls].count("initial") == 1
    assert not any(call[0] in {"receipt", "consume"} for call in calls)


def test_wrong_time_and_deadline_are_denied_before_effect(monkeypatch):
    evidence = _evidence("initial")
    authority, value, statement, *_rest = evidence
    calls = _install_fakes(monkeypatch, evidence)
    atomic_owner = _owner()
    with pytest.raises(owner.SocialEnrollmentAtomicOwnerUnavailable, match=ERROR):
        atomic_owner.execute_enrollment_activate(
            value,
            statement,
            observed_at=authority.observed_at,
            decided_at=authority.locked_deadline_ms,
        )
    assert not any(call[0] in {"initial", "receipt", "consume"} for call in calls)


def test_sqlite_and_missing_active_transaction_are_denied():
    engine = create_engine("sqlite://")
    try:
        with Session(engine) as session:
            session.begin()
            with pytest.raises(owner.SocialEnrollmentAtomicOwnerUnavailable, match=ERROR):
                _owner(session)
    finally:
        engine.dispose()


def test_source_has_no_transaction_lifecycle_runtime_route_or_connection_owner():
    source = SOURCE.read_text(encoding="utf-8")
    tree = ast.parse(source)
    called_attributes = {
        node.func.attr for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    imported_modules = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    assert not called_attributes & {"begin", "commit", "rollback", "close"}
    assert not imported_modules & {"flask", "os", "redis"}
    assert "create_engine" not in source
    assert "sessionmaker" not in source
    assert owner.RUNTIME_ENABLED is False
    assert owner.ATOMIC_COMMIT == "caller_owned"
    assert owner.FINAL_ADMISSION == "denied"


def test_provisional_result_fields_are_closed_and_history_is_non_authoritative():
    names = [field.name for field in owner.ProvisionalEnrollmentActivationV1.__dataclass_fields__.values()]
    assert names == [
        "authority",
        "effect",
        "association",
        "receipt",
        "consumed_challenge",
        "publication_status",
        "bearer_authority",
        "reexecution_authority",
        "final_admission",
    ]
    assert json.loads(_authorize("initial").wire)["operation"] == "enrollment-activate"
