from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone
import uuid

import pytest

import app.services.canonical_root_entitlement_materializer as materializer_module
from app.services.action_authorization import IdentityClass
from app.services.canonical_controlling_registration import ControllingRegistrationSelectionSource
from app.services.canonical_root_entitlement_materializer import (
    EVIDENCE_VALIDITY_SECONDS,
    CanonicalRootEntitlementMaterializationUnavailable,
    CanonicalRootEntitlementMaterializer,
)
from app.services.canonical_root_entitlement_policy import (
    EVIDENCE_SOURCE,
    POLICY_VERSION,
    evaluate_canonical_root_entitlement,
)
from app.services.covenant_relation import CovenantRelationReason
from app.services.current_entitlement_evidence import CONTRACT_VERSION, CurrentEntitlementEvidenceRecord
from app.services.edge_local_covenant_observation import EdgeLocalCovenantRelationResult

GRAPH = "hodlxxi.crt_membership_graph.v1"
SUBJECT = "3d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923"
NOW = datetime(2026, 8, 13, 12, 0, 0, 654321, tzinfo=timezone.utc)
IDENTIFIER = uuid.UUID("12345678-1234-5678-9234-567812345678")


def relation(**changes):
    values = dict(
        graph_or_protocol_id=GRAPH,
        subject_xonly_pubkey=SUBJECT,
        counterparty_xonly_pubkey="2f664095c520438506ddea8f584be08aeef210bc7ec37817a56478a489b72a8c",
        controlling_selection_source=ControllingRegistrationSelectionSource.CANONICAL_ROOT_REGISTRATION_BINDING,
        selector_record_id="00000000-0000-4000-8000-000000000001",
        selector_record_sha256="3" * 64,
        trusted_registration_id="00000000-0000-4000-8000-000000000002",
        trusted_registration_sha256="4" * 64,
        funding_set_id="00000000-0000-4000-8000-000000000003",
        funding_set_sha256="5" * 64,
        recognized_outpoint_count=5,
        qualifying_observation_count=5,
        observed_at=NOW - timedelta(seconds=1),
        observed_block_height=900000,
        incoming_sats=300000,
        outgoing_sats=300000,
        current_full_relation_satisfied=True,
        relation_reason=CovenantRelationReason.FULL_RELATION_SATISFIED,
        relation_source_evidence_sha256="6" * 64,
    )
    values.update(changes)
    return EdgeLocalCovenantRelationResult(**values)


class Repository:
    def __init__(self, error=None):
        self.error = error
        self.appended = []

    def append(self, record):
        if self.error:
            raise self.error
        self.appended.append(record)

    def get_latest(self, _subject):
        pytest.fail("materializer inspected prior evidence")


def service(repository=None, *, now=NOW, uuid_factory=lambda: IDENTIFIER):
    repository = repository or Repository()
    return CanonicalRootEntitlementMaterializer(
        repository, clock=lambda: now, uuid_factory=uuid_factory
    ), repository


def test_real_shaped_result_calls_policy_and_maps_exact_full_evidence(monkeypatch):
    original = materializer_module.evaluate_canonical_root_entitlement
    calls = []

    def evaluate(graph, subject, result):
        calls.append((graph, subject, result))
        return original(graph, subject, result)

    monkeypatch.setattr(materializer_module, "evaluate_canonical_root_entitlement", evaluate)
    source = relation()
    instance, repository = service()
    record = instance.materialize(GRAPH, SUBJECT, source)
    decision = evaluate_canonical_root_entitlement(GRAPH, SUBJECT, source)

    assert calls == [(GRAPH, SUBJECT, source)]
    assert repository.appended == [record]
    assert type(record) is CurrentEntitlementEvidenceRecord
    assert record.evidence_id == str(IDENTIFIER)
    assert record.contract_version == CONTRACT_VERSION
    assert record.subject_pubkey == decision.subject_xonly_pubkey
    assert record.identity_class is IdentityClass.FULL
    assert record.current_full_relation_satisfied is True
    assert record.evidence_source == decision.evidence_source == EVIDENCE_SOURCE
    assert record.evidence_version == decision.policy_version == POLICY_VERSION
    assert record.source_evidence_sha256 == decision.source_evidence_sha256
    assert record.observed_at == source.observed_at
    assert record.observed_at.microsecond == 654321
    assert record.valid_until == record.observed_at + timedelta(seconds=EVIDENCE_VALIDITY_SECONDS)
    assert record.created_at == NOW and record.revoked_at is None
    with pytest.raises(FrozenInstanceError):
        record.identity_class = IdentityClass.LIMITED


def test_legitimate_limited_is_appended_without_reading_older_full():
    limited = relation(
        qualifying_observation_count=1,
        incoming_sats=300000,
        outgoing_sats=0,
        current_full_relation_satisfied=False,
        relation_reason=CovenantRelationReason.MISSING_OUTGOING,
    )
    instance, repository = service()
    record = instance.materialize(GRAPH, SUBJECT, limited)
    assert repository.appended == [record]
    assert record.identity_class is IdentityClass.LIMITED
    assert record.current_full_relation_satisfied is False


@pytest.mark.parametrize(
    ("offset", "accepted"),
    [(-60, True), (-60.000001, False), (5, True), (5.000001, False)],
)
def test_freshness_boundaries(offset, accepted):
    source = relation(observed_at=NOW + timedelta(seconds=offset))
    instance, repository = service()
    if accepted:
        record = instance.materialize(GRAPH, SUBJECT, source)
        assert repository.appended == [record]
        assert record.created_at == max(NOW, source.observed_at)
    else:
        with pytest.raises(CanonicalRootEntitlementMaterializationUnavailable):
            instance.materialize(GRAPH, SUBJECT, source)
        assert repository.appended == []


def test_non_utc_clock_is_normalized_and_called_once():
    calls = []

    def clock():
        calls.append(1)
        return NOW.astimezone(timezone(timedelta(hours=-4)))

    repository = Repository()
    record = CanonicalRootEntitlementMaterializer(
        repository, clock=clock, uuid_factory=lambda: IDENTIFIER
    ).materialize(GRAPH, SUBJECT, relation())
    assert calls == [1]
    assert record.created_at == NOW
    assert record.created_at.tzinfo is timezone.utc


@pytest.mark.parametrize(
    "source",
    [
        object(),
        relation(controlling_selection_source=ControllingRegistrationSelectionSource.CANONICAL_ADMISSION_EDGE),
        relation(current_full_relation_satisfied=False),
        relation(selector_record_sha256="private malformed provenance"),
    ],
)
def test_malformed_policy_inputs_are_sanitized_before_append(source):
    instance, repository = service()
    with pytest.raises(CanonicalRootEntitlementMaterializationUnavailable) as caught:
        instance.materialize(GRAPH, SUBJECT, source)
    assert str(caught.value) == "canonical root entitlement materialization unavailable"
    assert repository.appended == []


def test_malformed_dependencies_clock_uuid_and_repository_failure_are_sanitized():
    with pytest.raises(CanonicalRootEntitlementMaterializationUnavailable):
        CanonicalRootEntitlementMaterializer(object())
    for clock, uuid_factory, repository in (
        (lambda: NOW.replace(tzinfo=None), lambda: IDENTIFIER, Repository()),
        (lambda: "bad clock", lambda: IDENTIFIER, Repository()),
        (lambda: NOW, lambda: str(IDENTIFIER), Repository()),
        (lambda: NOW, lambda: IDENTIFIER, Repository(RuntimeError("private database detail"))),
    ):
        instance = CanonicalRootEntitlementMaterializer(
            repository, clock=clock, uuid_factory=uuid_factory
        )
        with pytest.raises(CanonicalRootEntitlementMaterializationUnavailable) as caught:
            instance.materialize(GRAPH, SUBJECT, relation())
        assert "private" not in str(caught.value)
        assert repository.appended == []


def test_malformed_policy_return_is_rejected_before_uuid_and_append(monkeypatch):
    decision = evaluate_canonical_root_entitlement(GRAPH, SUBJECT, relation())
    monkeypatch.setattr(
        materializer_module,
        "evaluate_canonical_root_entitlement",
        lambda *_args: replace(decision, identity_class=IdentityClass.OPERATOR),
    )
    uuid_calls = []
    instance, repository = service(uuid_factory=lambda: uuid_calls.append(1) or IDENTIFIER)
    with pytest.raises(CanonicalRootEntitlementMaterializationUnavailable):
        instance.materialize(GRAPH, SUBJECT, relation())
    assert uuid_calls == [] and repository.appended == []


@pytest.mark.parametrize(
    ("field", "value"),
    [
        (
            "controlling_selection_source",
            ControllingRegistrationSelectionSource.CANONICAL_ADMISSION_EDGE,
        ),
        ("selector_record_id", "00000000-0000-4000-8000-000000000099"),
        ("selector_record_sha256", "7" * 64),
        ("trusted_registration_id", "00000000-0000-4000-8000-000000000099"),
        ("trusted_registration_sha256", "8" * 64),
        ("funding_set_id", "00000000-0000-4000-8000-000000000099"),
        ("funding_set_sha256", "9" * 64),
        ("recognized_outpoint_count", 6),
        ("qualifying_observation_count", 4),
        ("observed_at", NOW - timedelta(seconds=2)),
        ("observed_block_height", 900001),
        ("incoming_sats", 299999),
        ("outgoing_sats", 300001),
        ("relation_reason", CovenantRelationReason.MISSING_OUTGOING),
        ("relation_source_evidence_sha256", "a" * 64),
        ("source_evidence_sha256", "b" * 64),
    ],
)
def test_policy_return_with_mismatched_or_admission_provenance_never_appends(
    monkeypatch, field, value
):
    decision = evaluate_canonical_root_entitlement(GRAPH, SUBJECT, relation())
    monkeypatch.setattr(
        materializer_module,
        "evaluate_canonical_root_entitlement",
        lambda *_args: replace(decision, **{field: value}),
    )
    uuid_calls = []
    instance, repository = service(uuid_factory=lambda: uuid_calls.append(1) or IDENTIFIER)
    with pytest.raises(CanonicalRootEntitlementMaterializationUnavailable):
        instance.materialize(GRAPH, SUBJECT, relation())
    assert uuid_calls == []
    assert repository.appended == []


def test_replaced_valid_policy_digest_is_rejected_before_uuid_and_append(monkeypatch):
    decision = evaluate_canonical_root_entitlement(GRAPH, SUBJECT, relation())
    replacement = "f" * 64
    assert replacement != decision.source_evidence_sha256
    monkeypatch.setattr(
        materializer_module,
        "evaluate_canonical_root_entitlement",
        lambda *_args: replace(decision, source_evidence_sha256=replacement),
    )
    uuid_calls = []
    instance, repository = service(uuid_factory=lambda: uuid_calls.append(1) or IDENTIFIER)
    with pytest.raises(CanonicalRootEntitlementMaterializationUnavailable):
        instance.materialize(GRAPH, SUBJECT, relation())
    assert uuid_calls == []
    assert repository.appended == []


@pytest.mark.parametrize("failure", [KeyboardInterrupt(), SystemExit()])
def test_base_exceptions_from_policy_and_repository_are_preserved(monkeypatch, failure):
    def fail(*_args):
        raise failure

    monkeypatch.setattr(materializer_module, "evaluate_canonical_root_entitlement", fail)
    instance, repository = service()
    with pytest.raises(type(failure)):
        instance.materialize(GRAPH, SUBJECT, relation())
    assert repository.appended == []

    monkeypatch.setattr(
        materializer_module,
        "evaluate_canonical_root_entitlement",
        evaluate_canonical_root_entitlement,
    )
    with pytest.raises(type(failure)):
        service(Repository(failure))[0].materialize(GRAPH, SUBJECT, relation())
