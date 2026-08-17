from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timezone
import importlib.util
from pathlib import Path

import pytest

import app.services.edge_local_covenant_observation as service
from app.services.canonical_controlling_registration import (
    ControllingRegistrationSelection,
    ControllingRegistrationSelectionSource,
)
from app.services.canonical_covenant_funding_set import (
    CovenantFundingSetLifecycle,
    InvalidCanonicalCovenantFundingSet,
    RecognizedCovenantFundingOutpoint,
    create_canonical_covenant_funding_set,
    trusted_outpoints_from_canonical_funding_set,
)
from app.services.covenant_relation import (
    EVALUATION_SCHEMA,
    OBSERVATION_SCHEMA,
    CovenantDirection,
    CovenantRelationEvaluation,
    CovenantRelationObservation,
    CovenantRelationReason,
)
from app.services.edge_local_covenant_observation import (
    EdgeLocalCovenantObservationUnavailable,
    observe_edge_local_covenant_relation,
)
from app.services.trusted_covenant_registration import p2wsh_script_pubkey_sha256


def _module(name, path):
    spec = importlib.util.spec_from_file_location(name, Path(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fixtures = _module("funding_fixtures_for_edge_local", "tests/unit/test_canonical_covenant_funding_set.py")
NOW = datetime(2026, 8, 12, 1, 2, 3, 456789, tzinfo=timezone.utc)
GRAPH = "hodlxxi:test"


class FundingRepository:
    def __init__(self, value=None, error=None):
        self.value = value
        self.error = error
        self.calls = []

    def resolve_effective(self, registration_id):
        self.calls.append(registration_id)
        if self.error:
            raise self.error
        return self.value


class Observer:
    def __init__(self, *, spent=(), confirmations=1, error=None):
        self.spent = set(spent)
        self.confirmations = confirmations
        self.error = error
        self.calls = []

    def observe(self, outpoints):
        self.calls.append(outpoints)
        if self.error:
            raise self.error
        observations = tuple(
            CovenantRelationObservation(
                OBSERVATION_SCHEMA,
                item.subject_pubkey,
                item.counterparty_pubkey,
                item.direction,
                item.txid,
                item.vout,
                item.amount_sats,
                item.script_sha256,
                item.descriptor_sha256,
                0 if (item.txid, item.vout) in self.spent else self.confirmations,
                (item.txid, item.vout) not in self.spent,
            )
            for item in outpoints
        )
        return CovenantRelationEvaluation(
            EVALUATION_SCHEMA,
            "bitcoin",
            outpoints[0].subject_pubkey,
            outpoints[0].counterparty_pubkey,
            NOW,
            900000,
            observations,
        )


def _selection(registration):
    return ControllingRegistrationSelection(
        GRAPH,
        registration.subject_xonly_pubkey,
        ControllingRegistrationSelectionSource.CANONICAL_ADMISSION_EDGE,
        "00000000-0000-4000-8000-000000000020",
        "9" * 64,
        registration,
    )


def _run(monkeypatch, *, funding_set=None, observer=None, selector_error=None):
    registration = fixtures.registration()
    calls = []

    def select(graph, subject, **dependencies):
        calls.append((graph, subject, dependencies))
        if selector_error:
            raise selector_error
        return _selection(registration)

    monkeypatch.setattr(service, "resolve_controlling_registration", select)
    repository = FundingRepository(funding_set or fixtures.funding())
    result = observe_edge_local_covenant_relation(
        GRAPH,
        registration.subject_xonly_pubkey,
        evaluated_at=NOW,
        genesis_repository=object(),
        admission_edge_repository=object(),
        root_registration_binding_repository=object(),
        trusted_registration_repository=object(),
        funding_set_repository=repository,
        observer=observer or Observer(),
    )
    return result, calls, repository


def test_effective_funding_set_materializes_all_exact_trusted_outpoints():
    value = fixtures.funding()
    outpoints = trusted_outpoints_from_canonical_funding_set(value)
    assert len(outpoints) == 5
    assert [x.amount_sats for x in outpoints] == [133129, 44648, 122223, 122223, 177777]
    assert outpoints[0].subject_pubkey == value.subject_xonly_pubkey
    assert outpoints[0].counterparty_pubkey == value.counterparty_xonly_pubkey
    assert outpoints[0].descriptor_sha256 == "c" * 64
    assert outpoints[0].script_sha256 == p2wsh_script_pubkey_sha256(value.recognized_outpoints[0].witness_script_sha256)
    inactive = replace(value, lifecycle_state=CovenantFundingSetLifecycle.DISPUTED)
    with pytest.raises(InvalidCanonicalCovenantFundingSet):
        trusted_outpoints_from_canonical_funding_set(inactive)


def test_real_five_utxo_vector_uses_exact_authority_and_ignores_dust(monkeypatch):
    observer = Observer()
    result, selector_calls, repository = _run(monkeypatch, observer=observer)
    registration = fixtures.registration()
    assert selector_calls[0][:2] == (GRAPH, registration.subject_xonly_pubkey)
    assert repository.calls == [registration.registration_id]
    assert len(observer.calls) == 1 and len(observer.calls[0]) == 5
    assert {(x.txid, x.vout) for x in observer.calls[0]} == {
        (x.txid, x.vout) for x in fixtures.funding().recognized_outpoints
    }
    assert ("f" * 64, 9) not in {(x.txid, x.vout) for x in observer.calls[0]}
    assert result.recognized_outpoint_count == result.qualifying_observation_count == 5
    assert result.observed_at == NOW
    assert (result.incoming_sats, result.outgoing_sats) == (300000, 300000)
    assert result.current_full_relation_satisfied is True
    assert result.relation_reason is CovenantRelationReason.FULL_RELATION_SATISFIED
    with pytest.raises(FrozenInstanceError):
        result.incoming_sats = 0


def test_spent_recognized_output_is_not_replaced_and_returns_non_full(monkeypatch):
    observer = Observer(spent={("e" * 64, 4)})
    result, _, _ = _run(monkeypatch, observer=observer)
    assert len(observer.calls[0]) == 5
    assert result.qualifying_observation_count == 4
    assert (result.incoming_sats, result.outgoing_sats) == (300000, 122223)
    assert result.current_full_relation_satisfied is False
    assert result.relation_reason is CovenantRelationReason.OUTGOING_BELOW_INCOMING


def test_insufficient_confirmations_are_non_qualifying(monkeypatch):
    result, _, _ = _run(monkeypatch, observer=Observer(confirmations=0))
    assert result.qualifying_observation_count == 0
    assert (result.incoming_sats, result.outgoing_sats) == (0, 0)
    assert result.relation_reason is CovenantRelationReason.NO_QUALIFYING_OBSERVATIONS


@pytest.mark.parametrize(
    ("direction", "amount", "expected", "satisfied"),
    (
        (CovenantDirection.OUTGOING, 50000, (300000, 350000), True),
        (CovenantDirection.INCOMING, 50000, (350000, 300000), False),
    ),
)
def test_unequal_counts_and_unpaired_amounts_follow_total_relation_policy(
    monkeypatch,
    direction,
    amount,
    expected,
    satisfied,
):
    registration = fixtures.registration()
    base = fixtures.funding()
    script = (
        registration.mirrored_pair.incoming_leg_script_sha256
        if direction is CovenantDirection.INCOMING
        else registration.mirrored_pair.outgoing_leg_script_sha256
    )
    extra = RecognizedCovenantFundingOutpoint(
        direction,
        "f" * 64,
        8,
        amount,
        script,
    )
    funding_set = create_canonical_covenant_funding_set(
        funding_set_id="00000000-0000-4000-8000-000000000011",
        trusted_registration=registration,
        lifecycle_state=CovenantFundingSetLifecycle.EFFECTIVE,
        created_at=NOW,
        lifecycle_changed_at=NOW,
        effective_at=NOW,
        recognized_outpoints=base.recognized_outpoints + (extra,),
    )
    result, _, _ = _run(monkeypatch, funding_set=funding_set)
    assert (result.incoming_sats, result.outgoing_sats) == expected
    assert result.qualifying_observation_count == 6
    assert result.current_full_relation_satisfied is satisfied


@pytest.mark.parametrize("error", [RuntimeError("database secret"), ValueError("rpc secret")])
def test_dependency_failures_are_sanitized(monkeypatch, error):
    registration = fixtures.registration()
    monkeypatch.setattr(service, "resolve_controlling_registration", lambda *a, **k: _selection(registration))
    repository = FundingRepository(fixtures.funding(), error=error)
    with pytest.raises(EdgeLocalCovenantObservationUnavailable) as caught:
        observe_edge_local_covenant_relation(
            GRAPH,
            registration.subject_xonly_pubkey,
            evaluated_at=NOW,
            genesis_repository=object(),
            admission_edge_repository=object(),
            root_registration_binding_repository=object(),
            trusted_registration_repository=object(),
            funding_set_repository=repository,
            observer=Observer(),
        )
    assert str(caught.value) == "edge-local covenant observation unavailable"
    assert "secret" not in str(caught.value)


def test_malformed_observation_and_interrupt_fail_closed(monkeypatch):
    class Malformed:
        def observe(self, outpoints):
            return object()

    with pytest.raises(EdgeLocalCovenantObservationUnavailable):
        _run(monkeypatch, observer=Malformed())
    with pytest.raises(KeyboardInterrupt):
        _run(monkeypatch, selector_error=KeyboardInterrupt())
    with pytest.raises(SystemExit):
        _run(monkeypatch, selector_error=SystemExit())


def test_domain_valid_but_noncanonical_decision_is_rejected(monkeypatch):
    canonical = service.evaluate_covenant_relation

    def malformed(evaluation):
        decision = canonical(evaluation)
        return replace(
            decision,
            incoming_sats=decision.incoming_sats + 1,
            source_evidence_sha256="f" * 64,
        )

    monkeypatch.setattr(service, "evaluate_covenant_relation", malformed)
    with pytest.raises(EdgeLocalCovenantObservationUnavailable):
        _run(monkeypatch)


def test_foreign_registration_or_pair_funding_is_rejected_before_observation(monkeypatch):
    registration = fixtures.registration()
    observer = Observer()
    for field, value in (
        ("trusted_registration_id", "00000000-0000-4000-8000-000000000099"),
        ("pair_sha256", "f" * 64),
    ):
        with pytest.raises(EdgeLocalCovenantObservationUnavailable):
            _run(monkeypatch, funding_set=replace(fixtures.funding(), **{field: value}), observer=observer)
    assert observer.calls == []


def test_default_composition_uses_configured_rpc_and_existing_adapter(monkeypatch):
    import app.utils

    registration = fixtures.registration()
    monkeypatch.setattr(service, "resolve_controlling_registration", lambda *a, **k: _selection(registration))
    rpc = object()
    observed = Observer()
    constructed = []

    def adapter(value):
        constructed.append(value)
        return observed

    monkeypatch.setattr(service, "TrustedBitcoinCovenantObservationAdapter", adapter)
    monkeypatch.setattr(app.utils, "get_rpc_connection", lambda: rpc)
    result = observe_edge_local_covenant_relation(
        GRAPH,
        registration.subject_xonly_pubkey,
        evaluated_at=NOW,
        genesis_repository=object(),
        admission_edge_repository=object(),
        root_registration_binding_repository=object(),
        trusted_registration_repository=object(),
        funding_set_repository=FundingRepository(fixtures.funding()),
    )
    assert constructed == [rpc]
    assert len(observed.calls[0]) == result.recognized_outpoint_count == 5
