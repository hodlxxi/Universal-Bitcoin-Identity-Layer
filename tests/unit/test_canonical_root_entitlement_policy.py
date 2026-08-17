from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timezone

import pytest

import app.services.canonical_root_entitlement_policy as policy
from app.services.action_authorization import IdentityClass
from app.services.canonical_controlling_registration import ControllingRegistrationSelectionSource
from app.services.covenant_relation import MAX_BITCOIN_SATS, CovenantRelationReason
from app.services.edge_local_covenant_observation import EdgeLocalCovenantRelationResult

GRAPH = "hodlxxi:test"
SUBJECT = "1" * 64
NOW = datetime(2026, 8, 12, 1, 2, 3, 456789, tzinfo=timezone.utc)


def result(**changes):
    values = dict(
        graph_or_protocol_id=GRAPH,
        subject_xonly_pubkey=SUBJECT,
        counterparty_xonly_pubkey="2" * 64,
        controlling_selection_source=ControllingRegistrationSelectionSource.CANONICAL_ROOT_REGISTRATION_BINDING,
        selector_record_id="00000000-0000-4000-8000-000000000001",
        selector_record_sha256="3" * 64,
        trusted_registration_id="00000000-0000-4000-8000-000000000002",
        trusted_registration_sha256="4" * 64,
        funding_set_id="00000000-0000-4000-8000-000000000003",
        funding_set_sha256="5" * 64,
        recognized_outpoint_count=5,
        qualifying_observation_count=5,
        observed_at=NOW,
        observed_block_height=900000,
        incoming_sats=300000,
        outgoing_sats=300000,
        current_full_relation_satisfied=True,
        relation_reason=CovenantRelationReason.FULL_RELATION_SATISFIED,
        relation_source_evidence_sha256="6" * 64,
    )
    values.update(changes)
    return EdgeLocalCovenantRelationResult(**values)


def evaluate(value=None, graph=GRAPH, subject=SUBJECT):
    return policy.evaluate_canonical_root_entitlement(graph, subject, value or result())


def test_real_shaped_root_relation_maps_to_ordinary_full_and_is_immutable():
    decision = evaluate()
    assert decision.identity_class is IdentityClass.FULL
    assert decision.current_full_relation_satisfied is True
    assert decision.observed_at == NOW
    with pytest.raises(FrozenInstanceError):
        decision.identity_class = IdentityClass.LIMITED


@pytest.mark.parametrize(
    ("incoming", "outgoing", "qualifying", "reason"),
    (
        (0, 0, 0, CovenantRelationReason.NO_QUALIFYING_OBSERVATIONS),
        (0, 100, 1, CovenantRelationReason.MISSING_INCOMING),
        (100, 0, 1, CovenantRelationReason.MISSING_OUTGOING),
        (100, 99, 2, CovenantRelationReason.OUTGOING_BELOW_INCOMING),
    ),
)
def test_legitimate_negative_summaries_map_to_limited(incoming, outgoing, qualifying, reason):
    decision = evaluate(
        result(
            incoming_sats=incoming,
            outgoing_sats=outgoing,
            qualifying_observation_count=qualifying,
            relation_reason=reason,
            current_full_relation_satisfied=False,
        )
    )
    assert decision.identity_class is IdentityClass.LIMITED


@pytest.mark.parametrize(
    "changes",
    (
        {"incoming_sats": 0, "outgoing_sats": 0},
        {"relation_reason": CovenantRelationReason.MISSING_OUTGOING},
        {"current_full_relation_satisfied": False},
        {"qualifying_observation_count": 0},
        {"qualifying_observation_count": 1},
        {"qualifying_observation_count": 6},
        {"recognized_outpoint_count": 1},
        {"recognized_outpoint_count": 5, "qualifying_observation_count": 5, "incoming_sats": 1, "outgoing_sats": 1},
        {"incoming_sats": True},
        {"selector_record_sha256": "X" * 64},
        {"controlling_selection_source": ControllingRegistrationSelectionSource.CANONICAL_ADMISSION_EDGE},
    ),
)
def test_contradictory_or_malformed_input_is_sanitized(changes):
    with pytest.raises(policy.CanonicalRootEntitlementPolicyUnavailable) as caught:
        evaluate(result(**changes))
    assert str(caught.value) == "canonical root entitlement policy unavailable"


class StringSubclass(str):
    pass


@pytest.mark.parametrize(
    "changes",
    (
        {"graph_or_protocol_id": StringSubclass(GRAPH)},
        {"selector_record_id": "not-a-uuid"},
        {"observed_at": NOW.replace(tzinfo=None)},
        {"counterparty_xonly_pubkey": "X" * 64},
        {"counterparty_xonly_pubkey": SUBJECT},
    ),
)
def test_exact_graph_and_other_malformed_domain_fields_are_unavailable(changes):
    with pytest.raises(policy.CanonicalRootEntitlementPolicyUnavailable):
        evaluate(result(**changes))


def test_combined_money_bound_rejects_excess_and_accepts_exact_boundary():
    base = dict(
        recognized_outpoint_count=5,
        qualifying_observation_count=2,
        incoming_sats=1,
        relation_reason=CovenantRelationReason.FULL_RELATION_SATISFIED,
    )
    with pytest.raises(policy.CanonicalRootEntitlementPolicyUnavailable):
        evaluate(result(outgoing_sats=MAX_BITCOIN_SATS - 1, **base))
    decision = evaluate(result(outgoing_sats=MAX_BITCOIN_SATS - 4, **base))
    assert decision.identity_class is IdentityClass.FULL


@pytest.mark.parametrize(("graph", "subject"), (("other", SUBJECT), (GRAPH, "9" * 64)))
def test_caller_identity_mismatch_is_unavailable(graph, subject):
    with pytest.raises(policy.CanonicalRootEntitlementPolicyUnavailable):
        evaluate(graph=graph, subject=subject)


def test_digest_is_deterministic_and_commits_to_every_causal_result_field():
    original = evaluate()
    assert evaluate().source_evidence_sha256 == original.source_evidence_sha256
    alternatives = {
        "selector_record_sha256": "7" * 64,
        "trusted_registration_sha256": "8" * 64,
        "funding_set_sha256": "9" * 64,
        "relation_source_evidence_sha256": "a" * 64,
        "observed_block_height": 900001,
    }
    for name, value in alternatives.items():
        assert evaluate(result(**{name: value})).source_evidence_sha256 != original.source_evidence_sha256
    assert not hasattr(policy, "canonical_root_entitlement_bytes")
    assert {x.name for x in fields(original)} >= {"selector_record_id", "trusted_registration_id", "funding_set_id"}


def test_digest_commits_to_all_specified_causal_fields():
    baseline = evaluate()
    cases = (
        (result(graph_or_protocol_id="hodlxxi:other"), "hodlxxi:other", SUBJECT),
        (result(subject_xonly_pubkey="b" * 64), GRAPH, "b" * 64),
        (result(counterparty_xonly_pubkey="c" * 64), GRAPH, SUBJECT),
        (result(selector_record_id="00000000-0000-4000-8000-000000000011"), GRAPH, SUBJECT),
        (result(selector_record_sha256="7" * 64), GRAPH, SUBJECT),
        (result(trusted_registration_id="00000000-0000-4000-8000-000000000012"), GRAPH, SUBJECT),
        (result(trusted_registration_sha256="8" * 64), GRAPH, SUBJECT),
        (result(funding_set_id="00000000-0000-4000-8000-000000000013"), GRAPH, SUBJECT),
        (result(funding_set_sha256="9" * 64), GRAPH, SUBJECT),
        (result(recognized_outpoint_count=6), GRAPH, SUBJECT),
        (result(qualifying_observation_count=4), GRAPH, SUBJECT),
        (result(observed_at=NOW.replace(microsecond=456788)), GRAPH, SUBJECT),
        (result(observed_block_height=900001), GRAPH, SUBJECT),
        (result(incoming_sats=299999), GRAPH, SUBJECT),
        (result(outgoing_sats=300001), GRAPH, SUBJECT),
        (result(relation_source_evidence_sha256="a" * 64), GRAPH, SUBJECT),
    )
    for changed, graph, subject in cases:
        assert evaluate(changed, graph, subject).source_evidence_sha256 != baseline.source_evidence_sha256
