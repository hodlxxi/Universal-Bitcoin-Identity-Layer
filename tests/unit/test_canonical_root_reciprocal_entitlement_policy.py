from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timezone

import pytest

from app.services.action_authorization import IdentityClass
from app.services.canonical_controlling_registration import (
    ControllingRegistrationSelectionSource,
)
from app.services.canonical_root_reciprocal_entitlement_policy import (
    CanonicalRootReciprocalEntitlementPolicyUnavailable,
    evaluate_canonical_root_reciprocal_entitlement,
)
from app.services.covenant_relation import CovenantRelationReason
from app.services.edge_local_covenant_observation import (
    EdgeLocalCovenantRelationResult,
)

GRAPH = "hodlxxi:test"
ROOT = "1" * 64
COUNTERPARTY = "2" * 64

NOW = datetime(
    2026,
    8,
    12,
    1,
    2,
    3,
    456789,
    tzinfo=timezone.utc,
)


def relation(**changes):
    values = dict(
        graph_or_protocol_id=GRAPH,
        subject_xonly_pubkey=ROOT,
        counterparty_xonly_pubkey=COUNTERPARTY,
        controlling_selection_source=(ControllingRegistrationSelectionSource.CANONICAL_ROOT_REGISTRATION_BINDING),
        selector_record_id=("00000000-0000-4000-8000-000000000001"),
        selector_record_sha256="3" * 64,
        trusted_registration_id=("00000000-0000-4000-8000-000000000002"),
        trusted_registration_sha256="4" * 64,
        funding_set_id=("00000000-0000-4000-8000-000000000003"),
        funding_set_sha256="5" * 64,
        recognized_outpoint_count=5,
        qualifying_observation_count=5,
        observed_at=NOW,
        observed_block_height=900000,
        incoming_sats=300000,
        outgoing_sats=300000,
        current_full_relation_satisfied=True,
        relation_reason=(CovenantRelationReason.FULL_RELATION_SATISFIED),
        relation_source_evidence_sha256="6" * 64,
    )
    values.update(changes)
    return EdgeLocalCovenantRelationResult(**values)


def evaluate(value=None):
    return evaluate_canonical_root_reciprocal_entitlement(
        GRAPH,
        ROOT,
        value or relation(),
    )


def test_balanced_root_relation_produces_full_for_counterparty():
    decision = evaluate()

    assert decision.root_subject_xonly_pubkey == ROOT
    assert decision.subject_xonly_pubkey == COUNTERPARTY
    assert decision.counterparty_xonly_pubkey == ROOT

    assert decision.incoming_sats == 300000
    assert decision.outgoing_sats == 300000

    assert decision.identity_class is IdentityClass.FULL
    assert decision.current_full_relation_satisfied is True

    with pytest.raises(FrozenInstanceError):
        decision.subject_xonly_pubkey = ROOT


def test_counterparty_uses_same_rule_with_subject_relative_directions():
    # Root has outgoing >= incoming, therefore root is Full.
    # Counterparty sees those values reversed and is Limited.
    value = relation(
        incoming_sats=200000,
        outgoing_sats=300000,
    )

    decision = evaluate(value)

    assert decision.incoming_sats == 300000
    assert decision.outgoing_sats == 200000
    assert decision.identity_class is IdentityClass.LIMITED
    assert decision.current_full_relation_satisfied is False
    assert decision.relation_reason is CovenantRelationReason.OUTGOING_BELOW_INCOMING


def test_reverse_case_can_qualify_counterparty_under_same_policy():
    value = relation(
        incoming_sats=300000,
        outgoing_sats=200000,
        current_full_relation_satisfied=False,
        relation_reason=(CovenantRelationReason.OUTGOING_BELOW_INCOMING),
    )

    decision = evaluate(value)

    assert decision.incoming_sats == 200000
    assert decision.outgoing_sats == 300000
    assert decision.identity_class is IdentityClass.FULL
    assert decision.current_full_relation_satisfied is True


def test_digest_is_deterministic_and_commits_to_root_provenance():
    baseline = evaluate()

    assert evaluate().source_evidence_sha256 == (baseline.source_evidence_sha256)

    changed = evaluate(
        relation(
            funding_set_sha256="7" * 64,
        )
    )

    assert changed.source_evidence_sha256 != (baseline.source_evidence_sha256)


@pytest.mark.parametrize(
    "changed",
    (
        {"controlling_selection_source": ControllingRegistrationSelectionSource.CANONICAL_ADMISSION_EDGE},
        {
            "counterparty_xonly_pubkey": ROOT,
        },
        {
            "qualifying_observation_count": 1,
        },
        {"relation_reason": CovenantRelationReason.MISSING_OUTGOING},
        {
            "current_full_relation_satisfied": False,
        },
    ),
)
def test_malformed_or_non_root_source_fails_closed(changed):
    with pytest.raises(CanonicalRootReciprocalEntitlementPolicyUnavailable):
        evaluate(
            EdgeLocalCovenantRelationResult(
                **{
                    **{
                        field: getattr(relation(), field)
                        for field in EdgeLocalCovenantRelationResult.__dataclass_fields__
                    },
                    **changed,
                }
            )
        )


def test_wrong_caller_root_subject_fails_closed():
    with pytest.raises(CanonicalRootReciprocalEntitlementPolicyUnavailable):
        evaluate_canonical_root_reciprocal_entitlement(
            GRAPH,
            "9" * 64,
            relation(),
        )
