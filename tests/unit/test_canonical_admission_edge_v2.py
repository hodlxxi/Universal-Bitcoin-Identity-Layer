"""Canon V2 edge and complete sponsor path: evidence only, never Full."""

import hashlib
import json
from dataclasses import replace
from datetime import timedelta

import pytest

from app.services.canonical_admission_edge_v2 import (
    BOUNDARY,
    EDGE_SCHEMA,
    EDGE_VERSION,
    LINEAGE_SCHEMA,
    CanonicalSponsorLineageNodeEvidenceV2,
    InvalidCanonicalAdmissionEdgeV2,
    canonical_admission_edge_v2_bytes,
    canonical_admission_edge_v2_sha256,
    create_canonical_admission_edge_v2,
    evaluate_canonical_sponsor_lineage_v2,
)
from app.services.canonical_covenant_funding_set import (
    CovenantFundingSetLifecycle,
    RecognizedCovenantFundingOutpoint,
    create_canonical_covenant_funding_set,
)
from app.services.canonical_genesis_record import CanonicalGenesisEvaluationState
from app.services.trusted_covenant_registration import (
    RegisteredCovenantOutpoint,
    TrustedCovenantRegistrationLifecycle,
    create_trusted_covenant_registration,
)
from tests.unit.test_canonical_admission_proposal_v2 import (
    BOB,
    CHARLIE,
    NOW,
    _genesis,
    _make,
    _sources,
)

CHILD_EARLY_TX = "c" * 64
CHILD_LATE_TX = "d" * 64


def _root():
    proposal, sources, _ = _make()
    node = CanonicalSponsorLineageNodeEvidenceV2(
        create_canonical_admission_edge_v2(proposal),
        sources[1],
        sources[2],
        sources[3],
        sources[3],
    )
    return proposal, node


def _child(parent):
    policy, reg, _funding, snapshot, rpc = _sources(sponsor=BOB, child=CHARLIE, depth=1)
    new_id = {"a" * 64: CHILD_EARLY_TX, "b" * 64: CHILD_LATE_TX}
    reg = create_trusted_covenant_registration(
        reg.mirrored_pair,
        tuple(
            RegisteredCovenantOutpoint(
                o.direction,
                new_id[o.txid],
                o.vout,
                o.amount_sats,
                o.witness_script_sha256,
                o.descriptor_sha256,
            )
            for o in reg.outpoints
        ),
        registration_id=reg.registration_id,
        lifecycle_state=reg.lifecycle_state,
        registered_at=reg.registered_at,
        lifecycle_changed_at=reg.lifecycle_changed_at,
    )
    funding = create_canonical_covenant_funding_set(
        funding_set_id="00000000-0000-4000-8000-000000000022",
        trusted_registration=reg,
        lifecycle_state=CovenantFundingSetLifecycle.EFFECTIVE,
        created_at=NOW,
        lifecycle_changed_at=NOW,
        effective_at=NOW,
        recognized_outpoints=tuple(
            RecognizedCovenantFundingOutpoint(
                o.direction,
                o.txid,
                o.vout,
                o.amount_sats,
                o.witness_script_sha256,
                o.descriptor_sha256,
            )
            for o in reg.outpoints
        ),
    )
    snapshot = replace(
        snapshot,
        observations=tuple(replace(o, txid=new_id[o.txid]) for o in snapshot.observations),
    )
    proposal, _, _ = _make(
        sources=(policy, reg, funding, snapshot, rpc),
        basis=parent,
        depth=1,
    )
    node = CanonicalSponsorLineageNodeEvidenceV2(
        create_canonical_admission_edge_v2(proposal), reg, funding, snapshot, snapshot
    )
    return proposal, node


def _check(nodes, target=None, *, genesis=None, at=NOW):
    if genesis is None:
        genesis = _genesis()
    if target is None:
        target = nodes[-1].edge.edge_id
    return evaluate_canonical_sponsor_lineage_v2(target, nodes=nodes, genesis_evaluation=genesis, evaluated_at=at)


def test_alice_bob_v2_edge_has_distinct_schema_and_never_grants_full():
    proposal, node = _root()
    edge = node.edge
    assert edge.schema == EDGE_SCHEMA
    assert edge.version == EDGE_VERSION
    assert edge.authorization_boundary == BOUNDARY
    assert edge.edge_id == proposal.proposal_id
    assert (
        edge.proposal_sha256
        == hashlib.sha256(
            json.dumps(
                json.loads(canonical_admission_edge_v2_bytes(edge))["proposal"],
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("ascii")
        ).hexdigest()
    )
    assert len(canonical_admission_edge_v2_sha256(edge)) == 64
    assert edge.is_effective is False
    assert edge.grants_full is False


def test_alice_bob_one_edge_lineage_is_structural_not_full():
    proposal, node = _root()
    result = _check((node,))
    assert result.schema == LINEAGE_SCHEMA
    assert result.target_edge_id == proposal.proposal_id
    assert result.target_child_pubkey == BOB
    assert result.target_child_depth == 1
    assert result.edge_ids_root_to_child == (proposal.proposal_id,)
    assert len(result.edge_sha256_root_to_child) == 1
    assert len(result.current_observation_sha256_root_to_child) == 1
    assert result.grants_full is False
    assert result.sponsor_authorized is False
    assert result.is_effective is False


def test_bob_may_structurally_sponsor_charlie_at_depth_two():
    alice_bob, root = _root()
    bob_charlie, child = _child(alice_bob)
    result = _check((child, root), target=bob_charlie.proposal_id)
    assert result.target_child_pubkey == CHARLIE
    assert result.target_child_depth == 2
    assert result.edge_ids_root_to_child == (alice_bob.proposal_id, bob_charlie.proposal_id)
    assert result.grants_full is False
    assert result.sponsor_authorized is False
    assert result.authorization_boundary == BOUNDARY


def test_missing_parent_and_extra_edges_are_refused():
    parent, root = _root()
    child_proposal, child = _child(parent)
    with pytest.raises(InvalidCanonicalAdmissionEdgeV2, match="missing_or_extraneous_ancestry"):
        _check((child,), target=child_proposal.proposal_id)
    with pytest.raises(InvalidCanonicalAdmissionEdgeV2, match="missing_or_extraneous_ancestry"):
        _check((root, child), target=parent.proposal_id)


def test_duplicate_edge_ids_rejected():
    proposal, node = _root()
    with pytest.raises(InvalidCanonicalAdmissionEdgeV2, match="duplicate_edge_id"):
        _check((node, node), target=proposal.proposal_id)


def test_outpoints_cannot_be_reused_across_ancestor_and_child():
    proposal, root = _root()
    sources = _sources(sponsor=BOB, child=CHARLIE, depth=1)
    raw_child, _, _ = _make(sources=sources, basis=proposal, depth=1)
    child = CanonicalSponsorLineageNodeEvidenceV2(
        create_canonical_admission_edge_v2(raw_child),
        sources[1],
        sources[2],
        sources[3],
        sources[3],
    )
    with pytest.raises(InvalidCanonicalAdmissionEdgeV2, match="outpoint_reused_in_lineage"):
        _check((root, child), target=raw_child.proposal_id)


def test_wrong_parent_digest_is_not_merely_ignored():
    parent, root = _root()
    _, child = _child(parent)
    forged = replace(child.edge.proposal, basis_record_sha256="0" * 64)
    wrong = replace(child, edge=create_canonical_admission_edge_v2(forged))
    with pytest.raises(InvalidCanonicalAdmissionEdgeV2, match="parent_identity_or_digest_mismatch"):
        _check((root, wrong), target=wrong.edge.edge_id)


def test_untrusted_genesis_state_is_rejected():
    _, node = _root()
    genesis = replace(
        _genesis(),
        state=CanonicalGenesisEvaluationState.PROVISIONAL,
        selected_effective_record_id=None,
        selected_effective_record_sha256=None,
        reason_code="proposed_only",
    )
    with pytest.raises(InvalidCanonicalAdmissionEdgeV2, match="genesis_not_active"):
        _check((node,), genesis=genesis)


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema", "hodlxxi.canonical_admission_edge.v1"),
        ("version", "v1"),
        ("authorization_boundary", "grants_full"),
        ("proposal_sha256", "0" * 64),
        ("created_at", NOW + timedelta(seconds=1)),
    ],
)
def test_detached_or_forged_edge_metadata_cannot_be_accepted(field, value):
    _, node = _root()
    with pytest.raises(InvalidCanonicalAdmissionEdgeV2):
        replace(node.edge, **{field: value})


def test_mutated_current_outpoint_is_rejected_even_if_original_was_valid():
    _, node = _root()
    original = node.current_observation.observations[0]
    for tampered in (
        replace(original, unspent=False),
        replace(original, confirmations=0),
        replace(original, txid="e" * 64),
        replace(original, amount_sats=49999),
        replace(original, script_sha256="f" * 64),
    ):
        changed = replace(
            node,
            current_observation=replace(
                node.current_observation,
                observations=(tampered, node.current_observation.observations[1]),
            ),
        )
        with pytest.raises(InvalidCanonicalAdmissionEdgeV2, match="current_outpoints_missing_spent_or_mismatched"):
            _check((changed,))


def test_stale_or_future_observation_is_not_current():
    _, node = _root()
    with pytest.raises(InvalidCanonicalAdmissionEdgeV2, match="current_observation_missing_or_stale"):
        _check((node,), at=NOW + timedelta(seconds=121))
    with pytest.raises(InvalidCanonicalAdmissionEdgeV2, match="current_observation_missing_or_stale"):
        _check((node,), at=NOW - timedelta(seconds=1))


def test_revoked_source_fails_historical_or_current_binding():
    _, node = _root()
    revoked = replace(
        node.registration,
        lifecycle_state=TrustedCovenantRegistrationLifecycle.REVOKED,
    )
    with pytest.raises(InvalidCanonicalAdmissionEdgeV2, match="historical_proposal_sources_invalid"):
        _check((replace(node, registration=revoked),))


def test_misbound_current_observation_ignores_no_errors():
    _, root = _root()
    parent = root.edge.proposal
    _, child = _child(parent)
    wrong = replace(root, current_observation=child.current_observation)
    with pytest.raises(InvalidCanonicalAdmissionEdgeV2, match="current_observation_missing_or_stale"):
        _check((wrong,))


def test_original_observation_is_required_separately_from_current():
    _, node = _root()
    bogus = replace(
        node.original_observation,
        observations=tuple(replace(o, txid="f" * 64) for o in node.original_observation.observations),
    )
    with pytest.raises(InvalidCanonicalAdmissionEdgeV2, match="historical_proposal_sources_invalid"):
        _check((replace(node, original_observation=bogus),))


def test_untrusted_objects_and_missing_target_never_mint_structural_proof():
    _, node = _root()
    with pytest.raises(InvalidCanonicalAdmissionEdgeV2):
        create_canonical_admission_edge_v2({"fake": "proposal"})
    with pytest.raises(InvalidCanonicalAdmissionEdgeV2, match="missing_target_edge"):
        _check((node,), target="00000000-0000-4000-8000-000000009999")
    with pytest.raises(InvalidCanonicalAdmissionEdgeV2, match="lineage_evidence_type"):
        _check(({"fake": "node"},), target=node.edge.edge_id)
