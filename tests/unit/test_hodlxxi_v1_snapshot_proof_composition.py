from dataclasses import replace
from datetime import timedelta, timezone
import ast
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.services.canonical_crt_authorization_policy import CanonicalCrtAuthorizationClass
from app.services.canonical_admission_edge import (
    AdmissionEdgeEvaluationState, AdmissionEdgeLifecycle,
    evaluate_canonical_admission_edge_current,
)
from app.services.trusted_covenant_registration import (
    TrustedCovenantRegistrationLifecycle, trusted_registration_sha256,
)
from app.services.hodlxxi_v1_snapshot_proof_composition import *
from app.services import hodlxxi_v1_snapshot_proof_composition as composition_module
from app.services.trusted_crt_bitcoin_observation_snapshot import (
    TrustedCrtBitcoinObservationResolution, TrustedCrtBitcoinObservationSnapshotAdapter,
    TrustedCrtBitcoinObservationState,
)
from tests.unit.test_trusted_crt_bitcoin_observation_snapshot import (
    Clock, NOW, RPC, forged_snapshot, genesis_plan, mixed_plan, plan,
)
from tests.unit.test_canonical_sponsor_lineage import genesis, lineage_fixture, with_edge_state


def compose(source_plan):
    resolution = TrustedCrtBitcoinObservationSnapshotAdapter(
        rpc=RPC(source_plan), clock=Clock()).observe(source_plan=source_plan)
    request = HodlxxiV1SnapshotProofCompositionRequest(
        source_plan, resolution, NOW + timedelta(seconds=2), NOW + timedelta(minutes=5))
    return compose_hodlxxi_v1_snapshot_authorization_proof(request)


def test_exact_genesis_not_required_success_and_pinned_digest():
    result = compose(genesis_plan())
    assert result.bitcoin_observation_state is TrustedCrtBitcoinObservationState.NOT_REQUIRED
    assert result.edge_evidence == () and result.bitcoin_snapshot_sha256 is None
    assert result.authorization_proof.authorization_class is CanonicalCrtAuthorizationClass.FULL
    assert result.result_sha256 == "55b316a66f8f897bcc8f8e616b62979a5ba2bbc0c7105fdd17a952df52d8ba00"


@pytest.mark.parametrize("depth, digest", (
    (1, "b79ef0ef3d38a5d69c1606fd19c3549716b5412d93abca6cb8e658aa0939fcf5"),
    (3, "2ccbdecc2e25158b184ba5275903235997da57086b87fb970a34ec357fc59a6c"),
))
def test_active_ordinary_root_to_target_success(depth, digest):
    result = compose(plan(depth))
    assert tuple(x.record.child_depth for x in result.edge_evidence) == tuple(range(1, depth + 1))
    assert all(x.observation_evaluation is not None for x in result.edge_evidence)
    assert result.authorization_proof.authorization_class is CanonicalCrtAuthorizationClass.FULL
    assert result.result_sha256 == digest


def test_lifecycle_controlled_source_uses_no_fake_observation_and_is_not_full():
    result = compose(mixed_plan())
    assert [x.observation_evaluation is None for x in result.edge_evidence] == [False, True, False]
    assert result.authorization_proof.authorization_class is CanonicalCrtAuthorizationClass.LIMITED


def test_genesis_rejects_observed_and_active_rejects_not_required():
    genesis = genesis_plan()
    ordinary = plan()
    observed = TrustedCrtBitcoinObservationSnapshotAdapter(rpc=RPC(ordinary), clock=Clock()).observe(source_plan=ordinary)
    with pytest.raises(InvalidHodlxxiV1SnapshotProofComposition):
        HodlxxiV1SnapshotProofCompositionRequest(genesis, observed, NOW + timedelta(seconds=2), NOW + timedelta(minutes=5))
    omitted = TrustedCrtBitcoinObservationResolution(
        TrustedCrtBitcoinObservationState.NOT_REQUIRED, ordinary.manifest_sha256, None)
    with pytest.raises(InvalidHodlxxiV1SnapshotProofComposition):
        HodlxxiV1SnapshotProofCompositionRequest(
            ordinary, omitted, NOW + timedelta(seconds=2), NOW + timedelta(minutes=5))


@pytest.mark.parametrize("field,value", (
    ("evaluated_at", NOW.replace(tzinfo=timezone(timedelta(hours=1)))),
    ("evaluated_at", NOW.replace(microsecond=1)),
    ("freshness_deadline", NOW.replace(microsecond=1)),
))
def test_exact_utc_second_timestamps(field, value):
    source_plan = genesis_plan()
    resolution = TrustedCrtBitcoinObservationSnapshotAdapter(rpc=RPC(source_plan), clock=Clock()).observe(source_plan=source_plan)
    values = dict(source_plan=source_plan, bitcoin_observation_resolution=resolution,
                  evaluated_at=NOW, freshness_deadline=NOW + timedelta(minutes=1))
    values[field] = value
    with pytest.raises(InvalidHodlxxiV1SnapshotProofComposition):
        HodlxxiV1SnapshotProofCompositionRequest(**values)


def test_time_order_and_observation_completion_are_enforced_without_rounding():
    source_plan = plan()
    resolution = TrustedCrtBitcoinObservationSnapshotAdapter(rpc=RPC(source_plan), clock=Clock()).observe(source_plan=source_plan)
    for evaluated, deadline in ((NOW, NOW + timedelta(minutes=1)),
                                (NOW + timedelta(seconds=2), NOW + timedelta(seconds=1))):
        with pytest.raises(InvalidHodlxxiV1SnapshotProofComposition):
            HodlxxiV1SnapshotProofCompositionRequest(source_plan, resolution, evaluated, deadline)


def test_request_and_nested_result_subclasses_are_rejected():
    class Plan(type(genesis_plan())): pass
    class Resolution(TrustedCrtBitcoinObservationResolution): pass
    class Result(HodlxxiV1SnapshotProofCompositionResult): pass
    source_plan = genesis_plan()
    resolution = TrustedCrtBitcoinObservationSnapshotAdapter(rpc=RPC(source_plan), clock=Clock()).observe(source_plan=source_plan)
    with pytest.raises(InvalidHodlxxiV1SnapshotProofComposition):
        compose_hodlxxi_v1_snapshot_authorization_proof(object())
    with pytest.raises(Exception):
        Plan(*(getattr(source_plan, f) for f in source_plan.__dataclass_fields__))
    with pytest.raises(Exception):
        Resolution(resolution.state, resolution.source_plan_manifest_sha256, None)
    with pytest.raises(Exception):
        Result(*(getattr(compose(source_plan), f) for f in Result.__dataclass_fields__))


def test_result_and_evidence_digests_are_deterministic_and_bound():
    one, two = compose(plan(3)), compose(plan(3))
    assert hodlxxi_v1_snapshot_proof_composition_bytes(one) == hodlxxi_v1_snapshot_proof_composition_bytes(two)
    assert one.result_sha256 == hodlxxi_v1_snapshot_proof_composition_sha256(one)
    assert one.edge_evidence_manifest_sha256 == two.edge_evidence_manifest_sha256
    with pytest.raises(InvalidHodlxxiV1SnapshotProofComposition):
        replace(one, freshness_deadline=one.freshness_deadline + timedelta(seconds=1))


def test_static_pure_boundary_and_public_lower_layer_calls():
    path = Path("app/services/hodlxxi_v1_snapshot_proof_composition.py")
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imports = {alias.name for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))
               for alias in node.names}
    forbidden = ("flask", "sqlalchemy", "requests", "urllib", "socket", "subprocess", "os", "app.models", "app.db_storage")
    assert not any(name == item or name.startswith(item + ".") for name in imports for item in forbidden)
    calls = {node.func.id for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
    assert "resolve_canonical_crt_authorization_proof_from_snapshot" in calls
    assert "CanonicalSponsorLineageEdgeEvidence" in calls
    assert not ({"eval", "exec", "__import__"} & calls)


def forged_result(result, **changes):
    """Recompute the outer digest exactly; authoritative nested validation must win."""
    values = {field: getattr(result, field) for field in result.__dataclass_fields__}
    values.update(changes)
    values["result_sha256"] = composition_module._result_sha256_unchecked(
        SimpleNamespace(**values))
    return HodlxxiV1SnapshotProofCompositionResult(**values)


@pytest.mark.parametrize("field,value", (
    ("observed_block_height", 900001),
    ("observed_best_block_hash", "e" * 64),
    ("bitcoin_observation_state", TrustedCrtBitcoinObservationState.NOT_REQUIRED),
    ("source_plan_manifest_sha256", "0" * 64),
    ("bitcoin_snapshot_sha256", "0" * 64),
    ("participant_id", "0" * 64),
    ("target_edge_id", None),
    ("depth", 2),
    ("observation_started_at", NOW - timedelta(seconds=1)),
    ("observation_completed_at", NOW + timedelta(seconds=3)),
    ("edge_evidence_manifest_sha256", "0" * 64),
    ("authorization_proof_sha256", "0" * 64),
    ("graph_or_protocol_id", "forged.graph"),
    ("network", "testnet"),
), ids=("height", "block-hash", "state", "plan-digest", "snapshot-digest",
        "participant", "target", "depth", "started", "completed",
        "evidence-manifest", "proof-digest", "graph", "network"))
def test_recomputed_outer_digest_rejects_scalar_substitution(field, value):
    with pytest.raises(InvalidHodlxxiV1SnapshotProofComposition):
        forged_result(compose(plan(3)), **{field: value})


@pytest.mark.parametrize("field,value", (
    ("evaluated_at", NOW.replace(tzinfo=timezone(timedelta(hours=1)))),
    ("evaluated_at", (NOW + timedelta(seconds=2)).replace(microsecond=1)),
    ("evaluated_at", NOW),
    ("freshness_deadline", NOW.replace(tzinfo=timezone(timedelta(hours=1)))),
    ("freshness_deadline", (NOW + timedelta(minutes=5)).replace(microsecond=1)),
    ("freshness_deadline", NOW + timedelta(seconds=1)),
    ("freshness_deadline", NOW),
), ids=("evaluated-non-utc", "evaluated-microsecond", "evaluated-before-completion",
        "deadline-non-utc", "deadline-microsecond", "deadline-before-evaluated",
        "deadline-before-completion"))
def test_result_authoritatively_rejects_exact_time_inconsistency(field, value):
    with pytest.raises(InvalidHodlxxiV1SnapshotProofComposition):
        forged_result(compose(plan()), **{field: value})


@pytest.mark.parametrize("kind", ("plan", "resolution", "evidence", "proof"))
def test_recomputed_outer_digest_rejects_valid_nested_object_substitution(kind):
    original, other = compose(plan()), compose(plan(3))
    changes = {
        "plan": {"source_plan": other.source_plan},
        "resolution": {"bitcoin_observation_resolution": other.bitcoin_observation_resolution},
        "evidence": {"edge_evidence": other.edge_evidence},
        "proof": {"authorization_proof": other.authorization_proof,
                  "authorization_proof_sha256": other.authorization_proof_sha256},
    }[kind]
    with pytest.raises(InvalidHodlxxiV1SnapshotProofComposition):
        forged_result(original, **changes)


@pytest.mark.parametrize("nested", ("source_plan", "bitcoin_observation_resolution"))
def test_result_detaches_caller_aliases_and_serializer_revalidates(nested):
    source_plan = plan()
    resolution = TrustedCrtBitcoinObservationSnapshotAdapter(
        rpc=RPC(source_plan), clock=Clock()).observe(source_plan=source_plan)
    result = compose_hodlxxi_v1_snapshot_authorization_proof(
        HodlxxiV1SnapshotProofCompositionRequest(
            source_plan, resolution, NOW + timedelta(seconds=2), NOW + timedelta(minutes=5)))
    before = hodlxxi_v1_snapshot_proof_composition_bytes(result)
    object.__setattr__(source_plan if nested == "source_plan" else resolution,
                       "source_plan_manifest_sha256" if nested != "source_plan" else "participant_id",
                       "0" * 64)
    assert hodlxxi_v1_snapshot_proof_composition_bytes(result) == before


@pytest.mark.parametrize("shape", ("missing", "extra", "duplicate", "reordered", "foreign"))
def test_composer_rejects_nonexact_observed_relation_matrix(shape):
    source_plan = plan(3)
    resolution = TrustedCrtBitcoinObservationSnapshotAdapter(
        rpc=RPC(source_plan), clock=Clock()).observe(source_plan=source_plan)
    snapshot = resolution.snapshot
    relations = snapshot.observed_relations
    other_plan = plan()
    foreign = TrustedCrtBitcoinObservationSnapshotAdapter(
        rpc=RPC(other_plan), clock=Clock()).observe(source_plan=other_plan).snapshot.observed_relations[0]
    changed = {
        "missing": relations[:-1],
        "extra": relations + (relations[-1],),
        "duplicate": (relations[0], relations[0], relations[2]),
        "reordered": tuple(reversed(relations)),
        "foreign": (relations[0], relations[1], foreign),
    }[shape]
    with pytest.raises(Exception):
        forged_snapshot(snapshot, observed_relations=changed)


@pytest.mark.parametrize("lifecycle", (
    AdmissionEdgeLifecycle.PROPOSED, AdmissionEdgeLifecycle.DISPUTED,
    AdmissionEdgeLifecycle.REVOKED, AdmissionEdgeLifecycle.SUPERSEDED,
))
def test_lifecycle_controlled_edge_accepts_none_but_never_becomes_active(lifecycle):
    item = with_edge_state(lineage_fixture()[0], lifecycle)
    result = evaluate_canonical_admission_edge_current(
        item.record, trusted_registration=item.trusted_registration,
        observation_evaluation=None, genesis_evaluation=genesis(),
        parent_edge=None, evaluated_at=NOW,
    )
    assert result.state is not AdmissionEdgeEvaluationState.ACTIVE


@pytest.mark.parametrize("lifecycle", (
    TrustedCovenantRegistrationLifecycle.DISPUTED,
    TrustedCovenantRegistrationLifecycle.REVOKED,
    TrustedCovenantRegistrationLifecycle.SUPERSEDED,
))
def test_lifecycle_controlled_registration_accepts_none_but_never_active(lifecycle):
    item = lineage_fixture()[0]
    registration = replace(
        item.trusted_registration, lifecycle_state=lifecycle,
        superseded_by_registration_id=(
            "00000000-0000-4000-8000-000000000098"
            if lifecycle is TrustedCovenantRegistrationLifecycle.SUPERSEDED else None),
    )
    record = replace(item.record,
                     trusted_registration_sha256=trusted_registration_sha256(registration))
    result = evaluate_canonical_admission_edge_current(
        record, trusted_registration=registration, observation_evaluation=None,
        genesis_evaluation=genesis(), parent_edge=None, evaluated_at=NOW,
    )
    assert result.state is not AdmissionEdgeEvaluationState.ACTIVE
