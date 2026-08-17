from dataclasses import replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import hashlib
from types import SimpleNamespace

import pytest

from app.services.trusted_crt_bitcoin_observation_snapshot import *
from app.services import trusted_crt_bitcoin_observation_snapshot as snapshot_module
from app.services.trusted_crt_authorization_source_plan import TrustedCrtAuthorizationSourcePlan
from app.services.trusted_covenant_registration import trusted_registration_sha256
from tests.unit.test_trusted_crt_authorization_source_plan import adapter as plan_adapter, proposed_edge
from tests.unit.test_canonical_admission_edge import registration_for

NOW = datetime(2026, 8, 2, 12, tzinfo=timezone.utc)
BLOCK = "f" * 64


def plan(depth=1):
    value, evidence = plan_adapter(depth)
    target = evidence[-1].record
    return value.resolve(participant_id=target.child_participant_id, target_edge_id=target.edge_id).plan


def genesis_plan():
    value, _ = plan_adapter()
    from app.services.canonical_genesis_record import PARTICIPANT_ID

    return value.resolve(participant_id=PARTICIPANT_ID).plan


class RPC:
    def __init__(
        self,
        source_plan,
        *,
        heights=(900000, 900000),
        hashes=(BLOCK, BLOCK),
        blockhashes=(BLOCK, BLOCK),
        null=False,
        error=None,
        descriptor_text=None,
    ):
        self.calls = []
        self.heights = list(heights)
        self.hashes = list(hashes)
        self.blockhashes = list(blockhashes)
        self.null = null
        self.error = error
        self.descriptor_text = descriptor_text
        self.bindings = {}
        for source in source_plan.lineage_sources:
            for item in source.registration.outpoints:
                self.bindings[(item.txid, item.vout)] = item

    def getblockcount(self):
        self.calls.append(("getblockcount",))
        if self.error:
            raise self.error
        return self.heights.pop(0)

    def getbestblockhash(self):
        self.calls.append(("getbestblockhash",))
        return self.hashes.pop(0)

    def getblockhash(self, height):
        self.calls.append(("getblockhash", height))
        return self.blockhashes.pop(0)

    def gettxout(self, txid, vout, include_mempool):
        self.calls.append(("gettxout", txid, vout, include_mempool))
        if self.null:
            return None
        item = self.bindings[(txid, vout)]
        script = "0020" + item.witness_script_sha256
        response = {
            "bestblock": BLOCK,
            "confirmations": 3,
            "value": Decimal(item.amount_sats) / Decimal(100_000_000),
            "scriptPubKey": {"hex": script},
        }
        if item.descriptor_sha256 is not None:
            response["scriptPubKey"]["desc"] = self.descriptor_text or "wrong"
        return response


class Clock:
    def __init__(self, values=(NOW, NOW + timedelta(seconds=1)), error=None):
        self.values = list(values)
        self.calls = 0
        self.error = error

    def __call__(self):
        self.calls += 1
        if self.error:
            raise self.error
        return self.values.pop(0)


def observe(source_plan, **rpc_kwargs):
    rpc, clock = RPC(source_plan, **rpc_kwargs), Clock()
    result = TrustedCrtBitcoinObservationSnapshotAdapter(rpc=rpc, clock=clock).observe(source_plan=source_plan)
    return result, rpc, clock


def mixed_plan():
    value, evidence = plan_adapter(3)
    middle = proposed_edge(evidence[1].record)
    from app.services.canonical_admission_edge import canonical_admission_edge_sha256

    target = replace(evidence[-1].record, sponsor_basis_record_sha256=canonical_admission_edge_sha256(middle))
    value._admission_edge_repository.values[middle.edge_id] = middle
    value._admission_edge_repository.values[target.edge_id] = target
    return value.resolve(participant_id=target.child_participant_id, target_edge_id=target.edge_id).plan


def forged_snapshot(snapshot, **changes):
    """Invoke the public constructor with a matching recomputed payload digest."""
    values = {field: getattr(snapshot, field) for field in snapshot.__dataclass_fields__}
    values.update(changes)
    values["snapshot_sha256"] = hashlib.sha256(
        snapshot_module._snapshot_bytes_unchecked(SimpleNamespace(**values))
    ).hexdigest()
    return TrustedCrtBitcoinObservationSnapshot(**values)


def test_genesis_is_not_required_without_rpc_or_clock():
    p = genesis_plan()

    class Never:
        def __getattr__(self, name):
            if name in ("getblockcount", "getbestblockhash", "getblockhash", "gettxout"):
                return lambda *args: pytest.fail("unexpected RPC")
            raise AttributeError(name)

    clock = Clock(error=AssertionError("unexpected clock"))
    result = TrustedCrtBitcoinObservationSnapshotAdapter(rpc=Never(), clock=clock).observe(source_plan=p)
    assert result.state is TrustedCrtBitcoinObservationState.NOT_REQUIRED
    assert result.snapshot is None and clock.calls == 0
    assert result.source_plan_manifest_sha256 == p.manifest_sha256


def test_inactive_only_plan_is_not_required():
    p = plan()
    # Build a genuine inactive plan through the authoritative source-plan adapter.
    value, evidence = plan_adapter()
    value._admission_edge_repository.values[evidence[0].record.edge_id] = proposed_edge(evidence[0].record)
    target = value._admission_edge_repository.values[evidence[0].record.edge_id]
    inactive = value.resolve(participant_id=target.child_participant_id, target_edge_id=target.edge_id).plan
    result, rpc, clock = observe(inactive)
    assert result.state is TrustedCrtBitcoinObservationState.NOT_REQUIRED
    assert rpc.calls == [] and clock.calls == 0


@pytest.mark.parametrize("depth", (1, 3))
def test_observed_root_to_target_global_order_and_one_timestamp(depth):
    p = plan(depth)
    result, rpc, clock = observe(p)
    snapshot = result.snapshot
    assert result.state is TrustedCrtBitcoinObservationState.OBSERVED
    assert [x.depth for x in snapshot.observed_relations] == list(range(1, depth + 1))
    assert all(x.relation_evaluation.observed_at == NOW for x in snapshot.observed_relations)
    assert clock.calls == 2
    assert rpc.calls[:3] == [("getblockcount",), ("getbestblockhash",), ("getblockhash", 900000)]
    assert rpc.calls[-3:] == [("getblockcount",), ("getbestblockhash",), ("getblockhash", 900000)]
    assert all(call[-1] is False for call in rpc.calls if call[0] == "gettxout")
    assert len([x for x in rpc.calls if x[0] == "gettxout"]) == depth * 2
    assert snapshot.snapshot_sha256 == trusted_crt_bitcoin_observation_snapshot_sha256(snapshot)


def test_mixed_plan_observes_only_required_sources():
    p = mixed_plan()
    assert [x.observation_required for x in p.lineage_sources] == [True, False, True]
    result, rpc, _ = observe(p)
    assert [x.depth for x in result.snapshot.observed_relations] == [1, 3]
    assert len([x for x in rpc.calls if x[0] == "gettxout"]) == 4
    assert all(len(x.trusted_outpoints) == 2 for x in result.snapshot.observed_relations)


def test_duplicate_global_outpoint_is_rejected_before_clock_or_rpc():
    value, evidence = plan_adapter(3)
    root_txid = evidence[0].trusted_registration.outpoints[0].txid
    second = evidence[1].record
    registration = registration_for(
        second.sponsor_compressed_public_key,
        second.child_compressed_public_key,
        2,
        registration_id=second.trusted_registration_id,
        txids=(root_txid[0], "9"),
        amount=evidence[1].trusted_registration.outpoints[0].amount_sats,
    )
    from app.services.canonical_admission_edge import canonical_admission_edge_sha256

    second = replace(second, trusted_registration_sha256=trusted_registration_sha256(registration))
    third = replace(
        evidence[2].record,
        sponsor_basis_record_sha256=canonical_admission_edge_sha256(second),
    )
    value._trusted_registration_repository.values[registration.registration_id] = registration
    value._admission_edge_repository.values[second.edge_id] = second
    value._admission_edge_repository.values[third.edge_id] = third
    p = value.resolve(participant_id=third.child_participant_id, target_edge_id=third.edge_id).plan
    rpc, clock = RPC(p), Clock()
    with pytest.raises(TrustedCrtBitcoinObservationUnavailable):
        TrustedCrtBitcoinObservationSnapshotAdapter(rpc=rpc, clock=clock).observe(source_plan=p)
    assert rpc.calls == [] and clock.calls == 0


@pytest.mark.parametrize(
    "changes",
    (
        {"participant_id": "0" * 64},
        {"target_edge_id": "00000000-0000-4000-8000-000000000099"},
        {"graph_or_protocol_id": "internally-formatted-but-wrong"},
        {"source_plan_depth": 2},
        {"source_plan_manifest_sha256": "0" * 64},
    ),
    ids=("participant", "target", "graph", "depth", "plan-digest"),
)
def test_recomputed_snapshot_digest_cannot_forge_plan_bound_scalars(changes):
    snapshot = observe(plan())[0].snapshot
    with pytest.raises(TrustedCrtBitcoinObservationUnavailable):
        forged_snapshot(snapshot, **changes)


def test_snapshot_rejects_source_plan_subclass_and_mutation_with_recomputed_digest():
    snapshot = observe(plan())[0].snapshot
    source = snapshot.source_plan

    class Sub(TrustedCrtAuthorizationSourcePlan):
        pass

    subclass = object.__new__(Sub)
    for field in source.__dataclass_fields__:
        object.__setattr__(subclass, field, getattr(source, field))
    with pytest.raises(TrustedCrtBitcoinObservationUnavailable):
        forged_snapshot(snapshot, source_plan=subclass)
    mutated = plan()
    object.__setattr__(mutated, "participant_id", "0" * 64)
    with pytest.raises(TrustedCrtBitcoinObservationUnavailable):
        forged_snapshot(snapshot, source_plan=mutated)


@pytest.mark.parametrize(
    "field,value",
    (
        ("edge_id", "internally-formatted-but-not-plan-bound"),
        ("edge_sha256", "0" * 64),
        ("registration_id", "internally-formatted-but-not-plan-bound"),
        ("registration_sha256", "0" * 64),
    ),
)
def test_recomputed_digest_rejects_changed_relation_source_metadata(field, value):
    snapshot = observe(plan())[0].snapshot
    relation = replace(snapshot.observed_relations[0], **{field: value})
    with pytest.raises(TrustedCrtBitcoinObservationUnavailable):
        forged_snapshot(snapshot, observed_relations=(relation,))


def test_relation_or_outpoints_from_another_valid_plan_are_rejected():
    snapshot = observe(plan())[0].snapshot
    other = observe(plan(3))[0].snapshot.observed_relations[-1]
    with pytest.raises(TrustedCrtBitcoinObservationUnavailable):
        forged_snapshot(snapshot, observed_relations=(other,))
    original = snapshot.observed_relations[0]
    foreign = replace(
        other,
        depth=original.depth,
        edge_id=original.edge_id,
        edge_sha256=original.edge_sha256,
        registration_id=original.registration_id,
        registration_sha256=original.registration_sha256,
    )
    with pytest.raises(TrustedCrtBitcoinObservationUnavailable):
        forged_snapshot(snapshot, observed_relations=(foreign,))


def test_missing_extra_duplicate_reordered_and_gapped_required_relations_are_rejected():
    snapshot = observe(plan(3))[0].snapshot
    relations = snapshot.observed_relations
    invalid = (
        relations[:-1],
        relations + (relations[-1],),
        (relations[0], relations[0], relations[2]),
        tuple(reversed(relations)),
        (relations[0], relations[2]),
    )
    for value in invalid:
        with pytest.raises(TrustedCrtBitcoinObservationUnavailable):
            forged_snapshot(snapshot, observed_relations=value)


def test_required_subset_rejects_nonrequired_inclusion_and_required_omission():
    p = mixed_plan()
    snapshot = observe(p)[0].snapshot
    all_required_snapshot = observe(plan(3))[0].snapshot
    nonrequired_relation = all_required_snapshot.observed_relations[1]
    with pytest.raises(TrustedCrtBitcoinObservationUnavailable):
        forged_snapshot(
            snapshot,
            observed_relations=(snapshot.observed_relations[0], nonrequired_relation, snapshot.observed_relations[1]),
        )
    with pytest.raises(TrustedCrtBitcoinObservationUnavailable):
        forged_snapshot(snapshot, observed_relations=snapshot.observed_relations[:-1])


def test_relation_subject_counterparty_and_formatted_metadata_are_plan_bound():
    snapshot = observe(plan())[0].snapshot
    original = snapshot.observed_relations[0]
    other = observe(plan(3))[0].snapshot.observed_relations[-1]
    mismatched_identity = replace(
        other,
        depth=original.depth,
        edge_id=original.edge_id,
        edge_sha256=original.edge_sha256,
        registration_id=original.registration_id,
        registration_sha256=original.registration_sha256,
    )
    with pytest.raises(TrustedCrtBitcoinObservationUnavailable):
        forged_snapshot(snapshot, observed_relations=(mismatched_identity,))
    formatted = replace(original, edge_id="00000000-0000-4000-8000-000000000099")
    with pytest.raises(TrustedCrtBitcoinObservationUnavailable):
        forged_snapshot(snapshot, observed_relations=(formatted,))


def test_observed_resolution_revalidates_snapshot_plan_digest():
    snapshot = observe(plan())[0].snapshot
    with pytest.raises(TrustedCrtBitcoinObservationUnavailable):
        TrustedCrtBitcoinObservationResolution(
            TrustedCrtBitcoinObservationState.OBSERVED,
            "0" * 64,
            snapshot,
        )


def test_snapshot_serializer_revalidates_detached_plan_after_alias_or_internal_mutation():
    caller_plan = plan()
    snapshot = observe(caller_plan)[0].snapshot
    before = trusted_crt_bitcoin_observation_snapshot_bytes(snapshot)
    object.__setattr__(caller_plan, "participant_id", "0" * 64)
    assert trusted_crt_bitcoin_observation_snapshot_bytes(snapshot) == before
    object.__setattr__(snapshot.source_plan, "participant_id", "0" * 64)
    with pytest.raises(TrustedCrtBitcoinObservationUnavailable):
        trusted_crt_bitcoin_observation_snapshot_bytes(snapshot)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"heights": (900000, 900001)},
        {"hashes": (BLOCK, "e" * 64)},
        {"blockhashes": ("e" * 64, BLOCK)},
        {"blockhashes": (BLOCK, "e" * 64)},
        {"heights": (True, 900000)},
        {"hashes": ("F" * 64, BLOCK)},
    ],
)
def test_anchor_changes_mismatches_and_malformed_values_fail_closed(kwargs):
    p = plan()
    with pytest.raises(TrustedCrtBitcoinObservationUnavailable):
        observe(p, **kwargs)


@pytest.mark.parametrize("failure", ("bestblock", "amount", "script"))
def test_composed_observer_rejects_nonnull_response_mismatches(failure):
    p = plan()
    rpc = RPC(p)
    original = rpc.gettxout

    def invalid(*args):
        response = original(*args)
        if failure == "bestblock":
            response["bestblock"] = "e" * 64
        if failure == "amount":
            response["value"] += Decimal("0.00000001")
        if failure == "script":
            response["scriptPubKey"]["hex"] = "00"
        return response

    rpc.gettxout = invalid
    with pytest.raises(TrustedCrtBitcoinObservationUnavailable):
        TrustedCrtBitcoinObservationSnapshotAdapter(rpc=rpc, clock=Clock()).observe(source_plan=p)


def test_composed_observer_enforces_descriptor_digest():
    value, evidence = plan_adapter()
    source_registration = evidence[0].trusted_registration
    descriptor = "raw(51)#exact"
    descriptor_digest = hashlib.sha256(descriptor.encode()).hexdigest()
    registration = replace(
        source_registration,
        outpoints=(
            replace(source_registration.outpoints[0], descriptor_sha256=descriptor_digest),
            source_registration.outpoints[1],
        ),
    )
    edge = replace(evidence[0].record, trusted_registration_sha256=trusted_registration_sha256(registration))
    value._trusted_registration_repository.values[registration.registration_id] = registration
    value._admission_edge_repository.values[edge.edge_id] = edge
    p = value.resolve(participant_id=edge.child_participant_id, target_edge_id=edge.edge_id).plan
    rpc = RPC(p, descriptor_text="wrong")
    with pytest.raises(TrustedCrtBitcoinObservationUnavailable):
        TrustedCrtBitcoinObservationSnapshotAdapter(rpc=rpc, clock=Clock()).observe(source_plan=p)


def test_clock_exception_is_sanitized_and_rpc_base_exceptions_propagate():
    p = plan()
    secret = "clock-private-secret"
    with pytest.raises(TrustedCrtBitcoinObservationUnavailable) as caught:
        TrustedCrtBitcoinObservationSnapshotAdapter(
            rpc=RPC(p),
            clock=Clock(error=RuntimeError(secret)),
        ).observe(source_plan=p)
    assert secret not in str(caught.value)
    for exception in (KeyboardInterrupt(), SystemExit()):
        rpc = RPC(p, error=exception)
        with pytest.raises(type(exception)):
            TrustedCrtBitcoinObservationSnapshotAdapter(rpc=rpc, clock=Clock()).observe(source_plan=p)


def test_snapshot_digest_changes_for_global_hash_and_plan_bound_sources():
    first = observe(plan())[0].snapshot
    changed_hash = forged_snapshot(first, observed_best_block_hash="e" * 64)
    other_plan = observe(plan(3))[0].snapshot
    assert changed_hash.snapshot_sha256 != first.snapshot_sha256
    assert other_plan.snapshot_sha256 != first.snapshot_sha256
    assert other_plan.source_plan_manifest_sha256 != first.source_plan_manifest_sha256
    assert (
        other_plan.observed_relations[-1].trusted_outpoints_sha256
        != first.observed_relations[0].trusted_outpoints_sha256
    )
    assert (
        other_plan.observed_relations[-1].relation_evaluation_sha256
        != first.observed_relations[0].relation_evaluation_sha256
    )


def test_public_contracts_and_serializers_reject_subclasses():
    snapshot = observe(plan())[0].snapshot
    relation = snapshot.observed_relations[0]

    class RelationSubclass(TrustedCrtObservedLineageRelation):
        pass

    subclass = object.__new__(RelationSubclass)
    for field in relation.__dataclass_fields__:
        object.__setattr__(subclass, field, getattr(relation, field))
    with pytest.raises(TrustedCrtBitcoinObservationUnavailable):
        forged_snapshot(snapshot, observed_relations=(subclass,))

    class SnapshotSubclass(TrustedCrtBitcoinObservationSnapshot):
        pass

    snapshot_subclass = object.__new__(SnapshotSubclass)
    for field in snapshot.__dataclass_fields__:
        object.__setattr__(snapshot_subclass, field, getattr(snapshot, field))
    with pytest.raises(TrustedCrtBitcoinObservationUnavailable):
        trusted_crt_bitcoin_observation_snapshot_bytes(snapshot_subclass)


def test_null_is_authoritative_negative_and_canonical_forms_are_deterministic():
    p = plan()
    result, _, _ = observe(p, null=True)
    relation = result.snapshot.observed_relations[0]
    assert all(x.unspent is False and x.confirmations == 0 for x in relation.relation_evaluation.observations)
    assert trusted_crt_outpoint_manifest_bytes(relation.trusted_outpoints) == trusted_crt_outpoint_manifest_bytes(
        relation.trusted_outpoints
    )
    assert trusted_crt_bitcoin_observation_snapshot_bytes(
        result.snapshot
    ) == trusted_crt_bitcoin_observation_snapshot_bytes(result.snapshot)


def test_subclass_forged_manifest_rpc_and_clock_errors_are_sanitized_and_interrupts_propagate():
    p = plan()

    class Sub(TrustedCrtAuthorizationSourcePlan):
        pass

    sub = object.__new__(Sub)
    for field in p.__dataclass_fields__:
        object.__setattr__(sub, field, getattr(p, field))
    rpc = RPC(p)
    with pytest.raises(TrustedCrtBitcoinObservationUnavailable):
        TrustedCrtBitcoinObservationSnapshotAdapter(rpc=rpc).observe(source_plan=sub)
    assert rpc.calls == []
    forged = plan()
    object.__setattr__(forged, "manifest_sha256", "0" * 64)
    with pytest.raises(TrustedCrtBitcoinObservationUnavailable):
        TrustedCrtBitcoinObservationSnapshotAdapter(rpc=rpc).observe(source_plan=forged)
    secret = "rpc://private-secret"
    with pytest.raises(TrustedCrtBitcoinObservationUnavailable) as caught:
        observe(p, error=RuntimeError(secret))
    assert secret not in str(caught.value)
    for exc in (KeyboardInterrupt(), SystemExit()):
        with pytest.raises(type(exc)):
            TrustedCrtBitcoinObservationSnapshotAdapter(rpc=RPC(p), clock=Clock(error=exc)).observe(source_plan=p)


def test_completed_before_started_and_public_digest_forgery_fail_closed():
    p, rpc = plan(), None
    rpc = RPC(p)
    with pytest.raises(TrustedCrtBitcoinObservationUnavailable):
        TrustedCrtBitcoinObservationSnapshotAdapter(rpc=rpc, clock=Clock((NOW, NOW - timedelta(seconds=1)))).observe(
            source_plan=p
        )
    snapshot = observe(p)[0].snapshot
    with pytest.raises(TrustedCrtBitcoinObservationUnavailable):
        replace(snapshot, snapshot_sha256="0" * 64)


def test_rpc_dictionary_alias_is_not_retained():
    p = plan()
    rpc = RPC(p)
    responses = []
    original = rpc.gettxout

    def capture(*args):
        value = original(*args)
        responses.append(value)
        return value

    rpc.gettxout = capture
    snapshot = TrustedCrtBitcoinObservationSnapshotAdapter(rpc=rpc, clock=Clock()).observe(source_plan=p).snapshot
    before = trusted_crt_bitcoin_observation_snapshot_bytes(snapshot)
    responses[0]["bestblock"] = "0" * 64
    responses[0]["scriptPubKey"]["hex"] = "00"
    assert trusted_crt_bitcoin_observation_snapshot_bytes(snapshot) == before
