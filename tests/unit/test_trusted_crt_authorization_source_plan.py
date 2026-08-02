from dataclasses import replace
from pathlib import Path

import pytest

from app.services.canonical_admission_edge import (
    AdmissionEdgeLifecycle,
    SponsorBasisKind,
    canonical_admission_edge_bytes,
    canonical_admission_edge_sha256,
)
from app.services.canonical_genesis_record import (
    CanonicalGenesisLifecycle,
    CanonicalGenesisRecord,
    PARTICIPANT_ID,
    canonical_genesis_record_bytes,
    parse_canonical_genesis_record,
)
from app.services.trusted_crt_authorization_source_plan import *
from app.services.trusted_covenant_registration import (
    TrustedCovenantRegistration,
    TrustedCovenantRegistrationLifecycle,
    canonical_trusted_registration_bytes,
    trusted_registration_sha256,
)
from tests.unit.test_canonical_admission_edge import edge as make_edge, registration_for
from tests.unit.test_canonical_sponsor_lineage import child_edge, lineage_fixture


def genesis_record():
    return parse_canonical_genesis_record(Path("docs/data/e923_canonical_genesis_record_v1.json").read_bytes())


class GenesisRepo:
    def __init__(self, values): self.values = values; self.calls = 0
    def list_for_graph(self, graph): self.calls += 1; return self.values


class ItemRepo:
    def __init__(self, values): self.values = values; self.calls = []; self.writes = 0
    def get(self, item_id): self.calls.append(item_id); return self.values.get(item_id)
    def append(self, value): self.writes += 1


class ScriptedGenesisRepo:
    def __init__(self, values): self.values = list(values)
    def list_for_graph(self, graph):
        return self.values.pop(0) if len(self.values) > 1 else self.values[0]


class ScriptedItemRepo:
    def __init__(self, scripts): self.scripts = {key: list(value) for key, value in scripts.items()}
    def get(self, item_id):
        values = self.scripts.get(item_id, [None])
        return values.pop(0) if len(values) > 1 else values[0]


class MutatingSameItemRepo:
    def __init__(self, value, mutate_at, mutation):
        self.value = value
        self.mutate_at = mutate_at
        self.mutation = mutation
        self.calls = 0

    def get(self, item_id):
        self.calls += 1
        if self.calls == self.mutate_at:
            self.mutation(self.value)
        return self.value


class MutatingSameGenesisRepo:
    def __init__(self, values, mutate_at, mutation):
        self.values = values
        self.mutate_at = mutate_at
        self.mutation = mutation
        self.calls = 0

    def list_for_graph(self, graph):
        self.calls += 1
        if self.calls == self.mutate_at:
            self.mutation(self.values[0])
        return self.values


def mutate_edge_to_proposed(value):
    object.__setattr__(value, "lifecycle_state", AdmissionEdgeLifecycle.PROPOSED)
    object.__setattr__(value, "effective_at", None)
    object.__setattr__(value, "lifecycle_changed_at", value.created_at)


def mutate_registration_to_revoked(value):
    object.__setattr__(
        value, "lifecycle_state", TrustedCovenantRegistrationLifecycle.REVOKED,
    )


def mutate_genesis_to_proposed(value):
    object.__setattr__(value, "lifecycle_state", CanonicalGenesisLifecycle.PROPOSED)
    object.__setattr__(value, "effective_at", None)
    object.__setattr__(value, "lifecycle_changed_at", value.created_at)


def resolve_ordinary(value, evidence):
    target = evidence[-1].record
    return value.resolve(participant_id=target.child_participant_id, target_edge_id=target.edge_id)


def proposed_edge(value):
    return replace(
        value, lifecycle_state=AdmissionEdgeLifecycle.PROPOSED,
        effective_at=None, lifecycle_changed_at=value.created_at,
    )


def inactive_registration(value, lifecycle):
    return replace(
        value,
        lifecycle_state=lifecycle,
        superseded_by_registration_id=(
            "00000000-0000-4000-8000-000000000099"
            if lifecycle is TrustedCovenantRegistrationLifecycle.SUPERSEDED else None
        ),
    )


def registration_with_lifecycle(value, lifecycle):
    return value if lifecycle is TrustedCovenantRegistrationLifecycle.ACTIVE else inactive_registration(value, lifecycle)


def adapter(depth=1, genesis_values=None):
    evidence = lineage_fixture(depth)
    edges = {item.record.edge_id: item.record for item in evidence}
    registrations = {item.trusted_registration.registration_id: item.trusted_registration for item in evidence}
    return (
        TrustedCrtAuthorizationSourcePlanAdapter(
            genesis_repository=GenesisRepo((genesis_record(),) if genesis_values is None else genesis_values),
            admission_edge_repository=ItemRepo(edges),
            trusted_registration_repository=ItemRepo(registrations),
        ), evidence,
    )


def test_ready_genesis_and_empty_genesis_are_deterministic():
    value, _ = adapter()
    result = value.resolve(participant_id=PARTICIPANT_ID)
    assert result.state is TrustedCrtSourceResolutionState.READY
    assert result.plan.subject_kind is TrustedCrtSubjectKind.GENESIS
    assert result.plan.depth == 0 and result.plan.lineage_sources == ()
    assert result.plan.manifest_sha256 == trusted_crt_authorization_source_plan_manifest_sha256(result.plan)
    assert result.plan.manifest_sha256 == "a0673238c8150b0baf4585ee23de4922c8afed2b93c764fe70cad5c5be8baa3a"
    empty, _ = adapter(genesis_values=())
    assert empty.resolve(participant_id=PARTICIPANT_ID).plan.genesis_records == ()


@pytest.mark.parametrize("depth", (1, 3))
def test_ready_ordinary_root_to_target_without_writes(depth):
    value, evidence = adapter(depth)
    target = evidence[-1].record
    result = value.resolve(participant_id=target.child_participant_id, target_edge_id=target.edge_id)
    assert result.state is TrustedCrtSourceResolutionState.READY
    assert tuple(x.depth for x in result.plan.lineage_sources) == tuple(range(1, depth + 1))
    assert result.plan.compressed_public_key == target.child_compressed_public_key
    assert all(x.observation_required for x in result.plan.lineage_sources)
    assert result.plan.manifest_sha256 == {
        1: "9fab97fcf47e7a2d9996fd087cc14dd5271f32cbb873d846d24277f3ad302dfa",
        3: "9ae7b7195a73cc27de4934ba16fb6f5d037ab304e0965f86cca0ebd6dfe58668",
    }[depth]
    assert value._admission_edge_repository.writes == value._trusted_registration_repository.writes == 0


def test_genesis_repository_order_does_not_change_manifest():
    record = genesis_record()
    # A second canonical record can differ only by its canonical identity and lifecycle metadata.
    proposed = replace(record, record_id="00000000-0000-4000-8000-000000000099",
                       lifecycle_state=record.lifecycle_state.__class__.PROPOSED,
                       effective_at=None, lifecycle_changed_at=record.created_at)
    one, _ = adapter(genesis_values=(record, proposed))
    two, _ = adapter(genesis_values=(proposed, record))
    assert one.resolve(participant_id=PARTICIPANT_ID).plan.manifest_sha256 == two.resolve(participant_id=PARTICIPANT_ID).plan.manifest_sha256


def test_missing_target_is_typed_not_found():
    value, evidence = adapter()
    target = evidence[0].record
    value._admission_edge_repository.values = {}
    result = value.resolve(participant_id=target.child_participant_id, target_edge_id=target.edge_id)
    assert result.state is TrustedCrtSourceResolutionState.NOT_FOUND and result.plan is None


@pytest.mark.parametrize(
    "reads",
    (
        (None, lambda target: target),
        (lambda target: target, None),
        (lambda target: target, lambda target: proposed_edge(target)),
    ),
)
def test_target_appearance_disappearance_or_change_between_reads_is_unavailable(reads):
    value, evidence = adapter()
    target = evidence[0].record
    scripted = tuple(item(target) if callable(item) else item for item in reads)
    value._admission_edge_repository = ScriptedItemRepo({target.edge_id: scripted})
    with pytest.raises(TrustedCrtAuthorizationSourceUnavailable):
        resolve_ordinary(value, evidence)


def test_wrong_target_identity_and_missing_parent_fail_closed():
    value, evidence = adapter(3)
    target = evidence[-1].record
    with pytest.raises(TrustedCrtAuthorizationSourceUnavailable):
        value.resolve(participant_id="0" * 64, target_edge_id=target.edge_id)
    value, evidence = adapter(3)
    target = evidence[-1].record
    value._admission_edge_repository.values.pop(evidence[-2].record.edge_id)
    with pytest.raises(TrustedCrtAuthorizationSourceUnavailable):
        value.resolve(participant_id=target.child_participant_id, target_edge_id=target.edge_id)


def test_missing_ancestor_and_parent_digest_identity_and_depth_mismatches_fail_closed():
    value, evidence = adapter(3)
    target = evidence[-1].record
    value._admission_edge_repository.values.pop(evidence[0].record.edge_id)
    with pytest.raises(TrustedCrtAuthorizationSourceUnavailable):
        resolve_ordinary(value, evidence)


def test_parent_identity_mismatch_isolated_with_matching_depth_and_digest():
    value, evidence = adapter(3)
    root, target = evidence[0].record, evidence[-1].record
    alternate_child = "03f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
    alternate_registration = registration_for(
        root.child_compressed_public_key, alternate_child, 2,
        registration_id="00000000-0000-4000-8000-000000000061",
        txids=("4", "5"), amount=654,
    )
    alternate_parent = child_edge(
        root, alternate_registration, alternate_child, 2,
        "00000000-0000-4000-8000-000000000062",
    )
    rebound_target = replace(
        target,
        sponsor_basis_record_id=alternate_parent.edge_id,
        sponsor_basis_record_sha256=canonical_admission_edge_sha256(alternate_parent),
    )
    value._admission_edge_repository.values[target.edge_id] = rebound_target
    value._admission_edge_repository.values[alternate_parent.edge_id] = alternate_parent
    value._trusted_registration_repository.values[
        alternate_registration.registration_id
    ] = alternate_registration
    with pytest.raises(TrustedCrtAuthorizationSourceUnavailable):
        value.resolve(
            participant_id=target.child_participant_id,
            target_edge_id=target.edge_id,
        )


def test_parent_depth_mismatch_isolated_with_matching_identity(monkeypatch):
    value, evidence = adapter(3)
    parent, target = evidence[-2].record, evidence[-1].record
    expected_parent_digest = target.sponsor_basis_record_sha256
    object.__setattr__(parent, "child_depth", parent.child_depth - 1)
    monkeypatch.setattr(
        "app.services.trusted_crt_authorization_source_plan._edge_bytes",
        lambda edge: edge.edge_id.encode("ascii"),
    )
    monkeypatch.setattr(
        "app.services.trusted_crt_authorization_source_plan.canonical_admission_edge_sha256",
        lambda edge: expected_parent_digest if edge is parent else canonical_admission_edge_sha256(edge),
    )
    # All identity/key fields still match; only the selected parent's depth is
    # synthetically wrong, isolating the depth-arithmetic guard.
    with pytest.raises(TrustedCrtAuthorizationSourceUnavailable):
        value.resolve(
            participant_id=target.child_participant_id,
            target_edge_id=target.edge_id,
        )


def test_cross_record_identifier_collision_is_source_unavailable():
    value, evidence = adapter()
    original = evidence[0]
    colliding_registration = replace(
        original.trusted_registration,
        registration_id=original.record.edge_id,
    )
    colliding_edge = make_edge(colliding_registration)
    value._admission_edge_repository.values = {colliding_edge.edge_id: colliding_edge}
    value._trusted_registration_repository.values = {
        colliding_registration.registration_id: colliding_registration,
    }
    with pytest.raises(TrustedCrtAuthorizationSourceUnavailable):
        value.resolve(
            participant_id=colliding_edge.child_participant_id,
            target_edge_id=colliding_edge.edge_id,
        )

    value, evidence = adapter(3)
    target = evidence[-1].record
    value._admission_edge_repository.values[target.edge_id] = replace(
        target, sponsor_basis_record_sha256="0" * 64,
    )
    with pytest.raises(TrustedCrtAuthorizationSourceUnavailable):
        resolve_ordinary(value, evidence)

    value, evidence = adapter(3)
    target, wrong_parent = evidence[-1].record, evidence[0].record
    value._admission_edge_repository.values[target.edge_id] = replace(
        target,
        sponsor_basis_record_id=wrong_parent.edge_id,
        sponsor_basis_record_sha256=canonical_admission_edge_sha256(wrong_parent),
    )
    with pytest.raises(TrustedCrtAuthorizationSourceUnavailable):
        resolve_ordinary(value, evidence)


def test_cycle_repeated_id_and_malformed_maximum_depth_fail_closed():
    value, evidence = adapter(3)
    middle, target = evidence[1].record, evidence[2].record
    cyclic_middle = replace(
        middle,
        sponsor_basis_record_id=target.edge_id,
        sponsor_basis_record_sha256=canonical_admission_edge_sha256(target),
    )
    rebound_target = replace(
        target, sponsor_basis_record_sha256=canonical_admission_edge_sha256(cyclic_middle),
    )
    value._admission_edge_repository.values[middle.edge_id] = cyclic_middle
    value._admission_edge_repository.values[target.edge_id] = rebound_target
    with pytest.raises(TrustedCrtAuthorizationSourceUnavailable):
        resolve_ordinary(value, evidence)


def test_duplicate_child_identity_in_lineage_fails_closed():
    evidence = lineage_fixture(2)
    root, parent = evidence[0].record, evidence[1].record
    registration_value = registration_for(
        parent.child_compressed_public_key,
        root.child_compressed_public_key,
        3,
        registration_id="00000000-0000-4000-8000-000000000051",
        txids=("7", "8"),
        amount=987,
    )
    target = child_edge(
        parent, registration_value, root.child_compressed_public_key, 3,
        "00000000-0000-4000-8000-000000000052",
    )
    value = TrustedCrtAuthorizationSourcePlanAdapter(
        genesis_repository=GenesisRepo((genesis_record(),)),
        admission_edge_repository=ItemRepo({x.edge_id: x for x in (root, parent, target)}),
        trusted_registration_repository=ItemRepo({
            evidence[0].trusted_registration.registration_id: evidence[0].trusted_registration,
            evidence[1].trusted_registration.registration_id: evidence[1].trusted_registration,
            registration_value.registration_id: registration_value,
        }),
    )
    with pytest.raises(TrustedCrtAuthorizationSourceUnavailable):
        value.resolve(participant_id=target.child_participant_id, target_edge_id=target.edge_id)


@pytest.mark.parametrize("field,value", (("graph_or_protocol_id", "other.graph"), ("human_profile", "current_144")))
def test_malformed_graph_or_profile_source_fails_closed(field, value):
    adapter_value, evidence = adapter()
    target = evidence[0].record
    object.__setattr__(target, field, value)
    with pytest.raises(TrustedCrtAuthorizationSourceUnavailable):
        resolve_ordinary(adapter_value, evidence)

    value, evidence = adapter()
    target = evidence[0].record
    object.__setattr__(target, "child_depth", MAXIMUM_CANONICAL_CHILD_DEPTH + 1)
    with pytest.raises(TrustedCrtAuthorizationSourceUnavailable):
        resolve_ordinary(value, evidence)


def test_lifecycle_observation_hint_preserves_sources():
    value, evidence = adapter()
    edge = evidence[0].record
    reg = evidence[0].trusted_registration
    inactive = replace(reg, lifecycle_state=TrustedCovenantRegistrationLifecycle.REVOKED)
    changed_edge = replace(edge, trusted_registration_sha256=trusted_registration_sha256(inactive))
    value._admission_edge_repository.values[edge.edge_id] = changed_edge
    value._trusted_registration_repository.values[reg.registration_id] = inactive
    result = value.resolve(participant_id=edge.child_participant_id, target_edge_id=edge.edge_id)
    assert result.plan.lineage_sources[0].registration.lifecycle_state is TrustedCovenantRegistrationLifecycle.REVOKED
    assert result.plan.lineage_sources[0].observation_required is False


@pytest.mark.parametrize("registration_lifecycle", tuple(TrustedCovenantRegistrationLifecycle))
@pytest.mark.parametrize("edge_lifecycle", tuple(AdmissionEdgeLifecycle))
def test_observation_required_exact_complete_lifecycle_matrix(
    registration_lifecycle, edge_lifecycle,
):
    value, evidence = adapter()
    original_edge, original_registration = evidence[0].record, evidence[0].trusted_registration
    registration_value = registration_with_lifecycle(
        original_registration, registration_lifecycle,
    )
    edge_value = make_edge(registration_value, lifecycle=edge_lifecycle)
    value._admission_edge_repository.values[original_edge.edge_id] = edge_value
    value._trusted_registration_repository.values[original_registration.registration_id] = registration_value
    result = value.resolve(participant_id=edge_value.child_participant_id, target_edge_id=edge_value.edge_id)
    source = result.plan.lineage_sources[0]
    assert source.observation_required is (
        edge_lifecycle is AdmissionEdgeLifecycle.EFFECTIVE
        and registration_lifecycle is TrustedCovenantRegistrationLifecycle.ACTIVE
    )
    assert source.registration.lifecycle_state is registration_lifecycle
    with pytest.raises(TrustedCrtAuthorizationSourceUnavailable):
        replace(source, observation_required=not source.observation_required)


def test_active_effective_source_materializes_exactly_two_outpoints(monkeypatch):
    value, evidence = adapter()
    calls = []
    authoritative = trusted_outpoints_from_registration(evidence[0].trusted_registration)
    monkeypatch.setattr(
        "app.services.trusted_crt_authorization_source_plan.trusted_outpoints_from_registration",
        lambda registration: calls.append(registration.registration_id) or authoritative,
    )
    resolve_ordinary(value, evidence)
    assert calls == [evidence[0].trusted_registration.registration_id]


def test_missing_changed_and_digest_mismatched_registration_fail_closed():
    value, evidence = adapter()
    edge, registration_value = evidence[0].record, evidence[0].trusted_registration
    value._trusted_registration_repository.values = {}
    with pytest.raises(TrustedCrtAuthorizationSourceUnavailable): resolve_ordinary(value, evidence)

    value, evidence = adapter()
    edge, registration_value = evidence[0].record, evidence[0].trusted_registration
    changed = inactive_registration(registration_value, TrustedCovenantRegistrationLifecycle.REVOKED)
    value._trusted_registration_repository = ScriptedItemRepo(
        {registration_value.registration_id: (registration_value, changed)}
    )
    with pytest.raises(TrustedCrtAuthorizationSourceUnavailable): resolve_ordinary(value, evidence)

    value, evidence = adapter()
    edge = evidence[0].record
    value._admission_edge_repository.values[edge.edge_id] = replace(
        edge, trusted_registration_sha256="0" * 64,
    )
    with pytest.raises(TrustedCrtAuthorizationSourceUnavailable): resolve_ordinary(value, evidence)


def test_final_target_registration_and_genesis_rereads_detect_change():
    value, evidence = adapter()
    target = evidence[0].record
    value._admission_edge_repository = ScriptedItemRepo(
        {target.edge_id: (target, target, target, proposed_edge(target))}
    )
    with pytest.raises(TrustedCrtAuthorizationSourceUnavailable): resolve_ordinary(value, evidence)


def test_same_edge_alias_mutated_during_second_read_fails_closed():
    value, evidence = adapter()
    target = evidence[0].record
    value._admission_edge_repository = MutatingSameItemRepo(
        target, 2, mutate_edge_to_proposed,
    )
    with pytest.raises(TrustedCrtAuthorizationSourceUnavailable):
        resolve_ordinary(value, evidence)


def test_same_registration_alias_mutated_during_second_read_fails_closed():
    value, evidence = adapter()
    registration = evidence[0].trusted_registration
    value._trusted_registration_repository = MutatingSameItemRepo(
        registration, 2, mutate_registration_to_revoked,
    )
    with pytest.raises(TrustedCrtAuthorizationSourceUnavailable):
        resolve_ordinary(value, evidence)


def test_same_genesis_alias_mutated_between_snapshot_reads_fails_closed():
    value, _ = adapter()
    record = genesis_record()
    value._genesis_repository = MutatingSameGenesisRepo(
        (record,), 2, mutate_genesis_to_proposed,
    )
    with pytest.raises(TrustedCrtAuthorizationSourceUnavailable):
        value.resolve(participant_id=PARTICIPANT_ID)


def test_selected_edge_alias_mutated_during_final_target_reread_fails_closed():
    value, evidence = adapter()
    target = evidence[0].record
    value._admission_edge_repository = MutatingSameItemRepo(
        target, 3, mutate_edge_to_proposed,
    )
    with pytest.raises(TrustedCrtAuthorizationSourceUnavailable):
        resolve_ordinary(value, evidence)


def test_selected_registration_alias_mutated_during_final_reread_fails_closed():
    value, evidence = adapter()
    registration = evidence[0].trusted_registration
    value._trusted_registration_repository = MutatingSameItemRepo(
        registration, 3, mutate_registration_to_revoked,
    )
    with pytest.raises(TrustedCrtAuthorizationSourceUnavailable):
        resolve_ordinary(value, evidence)


def test_selected_genesis_alias_mutated_during_final_reread_fails_closed():
    value, _ = adapter()
    record = genesis_record()
    value._genesis_repository = MutatingSameGenesisRepo(
        (record,), 3, mutate_genesis_to_proposed,
    )
    with pytest.raises(TrustedCrtAuthorizationSourceUnavailable):
        value.resolve(participant_id=PARTICIPANT_ID)


def test_stable_same_reference_sources_are_accepted():
    value, evidence = adapter()
    target = evidence[0].record
    registration = evidence[0].trusted_registration
    record = genesis_record()
    value._admission_edge_repository = MutatingSameItemRepo(target, -1, lambda _: None)
    value._trusted_registration_repository = MutatingSameItemRepo(
        registration, -1, lambda _: None,
    )
    value._genesis_repository = MutatingSameGenesisRepo(
        (record,), -1, lambda _: None,
    )
    assert resolve_ordinary(value, evidence).state is TrustedCrtSourceResolutionState.READY


def test_returned_plan_sources_are_detached_from_repository_aliases():
    value, evidence = adapter()
    edge = evidence[0].record
    registration = evidence[0].trusted_registration
    record = genesis_record()
    value._genesis_repository = GenesisRepo((record,))
    result = resolve_ordinary(value, evidence)
    before = trusted_crt_authorization_source_plan_manifest_bytes(result.plan)

    mutate_edge_to_proposed(edge)
    mutate_registration_to_revoked(registration)
    mutate_genesis_to_proposed(record)

    assert trusted_crt_authorization_source_plan_manifest_bytes(result.plan) == before
    assert result.plan.manifest_sha256 == (
        trusted_crt_authorization_source_plan_manifest_sha256(result.plan)
    )
    assert result.plan.lineage_sources[0].edge is not edge
    assert result.plan.lineage_sources[0].registration is not registration
    assert result.plan.genesis_records[0] is not record


def test_not_found_final_genesis_reread_detects_change():
    value, evidence = adapter()
    target = evidence[0].record
    value._admission_edge_repository.values = {}
    record = genesis_record()
    changed = replace(
        record, lifecycle_state=CanonicalGenesisLifecycle.PROPOSED,
        effective_at=None, lifecycle_changed_at=record.created_at,
    )
    value._genesis_repository = ScriptedGenesisRepo(
        ((record,), (record,), (changed,), (changed,))
    )
    with pytest.raises(TrustedCrtAuthorizationSourceUnavailable):
        value.resolve(participant_id=target.child_participant_id, target_edge_id=target.edge_id)

    value, evidence = adapter()
    registration_value = evidence[0].trusted_registration
    changed = inactive_registration(registration_value, TrustedCovenantRegistrationLifecycle.REVOKED)
    value._trusted_registration_repository = ScriptedItemRepo(
        {registration_value.registration_id: (registration_value, registration_value, changed, changed)}
    )
    with pytest.raises(TrustedCrtAuthorizationSourceUnavailable): resolve_ordinary(value, evidence)

    value, evidence = adapter()
    record = genesis_record()
    changed_genesis = replace(
        record, lifecycle_state=CanonicalGenesisLifecycle.PROPOSED,
        effective_at=None, lifecycle_changed_at=record.created_at,
    )
    value._genesis_repository = ScriptedGenesisRepo(
        ((record,), (record,), (changed_genesis,), (changed_genesis,))
    )
    with pytest.raises(TrustedCrtAuthorizationSourceUnavailable): resolve_ordinary(value, evidence)


def test_genesis_snapshot_change_duplicate_id_digest_and_non_tuple_fail_closed():
    record = genesis_record()
    changed = replace(
        record, lifecycle_state=CanonicalGenesisLifecycle.PROPOSED,
        effective_at=None, lifecycle_changed_at=record.created_at,
    )
    for repository in (
        ScriptedGenesisRepo(((record,), (changed,))),
        GenesisRepo((record, changed)),
        GenesisRepo((record, record)),
        GenesisRepo([record]),
    ):
        value, _ = adapter()
        value._genesis_repository = repository
        with pytest.raises(TrustedCrtAuthorizationSourceUnavailable):
            value.resolve(participant_id=PARTICIPANT_ID)


def test_manifest_changes_with_selected_source_digest_and_is_canonical_ascii():
    first, evidence = adapter()
    first_plan = resolve_ordinary(first, evidence).plan
    second, second_evidence = adapter()
    edge, registration_value = second_evidence[0].record, second_evidence[0].trusted_registration
    changed = inactive_registration(registration_value, TrustedCovenantRegistrationLifecycle.REVOKED)
    second._trusted_registration_repository.values[registration_value.registration_id] = changed
    second._admission_edge_repository.values[edge.edge_id] = replace(
        edge, trusted_registration_sha256=trusted_registration_sha256(changed),
    )
    second_plan = second.resolve(participant_id=edge.child_participant_id, target_edge_id=edge.edge_id).plan
    manifest = trusted_crt_authorization_source_plan_manifest_bytes(second_plan)
    assert first_plan.manifest_sha256 != second_plan.manifest_sha256
    assert manifest.decode("ascii").encode("ascii") == manifest
    assert b'": ' not in manifest and b'", ' not in manifest and b"NaN" not in manifest


def test_caller_owned_sources_are_not_mutated():
    value, evidence = adapter(3)
    edges_before = tuple(canonical_admission_edge_bytes(item.record) for item in evidence)
    registrations_before = tuple(canonical_trusted_registration_bytes(item.trusted_registration) for item in evidence)
    genesis_before = canonical_genesis_record_bytes(genesis_record())
    resolve_ordinary(value, evidence)
    assert tuple(canonical_admission_edge_bytes(item.record) for item in evidence) == edges_before
    assert tuple(canonical_trusted_registration_bytes(item.trusted_registration) for item in evidence) == registrations_before
    assert canonical_genesis_record_bytes(genesis_record()) == genesis_before


def test_exact_source_types_and_subclasses_are_rejected():
    class GenesisSubclass(CanonicalGenesisRecord): pass
    record = genesis_record()
    subclass = GenesisSubclass(*(getattr(record, field) for field in record.__dataclass_fields__))
    value, _ = adapter()
    value._genesis_repository = GenesisRepo((subclass,))
    with pytest.raises(TrustedCrtAuthorizationSourceUnavailable):
        value.resolve(participant_id=PARTICIPANT_ID)

    class RegistrationSubclass(TrustedCovenantRegistration): pass
    value, evidence = adapter()
    registration_value = evidence[0].trusted_registration
    subclass_registration = RegistrationSubclass(*(
        getattr(registration_value, field) for field in registration_value.__dataclass_fields__
    ))
    value._trusted_registration_repository.values[registration_value.registration_id] = subclass_registration
    with pytest.raises(TrustedCrtAuthorizationSourceUnavailable): resolve_ordinary(value, evidence)


def test_public_contract_exact_tuple_and_primitive_rejection():
    value, evidence = adapter()
    plan = resolve_ordinary(value, evidence).plan
    for changes in (
        {"depth": True},
        {"genesis_records": list(plan.genesis_records)},
        {"lineage_sources": list(plan.lineage_sources)},
        {"relevant_records": list(plan.relevant_records)},
        {"human_interpretation_required": 1},
        {"subject_kind": "ordinary"},
    ):
        with pytest.raises(TrustedCrtAuthorizationSourceUnavailable):
            replace(plan, **changes)
    with pytest.raises(InvalidTrustedCrtAuthorizationSourceRequest):
        trusted_crt_authorization_source_plan_manifest_bytes(object())


def test_resolution_state_semantics_reject_non_none_not_found_plans_and_ready_mismatches():
    value, evidence = adapter()
    ready = resolve_ordinary(value, evidence)
    for invalid_plan in (object(), ready.plan):
        with pytest.raises(TrustedCrtAuthorizationSourceUnavailable):
            TrustedCrtAuthorizationSourceResolution(
                TrustedCrtSourceResolutionState.NOT_FOUND,
                ready.participant_id, ready.target_edge_id, invalid_plan,
            )
    with pytest.raises(TrustedCrtAuthorizationSourceUnavailable):
        replace(ready, participant_id="0" * 64)
    with pytest.raises(TrustedCrtAuthorizationSourceUnavailable):
        replace(ready, target_edge_id="00000000-0000-4000-8000-000000000099")
    with pytest.raises(TrustedCrtAuthorizationSourceUnavailable):
        TrustedCrtAuthorizationSourceResolution(
            TrustedCrtSourceResolutionState.NOT_FOUND,
            PARTICIPANT_ID, None, None,
        )


@pytest.mark.parametrize(
    "compressed",
    (
        "00" + "0" * 64,
        "04" + "0" * 64,
        "02" + "A" * 64,
        "02" + "0" * 62,
        "02" + "g" * 64,
        "zz" + "0" * 64,
    ),
)
def test_public_plan_rejects_noncanonical_compressed_keys(compressed):
    value, evidence = adapter()
    plan = resolve_ordinary(value, evidence).plan
    with pytest.raises(TrustedCrtAuthorizationSourceUnavailable):
        replace(plan, compressed_public_key=compressed)


def test_public_plan_binds_subject_depth_target_and_terminal_source():
    value, evidence = adapter(3)
    plan = resolve_ordinary(value, evidence).plan
    alternate = "0" * 64
    for changes in (
        {
            "participant_id": alternate,
            "compressed_public_key": "02" + alternate,
            "x_only_public_key": alternate,
        },
        {"depth": plan.depth - 1},
        {"target_edge_id": "00000000-0000-4000-8000-000000000099"},
        {"target_edge_sha256": "0" * 64},
    ):
        with pytest.raises(TrustedCrtAuthorizationSourceUnavailable):
            replace(plan, **changes)


def test_public_plan_rejects_reordered_noncontiguous_and_broken_lineage(monkeypatch):
    value, evidence = adapter(3)
    plan = resolve_ordinary(value, evidence).plan
    with pytest.raises(TrustedCrtAuthorizationSourceUnavailable):
        replace(plan, lineage_sources=tuple(reversed(plan.lineage_sources)))
    with pytest.raises(TrustedCrtAuthorizationSourceUnavailable):
        replace(plan, lineage_sources=(plan.lineage_sources[0], plan.lineage_sources[2]))

    child_source = plan.lineage_sources[1]
    broken_edge = replace(
        child_source.edge,
        sponsor_basis_record_id="00000000-0000-4000-8000-000000000099",
    )
    broken_digest = "9" * 64
    monkeypatch.setattr(
        "app.services.trusted_crt_authorization_source_plan.canonical_admission_edge_sha256",
        lambda edge: broken_digest if edge is broken_edge else canonical_admission_edge_sha256(edge),
    )
    broken_source = replace(
        child_source, edge=broken_edge, edge_sha256=broken_digest,
        edge_id=broken_edge.edge_id,
    )
    with pytest.raises(TrustedCrtAuthorizationSourceUnavailable):
        value._finish(**{
            field: (
                (plan.lineage_sources[0], broken_source, plan.lineage_sources[2])
                if field == "lineage_sources" else getattr(plan, field)
            )
            for field in plan.__dataclass_fields__ if field != "manifest_sha256"
        })


def test_public_plan_relevant_records_are_exact_sorted_union():
    value, evidence = adapter(3)
    plan = resolve_ordinary(value, evidence).plan
    variants = (
        plan.relevant_records[:-1],
        plan.relevant_records + (("00000000-0000-4000-8000-000000000099", "0" * 64),),
        plan.relevant_records + (plan.relevant_records[-1],),
        tuple(reversed(plan.relevant_records)),
    )
    for relevant in variants:
        with pytest.raises(TrustedCrtAuthorizationSourceUnavailable):
            replace(plan, relevant_records=relevant)


def test_public_plan_rejects_arbitrary_stale_and_mutated_manifest_digests():
    value, evidence = adapter()
    plan = resolve_ordinary(value, evidence).plan
    for digest in ("0" * 64, "f" * 64):
        with pytest.raises(TrustedCrtAuthorizationSourceUnavailable):
            replace(plan, manifest_sha256=digest)
    object.__setattr__(plan, "manifest_sha256", "0" * 64)
    with pytest.raises(TrustedCrtAuthorizationSourceUnavailable):
        trusted_crt_authorization_source_plan_manifest_bytes(plan)


def test_exact_edge_source_plan_and_resolution_subclasses_are_rejected():
    value, evidence = adapter()
    resolution = resolve_ordinary(value, evidence)
    source = resolution.plan.lineage_sources[0]

    class EdgeSubclass(type(source.edge)): pass
    edge_subclass = EdgeSubclass(*(
        getattr(source.edge, field) for field in source.edge.__dataclass_fields__
    ))
    with pytest.raises(TrustedCrtAuthorizationSourceUnavailable):
        replace(source, edge=edge_subclass)

    class SourceSubclass(TrustedCrtLineageSource): pass
    with pytest.raises(TrustedCrtAuthorizationSourceUnavailable):
        SourceSubclass(*(
            getattr(source, field) for field in source.__dataclass_fields__
        ))

    class PlanSubclass(TrustedCrtAuthorizationSourcePlan): pass
    with pytest.raises(TrustedCrtAuthorizationSourceUnavailable):
        PlanSubclass(*(
            getattr(resolution.plan, field)
            for field in resolution.plan.__dataclass_fields__
        ))

    class ResolutionSubclass(TrustedCrtAuthorizationSourceResolution): pass
    with pytest.raises(TrustedCrtAuthorizationSourceUnavailable):
        ResolutionSubclass(*(
            getattr(resolution, field) for field in resolution.__dataclass_fields__
        ))


def test_controlled_duplicate_edge_digest_defense(monkeypatch):
    value, evidence = adapter(3)
    target = evidence[-1].record
    duplicate = "d" * 64
    rebound_target = replace(target, sponsor_basis_record_sha256=duplicate)
    value._admission_edge_repository.values[target.edge_id] = rebound_target
    monkeypatch.setattr(
        "app.services.trusted_crt_authorization_source_plan.canonical_admission_edge_sha256",
        lambda edge: duplicate,
    )
    with pytest.raises(TrustedCrtAuthorizationSourceUnavailable):
        value.resolve(
            participant_id=target.child_participant_id,
            target_edge_id=target.edge_id,
        )


def test_controlled_repeated_id_cycle_defense_reaches_duplicate_check():
    value, evidence = adapter(3)
    parent, target = evidence[-2].record, evidence[-1].record
    repeated_parent = replace(parent, edge_id=target.edge_id)
    rebound_target = replace(
        target,
        sponsor_basis_record_id=target.edge_id,
        sponsor_basis_record_sha256=canonical_admission_edge_sha256(repeated_parent),
    )
    value._admission_edge_repository = ScriptedItemRepo({
        target.edge_id: (rebound_target, rebound_target, repeated_parent, repeated_parent),
    })
    # Strict positive depth makes a natural canonical cycle impossible; this
    # controlled same-ID sequence reaches the repeated-ID guard before another
    # parent traversal can occur.
    with pytest.raises(TrustedCrtAuthorizationSourceUnavailable):
        value.resolve(
            participant_id=target.child_participant_id,
            target_edge_id=target.edge_id,
        )


@pytest.mark.parametrize("repository_kind", ("edge", "registration"))
def test_edge_and_registration_repository_errors_are_sanitized(repository_kind):
    class Bad:
        def get(self, item_id): raise RuntimeError("secret connection table")
    value, evidence = adapter()
    if repository_kind == "edge":
        value._admission_edge_repository = Bad()
    else:
        value._trusted_registration_repository = Bad()
    with pytest.raises(TrustedCrtAuthorizationSourceUnavailable, match="^trusted CRT authorization source unavailable$"):
        resolve_ordinary(value, evidence)


@pytest.mark.parametrize("exception", (KeyboardInterrupt, SystemExit))
@pytest.mark.parametrize("repository_kind", ("edge", "registration"))
def test_edge_and_registration_base_exceptions_propagate(exception, repository_kind):
    class Stop:
        def get(self, item_id): raise exception()
    value, evidence = adapter()
    if repository_kind == "edge": value._admission_edge_repository = Stop()
    else: value._trusted_registration_repository = Stop()
    with pytest.raises(exception): resolve_ordinary(value, evidence)


@pytest.mark.parametrize("participant,target", ((PARTICIPANT_ID, "00000000-0000-4000-8000-000000000001"), ("A" * 64, None), ("0" * 64, "bad")))
def test_invalid_request_primitives(participant, target):
    value, _ = adapter()
    with pytest.raises(InvalidTrustedCrtAuthorizationSourceRequest):
        value.resolve(participant_id=participant, target_edge_id=target)


def test_repository_error_is_sanitized_and_base_exceptions_propagate():
    class Bad:
        def list_for_graph(self, graph): raise RuntimeError("postgres secret table")
    value, _ = adapter()
    value._genesis_repository = Bad()
    with pytest.raises(TrustedCrtAuthorizationSourceUnavailable, match="^trusted CRT authorization source unavailable$"):
        value.resolve(participant_id=PARTICIPANT_ID)
    for exception in (KeyboardInterrupt, SystemExit):
        class Stop:
            def list_for_graph(self, graph): raise exception()
        value._genesis_repository = Stop()
        with pytest.raises(exception): value.resolve(participant_id=PARTICIPANT_ID)
