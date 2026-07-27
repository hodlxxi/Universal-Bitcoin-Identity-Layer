from dataclasses import replace
from datetime import timedelta
from hashlib import sha256
import json

import pytest

from app.services.canonical_admission_edge import *
from app.services.canonical_sponsor_lineage import *
from app.services.covenant_relation import (
    EVALUATION_SCHEMA,
    OBSERVATION_SCHEMA,
    CovenantRelationEvaluation,
    CovenantRelationObservation,
)
from app.services.trusted_covenant_registration import (
    TrustedCovenantRegistrationLifecycle,
    trusted_registration_sha256,
)
from tests.unit.test_canonical_admission_edge import (
    NOW,
    GRANDCHILD,
    depth2,
    edge,
    genesis,
    registration,
    registration_for,
)

GREAT_GRANDCHILD = "03f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"


def observed(record, reg, *, confirmations=2, unspent=True):
    return CovenantRelationEvaluation(
        EVALUATION_SCHEMA,
        NETWORK,
        record.child_x_only_public_key,
        record.sponsor_x_only_public_key,
        NOW,
        900000,
        tuple(
            CovenantRelationObservation(
                OBSERVATION_SCHEMA,
                record.child_x_only_public_key,
                record.sponsor_x_only_public_key,
                binding.direction,
                binding.txid,
                binding.vout,
                binding.amount_sats,
                sha256(bytes.fromhex("0020" + binding.witness_script_sha256)).hexdigest(),
                binding.descriptor_sha256,
                confirmations,
                unspent,
            )
            for binding in reg.outpoints
        ),
    )


def child_edge(parent, reg, child_key, depth, edge_id):
    early, middle, late = cascade_heights(depth)
    sponsor = parent.child_compressed_public_key
    values = dict(
        schema=parent.schema,
        edge_version=parent.edge_version,
        edge_id=edge_id,
        graph_or_protocol_id=parent.graph_or_protocol_id,
        network=parent.network,
        human_profile=parent.human_profile,
        verification_rule=parent.verification_rule,
        sponsor_participant_id=sponsor[2:],
        sponsor_compressed_public_key=sponsor,
        sponsor_x_only_public_key=sponsor[2:],
        sponsor_depth=depth - 1,
        child_participant_id=child_key[2:],
        child_compressed_public_key=child_key,
        child_x_only_public_key=child_key[2:],
        child_depth=depth,
        early_height=early,
        middle_height=middle,
        late_height=late,
        trusted_registration_id=reg.registration_id,
        trusted_registration_sha256=trusted_registration_sha256(reg),
        pair_sha256=reg.pair_sha256,
        validator_version=reg.validator_version,
        sponsor_basis_kind=SponsorBasisKind.CANONICAL_ADMISSION_EDGE,
        sponsor_basis_record_id=parent.edge_id,
        sponsor_basis_record_sha256=canonical_admission_edge_sha256(parent),
        lifecycle_state=AdmissionEdgeLifecycle.EFFECTIVE,
        created_at=NOW,
        lifecycle_changed_at=NOW,
        effective_at=NOW,
        superseded_by_edge_id=None,
        legs=(
            CanonicalAdmissionLeg(
                AdmissionEdgeDirection.SPONSOR_TO_CHILD,
                sponsor[2:], sponsor, sponsor[2:],
                child_key[2:], child_key, child_key[2:],
                early, middle, reg.mirrored_pair.earlier_leg.raw_script_hex,
                reg.outpoints[0].txid, reg.outpoints[0].vout,
                reg.outpoints[0].amount_sats, reg.outpoints[0].witness_script_sha256, None,
            ),
            CanonicalAdmissionLeg(
                AdmissionEdgeDirection.CHILD_TO_SPONSOR,
                child_key[2:], child_key, child_key[2:],
                sponsor[2:], sponsor, sponsor[2:],
                middle, late, reg.mirrored_pair.later_leg.raw_script_hex,
                reg.outpoints[1].txid, reg.outpoints[1].vout,
                reg.outpoints[1].amount_sats, reg.outpoints[1].witness_script_sha256, None,
            ),
        ),
        contradiction_context=AdmissionContradictionContext(None, (), False),
        explicit_non_claims=parent.explicit_non_claims,
        retention_policy=RETENTION_POLICY,
        human_interpretation_required=True,
    )
    return CanonicalAdmissionEdge(**values)


def lineage_fixture(depth=3):
    reg1 = registration()
    one = edge(reg1)
    items = [CanonicalSponsorLineageEdgeEvidence(one, reg1, observed(one, reg1))]
    if depth >= 2:
        reg2 = registration_for(
            one.child_compressed_public_key,
            GRANDCHILD,
            2,
            registration_id="00000000-0000-4000-8000-000000000031",
            txids=("d", "e"),
            amount=456,
        )
        two = depth2(reg2, one)
        items.append(CanonicalSponsorLineageEdgeEvidence(two, reg2, observed(two, reg2)))
    if depth >= 3:
        reg3 = registration_for(
            two.child_compressed_public_key,
            GREAT_GRANDCHILD,
            3,
            registration_id="00000000-0000-4000-8000-000000000041",
            txids=("f", "9"),
            amount=789,
        )
        three = child_edge(
            two, reg3, GREAT_GRANDCHILD, 3,
            "00000000-0000-4000-8000-000000000042",
        )
        items.append(CanonicalSponsorLineageEdgeEvidence(three, reg3, observed(three, reg3)))
    return tuple(items)


def evaluate(items=None, genesis_value=None):
    items = items or lineage_fixture()
    target = max(items, key=lambda item: item.record.child_depth)
    return evaluate_canonical_sponsor_lineage(
        target.record.edge_id,
        edge_evidence=items,
        genesis_evaluation=genesis_value or genesis(),
        evaluated_at=NOW,
    )


@pytest.mark.parametrize("depth", (1, 2, 3))
def test_real_active_lineages(depth):
    items = lineage_fixture(depth)
    result = evaluate(items)
    assert result.state is CanonicalSponsorLineageState.ACTIVE
    assert tuple(node.depth for node in result.lineage_nodes) == tuple(range(1, depth + 1))
    assert all(
        node.local_evaluation_state is AdmissionEdgeEvaluationState.ACTIVE
        and node.local_evaluation_reason is AdmissionEdgeCurrentReason.EXACT_CURRENT_EDGE_ACTIVE
        for node in result.lineage_nodes
    )
    assert len(result.relevant_records) == 1 + 2 * depth
    assert parse_canonical_sponsor_lineage_evaluation(
        canonical_sponsor_lineage_evaluation_bytes(result)
    ) == result


def test_depth3_determinism_and_pinned_digest():
    items = lineage_fixture()
    ordered = evaluate(items)
    shuffled = evaluate((items[2], items[0], items[1]))
    assert ordered == shuffled
    assert canonical_sponsor_lineage_evaluation_bytes(ordered) == canonical_sponsor_lineage_evaluation_bytes(shuffled)
    assert canonical_sponsor_lineage_evaluation_sha256(ordered) == canonical_sponsor_lineage_evaluation_sha256(shuffled)
    assert len(ordered.relevant_records) == 7
    assert ordered.target_participant_id == items[-1].record.child_participant_id
    assert canonical_sponsor_lineage_evaluation_sha256(ordered) == (
        "fed39d556a9d9259411f7a86f57d54141134a9990a8c2a502c2a727491416d5e"
    )


def test_local_current_contract_is_distinct_and_canonical():
    item = lineage_fixture(1)[0]
    current = evaluate_canonical_admission_edge_current(
        item.record,
        trusted_registration=item.trusted_registration,
        observation_evaluation=item.observation_evaluation,
        genesis_evaluation=genesis(),
        evaluated_at=NOW,
    )
    legacy = evaluate_canonical_admission_edge(
        item.record,
        trusted_registration=item.trusted_registration,
        observation_evaluation=item.observation_evaluation,
        genesis_evaluation=genesis(),
        evaluated_at=NOW,
    )
    assert CanonicalAdmissionEdgeCurrentEvaluation is not CanonicalAdmissionEdgeEvaluation
    assert current.reason_code is AdmissionEdgeCurrentReason.EXACT_CURRENT_EDGE_ACTIVE
    assert legacy.reason_code is AdmissionEdgeReason.EXACT_DEPTH1_ADMISSION_ACTIVE
    encoded = canonical_admission_edge_current_evaluation_bytes(current)
    assert parse_canonical_admission_edge_current_evaluation(encoded) == current
    assert canonical_admission_edge_current_evaluation_sha256(current) == sha256(encoded).hexdigest()


def with_edge_state(item, lifecycle):
    context = AdmissionContradictionContext(None, (), False)
    if lifecycle in (AdmissionEdgeLifecycle.DISPUTED, AdmissionEdgeLifecycle.REVOKED):
        context = AdmissionContradictionContext(
            "matrix contradiction", ("c" * 64,), lifecycle is AdmissionEdgeLifecycle.DISPUTED
        )
    record = replace(
        item.record,
        lifecycle_state=lifecycle,
        contradiction_context=context,
        effective_at=NOW if lifecycle is AdmissionEdgeLifecycle.EFFECTIVE else None,
        superseded_by_edge_id=(
            "00000000-0000-4000-8000-000000000099"
            if lifecycle is AdmissionEdgeLifecycle.SUPERSEDED else None
        ),
    )
    return CanonicalSponsorLineageEdgeEvidence(
        record, item.trusted_registration, item.observation_evaluation
    )


@pytest.mark.parametrize(
    ("position", "lifecycle", "state", "reason"),
    (
        (0, AdmissionEdgeLifecycle.PROPOSED, CanonicalSponsorLineageState.PROVISIONAL, CanonicalSponsorLineageReason.ANCESTOR_PROVISIONAL),
        (0, AdmissionEdgeLifecycle.DISPUTED, CanonicalSponsorLineageState.DISPUTED, CanonicalSponsorLineageReason.ANCESTOR_DISPUTED),
        (0, AdmissionEdgeLifecycle.REVOKED, CanonicalSponsorLineageState.LINEAGE_INACTIVE, CanonicalSponsorLineageReason.ANCESTOR_EDGE_INACTIVE),
        (1, AdmissionEdgeLifecycle.SUPERSEDED, CanonicalSponsorLineageState.LINEAGE_INACTIVE, CanonicalSponsorLineageReason.ANCESTOR_EDGE_INACTIVE),
        (2, AdmissionEdgeLifecycle.PROPOSED, CanonicalSponsorLineageState.PROVISIONAL, CanonicalSponsorLineageReason.TARGET_PROVISIONAL),
        (2, AdmissionEdgeLifecycle.DISPUTED, CanonicalSponsorLineageState.DISPUTED, CanonicalSponsorLineageReason.TARGET_DISPUTED),
        (2, AdmissionEdgeLifecycle.REVOKED, CanonicalSponsorLineageState.LINEAGE_INACTIVE, CanonicalSponsorLineageReason.TARGET_EDGE_INACTIVE),
    ),
)
def test_root_to_target_edge_state_propagation(position, lifecycle, state, reason):
    items = list(lineage_fixture())
    items[position] = with_edge_state(items[position], lifecycle)
    # Rebind descendants so a non-effective parent remains structurally exact.
    for index in range(position + 1, len(items)):
        record = replace(
            items[index].record,
            sponsor_basis_record_sha256=canonical_admission_edge_sha256(items[index - 1].record),
        )
        items[index] = CanonicalSponsorLineageEdgeEvidence(
            record, items[index].trusted_registration, items[index].observation_evaluation
        )
    result = evaluate(tuple(items))
    assert (result.state, result.reason_code, result.controlling_depth) == (
        state, reason, position + 1
    )


@pytest.mark.parametrize(
    ("genesis_state", "genesis_reason", "state", "reason"),
    (
        (CanonicalGenesisEvaluationState.PROVISIONAL, "proposed_only", CanonicalSponsorLineageState.PROVISIONAL, CanonicalSponsorLineageReason.GENESIS_PROVISIONAL),
        (CanonicalGenesisEvaluationState.DISPUTED, "controlling_dispute", CanonicalSponsorLineageState.DISPUTED, CanonicalSponsorLineageReason.GENESIS_DISPUTED),
        (CanonicalGenesisEvaluationState.LINEAGE_INACTIVE, "all_records_revoked", CanonicalSponsorLineageState.LINEAGE_INACTIVE, CanonicalSponsorLineageReason.GENESIS_LINEAGE_INACTIVE),
        (CanonicalGenesisEvaluationState.UNKNOWN, "effective_timestamp_in_future", CanonicalSponsorLineageState.UNKNOWN, CanonicalSponsorLineageReason.GENESIS_UNKNOWN),
    ),
)
def test_genesis_precedes_every_descendant(genesis_state, genesis_reason, state, reason):
    base = genesis()
    changed = replace(
        base,
        state=genesis_state,
        reason_code=genesis_reason,
        selected_effective_record_id=None,
        selected_effective_record_sha256=None,
    )
    items = list(lineage_fixture())
    items[2] = with_edge_state(items[2], AdmissionEdgeLifecycle.DISPUTED)
    result = evaluate(tuple(items), changed)
    assert (result.state, result.reason_code, result.controlling_depth, result.controlling_edge_id) == (
        state, reason, 0, None
    )


def mutate_observation(item, kind):
    observations = item.observation_evaluation.observations
    if kind == "missing":
        observations = observations[:1]
    elif kind == "spent":
        observations = (replace(observations[0], unspent=False), observations[1])
    elif kind == "confirmations":
        observations = (replace(observations[0], confirmations=0), observations[1])
    elif kind == "binding":
        observations = (replace(observations[0], txid="8" * 64), observations[1])
    return CanonicalSponsorLineageEdgeEvidence(
        item.record,
        item.trusted_registration,
        replace(item.observation_evaluation, observations=observations),
    )


@pytest.mark.parametrize("position", (0, 1, 2))
@pytest.mark.parametrize(
    ("kind", "state"),
    (
        ("missing", CanonicalSponsorLineageState.LINEAGE_INACTIVE),
        ("spent", CanonicalSponsorLineageState.LINEAGE_INACTIVE),
        ("confirmations", CanonicalSponsorLineageState.LINEAGE_INACTIVE),
        ("binding", CanonicalSponsorLineageState.UNKNOWN),
    ),
)
def test_observation_state_propagation(position, kind, state):
    items = list(lineage_fixture())
    items[position] = mutate_observation(items[position], kind)
    result = evaluate(tuple(items))
    target = position == 2
    expected_reason = (
        CanonicalSponsorLineageReason.TARGET_LOCAL_EVALUATION_UNKNOWN
        if target and state is CanonicalSponsorLineageState.UNKNOWN
        else CanonicalSponsorLineageReason.ANCESTOR_LOCAL_EVALUATION_UNKNOWN
        if state is CanonicalSponsorLineageState.UNKNOWN
        else CanonicalSponsorLineageReason.TARGET_EDGE_INACTIVE
        if target
        else CanonicalSponsorLineageReason.ANCESTOR_EDGE_INACTIVE
    )
    assert (result.state, result.reason_code, result.controlling_depth) == (
        state, expected_reason, position + 1
    )


@pytest.mark.parametrize("position", (0, 1, 2))
@pytest.mark.parametrize(
    ("lifecycle", "state"),
    (
        (TrustedCovenantRegistrationLifecycle.DISPUTED, CanonicalSponsorLineageState.DISPUTED),
        (TrustedCovenantRegistrationLifecycle.REVOKED, CanonicalSponsorLineageState.LINEAGE_INACTIVE),
        (TrustedCovenantRegistrationLifecycle.SUPERSEDED, CanonicalSponsorLineageState.LINEAGE_INACTIVE),
    ),
)
def test_registration_state_propagation(position, lifecycle, state):
    items = list(lineage_fixture())
    old = items[position]
    reg = replace(
        old.trusted_registration,
        lifecycle_state=lifecycle,
        superseded_by_registration_id=(
            "00000000-0000-4000-8000-000000000098"
            if lifecycle is TrustedCovenantRegistrationLifecycle.SUPERSEDED else None
        ),
    )
    record = replace(
        old.record,
        trusted_registration_sha256=trusted_registration_sha256(reg),
    )
    items[position] = CanonicalSponsorLineageEdgeEvidence(
        record, reg, old.observation_evaluation
    )
    for index in range(position + 1, len(items)):
        items[index] = replace(
            items[index],
            record=replace(
                items[index].record,
                sponsor_basis_record_sha256=canonical_admission_edge_sha256(
                    items[index - 1].record
                ),
            ),
        )
    result = evaluate(tuple(items))
    target = position == 2
    reason = (
        CanonicalSponsorLineageReason.TARGET_DISPUTED
        if target and state is CanonicalSponsorLineageState.DISPUTED
        else CanonicalSponsorLineageReason.ANCESTOR_DISPUTED
        if state is CanonicalSponsorLineageState.DISPUTED
        else CanonicalSponsorLineageReason.TARGET_EDGE_INACTIVE
        if target
        else CanonicalSponsorLineageReason.ANCESTOR_EDGE_INACTIVE
    )
    assert (result.state, result.reason_code, result.controlling_depth) == (
        state, reason, position + 1
    )


def test_earliest_ancestor_controls_mixed_failures():
    items = list(lineage_fixture())
    items[0] = with_edge_state(items[0], AdmissionEdgeLifecycle.REVOKED)
    items[1] = with_edge_state(items[1], AdmissionEdgeLifecycle.DISPUTED)
    for index in (1, 2):
        items[index] = replace(
            items[index],
            record=replace(
                items[index].record,
                sponsor_basis_record_sha256=canonical_admission_edge_sha256(
                    items[index - 1].record
                ),
            ),
        )
    result = evaluate(tuple(items))
    assert result.reason_code is CanonicalSponsorLineageReason.ANCESTOR_EDGE_INACTIVE
    assert result.controlling_depth == 1


@pytest.mark.parametrize(
    ("first_position", "first_kind", "later_position", "later_lifecycle", "reason", "depth"),
    (
        (0, "disputed", 2, AdmissionEdgeLifecycle.REVOKED, CanonicalSponsorLineageReason.ANCESTOR_DISPUTED, 1),
        (1, "proposed", 2, AdmissionEdgeLifecycle.REVOKED, CanonicalSponsorLineageReason.ANCESTOR_PROVISIONAL, 2),
        (1, "binding", 2, AdmissionEdgeLifecycle.DISPUTED, CanonicalSponsorLineageReason.ANCESTOR_LOCAL_EVALUATION_UNKNOWN, 2),
    ),
)
def test_mixed_root_to_target_precedence(
    first_position, first_kind, later_position, later_lifecycle, reason, depth
):
    items = list(lineage_fixture())
    if first_kind == "binding":
        items[first_position] = mutate_observation(items[first_position], "binding")
    else:
        lifecycle = (
            AdmissionEdgeLifecycle.DISPUTED
            if first_kind == "disputed"
            else AdmissionEdgeLifecycle.PROPOSED
        )
        items[first_position] = with_edge_state(items[first_position], lifecycle)
    items[later_position] = with_edge_state(items[later_position], later_lifecycle)
    for index in range(1, len(items)):
        items[index] = replace(
            items[index],
            record=replace(
                items[index].record,
                sponsor_basis_record_sha256=canonical_admission_edge_sha256(
                    items[index - 1].record
                ),
            ),
        )
    result = evaluate(tuple(items))
    assert (result.reason_code, result.controlling_depth) == (reason, depth)


@pytest.mark.parametrize(
    ("mutator", "reason"),
    (
        (lambda xs: (), CanonicalSponsorLineageReason.MISSING_TARGET_EVIDENCE),
        (lambda xs: (xs[0], xs[2]), CanonicalSponsorLineageReason.MISSING_PARENT_EVIDENCE),
        (lambda xs: xs + (xs[0],), CanonicalSponsorLineageReason.DUPLICATE_EDGE_ID),
        (lambda xs: (xs[0], xs[1]), CanonicalSponsorLineageReason.MISSING_TARGET_EVIDENCE),
    ),
)
def test_structural_failures(mutator, reason):
    items = lineage_fixture()
    changed = mutator(items)
    result = evaluate_canonical_sponsor_lineage(
        items[-1].record.edge_id,
        edge_evidence=changed,
        genesis_evaluation=genesis(),
        evaluated_at=NOW,
    )
    assert result.reason_code is reason


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("target_depth", True),
        ("target_edge_sha256", "A" * 64),
        ("target_participant_id", None),
        ("controlling_depth", 1),
        ("controlling_edge_id", "00000000-0000-4000-8000-000000000021"),
        ("selected_genesis_record_id", None),
        ("relevant_records", ()),
        ("lineage_nodes", ()),
    ),
)
def test_evaluation_constructor_forgery_is_rejected(field, value):
    active = evaluate()
    with pytest.raises(InvalidCanonicalSponsorLineage):
        replace(active, **{field: value})


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("depth", True),
        ("edge_id", "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"),
        ("edge_sha256", "A" * 64),
        ("child_participant_id", GENESIS_PARTICIPANT_ID),
        ("local_evaluation_reason", AdmissionEdgeCurrentReason.RECORD_REVOKED),
        ("trusted_registration_sha256", None),
    ),
)
def test_node_constructor_forgery_is_rejected(field, value):
    node = evaluate().lineage_nodes[0]
    with pytest.raises(InvalidCanonicalSponsorLineage):
        replace(node, **{field: value})


@pytest.mark.parametrize("parser_name", ("local", "lineage"))
@pytest.mark.parametrize(
    "mutation",
    ("extra", "missing", "float", "nan", "offset", "microseconds", "duplicate"),
)
def test_canonical_json_adversarial(parser_name, mutation):
    item = lineage_fixture(1)[0]
    if parser_name == "local":
        value = evaluate_canonical_admission_edge_current(
            item.record,
            trusted_registration=item.trusted_registration,
            observation_evaluation=item.observation_evaluation,
            genesis_evaluation=genesis(),
            evaluated_at=NOW,
        )
        encoded = canonical_admission_edge_current_evaluation_bytes(value).decode()
        parser = parse_canonical_admission_edge_current_evaluation
    else:
        value = evaluate((item,))
        encoded = canonical_sponsor_lineage_evaluation_bytes(value).decode()
        parser = parse_canonical_sponsor_lineage_evaluation
    data = json.loads(encoded)
    if mutation == "extra":
        data["extra"] = True
    elif mutation == "missing":
        data.pop(next(iter(data)))
    elif mutation == "float":
        data["human_interpretation_required"] = 1.5
    elif mutation == "nan":
        data["human_interpretation_required"] = float("nan")
    elif mutation == "offset":
        data["evaluated_at"] = data["evaluated_at"][:-1] + "+00:00"
    elif mutation == "microseconds":
        data["evaluated_at"] = data["evaluated_at"][:-1] + ".000001Z"
    if mutation == "duplicate":
        encoded = encoded[:-1] + ',"schema":"duplicate"}'
    else:
        encoded = json.dumps(data, sort_keys=True, separators=(",", ":"), allow_nan=True)
    with pytest.raises((InvalidCanonicalAdmissionEdge, InvalidCanonicalSponsorLineage)):
        parser(encoded)


@pytest.mark.parametrize(
    "bad",
    (
        NOW.replace(tzinfo=None),
        NOW.replace(microsecond=1),
        NOW.astimezone(tz=__import__("datetime").timezone(timedelta(hours=1))),
    ),
)
def test_noncanonical_time_is_bounded(bad):
    items = lineage_fixture(1)
    with pytest.raises(InvalidCanonicalSponsorLineage):
        evaluate_canonical_sponsor_lineage(
            items[0].record.edge_id,
            edge_evidence=items,
            genesis_evaluation=genesis(),
            evaluated_at=bad,
        )
