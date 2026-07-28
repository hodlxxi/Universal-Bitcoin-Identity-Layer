from dataclasses import replace
from datetime import timedelta
import json

import pytest

from app.services.canonical_crt_membership import *
from app.services.canonical_genesis_record import canonical_genesis_evaluation_sha256
from app.services.canonical_sponsor_lineage import (
    CanonicalSponsorLineageReason,
    CanonicalSponsorLineageState,
    canonical_sponsor_lineage_evaluation_sha256,
)
from tests.unit.test_canonical_admission_edge import NOW, genesis
from tests.unit.test_canonical_sponsor_lineage import (
    evaluate,
    lineage_fixture,
    mutate_observation,
    with_edge_state,
)
from app.services.canonical_admission_edge import (
    AdmissionEdgeLifecycle,
    canonical_admission_edge_sha256,
)


def genesis_membership(source=None, **changes):
    source = source or genesis()
    values = dict(
        participant_id=source.genesis_participant_id,
        compressed_public_key=source.compressed_public_key,
        x_only_public_key=source.x_only_public_key,
        depth=0,
        evaluated_at=source.evaluated_at,
        genesis_evaluation=source,
    )
    values.update(changes)
    return evaluate_canonical_crt_membership(**values)


def ordinary_membership(source=None, **changes):
    source = source or evaluate()
    values = dict(
        participant_id=source.target_participant_id,
        compressed_public_key=source.target_compressed_public_key,
        x_only_public_key=source.target_x_only_public_key,
        depth=source.target_depth,
        target_edge_id=source.target_edge_id,
        evaluated_at=NOW,
        lineage_evaluation=source,
    )
    values.update(changes)
    return evaluate_canonical_crt_membership(**values)


def test_active_genesis_round_trip_and_pinned_digests():
    source = genesis()
    result = genesis_membership(source)
    assert (result.state, result.reason_code) == (
        CanonicalCrtMembershipState.GENESIS_ACTIVE,
        CanonicalCrtMembershipReason.EXACT_GENESIS_MEMBERSHIP_ACTIVE,
    )
    assert result.relevant_records == source.relevant_records
    assert result.source_evaluation_sha256 == canonical_genesis_evaluation_sha256(source)
    assert result.source_evaluation_sha256 == "b232285e842d7bc2ac3aed0845464ad7caed8252ed69d31ad5059e1ba42a9ebb"
    assert canonical_crt_membership_evaluation_sha256(result) == (
        "d56fda10cd7181f987560b719e23af6620e187ffdc83a5bea9f5ca33bcf3ab29"
    )
    assert parse_canonical_crt_membership_evaluation(
        canonical_crt_membership_evaluation_bytes(result)
    ) == result


@pytest.mark.parametrize(
    ("source_state", "source_reason", "state", "reason"),
    (
        ("provisional", "proposed_only", CanonicalCrtMembershipState.PROVISIONAL,
         CanonicalCrtMembershipReason.GENESIS_PROVISIONAL),
        ("disputed", "controlling_dispute", CanonicalCrtMembershipState.DISPUTED,
         CanonicalCrtMembershipReason.GENESIS_DISPUTED),
        ("lineage_inactive", "all_records_revoked", CanonicalCrtMembershipState.LINEAGE_INACTIVE,
         CanonicalCrtMembershipReason.GENESIS_LINEAGE_INACTIVE),
        ("unknown", "no_records", CanonicalCrtMembershipState.UNKNOWN,
         CanonicalCrtMembershipReason.GENESIS_UNKNOWN),
    ),
)
def test_genesis_state_mapping(source_state, source_reason, state, reason):
    source = genesis()
    source = replace(
        source,
        state=type(source.state)(source_state),
        reason_code=source_reason,
        selected_effective_record_id=None,
        selected_effective_record_sha256=None,
    )
    result = genesis_membership(source)
    assert (result.state, result.reason_code) == (state, reason)
    assert result.source_reason_code == source_reason
    assert result.controlling_depth == 0


@pytest.mark.parametrize("depth", (1, 2, 3))
def test_active_ordinary_membership(depth):
    source = evaluate(lineage_fixture(depth))
    result = ordinary_membership(source)
    assert (result.state, result.reason_code) == (
        CanonicalCrtMembershipState.ACTIVE,
        CanonicalCrtMembershipReason.EXACT_PARTICIPANT_MEMBERSHIP_ACTIVE,
    )
    assert result.source_evaluation_sha256 == canonical_sponsor_lineage_evaluation_sha256(source)
    assert result.relevant_records == source.relevant_records
    assert len(result.relevant_records) == 1 + 2 * depth
    assert result.controlling_depth is result.controlling_edge_id is None
    if depth == 3:
        assert result.source_evaluation_sha256 == (
            "fed39d556a9d9259411f7a86f57d54141134a9990a8c2a502c2a727491416d5e"
        )
        assert canonical_crt_membership_evaluation_sha256(result) == (
            "b79a29168180ba897a81ebbd8143262be6196b93c5603317a16831a3a9c1cee3"
        )


@pytest.mark.parametrize(
    ("position", "expected_state", "expected_reason"),
    (
        (2, CanonicalCrtMembershipState.EDGE_INACTIVE,
         CanonicalCrtMembershipReason.TARGET_EDGE_INACTIVE),
        (1, CanonicalCrtMembershipState.LINEAGE_INACTIVE,
         CanonicalCrtMembershipReason.ANCESTOR_EDGE_INACTIVE),
    ),
)
@pytest.mark.parametrize(
    "lifecycle",
    (AdmissionEdgeLifecycle.REVOKED, AdmissionEdgeLifecycle.SUPERSEDED),
)
def test_target_and_ancestor_inactivity_are_distinct(position, expected_state, expected_reason, lifecycle):
    items = list(lineage_fixture(2))
    items[position - 1] = with_edge_state(items[position - 1], lifecycle)
    for index in range(position, len(items)):
        from app.services.canonical_admission_edge import canonical_admission_edge_sha256
        record = replace(
            items[index].record,
            sponsor_basis_record_sha256=canonical_admission_edge_sha256(items[index - 1].record),
        )
        items[index] = type(items[index])(
            record, items[index].trusted_registration, items[index].observation_evaluation
        )
    source = evaluate(tuple(items))
    result = ordinary_membership(source)
    assert (result.state, result.reason_code) == (expected_state, expected_reason)
    assert result.controlling_depth == position


@pytest.mark.parametrize(
    "reason",
    tuple(reason for reason in CanonicalSponsorLineageReason if reason.value != "exact_lineage_active"),
)
def test_every_lineage_reason_maps_without_collapsing(reason):
    source = evaluate()
    requested = (
        source.target_participant_id, source.target_compressed_public_key,
        source.target_x_only_public_key, source.target_depth, source.target_edge_id,
    )
    mapping_state = (
        "provisional" if "provisional" in reason.value else
        "disputed" if "disputed" in reason.value else
        "lineage_inactive" if reason.value.endswith("edge_inactive")
        or reason.value == "genesis_lineage_inactive" else "unknown"
    )
    state = type(source.state)(mapping_state)
    metadata_absent = reason in {
        CanonicalSponsorLineageReason.MISSING_TARGET_EVIDENCE,
        CanonicalSponsorLineageReason.MALFORMED_OR_UNTRUSTED_INPUT,
    }
    kwargs = dict(state=state, reason_code=reason)
    if metadata_absent:
        kwargs.update(
            target_edge_sha256=None, target_participant_id=None,
            target_compressed_public_key=None, target_x_only_public_key=None,
            target_depth=None, selected_genesis_record_id=None,
            selected_genesis_record_sha256=None, lineage_nodes=(), relevant_records=(),
            controlling_depth=None, controlling_edge_id=None,
        )
    elif reason.value.startswith("genesis_"):
        kwargs.update(controlling_depth=0, controlling_edge_id=None)
    elif reason.value.startswith(("ancestor_", "target_")):
        position = source.target_depth if reason.value.startswith("target_") else 1
        kwargs.update(controlling_depth=position,
                      controlling_edge_id=source.lineage_nodes[position - 1].edge_id)
    else:
        kwargs.update(controlling_depth=None, controlling_edge_id=None)
    forged = replace(source, **kwargs)
    result = ordinary_membership(
        forged, participant_id=requested[0], compressed_public_key=requested[1],
        x_only_public_key=requested[2], depth=requested[3], target_edge_id=requested[4],
    )
    assert result.reason_code.value == reason.value


def test_source_binding_failures_are_unknown_and_control_free():
    source = evaluate()
    result = ordinary_membership(source, evaluated_at=NOW + timedelta(seconds=1))
    assert (result.state, result.reason_code, result.controlling_depth) == (
        CanonicalCrtMembershipState.UNKNOWN,
        CanonicalCrtMembershipReason.SOURCE_TIME_MISMATCH,
        None,
    )
    result = ordinary_membership(source, target_edge_id="00000000-0000-4000-8000-000000000099")
    assert result.reason_code is CanonicalCrtMembershipReason.SOURCE_SUBJECT_MISMATCH


@pytest.mark.parametrize(
    "changes",
    (
        {"depth": True},
        {"depth": 1},
        {"target_edge_id": "00000000-0000-4000-8000-000000000099"},
        {"compressed_public_key": "02" + "0" * 64},
        {"x_only_public_key": "0" * 64},
    ),
)
def test_invalid_genesis_requests_raise_only_membership_error(changes):
    with pytest.raises(InvalidCanonicalCrtMembership):
        genesis_membership(**changes)


def test_both_and_neither_sources_are_rejected():
    source = genesis()
    with pytest.raises(InvalidCanonicalCrtMembership):
        genesis_membership(source, lineage_evaluation=evaluate())
    with pytest.raises(InvalidCanonicalCrtMembership):
        evaluate_canonical_crt_membership(
            participant_id=source.genesis_participant_id,
            compressed_public_key=source.compressed_public_key,
            x_only_public_key=source.x_only_public_key,
            depth=0, evaluated_at=NOW,
        )
    result = genesis_membership(genesis_evaluation=None, lineage_evaluation=evaluate())
    assert result.reason_code is CanonicalCrtMembershipReason.SOURCE_KIND_MISMATCH


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("schema", "wrong"),
        ("evaluator_version", "wrong"),
        ("verification_rule", "wrong"),
        ("depth", True),
        ("participant_id", "0" * 64),
        ("target_edge_id", None),
        ("state", CanonicalCrtMembershipState.EDGE_INACTIVE),
        ("source_evaluation_sha256", None),
        ("controlling_depth", 1),
        ("relevant_records", ()),
        ("human_interpretation_required", False),
    ),
)
def test_constructor_forgery_rejected(field, value):
    with pytest.raises(InvalidCanonicalCrtMembership):
        replace(ordinary_membership(), **{field: value})


@pytest.mark.parametrize("mutation", ("duplicate", "extra", "missing", "float", "nan", "time", "enum", "upper"))
def test_membership_parser_adversarial(mutation):
    text = canonical_crt_membership_evaluation_bytes(ordinary_membership()).decode("ascii")
    data = json.loads(text)
    if mutation == "duplicate":
        text = text.replace('"schema":', '"schema":"duplicate","schema":', 1)
    elif mutation == "extra":
        data["extra"] = None
    elif mutation == "missing":
        data.pop("network")
    elif mutation == "float":
        data["depth"] = 3.0
    elif mutation == "nan":
        text = text.replace('"depth":3', '"depth":NaN')
    elif mutation == "time":
        data["evaluated_at"] = data["evaluated_at"].replace("Z", "+00:00")
    elif mutation == "enum":
        data["state"] = "full"
    else:
        data["source_evaluation_sha256"] = data["source_evaluation_sha256"].upper()
    if mutation not in {"duplicate", "nan"}:
        text = json.dumps(data, sort_keys=True, separators=(",", ":"))
    with pytest.raises(InvalidCanonicalCrtMembership):
        parse_canonical_crt_membership_evaluation(text)


def _rebind_descendants(items, changed_position):
    for index in range(changed_position + 1, len(items)):
        items[index] = replace(
            items[index],
            record=replace(
                items[index].record,
                sponsor_basis_record_sha256=canonical_admission_edge_sha256(
                    items[index - 1].record
                ),
            ),
        )
    return tuple(items)


def test_source_kind_mismatch_genesis_request_preserves_lineage_identity():
    source = evaluate()
    result = genesis_membership(
        genesis_evaluation=None,
        lineage_evaluation=source,
        evaluated_at=source.evaluated_at,
    )
    assert (
        result.state,
        result.reason_code,
        result.subject_kind,
        result.source_evaluation_kind,
    ) == (
        CanonicalCrtMembershipState.UNKNOWN,
        CanonicalCrtMembershipReason.SOURCE_KIND_MISMATCH,
        CanonicalCrtMembershipSubjectKind.GENESIS,
        CanonicalCrtMembershipSourceKind.CANONICAL_SPONSOR_LINEAGE_EVALUATION,
    )
    assert result.source_evaluation_sha256 == canonical_sponsor_lineage_evaluation_sha256(source)
    assert result.relevant_records == source.relevant_records
    assert result.target_edge_id is result.target_edge_sha256 is None
    assert result.controlling_depth is result.controlling_edge_id is None


def test_source_kind_mismatch_ordinary_request_preserves_genesis_identity():
    requested = evaluate()
    source = genesis()
    result = ordinary_membership(
        requested,
        lineage_evaluation=None,
        genesis_evaluation=source,
        evaluated_at=source.evaluated_at,
    )
    assert (
        result.state,
        result.reason_code,
        result.source_evaluation_kind,
    ) == (
        CanonicalCrtMembershipState.UNKNOWN,
        CanonicalCrtMembershipReason.SOURCE_KIND_MISMATCH,
        CanonicalCrtMembershipSourceKind.CANONICAL_GENESIS_EVALUATION,
    )
    assert result.target_edge_id == requested.target_edge_id
    assert result.target_edge_sha256 is None
    assert result.source_evaluation_sha256 == canonical_genesis_evaluation_sha256(source)
    assert result.relevant_records == source.relevant_records
    assert result.controlling_depth is result.controlling_edge_id is None


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("source_state", "active"),
        ("source_reason_code", "arbitrary"),
        ("source_reason_code", "proposed_only"),
    ),
)
def test_genesis_source_state_reason_forgery_rejected_even_on_binding_failure(field, value):
    result = genesis_membership(evaluated_at=genesis().evaluated_at + timedelta(seconds=1))
    with pytest.raises(InvalidCanonicalCrtMembership):
        replace(result, **{field: value})


@pytest.mark.parametrize(
    ("source_state", "source_reason"),
    (
        ("active", "target_edge_inactive"),
        ("unknown", "exact_lineage_active"),
        ("provisional", "ancestor_disputed"),
    ),
)
def test_lineage_source_state_reason_forgery_rejected_even_on_binding_failure(
    source_state, source_reason
):
    result = ordinary_membership(evaluated_at=NOW + timedelta(seconds=1))
    with pytest.raises(InvalidCanonicalCrtMembership):
        replace(result, source_state=source_state, source_reason_code=source_reason)


@pytest.mark.parametrize(
    ("position", "mode", "state", "reason"),
    (
        (2, "revoked", CanonicalCrtMembershipState.EDGE_INACTIVE,
         CanonicalCrtMembershipReason.TARGET_EDGE_INACTIVE),
        (2, "superseded", CanonicalCrtMembershipState.EDGE_INACTIVE,
         CanonicalCrtMembershipReason.TARGET_EDGE_INACTIVE),
        (2, "spent", CanonicalCrtMembershipState.EDGE_INACTIVE,
         CanonicalCrtMembershipReason.TARGET_EDGE_INACTIVE),
        (2, "confirmations", CanonicalCrtMembershipState.EDGE_INACTIVE,
         CanonicalCrtMembershipReason.TARGET_EDGE_INACTIVE),
        (0, "revoked", CanonicalCrtMembershipState.LINEAGE_INACTIVE,
         CanonicalCrtMembershipReason.ANCESTOR_EDGE_INACTIVE),
        (0, "superseded", CanonicalCrtMembershipState.LINEAGE_INACTIVE,
         CanonicalCrtMembershipReason.ANCESTOR_EDGE_INACTIVE),
        (0, "spent", CanonicalCrtMembershipState.LINEAGE_INACTIVE,
         CanonicalCrtMembershipReason.ANCESTOR_EDGE_INACTIVE),
        (0, "confirmations", CanonicalCrtMembershipState.LINEAGE_INACTIVE,
         CanonicalCrtMembershipReason.ANCESTOR_EDGE_INACTIVE),
        (2, "binding", CanonicalCrtMembershipState.UNKNOWN,
         CanonicalCrtMembershipReason.TARGET_LOCAL_EVALUATION_UNKNOWN),
        (0, "binding", CanonicalCrtMembershipState.UNKNOWN,
         CanonicalCrtMembershipReason.ANCESTOR_LOCAL_EVALUATION_UNKNOWN),
    ),
)
def test_genuine_lineage_composition_and_authoritative_control(position, mode, state, reason):
    items = list(lineage_fixture())
    if mode in {"revoked", "superseded"}:
        lifecycle = (
            AdmissionEdgeLifecycle.REVOKED
            if mode == "revoked"
            else AdmissionEdgeLifecycle.SUPERSEDED
        )
        items[position] = with_edge_state(items[position], lifecycle)
        items = list(_rebind_descendants(items, position))
    else:
        items[position] = mutate_observation(items[position], mode)
    source = evaluate(tuple(items))
    result = ordinary_membership(source)
    assert (result.state, result.reason_code) == (state, reason)
    assert (result.controlling_depth, result.controlling_edge_id) == (
        source.controlling_depth,
        source.controlling_edge_id,
    )


def test_genuine_genesis_inactive_composes_to_lineage_inactive():
    base = genesis()
    inactive = replace(
        base,
        state=type(base.state).LINEAGE_INACTIVE,
        reason_code="all_records_revoked",
        selected_effective_record_id=None,
        selected_effective_record_sha256=None,
    )
    source = evaluate(genesis_value=inactive)
    result = ordinary_membership(source)
    assert (result.state, result.reason_code, result.controlling_depth, result.controlling_edge_id) == (
        CanonicalCrtMembershipState.LINEAGE_INACTIVE,
        CanonicalCrtMembershipReason.GENESIS_LINEAGE_INACTIVE,
        0,
        None,
    )


@pytest.mark.parametrize(
    ("change", "reason"),
    (
        ({"evaluated_at": NOW + timedelta(seconds=1)},
         CanonicalCrtMembershipReason.SOURCE_TIME_MISMATCH),
        ({"target_edge_id": "00000000-0000-4000-8000-000000000099"},
         CanonicalCrtMembershipReason.SOURCE_SUBJECT_MISMATCH),
        ({"participant_id": "1" * 64, "compressed_public_key": "02" + "1" * 64,
          "x_only_public_key": "1" * 64},
         CanonicalCrtMembershipReason.SOURCE_SUBJECT_MISMATCH),
        ({"participant_id": "2" * 64, "compressed_public_key": "03" + "2" * 64,
          "x_only_public_key": "2" * 64},
         CanonicalCrtMembershipReason.SOURCE_SUBJECT_MISMATCH),
        ({"depth": 2}, CanonicalCrtMembershipReason.SOURCE_SUBJECT_MISMATCH),
    ),
)
def test_ordinary_binding_failures_are_separate_and_control_free(change, reason):
    source = evaluate()
    result = ordinary_membership(source, **change)
    assert (result.state, result.reason_code) == (
        CanonicalCrtMembershipState.UNKNOWN,
        reason,
    )
    assert result.controlling_depth is result.controlling_edge_id is None
    if change.get("target_edge_id", source.target_edge_id) != source.target_edge_id:
        assert result.target_edge_sha256 is None
    else:
        assert result.target_edge_sha256 == source.target_edge_sha256


@pytest.mark.parametrize(
    "change",
    (
        {"participant_id": "1" * 64},
        {"compressed_public_key": "02" + "1" * 64},
        {"x_only_public_key": "1" * 64},
    ),
)
def test_isolated_ordinary_identity_breaks_are_invalid_call_contracts(change):
    # The public subject contract couples participant ID, compressed key and
    # x-only key, so an isolated mismatch is not a valid-domain binding case.
    with pytest.raises(InvalidCanonicalCrtMembership):
        ordinary_membership(**change)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("graph_or_protocol_id", "wrong.graph"),
        ("network", "testnet"),
        ("human_profile", "current_144"),
    ),
)
def test_forged_fixed_lineage_source_is_invalid_public_source_not_binding_mismatch(
    field, value
):
    source = evaluate()
    forged = object.__new__(type(source))
    for name in source.__dataclass_fields__:
        object.__setattr__(
            forged,
            name,
            value if name == field else getattr(source, name),
        )
    with pytest.raises(InvalidCanonicalCrtMembership):
        ordinary_membership(forged)


def _replace_record_pair(records, old_pair, new_pair):
    return tuple(sorted(new_pair if item == old_pair else item for item in records))


@pytest.mark.parametrize("forgery", (
    "no_genesis", "genesis_absent", "wrong_genesis", "target_absent",
    "wrong_target", "unrelated_correct_count",
))
def test_active_ordinary_requires_semantic_genesis_and_target_pairs(forgery):
    result = ordinary_membership()
    genesis_pair = (
        result.selected_genesis_record_id,
        result.selected_genesis_record_sha256,
    )
    target_pair = (result.target_edge_id, result.target_edge_sha256)
    unrelated = ("00000000-0000-4000-8000-000000000099", "9" * 64)
    changes = {}
    if forgery == "no_genesis":
        changes.update(selected_genesis_record_id=None, selected_genesis_record_sha256=None)
    elif forgery == "genesis_absent":
        changes["relevant_records"] = _replace_record_pair(
            result.relevant_records, genesis_pair, unrelated
        )
    elif forgery == "wrong_genesis":
        changes.update(
            selected_genesis_record_id=unrelated[0],
            selected_genesis_record_sha256=unrelated[1],
        )
    elif forgery == "target_absent":
        changes["relevant_records"] = _replace_record_pair(
            result.relevant_records, target_pair, unrelated
        )
    elif forgery == "wrong_target":
        changes["target_edge_sha256"] = "8" * 64
    else:
        records = _replace_record_pair(result.relevant_records, genesis_pair, unrelated)
        changes["relevant_records"] = _replace_record_pair(
            records, target_pair,
            ("00000000-0000-4000-8000-000000000098", "8" * 64),
        )
    with pytest.raises(InvalidCanonicalCrtMembership):
        replace(result, **changes)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("subject_kind", CanonicalCrtMembershipSubjectKind.GENESIS),
        ("source_evaluation_kind",
         CanonicalCrtMembershipSourceKind.CANONICAL_GENESIS_EVALUATION),
        ("source_state", "unknown"),
        ("source_reason_code", "target_edge_inactive"),
        ("state", CanonicalCrtMembershipState.EDGE_INACTIVE),
        ("reason_code", CanonicalCrtMembershipReason.ANCESTOR_EDGE_INACTIVE),
        ("controlling_depth", 1),
        ("controlling_edge_id", "00000000-0000-4000-8000-000000000021"),
        ("target_edge_id", None),
        ("target_edge_sha256", None),
        ("selected_genesis_record_id", None),
        ("selected_genesis_record_sha256", None),
        ("relevant_records", tuple(reversed(ordinary_membership().relevant_records))),
    ),
)
def test_expanded_constructor_forgery_matrix(field, value):
    with pytest.raises(InvalidCanonicalCrtMembership):
        replace(ordinary_membership(), **{field: value})


def test_duplicate_record_id_and_duplicate_pair_are_rejected():
    result = ordinary_membership()
    duplicate_pair = tuple(sorted(result.relevant_records + (result.relevant_records[0],)))
    with pytest.raises(InvalidCanonicalCrtMembership):
        replace(result, relevant_records=duplicate_pair)
    same_id = (
        result.relevant_records[0][0],
        "9" * 64,
    )
    with pytest.raises(InvalidCanonicalCrtMembership):
        replace(result, relevant_records=tuple(sorted(result.relevant_records + (same_id,))))


def test_invalid_source_kind_mismatch_pairing_and_binding_control_rejected():
    mismatch = genesis_membership(
        genesis_evaluation=None,
        lineage_evaluation=evaluate(),
        evaluated_at=NOW,
    )
    with pytest.raises(InvalidCanonicalCrtMembership):
        replace(
            mismatch,
            source_evaluation_kind=CanonicalCrtMembershipSourceKind.CANONICAL_GENESIS_EVALUATION,
        )
    binding = ordinary_membership(evaluated_at=NOW + timedelta(seconds=1))
    with pytest.raises(InvalidCanonicalCrtMembership):
        replace(
            binding,
            controlling_depth=1,
            controlling_edge_id=evaluate().lineage_nodes[0].edge_id,
        )


def test_source_kind_mismatch_still_enforces_both_source_matrices():
    lineage_mismatch = genesis_membership(
        genesis_evaluation=None,
        lineage_evaluation=evaluate(),
        evaluated_at=NOW,
    )
    with pytest.raises(InvalidCanonicalCrtMembership):
        replace(
            lineage_mismatch,
            source_state="active",
            source_reason_code="target_edge_inactive",
        )
    genesis_source = genesis()
    ordinary_mismatch = ordinary_membership(
        lineage_evaluation=None,
        genesis_evaluation=genesis_source,
        evaluated_at=genesis_source.evaluated_at,
    )
    with pytest.raises(InvalidCanonicalCrtMembership):
        replace(
            ordinary_mismatch,
            source_state="genesis_active",
            source_reason_code="proposed_only",
        )


def test_control_reason_semantics_are_not_forgeable():
    target = ordinary_membership(
        evaluate(
            _rebind_descendants(
                [
                    lineage_fixture()[0],
                    lineage_fixture()[1],
                    with_edge_state(
                        lineage_fixture()[2], AdmissionEdgeLifecycle.REVOKED
                    ),
                ],
                2,
            )
        )
    )
    with pytest.raises(InvalidCanonicalCrtMembership):
        replace(
            target,
            controlling_depth=1,
            controlling_edge_id=evaluate().lineage_nodes[0].edge_id,
        )
    items = list(lineage_fixture())
    items[0] = with_edge_state(items[0], AdmissionEdgeLifecycle.REVOKED)
    ancestor = ordinary_membership(evaluate(_rebind_descendants(items, 0)))
    with pytest.raises(InvalidCanonicalCrtMembership):
        replace(
            ancestor,
            controlling_depth=ancestor.depth,
            controlling_edge_id=ancestor.target_edge_id,
        )
    genesis_controlled = ordinary_membership(
        evaluate(
            genesis_value=replace(
                genesis(),
                state=type(genesis().state).LINEAGE_INACTIVE,
                reason_code="all_records_revoked",
                selected_effective_record_id=None,
                selected_effective_record_sha256=None,
            )
        )
    )
    with pytest.raises(InvalidCanonicalCrtMembership):
        replace(
            genesis_controlled,
            controlling_edge_id=genesis_controlled.target_edge_id,
        )


def test_explicit_state_reason_cross_family_forgery_rejected():
    active = ordinary_membership()
    with pytest.raises(InvalidCanonicalCrtMembership):
        replace(
            active,
            state=CanonicalCrtMembershipState.EDGE_INACTIVE,
            reason_code=CanonicalCrtMembershipReason.ANCESTOR_EDGE_INACTIVE,
        )
    with pytest.raises(InvalidCanonicalCrtMembership):
        replace(
            active,
            state=CanonicalCrtMembershipState.LINEAGE_INACTIVE,
            reason_code=CanonicalCrtMembershipReason.TARGET_EDGE_INACTIVE,
        )


@pytest.mark.parametrize(
    "mutation",
    (
        "duplicate", "extra", "missing", "float", "nan", "infinity", "offset",
        "microseconds", "uppercase_uuid", "uppercase_digest", "subject", "state",
        "reason", "source_kind", "source_state", "source_reason",
        "source_incompatible", "reordered", "duplicate_record", "partial_target",
        "partial_genesis", "forged_active",
    ),
)
def test_complete_membership_parser_adversarial_matrix(mutation):
    encoded = canonical_crt_membership_evaluation_bytes(ordinary_membership()).decode("ascii")
    data = json.loads(encoded)
    if mutation == "duplicate":
        encoded = encoded[:-1] + ',"schema":"duplicate"}'
    elif mutation == "extra":
        data["extra"] = None
    elif mutation == "missing":
        data.pop("network")
    elif mutation == "float":
        data["depth"] = 3.5
    elif mutation == "nan":
        data["depth"] = float("nan")
    elif mutation == "infinity":
        data["depth"] = float("inf")
    elif mutation == "offset":
        data["evaluated_at"] = data["evaluated_at"][:-1] + "+00:00"
    elif mutation == "microseconds":
        data["evaluated_at"] = data["evaluated_at"][:-1] + ".000001Z"
    elif mutation == "uppercase_uuid":
        data["selected_genesis_record_id"] = data["selected_genesis_record_id"].upper()
    elif mutation == "uppercase_digest":
        data["target_edge_sha256"] = data["target_edge_sha256"].upper()
    elif mutation == "subject":
        data["subject_kind"] = "genesis"
    elif mutation == "state":
        data["state"] = "full"
    elif mutation == "reason":
        data["reason_code"] = "target_edge_inactive"
    elif mutation == "source_kind":
        data["source_evaluation_kind"] = "canonical_genesis_evaluation"
    elif mutation == "source_state":
        data["source_state"] = "unknown"
    elif mutation == "source_reason":
        data["source_reason_code"] = "wrong"
    elif mutation == "source_incompatible":
        data["source_state"] = "unknown"
    elif mutation == "reordered":
        data["relevant_records"] = list(reversed(data["relevant_records"]))
    elif mutation == "duplicate_record":
        data["relevant_records"].append(data["relevant_records"][0])
    elif mutation == "partial_target":
        data["target_edge_sha256"] = None
    elif mutation == "partial_genesis":
        data["selected_genesis_record_sha256"] = None
    else:
        data["selected_genesis_record_id"] = None
        data["selected_genesis_record_sha256"] = None
    if mutation != "duplicate":
        encoded = json.dumps(
            data, sort_keys=True, separators=(",", ":"), allow_nan=True
        )
    with pytest.raises(InvalidCanonicalCrtMembership):
        parse_canonical_crt_membership_evaluation(encoded)
