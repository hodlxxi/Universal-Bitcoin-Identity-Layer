import json
from dataclasses import replace

import pytest

from app.services.canonical_genesis_record import (
    GRAPH_ID,
    CanonicalGenesisEvaluationState,
    InvalidCanonicalGenesisRecord,
    canonical_genesis_evaluation_bytes,
    canonical_genesis_evaluation_sha256,
    evaluate_canonical_genesis,
    parse_canonical_genesis_evaluation,
)
from tests.unit.test_canonical_genesis_record import record


def test_genesis_evaluation_canonical_identity_and_pinned_digest():
    item = record()
    result = evaluate_canonical_genesis(
        (item,), graph_or_protocol_id=GRAPH_ID, evaluated_at=item.effective_at
    )
    encoded = canonical_genesis_evaluation_bytes(result)
    assert parse_canonical_genesis_evaluation(encoded) == result
    assert canonical_genesis_evaluation_sha256(result) == (
        "b232285e842d7bc2ac3aed0845464ad7caed8252ed69d31ad5059e1ba42a9ebb"
    )


@pytest.mark.parametrize("mutation", ("duplicate", "extra", "missing", "float", "nan", "enum", "time"))
def test_genesis_evaluation_parser_is_strict(mutation):
    item = record()
    result = evaluate_canonical_genesis(
        (item,), graph_or_protocol_id=GRAPH_ID, evaluated_at=item.effective_at
    )
    text = canonical_genesis_evaluation_bytes(result).decode("ascii")
    data = json.loads(text)
    if mutation == "duplicate":
        text = text.replace('"state":"genesis_active"', '"state":"genesis_active","state":"genesis_active"')
    elif mutation == "extra":
        data["extra"] = None
        text = json.dumps(data, sort_keys=True, separators=(",", ":"))
    elif mutation == "missing":
        data.pop("claim")
        text = json.dumps(data, sort_keys=True, separators=(",", ":"))
    elif mutation == "float":
        text = text.replace('"human_interpretation_required":true', '"human_interpretation_required":1.0')
    elif mutation == "nan":
        text = text.replace('"human_interpretation_required":true', '"human_interpretation_required":NaN')
    elif mutation == "enum":
        data["state"] = "active"
        text = json.dumps(data, sort_keys=True, separators=(",", ":"))
    else:
        data["evaluated_at"] = data["evaluated_at"].replace("Z", "+00:00")
        text = json.dumps(data, sort_keys=True, separators=(",", ":"))
    with pytest.raises(InvalidCanonicalGenesisRecord):
        parse_canonical_genesis_evaluation(text)


@pytest.mark.parametrize(
    ("state", "reason"),
    (
        (CanonicalGenesisEvaluationState.GENESIS_ACTIVE, "exact_effective_record"),
        (CanonicalGenesisEvaluationState.PROVISIONAL, "proposed_only"),
        (CanonicalGenesisEvaluationState.DISPUTED, "controlling_dispute"),
        (CanonicalGenesisEvaluationState.LINEAGE_INACTIVE, "all_records_revoked"),
        (CanonicalGenesisEvaluationState.UNKNOWN, "no_records"),
    ),
)
def test_all_five_genesis_evaluation_states_round_trip(state, reason):
    item = record()
    active = evaluate_canonical_genesis(
        (item,), graph_or_protocol_id=GRAPH_ID, evaluated_at=item.effective_at
    )
    value = replace(
        active,
        state=state,
        reason_code=reason,
        selected_effective_record_id=(
            active.selected_effective_record_id
            if state is CanonicalGenesisEvaluationState.GENESIS_ACTIVE
            else None
        ),
        selected_effective_record_sha256=(
            active.selected_effective_record_sha256
            if state is CanonicalGenesisEvaluationState.GENESIS_ACTIVE
            else None
        ),
    )
    assert parse_canonical_genesis_evaluation(
        canonical_genesis_evaluation_bytes(value)
    ) == value


@pytest.mark.parametrize(
    "mutation",
    (
        "infinity", "microseconds", "uppercase_uuid", "uppercase_digest",
        "unsorted", "duplicate_record", "partial_selected", "state_reason",
    ),
)
def test_genesis_evaluation_complete_adversarial_matrix(mutation):
    item = record()
    active = evaluate_canonical_genesis(
        (item,), graph_or_protocol_id=GRAPH_ID, evaluated_at=item.effective_at
    )
    if mutation == "unsorted":
        active = replace(
            active,
            state=CanonicalGenesisEvaluationState.DISPUTED,
            reason_code="controlling_dispute",
            selected_effective_record_id=None,
            selected_effective_record_sha256=None,
            relevant_records=tuple(sorted(active.relevant_records + (
                ("00000000-0000-4000-8000-000000000099", "9" * 64),
            ))),
        )
    data = json.loads(canonical_genesis_evaluation_bytes(active))
    if mutation == "infinity":
        data["human_interpretation_required"] = float("inf")
    elif mutation == "microseconds":
        data["evaluated_at"] = data["evaluated_at"][:-1] + ".000001Z"
    elif mutation == "uppercase_uuid":
        data["relevant_records"][0][0] = data["relevant_records"][0][0].upper()
    elif mutation == "uppercase_digest":
        data["relevant_records"][0][1] = data["relevant_records"][0][1].upper()
    elif mutation == "unsorted":
        data["relevant_records"].reverse()
    elif mutation == "duplicate_record":
        data["relevant_records"].append(data["relevant_records"][0])
    elif mutation == "partial_selected":
        data["selected_effective_record_sha256"] = None
    else:
        data["reason_code"] = "proposed_only"
    encoded = json.dumps(data, sort_keys=True, separators=(",", ":"), allow_nan=True)
    with pytest.raises(InvalidCanonicalGenesisRecord):
        parse_canonical_genesis_evaluation(encoded)
