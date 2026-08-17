from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest

from app.services.canonical_genesis_record import (
    CLAIM,
    COMPRESSED_KEY,
    EVALUATOR_VERSION,
    MANDATORY_NON_CLAIMS,
    PARTICIPANT_ID,
    XONLY_KEY,
    CanonicalGenesisEvaluation,
    CanonicalGenesisEvaluationState as State,
    CanonicalGenesisLifecycle as Lifecycle,
    GRAPH_ID,
    InvalidCanonicalGenesisRecord,
    canonical_genesis_record_bytes,
    canonical_genesis_record_sha256,
    evaluate_canonical_genesis,
    parse_canonical_genesis_record,
)


def record():
    return parse_canonical_genesis_record(Path("docs/data/e923_canonical_genesis_record_v1.json").read_bytes())


def test_exact_published_record_round_trip_hash_and_evaluation():
    item = record()
    assert canonical_genesis_record_sha256(item) == ("df0445177ad8e913ef18dbf4670e8f8bc7a23f8adb14b9d87d4425dc3c5b1339")
    assert parse_canonical_genesis_record(canonical_genesis_record_bytes(item)) == item
    result = evaluate_canonical_genesis((item,), graph_or_protocol_id=GRAPH_ID, evaluated_at=item.effective_at)
    assert result.state is State.GENESIS_ACTIVE
    assert result.reason_code == "exact_effective_record"
    assert result.selected_effective_record_sha256 == canonical_genesis_record_sha256(item)
    assert not any(value in result.claim for value in ("FULL", "LIMITED"))


def test_evidence_order_is_canonically_invariant():
    item = record()
    reversed_item = replace(item, evidence_references=tuple(reversed(item.evidence_references)))
    assert canonical_genesis_record_bytes(reversed_item) == canonical_genesis_record_bytes(item)


def test_evidence_integrity_basis_is_finite_and_consistent():
    evidence = {value.reference_id: value for value in record().evidence_references}
    assert evidence["canon_genesis_bootstrap_v1"].content_sha256 == (
        "fea957f51ad9a8c1962afa56f1e3da07ed533cc80368f9fd720fa52bede78b46"
    )
    assert evidence["e923_operator_continuity"].content_sha256 == (
        "1b22f6b4a3ba882d26efb7469e867bee8e12b52e74625ac318fd7f16c7c28488"
    )
    assert evidence["source_publication"].integrity_basis == ("self_canonical_digest_externally_pinned")
    assert evidence["source_publication"].content_sha256 is None
    for value in evidence.values():
        if value.integrity_basis == "content_sha256":
            with pytest.raises(InvalidCanonicalGenesisRecord):
                replace(value, content_sha256=None)
            with pytest.raises(InvalidCanonicalGenesisRecord):
                replace(value, content_sha256="0" * 63)
        else:
            with pytest.raises(InvalidCanonicalGenesisRecord):
                replace(value, content_sha256="0" * 64)
        with pytest.raises(InvalidCanonicalGenesisRecord):
            replace(value, integrity_basis="locator_sha256")


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("genesis_depth", True),
        ("genesis_depth", 0.0),
        ("genesis_depth", 1),
        ("network", "testnet"),
        ("human_profile", "current_144"),
        ("anchor_middle_height", 1777000),
        ("delta_blocks", 144),
        ("human_interpretation_required", False),
        ("record_id", "E9230000-0000-4000-8000-000000000001"),
    ),
)
def test_fixed_contract_rejects_substitution(field, value):
    with pytest.raises(InvalidCanonicalGenesisRecord):
        replace(record(), **{field: value})


def test_wrong_key_label_only_naive_time_and_forged_nested_objects_rejected():
    item = record()
    with pytest.raises(InvalidCanonicalGenesisRecord):
        replace(
            item,
            identity_anchor=replace(item.identity_anchor, compressed_public_key="02" + "0" * 64),
        )
    with pytest.raises(InvalidCanonicalGenesisRecord):
        replace(item, identity_anchor="E923")
    with pytest.raises(InvalidCanonicalGenesisRecord):
        replace(item, created_at=item.created_at.replace(tzinfo=None))
    with pytest.raises(InvalidCanonicalGenesisRecord):
        replace(item, identity_anchor=object.__new__(type(item.identity_anchor)))


@pytest.mark.parametrize("mutation", ("missing", "extra", "duplicate", "nonclaims", "float"))
def test_parser_rejects_nonexact_serialized_contract(mutation):
    data = json.loads(Path("docs/data/e923_canonical_genesis_record_v1.json").read_text())
    if mutation == "missing":
        data.pop("network")
    elif mutation == "extra":
        data["sponsor"] = None
    elif mutation == "duplicate":
        data["evidence_references"].append(data["evidence_references"][0])
    elif mutation == "nonclaims":
        data["explicit_non_claims"][0] = "FULL"
    else:
        data["delta_blocks"] = 777.0
    with pytest.raises(InvalidCanonicalGenesisRecord):
        parse_canonical_genesis_record(json.dumps(data))


@pytest.mark.parametrize(
    "payload",
    (
        '{"network":"testnet","network":"bitcoin"}',
        '{"evidence_references":[{"reference_id":"a","reference_id":"b"}]}',
    ),
)
def test_parser_rejects_duplicate_json_object_keys_at_every_depth(payload):
    with pytest.raises(InvalidCanonicalGenesisRecord):
        parse_canonical_genesis_record(payload)


def test_lifecycle_evaluation_matrix_and_future_effectiveness():
    item = record()
    proposed = replace(
        item,
        lifecycle_state=Lifecycle.PROPOSED,
        effective_at=None,
        lifecycle_changed_at=item.created_at,
    )
    revoked = replace(
        item,
        lifecycle_state=Lifecycle.REVOKED,
        contradiction_context=replace(
            item.contradiction_context,
            reason="terminal contradiction",
            evidence_reference_ids=("canon_genesis_bootstrap_v1",),
        ),
    )
    with pytest.raises(InvalidCanonicalGenesisRecord):
        replace(
            revoked,
            superseded_by_record_id="e9230000-0000-4000-8000-000000000002",
        )
    superseded = replace(
        item,
        lifecycle_state=Lifecycle.SUPERSEDED,
        superseded_by_record_id="e9230000-0000-4000-8000-000000000002",
    )
    disputed = replace(
        item,
        lifecycle_state=Lifecycle.DISPUTED,
        contradiction_context=replace(
            item.contradiction_context,
            reason="unresolved dispute",
            evidence_reference_ids=("canon_genesis_bootstrap_v1",),
            unresolved_controlling_dispute=True,
        ),
    )
    cases = (
        ((item,), State.GENESIS_ACTIVE),
        ((), State.UNKNOWN),
        ((proposed,), State.PROVISIONAL),
        ((revoked,), State.LINEAGE_INACTIVE),
        ((superseded,), State.LINEAGE_INACTIVE),
        ((disputed,), State.DISPUTED),
        ((item, revoked), State.UNKNOWN),
        ((item, proposed), State.UNKNOWN),
        ((item, superseded), State.UNKNOWN),
        (
            (item, replace(item, record_id="e9230000-0000-4000-8000-000000000002")),
            State.DISPUTED,
        ),
    )
    for records, expected in cases:
        assert (
            evaluate_canonical_genesis(records, graph_or_protocol_id=GRAPH_ID, evaluated_at=item.effective_at).state
            is expected
        )
    assert (
        evaluate_canonical_genesis(
            (item,),
            graph_or_protocol_id=GRAPH_ID,
            evaluated_at=item.effective_at - timedelta(seconds=1),
        ).state
        is State.UNKNOWN
    )


def test_cross_graph_and_untrusted_input_never_active():
    item = record()
    result = evaluate_canonical_genesis((object(),), graph_or_protocol_id=GRAPH_ID, evaluated_at=item.effective_at)
    assert result.state is State.UNKNOWN
    with pytest.raises(InvalidCanonicalGenesisRecord):
        evaluate_canonical_genesis((item,), graph_or_protocol_id="other", evaluated_at=item.effective_at)


def test_evaluation_time_and_output_contract_are_strict():
    item = record()
    for invalid in (
        item.effective_at.replace(tzinfo=None),
        item.effective_at.astimezone(timezone(timedelta(hours=1))),
        item.effective_at.replace(microsecond=1),
    ):
        with pytest.raises(InvalidCanonicalGenesisRecord):
            evaluate_canonical_genesis((item,), graph_or_protocol_id=GRAPH_ID, evaluated_at=invalid)
    valid = evaluate_canonical_genesis((item,), graph_or_protocol_id=GRAPH_ID, evaluated_at=item.effective_at)
    for field, value in (
        ("evaluator_version", "other"),
        ("graph_or_protocol_id", "other"),
        ("state", "genesis_active"),
        ("reason_code", "invented"),
        ("selected_effective_record_sha256", None),
        ("relevant_records", valid.relevant_records + valid.relevant_records),
        ("human_interpretation_required", False),
        ("claim", "other"),
        ("explicit_non_claims", ()),
    ):
        with pytest.raises(InvalidCanonicalGenesisRecord):
            replace(valid, **{field: value})
    with pytest.raises(InvalidCanonicalGenesisRecord):
        CanonicalGenesisEvaluation(
            EVALUATOR_VERSION,
            GRAPH_ID,
            State.UNKNOWN,
            PARTICIPANT_ID,
            COMPRESSED_KEY,
            XONLY_KEY,
            datetime(2026, 7, 26, tzinfo=timezone.utc),
            None,
            None,
            (("not-a-uuid", "0" * 64),),
            "no_records",
            True,
            CLAIM,
            MANDATORY_NON_CLAIMS,
        )
