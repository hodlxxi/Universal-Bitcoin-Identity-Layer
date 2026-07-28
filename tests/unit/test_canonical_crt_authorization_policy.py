from dataclasses import replace
from datetime import timedelta
import json

import pytest

from app.services.canonical_crt_authorization_policy import *
from app.services.canonical_crt_membership import (
    CanonicalCrtMembershipReason,
    CanonicalCrtMembershipState,
    canonical_crt_membership_evaluation_sha256,
)
from tests.unit.test_canonical_crt_membership import (
    genesis_membership,
    ordinary_membership,
)
from tests.unit.test_canonical_sponsor_lineage import evaluate, lineage_fixture
from tests.unit.test_canonical_sponsor_lineage import (
    mutate_observation,
    with_edge_state,
)
from tests.unit.test_canonical_admission_edge import NOW, genesis
from app.services.canonical_admission_edge import (
    AdmissionEdgeLifecycle,
    canonical_admission_edge_sha256,
)
from app.services.canonical_genesis_record import CanonicalGenesisEvaluationState
from app.services.canonical_sponsor_lineage import (
    CanonicalSponsorLineageReason,
    CanonicalSponsorLineageState,
    canonical_sponsor_lineage_evaluation_sha256,
    evaluate_canonical_sponsor_lineage,
)


def authorization(source=None):
    return evaluate_canonical_crt_authorization(source or ordinary_membership())


def assert_strict_authorization(source, expected_state, expected_membership_reason,
                                expected_authorization_reason):
    result = authorization(source)
    assert (source.state, source.reason_code) == (
        expected_state, expected_membership_reason
    )
    assert (result.authorization_class, result.reason_code) == (
        CanonicalCrtAuthorizationClass.LIMITED, expected_authorization_reason
    )
    assert result.current_full_membership_satisfied is False
    assert result.source_membership_evaluation == source
    assert result.source_membership_evaluation_sha256 == (
        canonical_crt_membership_evaluation_sha256(source)
    )
    assert (
        result.participant_id,
        result.target_edge_id,
        result.target_edge_sha256,
    ) == (
        source.participant_id,
        source.target_edge_id,
        source.target_edge_sha256,
    )
    assert (
        result.source_membership_evaluation.controlling_depth,
        result.source_membership_evaluation.controlling_edge_id,
    ) == (source.controlling_depth, source.controlling_edge_id)
    encoded = canonical_crt_authorization_evaluation_bytes(result)
    assert canonical_crt_authorization_evaluation_bytes(result) == encoded
    parsed = parse_canonical_crt_authorization_evaluation(encoded)
    assert parsed == result
    assert canonical_crt_authorization_evaluation_bytes(parsed) == encoded
    return result


@pytest.mark.parametrize("depth", (1, 2, 3))
def test_active_ordinary_is_full_and_source_bound(depth):
    source = ordinary_membership(evaluate(lineage_fixture(depth)))
    result = authorization(source)
    assert (result.authorization_class, result.reason_code) == (
        CanonicalCrtAuthorizationClass.FULL,
        CanonicalCrtAuthorizationReason.EXACT_PARTICIPANT_MEMBERSHIP_FULL,
    )
    assert result.current_full_membership_satisfied is True
    assert result.source_membership_evaluation == source
    assert result.source_membership_evaluation_sha256 == (
        canonical_crt_membership_evaluation_sha256(source)
    )
    assert parse_canonical_crt_authorization_evaluation(
        canonical_crt_authorization_evaluation_bytes(result)
    ) == result


def test_active_genesis_is_full_and_pinned():
    source = genesis_membership()
    result = authorization(source)
    assert (result.authorization_class, result.reason_code) == (
        CanonicalCrtAuthorizationClass.FULL,
        CanonicalCrtAuthorizationReason.EXACT_GENESIS_MEMBERSHIP_FULL,
    )
    assert result.current_full_membership_satisfied is True
    assert result.source_membership_evaluation_sha256 == (
        "d56fda10cd7181f987560b719e23af6620e187ffdc83a5bea9f5ca33bcf3ab29"
    )


@pytest.mark.parametrize("depth", (True, False, 1.0, 3.0))
def test_direct_constructor_rejects_non_exact_integer_depth(depth):
    base = authorization(
        ordinary_membership(evaluate(lineage_fixture(3 if depth == 3.0 else 1)))
    )
    with pytest.raises(InvalidCanonicalCrtAuthorization):
        replace(base, depth=depth)
    with pytest.raises(InvalidCanonicalCrtAuthorization):
        canonical_crt_authorization_evaluation_bytes(
            object.__new__(CanonicalCrtAuthorizationEvaluation)
        )


@pytest.mark.parametrize(
    "field",
    (
        "graph_or_protocol_id",
        "network",
        "human_profile",
        "participant_id",
        "compressed_public_key",
        "x_only_public_key",
        "target_edge_id",
        "target_edge_sha256",
        "source_membership_evaluation_sha256",
    ),
)
def test_direct_constructor_rejects_primitive_string_subclasses(field):
    class StringSubclass(str):
        pass

    base = authorization()
    with pytest.raises(InvalidCanonicalCrtAuthorization):
        replace(base, **{field: StringSubclass(getattr(base, field))})


def test_direct_constructor_rejects_datetime_subclass():
    class DatetimeSubclass(type(NOW)):
        pass

    base = authorization()
    forged = DatetimeSubclass.fromtimestamp(
        base.evaluated_at.timestamp(), tz=base.evaluated_at.tzinfo
    )
    with pytest.raises(InvalidCanonicalCrtAuthorization):
        replace(base, evaluated_at=forged)


def test_every_accepted_policy_result_strictly_self_round_trips():
    sources = (genesis_membership(), ordinary_membership())
    for source in sources:
        result = authorization(source)
        encoded = canonical_crt_authorization_evaluation_bytes(result)
        parsed = parse_canonical_crt_authorization_evaluation(encoded)
        assert parsed == result
        assert canonical_crt_authorization_evaluation_bytes(parsed) == encoded


@pytest.mark.parametrize(
    ("position", "kind"),
    (
        (2, "revoked"),
        (2, "superseded"),
        (2, "spent"),
        (2, "confirmations"),
        (0, "revoked"),
        (0, "superseded"),
        (0, "spent"),
        (0, "confirmations"),
    ),
)
def test_genuine_pr611_pr612_inactive_composition(position, kind):
    items = list(lineage_fixture(3))
    if kind in {"revoked", "superseded"}:
        lifecycle = (
            AdmissionEdgeLifecycle.REVOKED
            if kind == "revoked"
            else AdmissionEdgeLifecycle.SUPERSEDED
        )
        items[position] = with_edge_state(items[position], lifecycle)
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
    else:
        items[position] = mutate_observation(items[position], kind)
    lineage = evaluate(tuple(items))
    membership = ordinary_membership(lineage)
    target = position == 2
    assert membership.source_evaluation_sha256 == (
        canonical_sponsor_lineage_evaluation_sha256(lineage)
    )
    assert_strict_authorization(
        membership,
        CanonicalCrtMembershipState.EDGE_INACTIVE
        if target else CanonicalCrtMembershipState.LINEAGE_INACTIVE,
        CanonicalCrtMembershipReason.TARGET_EDGE_INACTIVE
        if target else CanonicalCrtMembershipReason.ANCESTOR_EDGE_INACTIVE,
        CanonicalCrtAuthorizationReason.EDGE_INACTIVE_MEMBERSHIP_LIMITED
        if target else CanonicalCrtAuthorizationReason.LINEAGE_INACTIVE_MEMBERSHIP_LIMITED,
    )


def test_genuine_pr611_pr612_inactive_genesis_composition():
    source = genesis()
    inactive = replace(
        source,
        state=CanonicalGenesisEvaluationState.LINEAGE_INACTIVE,
        reason_code="all_records_revoked",
        selected_effective_record_id=None,
        selected_effective_record_sha256=None,
    )
    lineage = evaluate(lineage_fixture(3), inactive)
    membership = ordinary_membership(lineage)
    assert_strict_authorization(
        membership,
        CanonicalCrtMembershipState.LINEAGE_INACTIVE,
        CanonicalCrtMembershipReason.GENESIS_LINEAGE_INACTIVE,
        CanonicalCrtAuthorizationReason.LINEAGE_INACTIVE_MEMBERSHIP_LIMITED,
    )


def _genuine_unknown_lineage(kind, monkeypatch):
    items = list(lineage_fixture(3))
    target_edge_id = items[-1].record.edge_id
    if kind == "target_binding":
        items[2] = mutate_observation(items[2], "binding")
    elif kind == "ancestor_binding":
        items[0] = mutate_observation(items[0], "binding")
    elif kind == "missing_target":
        items = items[:2]
    elif kind == "missing_parent":
        items = [items[0], items[2]]
    elif kind == "cycle":
        return replace(
            evaluate(tuple(items)),
            state=CanonicalSponsorLineageState.UNKNOWN,
            reason_code=CanonicalSponsorLineageReason.CYCLE_DETECTED,
            controlling_depth=None,
            controlling_edge_id=None,
        )
    elif kind == "maximum_depth":
        return replace(
            evaluate(tuple(items)),
            state=CanonicalSponsorLineageState.UNKNOWN,
            reason_code=CanonicalSponsorLineageReason.MAXIMUM_DEPTH_EXCEEDED,
            controlling_depth=None,
            controlling_edge_id=None,
        )
    return evaluate_canonical_sponsor_lineage(
        target_edge_id,
        edge_evidence=tuple(items),
        genesis_evaluation=genesis(),
        evaluated_at=NOW,
    )


@pytest.mark.parametrize(
    ("kind", "reason"),
    (
        ("target_binding", CanonicalCrtMembershipReason.TARGET_LOCAL_EVALUATION_UNKNOWN),
        ("ancestor_binding", CanonicalCrtMembershipReason.ANCESTOR_LOCAL_EVALUATION_UNKNOWN),
        ("missing_target", CanonicalCrtMembershipReason.MISSING_TARGET_EVIDENCE),
        ("missing_parent", CanonicalCrtMembershipReason.MISSING_PARENT_EVIDENCE),
        ("cycle", CanonicalCrtMembershipReason.CYCLE_DETECTED),
        ("maximum_depth", CanonicalCrtMembershipReason.MAXIMUM_DEPTH_EXCEEDED),
    ),
)
def test_genuine_pr611_pr612_unknown_propagation(kind, reason, monkeypatch):
    lineage = _genuine_unknown_lineage(kind, monkeypatch)
    membership = ordinary_membership(
        lineage,
        participant_id=lineage_fixture(3)[-1].record.child_participant_id,
        compressed_public_key=lineage_fixture(3)[-1].record.child_compressed_public_key,
        x_only_public_key=lineage_fixture(3)[-1].record.child_x_only_public_key,
        depth=lineage_fixture(3)[-1].record.child_depth,
        target_edge_id=lineage_fixture(3)[-1].record.edge_id,
    )
    assert_strict_authorization(
        membership,
        CanonicalCrtMembershipState.UNKNOWN,
        reason,
        CanonicalCrtAuthorizationReason.UNKNOWN_MEMBERSHIP_LIMITED,
    )


@pytest.mark.parametrize(
    ("state", "reason", "policy_reason"),
    (
        (CanonicalCrtMembershipState.PROVISIONAL,
         CanonicalCrtMembershipReason.TARGET_PROVISIONAL,
         CanonicalCrtAuthorizationReason.PROVISIONAL_MEMBERSHIP_LIMITED),
        (CanonicalCrtMembershipState.EDGE_INACTIVE,
         CanonicalCrtMembershipReason.TARGET_EDGE_INACTIVE,
         CanonicalCrtAuthorizationReason.EDGE_INACTIVE_MEMBERSHIP_LIMITED),
        (CanonicalCrtMembershipState.LINEAGE_INACTIVE,
         CanonicalCrtMembershipReason.ANCESTOR_EDGE_INACTIVE,
         CanonicalCrtAuthorizationReason.LINEAGE_INACTIVE_MEMBERSHIP_LIMITED),
        (CanonicalCrtMembershipState.DISPUTED,
         CanonicalCrtMembershipReason.TARGET_DISPUTED,
         CanonicalCrtAuthorizationReason.DISPUTED_MEMBERSHIP_LIMITED),
        (CanonicalCrtMembershipState.UNKNOWN,
         CanonicalCrtMembershipReason.SOURCE_TIME_MISMATCH,
         CanonicalCrtAuthorizationReason.UNKNOWN_MEMBERSHIP_LIMITED),
    ),
)
def test_every_non_active_state_is_limited(state, reason, policy_reason):
    base = ordinary_membership(evaluated_at=NOW.replace(year=NOW.year + 1))
    if state is not CanonicalCrtMembershipState.UNKNOWN:
        source = ordinary_membership()
        control = source.depth if reason.value.startswith("target_") else 1
        source = replace(
            source,
            state=state,
            reason_code=reason,
            source_state={
                CanonicalCrtMembershipState.PROVISIONAL: "provisional",
                CanonicalCrtMembershipState.EDGE_INACTIVE: "lineage_inactive",
                CanonicalCrtMembershipState.LINEAGE_INACTIVE: "lineage_inactive",
                CanonicalCrtMembershipState.DISPUTED: "disputed",
            }[state],
            source_reason_code=reason.value,
            controlling_depth=control,
            controlling_edge_id=(
                source.target_edge_id
                if control == source.depth
                else evaluate().lineage_nodes[0].edge_id
            ),
        )
    else:
        source = base
    result = authorization(source)
    assert (result.authorization_class, result.reason_code) == (
        CanonicalCrtAuthorizationClass.LIMITED,
        policy_reason,
    )
    assert result.current_full_membership_satisfied is False
    assert result.source_membership_evaluation == source


@pytest.mark.parametrize("membership_reason", tuple(CanonicalCrtMembershipReason))
def test_every_membership_reason_family_maps_without_skips(membership_reason):
    if membership_reason is CanonicalCrtMembershipReason.EXACT_GENESIS_MEMBERSHIP_ACTIVE:
        source = genesis_membership()
    elif membership_reason is CanonicalCrtMembershipReason.EXACT_PARTICIPANT_MEMBERSHIP_ACTIVE:
        source = ordinary_membership()
    elif membership_reason.value.startswith("source_"):
        if membership_reason is CanonicalCrtMembershipReason.SOURCE_KIND_MISMATCH:
            requested = evaluate()
            genesis_source = genesis()
            source = ordinary_membership(
                requested,
                lineage_evaluation=None,
                genesis_evaluation=genesis_source,
                evaluated_at=genesis_source.evaluated_at,
            )
        else:
            binding = ordinary_membership(
                evaluated_at=NOW.replace(year=NOW.year + 1)
            )
            source = replace(binding, reason_code=membership_reason)
    else:
        lineage_reason = CanonicalSponsorLineageReason(membership_reason.value)
        lineage = evaluate()
        state = (
            CanonicalSponsorLineageState.PROVISIONAL
            if "provisional" in lineage_reason.value
            else CanonicalSponsorLineageState.DISPUTED
            if "disputed" in lineage_reason.value
            else CanonicalSponsorLineageState.LINEAGE_INACTIVE
            if lineage_reason.value.endswith("edge_inactive")
            or lineage_reason is CanonicalSponsorLineageReason.GENESIS_LINEAGE_INACTIVE
            else CanonicalSponsorLineageState.UNKNOWN
        )
        changes = {"state": state, "reason_code": lineage_reason}
        if lineage_reason in {
            CanonicalSponsorLineageReason.MISSING_TARGET_EVIDENCE,
            CanonicalSponsorLineageReason.MALFORMED_OR_UNTRUSTED_INPUT,
        }:
            changes.update(
                target_edge_sha256=None,
                target_participant_id=None,
                target_compressed_public_key=None,
                target_x_only_public_key=None,
                target_depth=None,
                selected_genesis_record_id=None,
                selected_genesis_record_sha256=None,
                lineage_nodes=(),
                relevant_records=(),
                controlling_depth=None,
                controlling_edge_id=None,
            )
        elif lineage_reason.value.startswith("genesis_"):
            changes.update(controlling_depth=0, controlling_edge_id=None)
        elif lineage_reason.value.startswith(("ancestor_", "target_")):
            position = (
                lineage.target_depth
                if lineage_reason.value.startswith("target_")
                else 1
            )
            changes.update(
                controlling_depth=position,
                controlling_edge_id=lineage.lineage_nodes[position - 1].edge_id,
            )
        else:
            changes.update(controlling_depth=None, controlling_edge_id=None)
        forged_lineage = replace(lineage, **changes)
        source = ordinary_membership(
            forged_lineage,
            participant_id=lineage.target_participant_id,
            compressed_public_key=lineage.target_compressed_public_key,
            x_only_public_key=lineage.target_x_only_public_key,
            depth=lineage.target_depth,
            target_edge_id=lineage.target_edge_id,
        )
    result = authorization(source)
    if source.state in {
        CanonicalCrtMembershipState.GENESIS_ACTIVE,
        CanonicalCrtMembershipState.ACTIVE,
    }:
        assert result.authorization_class is CanonicalCrtAuthorizationClass.FULL
    else:
        assert result.authorization_class is CanonicalCrtAuthorizationClass.LIMITED


@pytest.mark.parametrize("invalid", (None, {}, "active", 1))
def test_public_input_failure_is_authorization_error(invalid):
    with pytest.raises(InvalidCanonicalCrtAuthorization):
        evaluate_canonical_crt_authorization(invalid)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("schema", "wrong"),
        ("policy_version", "wrong"),
        ("verification_rule", "wrong"),
        ("graph_or_protocol_id", "wrong"),
        ("network", "testnet"),
        ("human_profile", "wrong"),
        ("participant_id", "0" * 64),
        ("compressed_public_key", "02" + "0" * 64),
        ("x_only_public_key", "0" * 64),
        ("depth", 99),
        ("target_edge_id", None),
        ("target_edge_sha256", None),
        ("evaluated_at", NOW.replace(year=NOW.year + 1)),
        ("source_membership_state", CanonicalCrtMembershipState.UNKNOWN),
        ("source_membership_reason_code", CanonicalCrtMembershipReason.GENESIS_UNKNOWN),
        ("source_membership_evaluation_sha256", "0" * 64),
        ("authorization_class", CanonicalCrtAuthorizationClass.LIMITED),
        ("reason_code", CanonicalCrtAuthorizationReason.UNKNOWN_MEMBERSHIP_LIMITED),
        ("current_full_membership_satisfied", False),
        ("current_full_membership_satisfied", 1),
        ("explicit_non_claims", ()),
        ("human_interpretation_required", False),
    ),
)
def test_full_constructor_forgery_matrix(field, value):
    with pytest.raises(InvalidCanonicalCrtAuthorization):
        replace(authorization(), **{field: value})


def test_limited_cannot_be_forged_full_or_true():
    limited = authorization(ordinary_membership(evaluated_at=NOW.replace(year=NOW.year + 1)))
    for changes in (
        {"authorization_class": CanonicalCrtAuthorizationClass.FULL},
        {"reason_code": CanonicalCrtAuthorizationReason.EXACT_PARTICIPANT_MEMBERSHIP_FULL},
        {"current_full_membership_satisfied": True},
        {"current_full_membership_satisfied": 0},
    ):
        with pytest.raises(InvalidCanonicalCrtAuthorization):
            replace(limited, **changes)


def test_forged_nested_membership_is_translated():
    result = authorization()
    source = result.source_membership_evaluation
    forged = object.__new__(type(source))
    for field in source.__dataclass_fields__:
        object.__setattr__(
            forged, field, "wrong" if field == "schema" else getattr(source, field)
        )
    with pytest.raises(InvalidCanonicalCrtAuthorization):
        replace(result, source_membership_evaluation=forged)
    with pytest.raises(InvalidCanonicalCrtAuthorization):
        evaluate_canonical_crt_authorization(forged)


def _unchecked_membership(source, **changes):
    forged = object.__new__(type(source))
    for field in source.__dataclass_fields__:
        object.__setattr__(forged, field, changes.get(field, getattr(source, field)))
    return forged


def test_valid_nested_source_substitution_matrix_is_rejected():
    result = authorization()
    other_lineage = evaluate(lineage_fixture(2))
    other = ordinary_membership(other_lineage)
    genesis_source = genesis_membership()
    genesis_result = authorization(genesis_source)
    for base, substitute in (
        (result, other),
        (result, genesis_source),
        (genesis_result, ordinary_membership()),
    ):
        with pytest.raises(InvalidCanonicalCrtAuthorization):
            replace(base, source_membership_evaluation=substitute)
    with pytest.raises(InvalidCanonicalCrtAuthorization):
        replace(
            result,
            source_membership_evaluation=other,
            source_membership_evaluation_sha256=(
                canonical_crt_membership_evaluation_sha256(other)
            ),
        )
    with pytest.raises(InvalidCanonicalCrtAuthorization):
        replace(
            result,
            source_membership_evaluation_sha256=(
                canonical_crt_membership_evaluation_sha256(other)
            ),
        )


@pytest.mark.parametrize(
    "changes",
    (
        {"controlling_depth": 1},
        {"target_edge_sha256": None},
        {"selected_genesis_record_sha256": None},
        {"relevant_records": lambda source: source.relevant_records + source.relevant_records[:1]},
        {"relevant_records": lambda source: tuple(reversed(source.relevant_records))},
    ),
)
def test_invalid_nested_source_shapes_are_authorization_errors(changes):
    result = authorization()
    source = result.source_membership_evaluation
    resolved = {
        field: value(source) if callable(value) else value
        for field, value in changes.items()
    }
    with pytest.raises(InvalidCanonicalCrtAuthorization):
        replace(
            result,
            source_membership_evaluation=_unchecked_membership(source, **resolved),
        )


@pytest.mark.parametrize(
    ("source_factory", "reason"),
    (
        (genesis_membership,
         CanonicalCrtAuthorizationReason.EXACT_PARTICIPANT_MEMBERSHIP_FULL),
        (ordinary_membership,
         CanonicalCrtAuthorizationReason.EXACT_GENESIS_MEMBERSHIP_FULL),
    ),
)
def test_full_reasons_cannot_cross_membership_states(source_factory, reason):
    with pytest.raises(InvalidCanonicalCrtAuthorization):
        replace(authorization(source_factory()), reason_code=reason)


@pytest.mark.parametrize(
    ("state", "membership_reason", "wrong_reason"),
    (
        (CanonicalCrtMembershipState.EDGE_INACTIVE,
         CanonicalCrtMembershipReason.TARGET_EDGE_INACTIVE,
         CanonicalCrtAuthorizationReason.LINEAGE_INACTIVE_MEMBERSHIP_LIMITED),
        (CanonicalCrtMembershipState.LINEAGE_INACTIVE,
         CanonicalCrtMembershipReason.ANCESTOR_EDGE_INACTIVE,
         CanonicalCrtAuthorizationReason.EDGE_INACTIVE_MEMBERSHIP_LIMITED),
        (CanonicalCrtMembershipState.PROVISIONAL,
         CanonicalCrtMembershipReason.TARGET_PROVISIONAL,
         CanonicalCrtAuthorizationReason.DISPUTED_MEMBERSHIP_LIMITED),
        (CanonicalCrtMembershipState.UNKNOWN,
         CanonicalCrtMembershipReason.SOURCE_TIME_MISMATCH,
         CanonicalCrtAuthorizationReason.PROVISIONAL_MEMBERSHIP_LIMITED),
    ),
)
def test_limited_reasons_cannot_cross_membership_states(
    state, membership_reason, wrong_reason
):
    source = ordinary_membership(evaluated_at=NOW + timedelta(seconds=1))
    if state is not CanonicalCrtMembershipState.UNKNOWN:
        control = (
            source.depth
            if membership_reason.value.startswith("target_")
            else 1
        )
        source = replace(
            ordinary_membership(),
            state=state,
            reason_code=membership_reason,
            source_state="provisional"
            if state is CanonicalCrtMembershipState.PROVISIONAL else "lineage_inactive",
            source_reason_code=membership_reason.value,
            controlling_depth=control,
            controlling_edge_id=(
                ordinary_membership().target_edge_id
                if control == ordinary_membership().depth
                else evaluate().lineage_nodes[0].edge_id
            ),
        )
    with pytest.raises(InvalidCanonicalCrtAuthorization):
        replace(authorization(source), reason_code=wrong_reason)


@pytest.mark.parametrize(
    "mutation",
    (
        "duplicate_top", "duplicate_nested", "extra_top", "extra_nested",
        "missing_top", "missing_nested", "true_top", "false_top",
        "float_top_one", "float_top_three", "float_nested", "nan",
        "infinity", "offset_top", "offset_nested", "microseconds",
        "uppercase_uuid", "uppercase_digest", "wrong_class", "wrong_reason",
        "wrong_nested_state", "wrong_nested_reason", "digest_mismatch",
        "reordered_records", "duplicate_records", "identity_mismatch",
        "full_from_unknown", "limited_from_active", "boolean_mismatch",
        "noncanonical_order",
    ),
)
def test_parser_adversarial_matrix(mutation):
    active = authorization()
    if mutation in {"full_from_unknown"}:
        active = authorization(
            ordinary_membership(evaluated_at=NOW.replace(year=NOW.year + 1))
        )
    text = canonical_crt_authorization_evaluation_bytes(active).decode("ascii")
    data = json.loads(text)
    nested = data["source_membership_evaluation"]
    raw = None
    if mutation == "duplicate_top":
        raw = text[:-1] + ',"schema":"duplicate"}'
    elif mutation == "duplicate_nested":
        raw = text.replace('"state":', '"state":"active","state":', 1)
    elif mutation == "extra_top":
        data["extra"] = None
    elif mutation == "extra_nested":
        nested["extra"] = None
    elif mutation == "missing_top":
        data.pop("network")
    elif mutation == "missing_nested":
        nested.pop("network")
    elif mutation == "true_top":
        data["depth"] = True
    elif mutation == "false_top":
        data["depth"] = False
    elif mutation == "float_top_one":
        active = authorization(ordinary_membership(evaluate(lineage_fixture(1))))
        data = json.loads(
            canonical_crt_authorization_evaluation_bytes(active).decode("ascii")
        )
        data["depth"] = 1.0
        nested = data["source_membership_evaluation"]
    elif mutation == "float_top_three":
        active = authorization(ordinary_membership(evaluate(lineage_fixture(3))))
        data = json.loads(
            canonical_crt_authorization_evaluation_bytes(active).decode("ascii")
        )
        data["depth"] = 3.0
        nested = data["source_membership_evaluation"]
    elif mutation == "float_nested":
        nested["depth"] = 3.0
    elif mutation == "nan":
        data["depth"] = float("nan")
    elif mutation == "infinity":
        nested["depth"] = float("inf")
    elif mutation == "offset_top":
        data["evaluated_at"] = data["evaluated_at"][:-1] + "+00:00"
    elif mutation == "offset_nested":
        nested["evaluated_at"] = nested["evaluated_at"][:-1] + "+00:00"
    elif mutation == "microseconds":
        data["evaluated_at"] = data["evaluated_at"][:-1] + ".000001Z"
    elif mutation == "uppercase_uuid":
        nested["selected_genesis_record_id"] = (
            nested["selected_genesis_record_id"].upper()
        )
    elif mutation == "uppercase_digest":
        data["source_membership_evaluation_sha256"] = (
            data["source_membership_evaluation_sha256"].upper()
        )
    elif mutation == "wrong_class":
        data["authorization_class"] = "operator"
    elif mutation == "wrong_reason":
        data["reason_code"] = "allowed"
    elif mutation == "wrong_nested_state":
        nested["state"] = "unknown"
    elif mutation == "wrong_nested_reason":
        nested["reason_code"] = "genesis_unknown"
    elif mutation == "digest_mismatch":
        data["source_membership_evaluation_sha256"] = "0" * 64
    elif mutation == "reordered_records":
        nested["relevant_records"].reverse()
    elif mutation == "duplicate_records":
        nested["relevant_records"].append(nested["relevant_records"][0])
    elif mutation == "identity_mismatch":
        data["participant_id"] = "0" * 64
    elif mutation == "full_from_unknown":
        data["authorization_class"] = "full"
        data["reason_code"] = "exact_participant_membership_full"
        data["current_full_membership_satisfied"] = True
    elif mutation == "limited_from_active":
        data["authorization_class"] = "limited"
        data["reason_code"] = "unknown_membership_limited"
        data["current_full_membership_satisfied"] = False
    elif mutation == "boolean_mismatch":
        data["current_full_membership_satisfied"] = False
    else:
        raw = json.dumps(
            dict(reversed(tuple(data.items()))), separators=(",", ":"), sort_keys=False
        )
    if raw is None:
        raw = json.dumps(data, sort_keys=True, separators=(",", ":"), allow_nan=True)
    with pytest.raises(InvalidCanonicalCrtAuthorization):
        parse_canonical_crt_authorization_evaluation(raw)


def test_determinism_and_pinned_digests():
    genesis_full = authorization(genesis_membership())
    depth3_full = authorization(
        ordinary_membership(evaluate(lineage_fixture(3)))
    )
    unknown = authorization(
        ordinary_membership(evaluated_at=NOW.replace(year=NOW.year + 1))
    )
    assert canonical_crt_authorization_evaluation_sha256(genesis_full) == (
        "c63f6f83f287898e192e41f50b428801423e2ad1a23c92d2cba38dad2ebba16f"
    )
    assert canonical_crt_authorization_evaluation_sha256(depth3_full) == (
        "e82b88c4d595be9ced0cf8c64dd6b0df1eb673ad120dfdccc3b1afd9000ff562"
    )
    assert canonical_crt_authorization_evaluation_sha256(unknown) == (
        "91841e6f2cecb1c77a555de553e2044a37ea48d941e0c5680fb2e2a351059434"
    )
    assert canonical_crt_membership_evaluation_sha256(
        depth3_full.source_membership_evaluation
    ) == "b79a29168180ba897a81ebbd8143262be6196b93c5603317a16831a3a9c1cee3"
