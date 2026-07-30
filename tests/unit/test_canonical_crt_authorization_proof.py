from dataclasses import replace
from datetime import timedelta
import json

import pytest

import app.services.canonical_crt_authorization_proof as proof_module
from app.services.canonical_crt_authorization_policy import (
    CanonicalCrtAuthorizationReason,
    canonical_crt_authorization_evaluation_sha256,
    evaluate_canonical_crt_authorization,
)
from app.services.canonical_crt_authorization_proof import *
from app.services.canonical_crt_membership import (
    CanonicalCrtMembershipReason,
    CanonicalCrtMembershipState,
    canonical_crt_membership_evaluation_sha256,
)
from app.services.canonical_genesis_record import (
    CanonicalGenesisLifecycle,
    evaluate_canonical_genesis,
)
from tests.unit.test_canonical_admission_edge import NOW, genesis
from tests.unit.test_canonical_genesis_record import record as genesis_record
from tests.unit.test_canonical_crt_membership import (
    genesis_membership,
    ordinary_membership,
)
from tests.unit.test_canonical_sponsor_lineage import evaluate, lineage_fixture
from app.services.canonical_sponsor_lineage import (
    CanonicalSponsorLineageReason,
    CanonicalSponsorLineageState,
)


def proof(source=None):
    authorization = evaluate_canonical_crt_authorization(
        source or ordinary_membership()
    )
    return build_canonical_crt_authorization_proof(authorization)


@pytest.mark.parametrize("depth", (1, 2, 3))
def test_active_ordinary_full_matrix(depth):
    membership = ordinary_membership(evaluate(lineage_fixture(depth)))
    authorization = evaluate_canonical_crt_authorization(membership)
    result = build_canonical_crt_authorization_proof(authorization)
    assert result.source_authorization_evaluation == authorization
    assert result.source_membership_evaluation_sha256 == (
        canonical_crt_membership_evaluation_sha256(membership)
    )
    assert result.proof_conclusion is (
        CanonicalCrtAuthorizationProofConclusion
        .FULL_BY_EXACT_PARTICIPANT_MEMBERSHIP
    )
    assert result.proof_basis is (
        CanonicalCrtAuthorizationProofBasis.COMPLETE_SPONSOR_LINEAGE
    )
    assert result.canonical_explanation == (
        "authorization_class=full; "
        "authorization_reason=exact_participant_membership_full; "
        "membership_state=active; "
        "membership_reason=exact_participant_membership_active; "
        "proof_basis=complete_sponsor_lineage"
    )
    encoded = canonical_crt_authorization_proof_bytes(result)
    assert parse_canonical_crt_authorization_proof(encoded) == result
    assert canonical_crt_authorization_proof_bytes(result) == encoded


def test_active_genesis_full_matrix():
    membership = genesis_membership()
    result = proof(membership)
    assert result.proof_conclusion is (
        CanonicalCrtAuthorizationProofConclusion
        .FULL_BY_EXACT_GENESIS_MEMBERSHIP
    )
    assert result.proof_basis is CanonicalCrtAuthorizationProofBasis.GENESIS_RECORD
    assert result.subject_kind.value == "genesis"
    assert result.controlling_depth is membership.controlling_depth is None
    assert result.controlling_edge_id is membership.controlling_edge_id is None


def _genesis_evaluation(case):
    item = genesis_record()
    if case == "proposed_only":
        records = (replace(
            item,
            lifecycle_state=CanonicalGenesisLifecycle.PROPOSED,
            effective_at=None,
            lifecycle_changed_at=item.created_at,
        ),)
        evaluated_at = item.created_at
    elif case == "controlling_dispute":
        records = (replace(
            item,
            lifecycle_state=CanonicalGenesisLifecycle.DISPUTED,
            contradiction_context=replace(
                item.contradiction_context,
                reason="unresolved dispute",
                evidence_reference_ids=("canon_genesis_bootstrap_v1",),
                unresolved_controlling_dispute=True,
            ),
        ),)
        evaluated_at = item.effective_at
    elif case == "multiple_effective_records":
        records = (
            item,
            replace(
                item,
                record_id="e9230000-0000-4000-8000-000000000002",
            ),
        )
        evaluated_at = item.effective_at
    elif case == "all_records_revoked":
        records = (replace(
            item,
            lifecycle_state=CanonicalGenesisLifecycle.REVOKED,
            contradiction_context=replace(
                item.contradiction_context,
                reason="terminal contradiction",
                evidence_reference_ids=("canon_genesis_bootstrap_v1",),
            ),
        ),)
        evaluated_at = item.effective_at
    elif case == "no_records":
        records = ()
        evaluated_at = item.effective_at
    else:
        records = (item,)
        evaluated_at = item.effective_at - timedelta(seconds=1)
    return evaluate_canonical_genesis(
        records,
        graph_or_protocol_id=item.graph_or_protocol_id,
        evaluated_at=evaluated_at,
    )


@pytest.mark.parametrize(
    ("case", "state", "reason", "conclusion"),
    (
        ("proposed_only", "provisional", "genesis_provisional",
         "limited_by_provisional_membership"),
        ("controlling_dispute", "disputed", "genesis_disputed",
         "limited_by_disputed_membership"),
        ("multiple_effective_records", "disputed", "genesis_disputed",
         "limited_by_disputed_membership"),
        ("all_records_revoked", "lineage_inactive", "genesis_lineage_inactive",
         "limited_by_lineage_inactivity"),
        ("no_records", "unknown", "genesis_unknown",
         "limited_by_unknown_membership"),
        ("effective_timestamp_in_future", "unknown", "genesis_unknown",
         "limited_by_unknown_membership"),
    ),
)
def test_genuine_genesis_limited_composition(
    case, state, reason, conclusion,
):
    genesis_evaluation = _genesis_evaluation(case)
    membership = genesis_membership(genesis_evaluation)
    authorization = evaluate_canonical_crt_authorization(membership)
    result = build_canonical_crt_authorization_proof(authorization)
    assert result.authorization_class.value == "limited"
    assert result.current_full_membership_satisfied is False
    assert result.source_authorization_evaluation == authorization
    assert result.source_authorization_evaluation_sha256 == (
        canonical_crt_authorization_evaluation_sha256(authorization)
    )
    assert result.source_authorization_evaluation.source_membership_evaluation == (
        membership
    )
    assert result.source_membership_evaluation_sha256 == (
        canonical_crt_membership_evaluation_sha256(membership)
    )
    assert result.membership_state.value == state
    assert result.membership_reason_code.value == reason
    assert result.proof_conclusion.value == conclusion
    assert result.proof_basis.value == "genesis_record"
    assert result.controlling_depth == membership.controlling_depth == 0
    assert result.controlling_edge_id is membership.controlling_edge_id is None
    assert result.selected_genesis_record_id == (
        membership.selected_genesis_record_id
    )
    assert result.selected_genesis_record_sha256 == (
        membership.selected_genesis_record_sha256
    )
    assert result.selected_genesis_record_id is None
    assert result.selected_genesis_record_sha256 is None
    assert result.canonical_explanation == (
        f"authorization_class=limited; "
        f"authorization_reason={authorization.reason_code.value}; "
        f"membership_state={state}; membership_reason={reason}; "
        "proof_basis=genesis_record"
    )
    encoded = canonical_crt_authorization_proof_bytes(result)
    assert canonical_crt_authorization_proof_bytes(result) == encoded
    assert parse_canonical_crt_authorization_proof(encoded) == result


def test_unknown_limited_is_a_valid_proof():
    result = proof(
        ordinary_membership(evaluated_at=NOW.replace(year=NOW.year + 1))
    )
    assert result.authorization_class.value == "limited"
    assert result.current_full_membership_satisfied is False
    assert result.proof_conclusion is (
        CanonicalCrtAuthorizationProofConclusion.LIMITED_BY_UNKNOWN_MEMBERSHIP
    )
    assert result.proof_basis is CanonicalCrtAuthorizationProofBasis.SOURCE_BINDING


@pytest.mark.parametrize(
    "reason",
    (
        CanonicalCrtMembershipReason.SOURCE_KIND_MISMATCH,
        CanonicalCrtMembershipReason.SOURCE_SUBJECT_MISMATCH,
        CanonicalCrtMembershipReason.SOURCE_TIME_MISMATCH,
        CanonicalCrtMembershipReason.SOURCE_GRAPH_OR_PROFILE_MISMATCH,
    ),
)
def test_genesis_source_binding_precedes_genesis_record(reason):
    if reason is CanonicalCrtMembershipReason.SOURCE_KIND_MISMATCH:
        membership = genesis_membership(
            genesis_evaluation=None,
            lineage_evaluation=evaluate(),
            evaluated_at=NOW,
        )
    else:
        # These are valid defensive canonical result objects.  The membership
        # contract permits all source-binding reasons on the same unknown
        # genesis-subject result shape; runtime reachability is not asserted.
        binding = genesis_membership(
            evaluated_at=genesis_record().effective_at + timedelta(seconds=1)
        )
        membership = replace(binding, reason_code=reason)
    authorization = evaluate_canonical_crt_authorization(membership)
    result = build_canonical_crt_authorization_proof(authorization)
    assert result.proof_conclusion.value == "limited_by_unknown_membership"
    assert result.proof_basis.value == "source_binding"
    assert result.controlling_depth is membership.controlling_depth is None
    assert result.controlling_edge_id is membership.controlling_edge_id is None
    assert result.source_authorization_evaluation == authorization
    assert result.source_membership_evaluation_sha256 == (
        canonical_crt_membership_evaluation_sha256(membership)
    )
    assert result.canonical_explanation.endswith(
        f"membership_reason={reason.value}; proof_basis=source_binding"
    )
    encoded = canonical_crt_authorization_proof_bytes(result)
    assert parse_canonical_crt_authorization_proof(encoded) == result


class _TupleSubclass(tuple):
    pass


class _StringSubclass(str):
    pass


@pytest.mark.parametrize(
    "mutation",
    (
        "outer_records_tuple",
        "inner_records_tuple",
        "record_id_string",
        "record_digest_string",
        "nonclaims_tuple",
        "nonclaim_string",
    ),
)
def test_collection_primitive_types_are_exact(mutation):
    result = proof()
    records = result.relevant_records
    nonclaims = result.explicit_non_claims
    if mutation == "outer_records_tuple":
        changes = {"relevant_records": _TupleSubclass(records)}
    elif mutation == "inner_records_tuple":
        changes = {
            "relevant_records": (_TupleSubclass(records[0]),) + records[1:]
        }
    elif mutation == "record_id_string":
        changes = {
            "relevant_records": (
                (_StringSubclass(records[0][0]), records[0][1]),
            ) + records[1:]
        }
    elif mutation == "record_digest_string":
        changes = {
            "relevant_records": (
                (records[0][0], _StringSubclass(records[0][1])),
            ) + records[1:]
        }
    elif mutation == "nonclaims_tuple":
        changes = {"explicit_non_claims": _TupleSubclass(nonclaims)}
    else:
        changes = {
            "explicit_non_claims": (
                _StringSubclass(nonclaims[0]),
            ) + nonclaims[1:]
        }
    with pytest.raises(InvalidCanonicalCrtAuthorizationProof):
        replace(result, **changes)


def test_mappings_are_explicit_immutable_and_exhaustive():
    assert set(proof_module._CONCLUSION_BY_REASON) == set(
        CanonicalCrtAuthorizationReason
    )
    assert set(proof_module._BASIS_BY_REASON) == set(
        CanonicalCrtMembershipReason
    )
    with pytest.raises(TypeError):
        proof_module._BASIS_BY_REASON[
            CanonicalCrtMembershipReason.GENESIS_UNKNOWN
        ] = CanonicalCrtAuthorizationProofBasis.SOURCE_BINDING


def _membership_for_reason(reason):
    if reason is CanonicalCrtMembershipReason.EXACT_GENESIS_MEMBERSHIP_ACTIVE:
        return genesis_membership()
    if reason is CanonicalCrtMembershipReason.EXACT_PARTICIPANT_MEMBERSHIP_ACTIVE:
        return ordinary_membership()
    if reason in {
        CanonicalCrtMembershipReason.GENESIS_PROVISIONAL,
        CanonicalCrtMembershipReason.GENESIS_DISPUTED,
        CanonicalCrtMembershipReason.GENESIS_LINEAGE_INACTIVE,
        CanonicalCrtMembershipReason.GENESIS_UNKNOWN,
    }:
        case = {
            CanonicalCrtMembershipReason.GENESIS_PROVISIONAL: "proposed_only",
            CanonicalCrtMembershipReason.GENESIS_DISPUTED: "controlling_dispute",
            CanonicalCrtMembershipReason.GENESIS_LINEAGE_INACTIVE:
                "all_records_revoked",
            CanonicalCrtMembershipReason.GENESIS_UNKNOWN: "no_records",
        }[reason]
        return genesis_membership(_genesis_evaluation(case))
    if reason in proof_module._SOURCE_BINDING_REASONS:
        if reason is CanonicalCrtMembershipReason.SOURCE_KIND_MISMATCH:
            return ordinary_membership(
                evaluate(),
                lineage_evaluation=None,
                genesis_evaluation=genesis(),
                evaluated_at=genesis().evaluated_at,
            )
        binding = ordinary_membership(
            evaluated_at=NOW.replace(year=NOW.year + 1)
        )
        return replace(binding, reason_code=reason)

    lineage_reason = CanonicalSponsorLineageReason(reason.value)
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
    defensive_lineage = replace(lineage, **changes)
    return ordinary_membership(
        defensive_lineage,
        participant_id=lineage.target_participant_id,
        compressed_public_key=lineage.target_compressed_public_key,
        x_only_public_key=lineage.target_x_only_public_key,
        depth=lineage.target_depth,
        target_edge_id=lineage.target_edge_id,
    )


@pytest.mark.parametrize("membership_reason", tuple(CanonicalCrtMembershipReason))
def test_every_membership_reason_executes_a_complete_proof(membership_reason):
    # Structural lineage failures are canonical defensive result objects; this
    # test does not claim every one is reachable from every runtime snapshot.
    membership = _membership_for_reason(membership_reason)
    authorization = evaluate_canonical_crt_authorization(membership)
    result = build_canonical_crt_authorization_proof(authorization)
    expected_basis = proof_module._basis(authorization)
    assert result.source_authorization_evaluation == authorization
    assert result.source_authorization_evaluation_sha256 == (
        canonical_crt_authorization_evaluation_sha256(authorization)
    )
    assert result.source_membership_evaluation_sha256 == (
        canonical_crt_membership_evaluation_sha256(membership)
    )
    flattened_authorization_fields = (
        "graph_or_protocol_id",
        "network",
        "human_profile",
        "subject_kind",
        "participant_id",
        "compressed_public_key",
        "x_only_public_key",
        "depth",
        "target_edge_id",
        "target_edge_sha256",
        "evaluated_at",
        "authorization_class",
        "current_full_membership_satisfied",
    )
    for field in flattened_authorization_fields:
        assert getattr(result, field) == getattr(authorization, field)
    assert result.authorization_reason_code is authorization.reason_code
    assert result.membership_state is membership.state
    assert result.membership_reason_code is membership.reason_code
    flattened_membership_fields = (
        "source_evaluation_kind",
        "source_evaluation_sha256",
        "source_state",
        "source_reason_code",
        "controlling_depth",
        "controlling_edge_id",
        "selected_genesis_record_id",
        "selected_genesis_record_sha256",
        "relevant_records",
    )
    for field in flattened_membership_fields:
        assert getattr(result, field) == getattr(membership, field)
    assert result.proof_conclusion is (
        proof_module._CONCLUSION_BY_REASON[authorization.reason_code]
    )
    assert result.proof_basis is expected_basis
    assert result.canonical_explanation == proof_module._explanation(
        authorization.authorization_class,
        authorization.reason_code,
        membership.state,
        membership.reason_code,
        expected_basis,
    )
    encoded = canonical_crt_authorization_proof_bytes(result)
    assert parse_canonical_crt_authorization_proof(encoded) == result


@pytest.mark.parametrize("controlling_depth", (None, 1, True, 0.0))
def test_non_active_genesis_control_forgery_rejected(controlling_depth):
    source = proof(genesis_membership(_genesis_evaluation("proposed_only")))
    with pytest.raises(InvalidCanonicalCrtAuthorizationProof):
        replace(source, controlling_depth=controlling_depth)


def test_active_genesis_control_forgery_rejected():
    with pytest.raises(InvalidCanonicalCrtAuthorizationProof):
        replace(proof(genesis_membership()), controlling_depth=0)


def test_genesis_source_binding_control_forgery_rejected():
    membership = genesis_membership(
        evaluated_at=genesis_record().effective_at + timedelta(seconds=1)
    )
    source = proof(membership)
    assert source.proof_basis is CanonicalCrtAuthorizationProofBasis.SOURCE_BINDING
    with pytest.raises(InvalidCanonicalCrtAuthorizationProof):
        replace(source, controlling_depth=0)


@pytest.mark.parametrize(
    ("reason", "basis"),
    (
        ("exact_genesis_membership_active", "genesis_record"),
        ("exact_participant_membership_active", "complete_sponsor_lineage"),
        ("genesis_provisional", "genesis_control"),
        ("target_provisional", "target_edge"),
        ("ancestor_provisional", "ancestor_edge"),
        ("missing_target_evidence", "target_evidence"),
        ("missing_parent_evidence", "lineage_structure"),
        ("source_time_mismatch", "source_binding"),
    ),
)
def test_all_basis_families_are_named(reason, basis):
    assert proof_module._BASIS_BY_REASON[
        CanonicalCrtMembershipReason(reason)
    ].value == basis


@pytest.mark.parametrize(
    "value",
    (None, {}, b"{}", "{}", ordinary_membership()),
)
def test_public_builder_failure_contract(value):
    with pytest.raises(InvalidCanonicalCrtAuthorizationProof):
        build_canonical_crt_authorization_proof(value)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("schema", "wrong"),
        ("builder_version", "wrong"),
        ("verification_rule", "wrong"),
        ("depth", True),
        ("depth", 3.0),
        ("network", "testnet"),
        ("canonical_explanation", " wrong"),
        ("source_authorization_evaluation_sha256", "0" * 64),
        ("source_membership_evaluation_sha256", "0" * 64),
        ("explicit_non_claims", ()),
        ("human_interpretation_required", False),
        ("proof_basis", CanonicalCrtAuthorizationProofBasis.TARGET_EDGE),
        (
            "proof_conclusion",
            CanonicalCrtAuthorizationProofConclusion
            .FULL_BY_EXACT_GENESIS_MEMBERSHIP,
        ),
    ),
)
def test_constructor_forgery_rejected(field, value):
    with pytest.raises(InvalidCanonicalCrtAuthorizationProof):
        replace(proof(), **{field: value})


def test_valid_nested_source_substitution_rejected():
    base = proof(ordinary_membership(evaluate(lineage_fixture(3))))
    other = evaluate_canonical_crt_authorization(
        ordinary_membership(evaluate(lineage_fixture(2)))
    )
    with pytest.raises(InvalidCanonicalCrtAuthorizationProof):
        replace(
            base,
            source_authorization_evaluation=other,
            source_authorization_evaluation_sha256=(
                canonical_crt_authorization_evaluation_sha256(other)
            ),
        )


@pytest.mark.parametrize(
    "mutation",
    (
        "duplicate_top", "duplicate_authorization", "duplicate_membership",
        "extra_top", "extra_authorization", "extra_membership",
        "missing_top", "missing_authorization", "missing_membership",
        "float_top", "float_authorization", "float_membership", "nan",
        "infinity", "boolean_depth", "offset", "microseconds",
        "wrong_conclusion", "wrong_basis", "wrong_explanation",
        "authorization_digest", "membership_digest", "reordered_records",
        "duplicate_records", "noncanonical_order",
    ),
)
def test_parser_adversarial_matrix(mutation):
    raw = canonical_crt_authorization_proof_bytes(proof()).decode("ascii")
    data = json.loads(raw)
    authorization = data["source_authorization_evaluation"]
    membership = authorization["source_membership_evaluation"]
    if mutation == "duplicate_top":
        raw = raw[:-1] + ',"schema":"duplicate"}'
    elif mutation == "duplicate_authorization":
        raw = raw.replace('"policy_version":', '"policy_version":"x","policy_version":', 1)
    elif mutation == "duplicate_membership":
        marker = '"source_membership_evaluation":{'
        raw = raw.replace(marker, marker + '"state":"active",', 1)
    elif mutation == "extra_top":
        data["extra"] = None
    elif mutation == "extra_authorization":
        authorization["extra"] = None
    elif mutation == "extra_membership":
        membership["extra"] = None
    elif mutation == "missing_top":
        data.pop("network")
    elif mutation == "missing_authorization":
        authorization.pop("network")
    elif mutation == "missing_membership":
        membership.pop("network")
    elif mutation == "float_top":
        data["depth"] = 3.0
    elif mutation == "float_authorization":
        authorization["depth"] = 3.0
    elif mutation == "float_membership":
        membership["depth"] = 3.0
    elif mutation == "nan":
        data["depth"] = float("nan")
    elif mutation == "infinity":
        membership["depth"] = float("inf")
    elif mutation == "boolean_depth":
        data["depth"] = True
    elif mutation == "offset":
        data["evaluated_at"] = data["evaluated_at"][:-1] + "+00:00"
    elif mutation == "microseconds":
        data["evaluated_at"] = data["evaluated_at"][:-1] + ".000001Z"
    elif mutation == "wrong_conclusion":
        data["proof_conclusion"] = "limited_by_unknown_membership"
    elif mutation == "wrong_basis":
        data["proof_basis"] = "target_edge"
    elif mutation == "wrong_explanation":
        data["canonical_explanation"] += " "
    elif mutation == "authorization_digest":
        data["source_authorization_evaluation_sha256"] = "0" * 64
    elif mutation == "membership_digest":
        data["source_membership_evaluation_sha256"] = "0" * 64
    elif mutation == "reordered_records":
        data["relevant_records"].reverse()
    elif mutation == "duplicate_records":
        data["relevant_records"].append(data["relevant_records"][0])
    elif mutation == "noncanonical_order":
        raw = json.dumps(dict(reversed(tuple(data.items()))), separators=(",", ":"))
    if mutation not in {
        "duplicate_top", "duplicate_authorization", "duplicate_membership",
        "noncanonical_order",
    }:
        raw = json.dumps(
            data, sort_keys=True, separators=(",", ":"), allow_nan=True
        )
    with pytest.raises(InvalidCanonicalCrtAuthorizationProof):
        parse_canonical_crt_authorization_proof(raw)


def test_pinned_proof_and_unchanged_source_digests():
    genesis = proof(genesis_membership())
    depth3 = proof(ordinary_membership(evaluate(lineage_fixture(3))))
    unknown = proof(
        ordinary_membership(evaluated_at=NOW.replace(year=NOW.year + 1))
    )
    assert canonical_crt_authorization_proof_sha256(genesis) == (
        "1e7508f12641f32e8813ddea1dd4b8bc9f0d5e862512773f36a4f414e7db4945"
    )
    assert canonical_crt_authorization_proof_sha256(depth3) == (
        "48f1d49935e2f5a580fab0c56d350cba036c859bdb726c38a259ef6011ec0b98"
    )
    assert canonical_crt_authorization_proof_sha256(unknown) == (
        "cf8aff59d98a2c0ec7bf62253fcfb1d0cce264517476ddecb6297153080e401c"
    )
    assert genesis.source_authorization_evaluation_sha256 == (
        "c63f6f83f287898e192e41f50b428801423e2ad1a23c92d2cba38dad2ebba16f"
    )
    assert depth3.source_authorization_evaluation_sha256 == (
        "e82b88c4d595be9ced0cf8c64dd6b0df1eb673ad120dfdccc3b1afd9000ff562"
    )
    assert unknown.source_authorization_evaluation_sha256 == (
        "91841e6f2cecb1c77a555de553e2044a37ea48d941e0c5680fb2e2a351059434"
    )
