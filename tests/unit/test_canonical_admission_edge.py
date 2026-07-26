from dataclasses import replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.services.canonical_admission_edge import *
from app.services.canonical_genesis_record import (
    GRAPH_ID as GENESIS_GRAPH,
    canonical_genesis_record_sha256,
    evaluate_canonical_genesis,
    parse_canonical_genesis_record,
)
from app.services.covenant_relation import (
    EVALUATION_SCHEMA,
    OBSERVATION_SCHEMA,
    CovenantDirection,
    CovenantRelationEvaluation,
    CovenantRelationObservation,
)
from app.services.mirrored_covenant_pair import (
    CovenantDeltaProfile,
    validate_mirrored_covenant_pair,
)
from app.services.trusted_covenant_registration import (
    RegisteredCovenantOutpoint,
    TrustedCovenantRegistrationLifecycle,
    create_trusted_covenant_registration,
    trusted_registration_sha256,
)

SPONSOR = GENESIS_COMPRESSED_KEY
CHILD = "032f664095c520438506ddea8f584be08aeef210bc7ec37817a56478a489b72a8c"
NOW = datetime(2026, 7, 26, 12, tzinfo=timezone.utc)


def _num(value):
    data = bytearray()
    while value:
        data.append(value & 255)
        value >>= 8
    if data[-1] & 128:
        data.append(0)
    return bytes((len(data),)) + bytes(data)


def _push(key):
    raw = bytes.fromhex(key)
    return bytes((len(raw),)) + raw


def _leg(receiver, sender, receiver_height, sender_height):
    return (
        b"\x63"
        + _num(receiver_height)
        + b"\xb1\x75"
        + _push(receiver)
        + b"\xac\x67"
        + _num(sender_height)
        + b"\xb1\x75"
        + _push(sender)
        + b"\xac\x68"
    ).hex()


def _cooperative(receiver, sender, receiver_height, sender_height):
    first, second = sorted((receiver, sender))
    return (
        b"\x63\x52"
        + _push(first)
        + _push(second)
        + b"\x52\xae\x67\x63"
        + _num(receiver_height)
        + b"\xb1\x75"
        + _push(receiver)
        + b"\xac\x67"
        + _num(sender_height)
        + b"\xb1\x75"
        + _push(sender)
        + b"\xac\x68\x68"
    ).hex()


LEG1 = _leg(CHILD, SPONSOR, 1777000, 1777777)
LEG2 = _leg(SPONSOR, CHILD, 1777777, 1778554)


def registration(amounts=(123, 123), state=TrustedCovenantRegistrationLifecycle.ACTIVE):
    pair = validate_mirrored_covenant_pair(
        LEG1,
        LEG2,
        subject_pubkey=CHILD,
        allowed_delta_profiles=(CovenantDeltaProfile.LEGACY_777,),
    )
    return create_trusted_covenant_registration(
        pair,
        (
            RegisteredCovenantOutpoint(
                CovenantDirection.INCOMING,
                "a" * 64,
                0,
                amounts[0],
                pair.incoming_leg_script_sha256,
            ),
            RegisteredCovenantOutpoint(
                CovenantDirection.OUTGOING,
                "b" * 64,
                1,
                amounts[1],
                pair.outgoing_leg_script_sha256,
            ),
        ),
        registration_id="00000000-0000-4000-8000-000000000011",
        lifecycle_state=state,
        registered_at=NOW,
        lifecycle_changed_at=NOW,
        superseded_by_registration_id=(
            "00000000-0000-4000-8000-000000000099" if state is TrustedCovenantRegistrationLifecycle.SUPERSEDED else None
        ),
    )


def genesis():
    record = parse_canonical_genesis_record(Path("docs/data/e923_canonical_genesis_record_v1.json").read_bytes())
    return evaluate_canonical_genesis((record,), graph_or_protocol_id=GENESIS_GRAPH, evaluated_at=record.effective_at)


def edge(reg=None, lifecycle=AdmissionEdgeLifecycle.EFFECTIVE, **changes):
    reg = reg or registration()
    context = AdmissionContradictionContext(None, (), False)
    if lifecycle in (AdmissionEdgeLifecycle.DISPUTED, AdmissionEdgeLifecycle.REVOKED):
        context = AdmissionContradictionContext(
            "synthetic contradiction",
            ("c" * 64,),
            lifecycle is AdmissionEdgeLifecycle.DISPUTED,
        )
    values = dict(
        schema=EDGE_SCHEMA,
        edge_version=EDGE_VERSION,
        edge_id="00000000-0000-4000-8000-000000000021",
        graph_or_protocol_id=GRAPH_ID,
        network=NETWORK,
        human_profile=HUMAN_PROFILE,
        verification_rule=VERIFICATION_RULE,
        sponsor_participant_id=GENESIS_PARTICIPANT_ID,
        sponsor_compressed_public_key=SPONSOR,
        sponsor_x_only_public_key=SPONSOR[2:],
        sponsor_depth=0,
        child_participant_id=CHILD[2:],
        child_compressed_public_key=CHILD,
        child_x_only_public_key=CHILD[2:],
        child_depth=1,
        early_height=1777000,
        middle_height=1777777,
        late_height=1778554,
        trusted_registration_id=reg.registration_id,
        trusted_registration_sha256=trusted_registration_sha256(reg),
        pair_sha256=reg.pair_sha256,
        validator_version=reg.validator_version,
        sponsor_basis_kind=SponsorBasisKind.CANONICAL_GENESIS_RECORD,
        sponsor_basis_record_id=genesis().selected_effective_record_id,
        sponsor_basis_record_sha256=genesis().selected_effective_record_sha256,
        lifecycle_state=lifecycle,
        created_at=NOW,
        lifecycle_changed_at=NOW,
        effective_at=NOW if lifecycle is AdmissionEdgeLifecycle.EFFECTIVE else None,
        superseded_by_edge_id=(
            "00000000-0000-4000-8000-000000000022" if lifecycle is AdmissionEdgeLifecycle.SUPERSEDED else None
        ),
        legs=(
            CanonicalAdmissionLeg(
                AdmissionEdgeDirection.SPONSOR_TO_CHILD,
                GENESIS_PARTICIPANT_ID,
                SPONSOR,
                SPONSOR[2:],
                CHILD[2:],
                CHILD,
                CHILD[2:],
                1777000,
                1777777,
                LEG1,
                "a" * 64,
                0,
                reg.outpoints[0].amount_sats,
                reg.outpoints[0].witness_script_sha256,
                None,
            ),
            CanonicalAdmissionLeg(
                AdmissionEdgeDirection.CHILD_TO_SPONSOR,
                CHILD[2:],
                CHILD,
                CHILD[2:],
                GENESIS_PARTICIPANT_ID,
                SPONSOR,
                SPONSOR[2:],
                1777777,
                1778554,
                LEG2,
                "b" * 64,
                1,
                reg.outpoints[1].amount_sats,
                reg.outpoints[1].witness_script_sha256,
                None,
            ),
        ),
        contradiction_context=context,
        explicit_non_claims=MANDATORY_NON_CLAIMS,
        retention_policy=RETENTION_POLICY,
        human_interpretation_required=True,
    )
    values.update(changes)
    return CanonicalAdmissionEdge(**values)


def observations(reg=None, confirmations=2, unspent=True):
    reg = reg or registration()
    return CovenantRelationEvaluation(
        EVALUATION_SCHEMA,
        NETWORK,
        CHILD[2:],
        SPONSOR[2:],
        NOW,
        900000,
        tuple(
            CovenantRelationObservation(
                OBSERVATION_SCHEMA,
                CHILD[2:],
                SPONSOR[2:],
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


def registration_for(sponsor, child, depth, *, registration_id, txids=("e", "f"), amount=321):
    early, middle, late = cascade_heights(depth)
    first = _leg(child, sponsor, early, middle)
    second = _leg(sponsor, child, middle, late)
    pair = validate_mirrored_covenant_pair(
        first,
        second,
        subject_pubkey=child,
        allowed_delta_profiles=(CovenantDeltaProfile.LEGACY_777,),
    )
    return create_trusted_covenant_registration(
        pair,
        (
            RegisteredCovenantOutpoint(
                CovenantDirection.INCOMING, txids[0] * 64, 2, amount, pair.incoming_leg_script_sha256
            ),
            RegisteredCovenantOutpoint(
                CovenantDirection.OUTGOING, txids[1] * 64, 3, amount, pair.outgoing_leg_script_sha256
            ),
        ),
        registration_id=registration_id,
        lifecycle_state=TrustedCovenantRegistrationLifecycle.ACTIVE,
        registered_at=NOW,
        lifecycle_changed_at=NOW,
    )


GRANDCHILD = "02019e7a92d22e4467e0afb20ce62976e976d1558e553351e1fb1a886b4a149f92"


def depth2(reg=None, parent=None, **changes):
    parent = parent or edge()
    reg = reg or registration_for(
        CHILD,
        GRANDCHILD,
        2,
        registration_id="00000000-0000-4000-8000-000000000031",
    )
    early, middle, late = cascade_heights(2)
    values = dict(
        schema=EDGE_SCHEMA,
        edge_version=EDGE_VERSION,
        edge_id="00000000-0000-4000-8000-000000000032",
        graph_or_protocol_id=GRAPH_ID,
        network=NETWORK,
        human_profile=HUMAN_PROFILE,
        verification_rule=VERIFICATION_RULE,
        sponsor_participant_id=CHILD[2:],
        sponsor_compressed_public_key=CHILD,
        sponsor_x_only_public_key=CHILD[2:],
        sponsor_depth=1,
        child_participant_id=GRANDCHILD[2:],
        child_compressed_public_key=GRANDCHILD,
        child_x_only_public_key=GRANDCHILD[2:],
        child_depth=2,
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
                CHILD[2:],
                CHILD,
                CHILD[2:],
                GRANDCHILD[2:],
                GRANDCHILD,
                GRANDCHILD[2:],
                early,
                middle,
                reg.mirrored_pair.earlier_leg.raw_script_hex,
                reg.outpoints[0].txid,
                reg.outpoints[0].vout,
                reg.outpoints[0].amount_sats,
                reg.outpoints[0].witness_script_sha256,
                None,
            ),
            CanonicalAdmissionLeg(
                AdmissionEdgeDirection.CHILD_TO_SPONSOR,
                GRANDCHILD[2:],
                GRANDCHILD,
                GRANDCHILD[2:],
                CHILD[2:],
                CHILD,
                CHILD[2:],
                middle,
                late,
                reg.mirrored_pair.later_leg.raw_script_hex,
                reg.outpoints[1].txid,
                reg.outpoints[1].vout,
                reg.outpoints[1].amount_sats,
                reg.outpoints[1].witness_script_sha256,
                None,
            ),
        ),
        contradiction_context=AdmissionContradictionContext(None, (), False),
        explicit_non_claims=MANDATORY_NON_CLAIMS,
        retention_policy=RETENTION_POLICY,
        human_interpretation_required=True,
    )
    values.update(changes)
    return CanonicalAdmissionEdge(**values)


def test_exact_depth1_contract_directions_and_digest():
    item = edge()
    assert cascade_heights(1) == (1777000, 1777777, 1778554)
    assert [x.direction.value for x in item.legs] == [
        "sponsor_to_child",
        "child_to_sponsor",
    ]
    assert item.legs[0].receiver_cltv_height == item.early_height
    assert item.legs[1].receiver_cltv_height == item.middle_height
    assert parse_canonical_admission_edge(canonical_admission_edge_bytes(item)) == item
    assert canonical_admission_edge_sha256(item) == canonical_admission_edge_sha256(item)


@pytest.mark.parametrize("amounts", ((123, 124), (124, 123)))
def test_admission_independently_rejects_unequal_registration_amounts(amounts):
    reg = registration(amounts)
    with pytest.raises(InvalidCanonicalAdmissionEdge):
        edge(reg)


@pytest.mark.parametrize("value", (0, True, 1.0))
def test_leg_rejects_nonpositive_bool_and_float_amounts(value):
    with pytest.raises(InvalidCanonicalAdmissionEdge):
        replace(edge().legs[0], amount_sats=value)


def test_strict_parser_rejects_missing_extra_float_and_duplicate_keys():
    payload = json.loads(canonical_admission_edge_bytes(edge()))
    for mutation in ("missing", "extra", "float"):
        data = dict(payload)
        if mutation == "missing":
            data.pop("network")
        elif mutation == "extra":
            data["extra"] = True
        else:
            data["child_depth"] = 1.0
        with pytest.raises(InvalidCanonicalAdmissionEdge):
            parse_canonical_admission_edge(json.dumps(data))
    with pytest.raises(InvalidCanonicalAdmissionEdge):
        parse_canonical_admission_edge('{"schema":"a","schema":"b"}')
    with pytest.raises(InvalidCanonicalAdmissionEdge):
        parse_canonical_admission_edge('{"legs":[{"txid":"a","txid":"b"}]}')


def test_source_binding_and_active_evaluation():
    reg, item = registration(), edge()
    validate_admission_sources(item, reg, genesis_evaluation=genesis())
    result = evaluate_canonical_admission_edge(
        item,
        trusted_registration=reg,
        observation_evaluation=observations(),
        genesis_evaluation=genesis(),
        evaluated_at=NOW,
    )
    assert (result.state, result.reason_code) == (
        AdmissionEdgeEvaluationState.ACTIVE,
        AdmissionEdgeReason.EXACT_DEPTH1_ADMISSION_ACTIVE,
    )
    assert result.selected_registration_id == reg.registration_id
    assert result.observation_source_sha256 is not None


@pytest.mark.parametrize(
    ("lifecycle", "state"),
    (
        (AdmissionEdgeLifecycle.PROPOSED, AdmissionEdgeEvaluationState.PROVISIONAL),
        (AdmissionEdgeLifecycle.DISPUTED, AdmissionEdgeEvaluationState.DISPUTED),
        (AdmissionEdgeLifecycle.REVOKED, AdmissionEdgeEvaluationState.EDGE_INACTIVE),
        (AdmissionEdgeLifecycle.SUPERSEDED, AdmissionEdgeEvaluationState.EDGE_INACTIVE),
    ),
)
def test_record_lifecycle_precedence(lifecycle, state):
    reg = registration()
    result = evaluate_canonical_admission_edge(
        edge(reg, lifecycle),
        trusted_registration=reg,
        observation_evaluation=observations(reg),
        genesis_evaluation=genesis(),
        evaluated_at=NOW,
    )
    assert result.state is state


@pytest.mark.parametrize(
    ("lifecycle", "expected_state", "expected_reason"),
    (
        (
            TrustedCovenantRegistrationLifecycle.DISPUTED,
            AdmissionEdgeEvaluationState.DISPUTED,
            AdmissionEdgeReason.REGISTRATION_DISPUTED,
        ),
        (
            TrustedCovenantRegistrationLifecycle.REVOKED,
            AdmissionEdgeEvaluationState.EDGE_INACTIVE,
            AdmissionEdgeReason.REGISTRATION_REVOKED,
        ),
        (
            TrustedCovenantRegistrationLifecycle.SUPERSEDED,
            AdmissionEdgeEvaluationState.EDGE_INACTIVE,
            AdmissionEdgeReason.REGISTRATION_SUPERSEDED,
        ),
    ),
)
def test_complete_registration_lifecycle_matrix(lifecycle, expected_state, expected_reason):
    reg = registration(state=lifecycle)
    item = edge(reg)
    result = evaluate_canonical_admission_edge(
        item,
        trusted_registration=reg,
        observation_evaluation=observations(reg),
        genesis_evaluation=genesis(),
        evaluated_at=NOW,
    )
    assert (result.state, result.reason_code) == (expected_state, expected_reason)


@pytest.mark.parametrize(
    ("state", "reason", "expected_state", "expected_reason"),
    (
        (
            CanonicalGenesisEvaluationState.PROVISIONAL,
            "proposed_only",
            AdmissionEdgeEvaluationState.PROVISIONAL,
            AdmissionEdgeReason.GENESIS_PROVISIONAL,
        ),
        (
            CanonicalGenesisEvaluationState.DISPUTED,
            "controlling_dispute",
            AdmissionEdgeEvaluationState.DISPUTED,
            AdmissionEdgeReason.GENESIS_DISPUTED,
        ),
        (
            CanonicalGenesisEvaluationState.LINEAGE_INACTIVE,
            "all_records_revoked",
            AdmissionEdgeEvaluationState.LINEAGE_INACTIVE,
            AdmissionEdgeReason.GENESIS_LINEAGE_INACTIVE,
        ),
        (
            CanonicalGenesisEvaluationState.UNKNOWN,
            "no_records",
            AdmissionEdgeEvaluationState.UNKNOWN,
            AdmissionEdgeReason.GENESIS_UNKNOWN,
        ),
    ),
)
def test_complete_genesis_state_matrix(state, reason, expected_state, expected_reason):
    source = genesis()
    source = replace(
        source,
        state=state,
        reason_code=reason,
        selected_effective_record_id=None,
        selected_effective_record_sha256=None,
    )
    result = evaluate_canonical_admission_edge(
        edge(),
        trusted_registration=registration(),
        observation_evaluation=observations(),
        genesis_evaluation=source,
        evaluated_at=NOW,
    )
    assert (result.state, result.reason_code) == (expected_state, expected_reason)


@pytest.mark.parametrize(("confirmations", "unspent"), ((0, True), (2, False)))
def test_own_observation_inactivity(confirmations, unspent):
    reg = registration()
    result = evaluate_canonical_admission_edge(
        edge(reg),
        trusted_registration=reg,
        observation_evaluation=observations(reg, confirmations, unspent),
        genesis_evaluation=genesis(),
        evaluated_at=NOW,
    )
    assert result.state is AdmissionEdgeEvaluationState.EDGE_INACTIVE


def test_exact_heights_depths_one_two_three_and_raw_script_binding():
    assert cascade_heights(1) == (1777000, 1777777, 1778554)
    assert cascade_heights(2) == (1776223, 1777000, 1777777)
    assert cascade_heights(3) == (1775446, 1776223, 1777000)
    leg = edge().legs[0]
    with pytest.raises(InvalidCanonicalAdmissionEdge):
        replace(leg, receiver_cltv_height=leg.receiver_cltv_height + 1)
    with pytest.raises(InvalidCanonicalAdmissionEdge):
        replace(leg, sender_cltv_height=leg.sender_cltv_height + 1)
    with pytest.raises(InvalidCanonicalAdmissionEdge):
        replace(leg, receiver_compressed_public_key=GRANDCHILD, receiver_x_only_public_key=GRANDCHILD[2:])


def test_arbitrary_legacy_777_middle_height_rejected_by_edge_binding():
    wrong = registration_for(
        SPONSOR,
        CHILD,
        2,
        registration_id="00000000-0000-4000-8000-000000000041",
        txids=("8", "9"),
    )
    with pytest.raises(InvalidCanonicalAdmissionEdge):
        edge(wrong)


@pytest.mark.parametrize(
    "raw",
    (
        _leg(CHILD, SPONSOR, 1777777, 1777921),
        _cooperative(CHILD, SPONSOR, 1777000, 1777777),
    ),
)
def test_current_144_and_cooperative_scripts_rejected(raw):
    with pytest.raises(InvalidCanonicalAdmissionEdge):
        replace(edge().legs[0], raw_script_hex=raw, witness_script_sha256=sha256(bytes.fromhex(raw)).hexdigest())


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("child_participant_id", "child-alias"),
        ("sponsor_participant_id", "genesis-alias"),
        ("child_depth", True),
        ("sponsor_depth", True),
        ("human_profile", "current_144"),
    ),
)
def test_participant_convention_and_exact_primitives(field, value):
    with pytest.raises(InvalidCanonicalAdmissionEdge):
        replace(edge(), **{field: value})


def test_self_sponsorship_key_collisions_and_leg_cardinality_rejected():
    item = edge()
    with pytest.raises(InvalidCanonicalAdmissionEdge):
        replace(
            item,
            child_participant_id=GENESIS_XONLY_KEY,
            child_compressed_public_key=GENESIS_COMPRESSED_KEY,
            child_x_only_public_key=GENESIS_XONLY_KEY,
        )
    with pytest.raises(InvalidCanonicalAdmissionEdge):
        replace(item, legs=item.legs[:1])
    with pytest.raises(InvalidCanonicalAdmissionEdge):
        replace(item, legs=item.legs + (item.legs[0],))
    with pytest.raises(InvalidCanonicalAdmissionEdge):
        replace(item, legs=(item.legs[0], item.legs[0]))
    with pytest.raises(InvalidCanonicalAdmissionEdge):
        replace(item, legs=(item.legs[0], replace(item.legs[1], txid=item.legs[0].txid, vout=item.legs[0].vout)))


@pytest.mark.parametrize(
    "field",
    ("created_at", "lifecycle_changed_at", "effective_at"),
)
@pytest.mark.parametrize(
    "bad",
    (
        NOW.replace(tzinfo=None),
        NOW.astimezone(timezone(timedelta(hours=1))),
        NOW.replace(microsecond=1),
    ),
)
def test_record_timestamps_require_exact_utc_seconds(field, bad):
    with pytest.raises(InvalidCanonicalAdmissionEdge):
        replace(edge(), **{field: bad})


def test_exact_utc_z_round_trip_and_evaluation_offset_rejected():
    item = edge()
    assert parse_canonical_admission_edge(canonical_admission_edge_bytes(item)) == item
    assert b'"created_at":"2026-07-26T12:00:00Z"' in canonical_admission_edge_bytes(item)
    with pytest.raises(InvalidCanonicalAdmissionEdge):
        evaluate_canonical_admission_edge(
            item,
            trusted_registration=registration(),
            observation_evaluation=observations(),
            genesis_evaluation=genesis(),
            evaluated_at=NOW.astimezone(timezone(timedelta(hours=-7))),
        )


def _forged_evaluation(**changes):
    value = observations()
    fields = {name: getattr(value, name) for name in value.__dataclass_fields__}
    fields.update(changes)
    return SimpleNamespace(**fields)


@pytest.mark.parametrize(
    "changes",
    (
        {"network": "testnet"},
        {"subject_pubkey": "1" * 64},
        {"counterparty_pubkey": "2" * 64},
        {"observed_at": NOW + timedelta(seconds=1)},
    ),
)
def test_observation_evaluation_identity_source_mismatch_is_unknown(changes):
    result = evaluate_canonical_admission_edge(
        edge(),
        trusted_registration=registration(),
        observation_evaluation=_forged_evaluation(**changes),
        genesis_evaluation=genesis(),
        evaluated_at=NOW,
    )
    assert (result.state, result.reason_code) == (
        AdmissionEdgeEvaluationState.UNKNOWN,
        AdmissionEdgeReason.OBSERVATION_BINDING_MISMATCH,
    )


@pytest.mark.parametrize(
    "field",
    ("txid", "vout", "amount_sats", "script_sha256", "descriptor_sha256", "subject_pubkey", "counterparty_pubkey"),
)
def test_each_observation_binding_field_mismatch_is_unknown(field):
    value = observations()
    first = value.observations[0]
    replacement = {
        "txid": "7" * 64,
        "vout": 99,
        "amount_sats": first.amount_sats + 1,
        "script_sha256": "7" * 64,
        "descriptor_sha256": "7" * 64,
        "subject_pubkey": "7" * 64,
        "counterparty_pubkey": "8" * 64,
    }[field]
    forged = SimpleNamespace(
        **{
            **{name: getattr(value, name) for name in value.__dataclass_fields__},
            "observations": (replace(first, **{field: replacement}), value.observations[1]),
        }
    )
    result = evaluate_canonical_admission_edge(
        edge(),
        trusted_registration=registration(),
        observation_evaluation=forged,
        genesis_evaluation=genesis(),
        evaluated_at=NOW,
    )
    assert result.reason_code is AdmissionEdgeReason.OBSERVATION_BINDING_MISMATCH


def test_duplicate_direction_and_third_observation_are_unknown():
    value = observations()
    for forged_observations in (
        (value.observations[0], replace(value.observations[1], direction=CovenantDirection.INCOMING)),
        value.observations + (value.observations[0],),
    ):
        forged = SimpleNamespace(
            **{
                **{name: getattr(value, name) for name in value.__dataclass_fields__},
                "observations": forged_observations,
            }
        )
        result = evaluate_canonical_admission_edge(
            edge(),
            trusted_registration=registration(),
            observation_evaluation=forged,
            genesis_evaluation=genesis(),
            evaluated_at=NOW,
        )
        assert result.reason_code is AdmissionEdgeReason.OBSERVATION_BINDING_MISMATCH


def test_valid_depth2_sources_and_evaluator_boundary():
    parent, reg = edge(), registration_for(
        CHILD,
        GRANDCHILD,
        2,
        registration_id="00000000-0000-4000-8000-000000000031",
    )
    item = depth2(reg, parent)
    validate_admission_sources(item, reg, parent_edge=parent)
    result = evaluate_canonical_admission_edge(
        item,
        trusted_registration=reg,
        observation_evaluation=object(),
        genesis_evaluation=object(),
        evaluated_at=NOW,
    )
    assert (result.state, result.reason_code) == (
        AdmissionEdgeEvaluationState.UNKNOWN,
        AdmissionEdgeReason.SPONSOR_LINEAGE_EVALUATOR_UNAVAILABLE,
    )


@pytest.mark.parametrize(
    "mutation",
    ("id", "digest", "identity", "depth", "non_effective"),
)
def test_depth2_rejects_incorrect_parent_basis(mutation):
    parent = edge()
    item = depth2(parent=parent)
    if mutation == "id":
        item = replace(item, sponsor_basis_record_id="00000000-0000-4000-8000-000000000099")
    elif mutation == "digest":
        item = replace(item, sponsor_basis_record_sha256="0" * 64)
    elif mutation == "identity":
        forged = object.__new__(CanonicalAdmissionEdge)
        for field in parent.__dataclass_fields__:
            object.__setattr__(
                forged,
                field,
                GRANDCHILD[2:] if field == "child_participant_id" else getattr(parent, field),
            )
        parent = forged
    elif mutation == "depth":
        parent = depth2()
    else:
        parent = replace(parent, lifecycle_state=AdmissionEdgeLifecycle.PROPOSED, effective_at=None)
    with pytest.raises(InvalidCanonicalAdmissionEdge):
        validate_admission_sources(
            item,
            registration_for(CHILD, GRANDCHILD, 2, registration_id="00000000-0000-4000-8000-000000000031"),
            parent_edge=parent,
        )


def test_basis_kind_is_depth_bound():
    with pytest.raises(InvalidCanonicalAdmissionEdge):
        replace(edge(), sponsor_basis_kind=SponsorBasisKind.CANONICAL_ADMISSION_EDGE)
    with pytest.raises(InvalidCanonicalAdmissionEdge):
        replace(depth2(), sponsor_basis_kind=SponsorBasisKind.CANONICAL_GENESIS_RECORD)


def test_evaluation_output_reference_contract():
    active = evaluate_canonical_admission_edge(
        edge(),
        trusted_registration=registration(),
        observation_evaluation=observations(),
        genesis_evaluation=genesis(),
        evaluated_at=NOW,
    )
    assert len(active.relevant_records) == 3
    with pytest.raises(InvalidCanonicalAdmissionEdge):
        replace(active, relevant_records=active.relevant_records[:1])
    with pytest.raises(InvalidCanonicalAdmissionEdge):
        replace(active, child_depth=2, early_height=1776223, middle_height=1777000, late_height=1777777)
    inactive = evaluate_canonical_admission_edge(
        edge(lifecycle=AdmissionEdgeLifecycle.PROPOSED),
        trusted_registration=registration(),
        observation_evaluation=observations(),
        genesis_evaluation=genesis(),
        evaluated_at=NOW,
    )
    with pytest.raises(InvalidCanonicalAdmissionEdge):
        replace(
            inactive,
            selected_registration_id=registration().registration_id,
            selected_registration_sha256=trusted_registration_sha256(registration()),
        )


def test_pinned_synthetic_canonical_digest():
    assert canonical_admission_edge_sha256(edge()) == "75b1e40ca8580d7598125c30b568726c22440128339538738502266a7c304fdf"
