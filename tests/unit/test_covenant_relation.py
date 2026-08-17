from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path

import pytest

from app.services.covenant_relation import (
    DECISION_SCHEMA,
    EVALUATION_SCHEMA,
    MAX_BITCOIN_SATS,
    MAX_VOUT,
    OBSERVATION_SCHEMA,
    CovenantDirection,
    CovenantRelationDecision,
    CovenantRelationEvaluation,
    CovenantRelationObservation,
    CovenantRelationReason,
    InvalidCovenantRelation,
    canonical_relation_bytes,
    covenant_relation_source_sha256,
    evaluate_covenant_relation,
)

SUBJECT = "a" * 64
ALICE = "b" * 64
BOB = "c" * 64
NOW = datetime(2026, 7, 22, 12, 34, 56, 123456, tzinfo=timezone.utc)


def observation(**changes):
    values = dict(
        schema=OBSERVATION_SCHEMA,
        subject_pubkey=SUBJECT,
        counterparty_pubkey=ALICE,
        direction=CovenantDirection.INCOMING,
        txid="1" * 64,
        vout=0,
        amount_sats=100,
        script_sha256="d" * 64,
        descriptor_sha256=None,
        confirmations=1,
        unspent=True,
    )
    values.update(changes)
    return CovenantRelationObservation(**values)


def evaluation(observations=(), **changes):
    values = dict(
        schema=EVALUATION_SCHEMA,
        network="bitcoin",
        subject_pubkey=SUBJECT,
        counterparty_pubkey=ALICE,
        observed_at=NOW,
        observed_block_height=900_000,
        observations=observations,
    )
    values.update(changes)
    return CovenantRelationEvaluation(**values)


def outgoing(txid="2" * 64, amount_sats=100, **changes):
    return observation(direction=CovenantDirection.OUTGOING, txid=txid, amount_sats=amount_sats, **changes)


def test_valid_observations_are_strict_and_immutable():
    incoming = observation(descriptor_sha256="e" * 64)
    sent = outgoing()
    assert incoming.direction is CovenantDirection.INCOMING
    assert sent.direction is CovenantDirection.OUTGOING
    with pytest.raises(FrozenInstanceError):
        incoming.amount_sats = 5


def test_observation_contract_contains_only_the_required_digest_safe_fields():
    assert tuple(CovenantRelationObservation.__dataclass_fields__) == (
        "schema",
        "subject_pubkey",
        "counterparty_pubkey",
        "direction",
        "txid",
        "vout",
        "amount_sats",
        "script_sha256",
        "descriptor_sha256",
        "confirmations",
        "unspent",
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"schema": "wrong"},
        {"subject_pubkey": "a" * 63},
        {"counterparty_pubkey": "nope"},
        {"counterparty_pubkey": SUBJECT},
        {"subject_pubkey": "A" * 64},
        {"direction": "incoming"},
        {"txid": "z" * 64},
        {"txid": "A" * 64},
        {"vout": True},
        {"vout": -1},
        {"vout": MAX_VOUT + 1},
        {"amount_sats": False},
        {"amount_sats": 0},
        {"amount_sats": MAX_BITCOIN_SATS + 1},
        {"amount_sats": 1.0},
        {"script_sha256": "d" * 63},
        {"descriptor_sha256": "E" * 64},
        {"confirmations": True},
        {"confirmations": -1},
        {"unspent": 1},
    ],
)
def test_invalid_observation_fails_closed(changes):
    with pytest.raises(InvalidCovenantRelation):
        observation(**changes)


def test_evaluation_normalizes_utc_and_accepts_empty_tuple():
    request = evaluation(observed_at=NOW.astimezone(timezone(timedelta(hours=5))))
    assert request.observed_at == NOW
    assert request.observed_at.tzinfo is timezone.utc
    assert evaluate_covenant_relation(request).reason is CovenantRelationReason.NO_QUALIFYING_OBSERVATIONS


@pytest.mark.parametrize(
    "changes",
    [
        {"schema": "wrong"},
        {"network": "testnet"},
        {"subject_pubkey": "A" * 64},
        {"counterparty_pubkey": SUBJECT},
        {"observed_at": NOW.replace(tzinfo=None)},
        {"observed_block_height": True},
        {"observed_block_height": -1},
        {"observations": []},
        {"observations": (object(),)},
    ],
)
def test_invalid_evaluation_fails_closed(changes):
    with pytest.raises(InvalidCovenantRelation):
        evaluation(**changes)


def test_observation_subclass_and_evaluation_subclass_are_rejected():
    class ObservationSubclass(CovenantRelationObservation):
        pass

    class EvaluationSubclass(CovenantRelationEvaluation):
        pass

    subclass = ObservationSubclass(
        OBSERVATION_SCHEMA, SUBJECT, ALICE, CovenantDirection.INCOMING, "1" * 64, 0, 100, "d" * 64, None, 1, True
    )
    with pytest.raises(InvalidCovenantRelation):
        evaluation((subclass,))
    with pytest.raises(InvalidCovenantRelation):
        evaluate_covenant_relation(EvaluationSubclass(EVALUATION_SCHEMA, "bitcoin", SUBJECT, ALICE, NOW, 1, ()))


def test_pair_mismatch_duplicate_outpoint_and_total_limit_are_rejected():
    with pytest.raises(InvalidCovenantRelation, match="subject"):
        evaluation((observation(subject_pubkey="f" * 64),))
    with pytest.raises(InvalidCovenantRelation, match="counterparty"):
        evaluation((observation(counterparty_pubkey=BOB),))
    with pytest.raises(InvalidCovenantRelation, match="duplicate"):
        evaluation((observation(), outgoing(txid="1" * 64)))
    with pytest.raises(InvalidCovenantRelation, match="MAX_BITCOIN_SATS"):
        evaluation((observation(amount_sats=MAX_BITCOIN_SATS), outgoing(amount_sats=1)))


@pytest.mark.parametrize(
    ("items", "reason", "incoming", "sent", "qualifying", "ignored"),
    [
        ((), CovenantRelationReason.NO_QUALIFYING_OBSERVATIONS, 0, 0, 0, 0),
        ((observation(unspent=False),), CovenantRelationReason.NO_QUALIFYING_OBSERVATIONS, 0, 0, 0, 1),
        ((observation(confirmations=0),), CovenantRelationReason.NO_QUALIFYING_OBSERVATIONS, 0, 0, 0, 1),
        ((observation(),), CovenantRelationReason.MISSING_OUTGOING, 100, 0, 1, 0),
        ((outgoing(),), CovenantRelationReason.MISSING_INCOMING, 0, 100, 1, 0),
        ((observation(), outgoing(amount_sats=99)), CovenantRelationReason.OUTGOING_BELOW_INCOMING, 100, 99, 2, 0),
        ((observation(), outgoing()), CovenantRelationReason.FULL_RELATION_SATISFIED, 100, 100, 2, 0),
        ((observation(), outgoing(amount_sats=101)), CovenantRelationReason.FULL_RELATION_SATISFIED, 100, 101, 2, 0),
    ],
)
def test_decision_reason_priority_and_counts(items, reason, incoming, sent, qualifying, ignored):
    decision = evaluate_covenant_relation(evaluation(items))
    assert decision.reason is reason
    assert decision.incoming_sats == incoming
    assert decision.outgoing_sats == sent
    assert decision.qualifying_observation_count == qualifying
    assert decision.ignored_observation_count == ignored
    assert decision.current_full_relation_satisfied is (reason is CovenantRelationReason.FULL_RELATION_SATISFIED)


def test_multiple_utxos_sum_only_qualifying_observations_for_one_pair():
    items = (
        observation(txid="1" * 64, amount_sats=40),
        observation(txid="2" * 64, amount_sats=60),
        outgoing(txid="3" * 64, amount_sats=50),
        outgoing(txid="4" * 64, amount_sats=50),
        outgoing(txid="5" * 64, amount_sats=999, unspent=False),
        observation(txid="6" * 64, amount_sats=999, confirmations=0),
    )
    decision = evaluate_covenant_relation(evaluation(items))
    assert (decision.incoming_sats, decision.outgoing_sats) == (100, 100)
    assert (decision.qualifying_observation_count, decision.ignored_observation_count) == (4, 2)
    assert decision.current_full_relation_satisfied


def test_alice_and_bob_cannot_aggregate_but_alice_pair_can_be_full():
    alice_incoming = observation()
    bob_outgoing = outgoing(counterparty_pubkey=BOB)
    with pytest.raises(InvalidCovenantRelation):
        evaluation((alice_incoming, bob_outgoing))
    assert evaluate_covenant_relation(evaluation((alice_incoming, outgoing()))).current_full_relation_satisfied
    alice_only = evaluate_covenant_relation(evaluation((alice_incoming,)))
    assert alice_only.reason is CovenantRelationReason.MISSING_OUTGOING


def test_exact_canonical_json_bytes_order_timestamp_enum_and_null():
    request = evaluation((outgoing(), observation()))
    payload = json.loads(canonical_relation_bytes(request))
    assert canonical_relation_bytes(request) == json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    assert payload["observed_at"] == "2026-07-22T12:34:56.123456Z"
    assert payload["observations"][0]["direction"] == "incoming"
    assert payload["observations"][0]["descriptor_sha256"] is None
    assert payload["observations"][1]["direction"] == "outgoing"


def test_exact_expected_canonical_json_bytes_for_empty_evaluation():
    expected = (
        b'{"counterparty_pubkey":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",'
        b'"network":"bitcoin","observations":[],"observed_at":"2026-07-22T12:34:56.123456Z",'
        b'"observed_block_height":900000,"schema":"hodlxxi.covenant_relation_evaluation.v1",'
        b'"subject_pubkey":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'
    )
    assert canonical_relation_bytes(evaluation()) == expected


def test_canonical_order_independence_and_exact_digest():
    first = observation()
    second = outgoing()
    left = evaluation((first, second))
    right = evaluation((second, first))
    assert canonical_relation_bytes(left) == canonical_relation_bytes(right)
    assert covenant_relation_source_sha256(left) == covenant_relation_source_sha256(right)
    assert evaluate_covenant_relation(left) == evaluate_covenant_relation(right)
    decision = evaluate_covenant_relation(left)
    assert decision.source_evidence_sha256 == hashlib.sha256(canonical_relation_bytes(left)).hexdigest()


@pytest.mark.parametrize(
    "changed",
    [
        observation(amount_sats=101),
        outgoing(txid="1" * 64),
        observation(txid="9" * 64),
        observation(unspent=False),
        observation(confirmations=0),
    ],
)
def test_every_material_observation_field_changes_canonical_source(changed):
    assert canonical_relation_bytes(evaluation((changed,))) != canonical_relation_bytes(evaluation((observation(),)))


def test_only_full_reason_can_construct_a_positive_decision():
    full = evaluate_covenant_relation(evaluation((observation(), outgoing())))
    assert full.schema == DECISION_SCHEMA
    values = {field: getattr(full, field) for field in full.__dataclass_fields__}
    values["reason"] = CovenantRelationReason.MISSING_INCOMING
    with pytest.raises(InvalidCovenantRelation):
        CovenantRelationDecision(**values)


def test_production_module_has_no_forbidden_runtime_dependencies_or_helpers():
    source = (Path(__file__).parents[2] / "app/services/covenant_relation.py").read_text()
    forbidden = (
        "flask",
        "sqlalchemy",
        "app.models",
        "app.database",
        "app.db_storage",
        "requests",
        "httpx",
        "redis",
        "subprocess",
        "current_app",
        "session",
        "covenant_visualizer",
        "get_save_and_check_balances_for_pubkey",
        "listdescriptors",
        "listunspent",
        "deriveaddresses",
        "getdescriptorinfo",
        "scantxoutset",
    )
    assert not [name for name in forbidden if name in source.lower()]
