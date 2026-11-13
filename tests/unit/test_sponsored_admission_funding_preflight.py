"""Exact-snapshot funding preflight for real Alice/Bob and cascading sponsors."""

import hashlib
from datetime import datetime, timezone
from decimal import Decimal

import pytest

from app.services.sponsored_admission_funding_preflight import (
    SCHEMA,
    CandidateOutpoint,
    assess_sponsored_funding_snapshot,
)

ALICE = "023d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923"
BOB = "02c870934f7aaa2fd1c40834989fd97933a8866ebcf35f3e529d95b50d320f80a3"
CHARLIE = "032f664095c520438506ddea8f584be08aeef210bc7ec37817a56478a489b72a8c"
BLOCK_HASH = "f" * 64
EARLIER_TXID = "a" * 64
LATER_TXID = "b" * 64
NOW = datetime(2026, 11, 13, tzinfo=timezone.utc)


def _num(n):
    data = bytearray()
    while n:
        data.append(n & 255)
        n >>= 8
    if data[-1] & 128:
        data.append(0)
    return bytes((len(data),)) + data


def _leg(receiver, sender, early, late):
    return (
        b"\x63"
        + _num(early)
        + b"\xb1\x75"
        + bytes.fromhex("21" + receiver)
        + b"\xac\x67"
        + _num(late)
        + b"\xb1\x75"
        + bytes.fromhex("21" + sender)
        + b"\xac\x68"
    ).hex()


DEMO_EARLY = _leg(ALICE, BOB, 1777000, 1777777)
DEMO_LATE = _leg(BOB, ALICE, 1777777, 1778554)


def _txout(script, *, sats=50000, confirmations=6, block=BLOCK_HASH):
    return {
        "bestblock": block,
        "confirmations": confirmations,
        "value": Decimal(sats) / Decimal(100_000_000),
        "scriptPubKey": {"hex": "0020" + hashlib.sha256(bytes.fromhex(script)).hexdigest()},
    }


class StubRpc:
    def __init__(self, outputs):
        self.outputs = outputs
        self.calls = []
        self.height = 900000
        self.hash = BLOCK_HASH
        self.change_height_on_second_read = False
        self._height_calls = 0

    def getblockcount(self):
        self._height_calls += 1
        if self.change_height_on_second_read and self._height_calls > 1:
            return self.height + 1
        return self.height

    def getbestblockhash(self):
        return self.hash

    def gettxout(self, txid, vout, include_mempool):
        self.calls.append((txid, vout, include_mempool))
        return self.outputs.get((txid, vout))


def _rpc(early_script=DEMO_EARLY, late_script=DEMO_LATE):
    return StubRpc(
        {
            (EARLIER_TXID, 0): _txout(early_script),
            (LATER_TXID, 1): _txout(late_script),
        }
    )


def _assess(
    rpc,
    *,
    early=DEMO_EARLY,
    late=DEMO_LATE,
    sponsor=ALICE,
    depth=0,
    earlier=None,
    later=None,
):
    return assess_sponsored_funding_snapshot(
        early,
        late,
        sponsor_compressed_pubkey=sponsor,
        sponsor_depth=depth,
        earlier_outpoint=earlier or CandidateOutpoint(EARLIER_TXID, 0, 50000),
        later_outpoint=later or CandidateOutpoint(LATER_TXID, 1, 50000),
        rpc=rpc,
        clock=lambda: NOW,
    )


def test_exact_real_alice_bob_pair_observed_but_never_grants_full():
    rpc = _rpc()
    result = _assess(rpc)
    assert result.schema == SCHEMA
    assert result.status == "two_exact_utxos_observed_no_admission"
    assert result.structural_status == "reverse_branch_roles_requires_policy_review"
    assert result.sponsor_xonly_pubkey == ALICE[2:]
    assert result.candidate_child_xonly_pubkey == BOB[2:]
    assert result.child_depth == 1
    assert len(result.pair_sha256) == 64
    assert result.observed_at == NOW
    assert result.observed_block_height == 900000
    assert result.mirror_sats_per_leg == 50000
    assert result.grants_full is False
    assert set(rpc.calls) == {(EARLIER_TXID, 0, False), (LATER_TXID, 1, False)}


def test_swapped_input_scripts_are_still_canonicalized():
    rpc = _rpc()
    result = _assess(rpc, early=DEMO_LATE, late=DEMO_EARLY)
    assert result.status == "two_exact_utxos_observed_no_admission"
    assert result.grants_full is False


def test_bob_can_be_structurally_examined_as_a_sponsor_without_root_exception():
    early = _leg(BOB, CHARLIE, 1776223, 1777000)
    late = _leg(CHARLIE, BOB, 1777000, 1777777)
    rpc = _rpc(early, late)
    result = _assess(rpc, early=early, late=late, sponsor=BOB, depth=1)
    assert result.status == "two_exact_utxos_observed_no_admission"
    assert result.structural_status == "reverse_branch_roles_requires_policy_review"
    assert result.child_depth == 2
    assert result.candidate_child_xonly_pubkey == CHARLIE[2:]
    assert result.grants_full is False


def test_canon_v1_orientation_is_only_funding_observation_not_full():
    early = _leg(BOB, ALICE, 1777000, 1777777)
    late = _leg(ALICE, BOB, 1777777, 1778554)
    result = _assess(_rpc(early, late), early=early, late=late)
    assert result.structural_status == "canonical_script_shape_only"
    assert result.status == "two_exact_utxos_observed_no_admission"
    assert result.grants_full is False


def test_invalid_pair_does_not_call_bitcoin_rpc():
    rpc = _rpc()
    result = _assess(rpc, early=DEMO_EARLY, late=DEMO_EARLY)
    assert result.status == "structural_candidate_rejected"
    assert result.pair_sha256 is None
    assert result.grants_full is False
    assert rpc.calls == []
    assert rpc._height_calls == 0


def test_wrong_cascade_depth_does_not_call_bitcoin_rpc():
    rpc = _rpc()
    result = _assess(rpc, depth=1)
    assert result.status == "structural_candidate_rejected"
    assert result.structural_status == "wrong_admission_schedule"
    assert rpc.calls == []


@pytest.mark.parametrize(
    "earlier,later",
    [
        (CandidateOutpoint(EARLIER_TXID, 0, 50000), CandidateOutpoint(EARLIER_TXID, 0, 50000)),
        (CandidateOutpoint(EARLIER_TXID, 0, 50000), CandidateOutpoint(LATER_TXID, 1, 49999)),
    ],
)
def test_duplicate_or_unequal_candidate_bindings_rejected_without_rpc(earlier, later):
    rpc = _rpc()
    result = _assess(rpc, earlier=earlier, later=later)
    assert result.status == "invalid_outpoint_binding"
    assert result.grants_full is False
    assert rpc.calls == []


@pytest.mark.parametrize(
    "txid,vout,sats",
    [
        ("A" * 64, 0, 50000),
        ("a" * 63, 0, 50000),
        ("z" * 64, 0, 50000),
        (EARLIER_TXID, True, 50000),
        (EARLIER_TXID, -1, 50000),
        (EARLIER_TXID, 4294967296, 50000),
        (EARLIER_TXID, 0, True),
        (EARLIER_TXID, 0, 0),
        (EARLIER_TXID, 0, -1),
        (EARLIER_TXID, 0, 1.5),
    ],
)
def test_candidate_outpoint_requires_exact_public_binding(txid, vout, sats):
    with pytest.raises(ValueError):
        CandidateOutpoint(txid, vout, sats)


@pytest.mark.parametrize("missing", ["earlier", "later"])
def test_missing_or_spent_outpoint_fails_closed(missing):
    rpc = _rpc()
    key = (EARLIER_TXID, 0) if missing == "earlier" else (LATER_TXID, 1)
    rpc.outputs[key] = None
    result = _assess(rpc)
    assert result.status == "missing_or_insufficient_qualifying_utxo"
    assert result.grants_full is False


def test_unconfirmed_output_fails_closed():
    rpc = _rpc()
    rpc.outputs[(EARLIER_TXID, 0)]["confirmations"] = 0
    result = _assess(rpc)
    assert result.status == "missing_or_insufficient_qualifying_utxo"
    assert not result.grants_full


def test_swapped_outpoint_script_binding_fails_closed():
    rpc = _rpc()
    rpc.outputs[(EARLIER_TXID, 0)] = _txout(DEMO_LATE)
    rpc.outputs[(LATER_TXID, 1)] = _txout(DEMO_EARLY)
    result = _assess(rpc)
    assert result.status == "observation_unavailable"
    assert result.grants_full is False


def test_incorrect_value_and_wrong_script_pubkey_fail_closed():
    rpc = _rpc()
    rpc.outputs[(EARLIER_TXID, 0)]["value"] = Decimal("0.0006")
    assert _assess(rpc).status == "observation_unavailable"

    rpc = _rpc()
    rpc.outputs[(EARLIER_TXID, 0)]["scriptPubKey"]["hex"] = "0014" + "0" * 40
    assert _assess(rpc).status == "observation_unavailable"


def test_inconsistent_best_block_fails_closed():
    rpc = _rpc()
    rpc.outputs[(EARLIER_TXID, 0)]["bestblock"] = "0" * 64
    assert _assess(rpc).status == "observation_unavailable"


def test_chain_height_change_fails_closed():
    rpc = _rpc()
    rpc.change_height_on_second_read = True
    assert _assess(rpc).status == "observation_unavailable"


def test_rpc_failure_is_never_treated_as_full():
    class BrokenRpc(StubRpc):
        def gettxout(self, *args):
            raise RuntimeError("rpc disconnected")

    result = _assess(BrokenRpc({}))
    assert result.status == "observation_unavailable"
    assert result.observed_at is None
    assert result.grants_full is False
