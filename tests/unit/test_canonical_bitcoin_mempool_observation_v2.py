"""Mempool-inclusive source-only observation tests for real N+M collateral shapes.

Offline fake RPC is NOT Bitcoin Core or a trusted producer of Full.
"""

from dataclasses import replace

import pytest

from app.services.canonical_bitcoin_mempool_observation_v2 import (
    CanonicalBitcoinMempoolObservationUnavailableV2,
    observe_multileg_with_mempool_v2,
)
from tests.unit.test_canonical_admission_proposal_v2 import NOW
from tests.unit.test_canonical_multi_outpoint_mirror_v2 import Rpc, _bundle


class CoreRpc(Rpc):
    def __init__(self, mirror):
        super().__init__(mirror)
        self.sequence_calls = 0
        self.change_sequence = False
        self.mempool_spent = False
        self.unconfirmed = False
        self.invalid_mempool_shape = False
        self.tip_changes = False

    def getrawmempool(self, verbose, mempool_sequence):
        assert verbose is False and mempool_sequence is True
        self.sequence_calls += 1
        if self.invalid_mempool_shape:
            return {"mempool_sequence": "1", "txids": []}
        return {
            "txids": [],
            "mempool_sequence": 1 + int(self.change_sequence and self.sequence_calls == 2),
        }

    def getbestblockhash(self):
        if self.tip_changes and self.height_calls >= 3:
            return "e" * 64
        return super().getbestblockhash()

    def gettxout(self, txid, vout, include_mempool):
        assert include_mempool is True
        if self.mempool_spent:
            self.calls.append((txid, vout, include_mempool))
            return None
        result = super().gettxout(txid, vout, include_mempool)
        if self.unconfirmed:
            result = {**result, "confirmations": 0}
        return result


def _observe(bundle, rpc, *, at=NOW):
    return observe_multileg_with_mempool_v2(bundle, bitcoin_rpc=rpc, now=at)


def test_three_plus_two_mempool_observation_checks_every_outpoint():
    mirror = _bundle()
    rpc = CoreRpc(mirror)
    result = _observe(mirror, rpc)
    assert len(rpc.calls) == len(mirror.outpoints) == 5
    assert all(include is True for _, _, include in rpc.calls)
    assert rpc.sequence_calls == 2
    assert result.snapshot.outpoint_count == 5
    assert result.snapshot.trust_ceiling_sats == 300000
    assert result.best_block_hash == "f" * 64
    assert result.mempool_sequence == 1
    assert not result.is_effective and not result.grants_full
    assert not result.source_is_authoritative


def test_unequal_aggregate_sides_compute_minimum_ceiling():
    mirror = _bundle(outgoing=(80000, 80000, 40000), incoming=(150000, 150000))
    result = _observe(mirror, CoreRpc(mirror))
    assert (result.snapshot.earlier_sats, result.snapshot.later_sats) == (200000, 300000)
    assert result.snapshot.trust_ceiling_sats == 200000


def test_mempool_spend_refuses_all_collected_utxos():
    mirror = _bundle()
    rpc = CoreRpc(mirror)
    rpc.mempool_spent = True
    with pytest.raises(CanonicalBitcoinMempoolObservationUnavailableV2):
        _observe(mirror, rpc)
    assert rpc.calls and all(include for _, _, include in rpc.calls)


def test_unconfirmed_output_cannot_qualify():
    mirror = _bundle()
    rpc = CoreRpc(mirror)
    rpc.unconfirmed = True
    with pytest.raises(CanonicalBitcoinMempoolObservationUnavailableV2):
        _observe(mirror, rpc)


def test_mempool_sequence_change_during_scan_is_rejected():
    mirror = _bundle()
    rpc = CoreRpc(mirror)
    rpc.change_sequence = True
    with pytest.raises(CanonicalBitcoinMempoolObservationUnavailableV2):
        _observe(mirror, rpc)
    assert rpc.sequence_calls == 2


def test_tip_change_during_scan_is_rejected():
    mirror = _bundle()
    rpc = CoreRpc(mirror)
    rpc.tip_changes = True
    with pytest.raises(CanonicalBitcoinMempoolObservationUnavailableV2):
        _observe(mirror, rpc)


def test_malformed_mempool_sequence_fails_closed():
    mirror = _bundle()
    rpc = CoreRpc(mirror)
    rpc.invalid_mempool_shape = True
    with pytest.raises(CanonicalBitcoinMempoolObservationUnavailableV2):
        _observe(mirror, rpc)


def test_missing_rpc_or_malformed_clock_rejected():
    mirror = _bundle()
    with pytest.raises(CanonicalBitcoinMempoolObservationUnavailableV2):
        _observe(mirror, object())
    with pytest.raises(CanonicalBitcoinMempoolObservationUnavailableV2):
        _observe(mirror, CoreRpc(mirror), at=NOW.replace(microsecond=1))


def test_mismatched_utxo_script_or_amount_fails_closed():
    mirror = _bundle()
    rpc = CoreRpc(mirror)
    rpc.fail_script = True
    with pytest.raises(CanonicalBitcoinMempoolObservationUnavailableV2):
        _observe(mirror, rpc)


def test_legacy_false_mempool_adapter_is_not_the_new_authority():
    mirror = _bundle()
    rpc = CoreRpc(mirror)
    outpoint = mirror.outpoints[0]
    assert outpoint.txid
    result = _observe(mirror, rpc)
    assert result.observation.observed_at == NOW
    assert result.snapshot.bundle_sha256
    assert all(call[2] is True for call in rpc.calls)
