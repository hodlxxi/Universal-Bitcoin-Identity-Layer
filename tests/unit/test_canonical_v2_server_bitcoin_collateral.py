"""Server-owned Bitcoin Core boundary tests: no RPC or Full from a caller.

A fake Core is used only for CI. It does NOT prove live Bitcoin funding.
"""

from datetime import datetime

import pytest

import app.services.canonical_v2_server_bitcoin_collateral as service
from tests.unit.test_canonical_admission_proposal_v2 import NOW
from tests.unit.test_canonical_bitcoin_mempool_observation_v2 import CoreRpc
from tests.unit.test_canonical_multi_outpoint_mirror_v2 import BLOCK_HASH, HEIGHT, _bundle


class LocalCore(CoreRpc):
    def __init__(self, mirror):
        super().__init__(mirror)
        self.chain = "regtest"
        self.ibd = False
        self.headers = HEIGHT
        self.chain_calls = 0
        self.change_chain = False

    def getblockchaininfo(self):
        self.chain_calls += 1
        chain = "main" if self.change_chain and self.chain_calls == 2 else self.chain
        return {
            "chain": chain,
            "blocks": HEIGHT,
            "headers": self.headers,
            "bestblockhash": BLOCK_HASH,
            "initialblockdownload": self.ibd,
        }


def _mock_local(monkeypatch, rpc):
    monkeypatch.setattr(service, "_new_rpc", lambda: rpc)
    monkeypatch.setattr(service, "_expected_chain", lambda: "regtest")
    monkeypatch.setattr(service, "_clock", lambda: NOW)


def test_server_local_core_checks_all_three_plus_two_outpoints(monkeypatch):
    mirror = _bundle()
    rpc = LocalCore(mirror)
    _mock_local(monkeypatch, rpc)
    result = service.observe_server_bitcoin_collateral_v2(mirror)
    assert result.network == "regtest"
    assert result.observed_at == NOW
    assert result.scan.snapshot.outpoint_count == 5
    assert result.scan.snapshot.trust_ceiling_sats == 300000
    assert len(rpc.calls) == 5
    assert all(include is True for _, _, include in rpc.calls)
    assert rpc.sequence_calls == 2
    assert rpc.chain_calls == 2
    assert result.source_is_authoritative is False
    assert result.is_effective is False
    assert result.grants_full is False
    assert service.RUNTIME_ENABLED is False


@pytest.mark.parametrize("change", ("chain", "ibd", "headers", "chain_drift", "mempool_spend", "tip_drift"))
def test_server_local_core_fails_closed_on_mismatched_state(monkeypatch, change):
    mirror = _bundle()
    rpc = LocalCore(mirror)
    _mock_local(monkeypatch, rpc)
    if change == "chain":
        rpc.chain = "main"
    elif change == "ibd":
        rpc.ibd = True
    elif change == "headers":
        rpc.headers = HEIGHT - 1
    elif change == "chain_drift":
        rpc.change_chain = True
    elif change == "mempool_spend":
        rpc.mempool_spent = True
    else:
        rpc.tip_changes = True
    with pytest.raises(service.CanonicalV2ServerBitcoinUnavailable):
        service.observe_server_bitcoin_collateral_v2(mirror)


def test_bad_server_clock_rejects_even_valid_core(monkeypatch):
    mirror = _bundle()
    rpc = LocalCore(mirror)
    _mock_local(monkeypatch, rpc)
    monkeypatch.setattr(service, "_clock", lambda: datetime(2026, 11, 13))
    with pytest.raises(service.CanonicalV2ServerBitcoinUnavailable):
        service.observe_server_bitcoin_collateral_v2(mirror)


def test_server_expected_chain_is_explicit_and_exact(monkeypatch):
    monkeypatch.delenv("CANON_V2_BITCOIN_CHAIN", raising=False)
    with pytest.raises(service.CanonicalV2ServerBitcoinUnavailable):
        service._expected_chain()
    monkeypatch.setenv("CANON_V2_BITCOIN_CHAIN", "REGTEST")
    with pytest.raises(service.CanonicalV2ServerBitcoinUnavailable):
        service._expected_chain()
    monkeypatch.setenv("CANON_V2_BITCOIN_CHAIN", "regtest")
    assert service._expected_chain() == "regtest"


@pytest.mark.parametrize(
    "bad",
    (
        {"RPC_HOST": "remote.example"},
        {"RPC_HOST": "localhost"},
        {"RPC_PORT": "abc"},
        {"RPC_PORT": "0"},
        {"RPC_PORT": "65536"},
        {"RPC_USER": ""},
        {"RPC_PASSWORD": ""},
    ),
)
def test_server_owned_rpc_never_uses_unsafe_config(monkeypatch, bad):
    settings = {
        "RPC_HOST": "127.0.0.1",
        "RPC_PORT": "8332",
        "RPC_USER": "bitcoin",
        "RPC_PASSWORD": "secret",
    }
    settings.update(bad)
    for key, value in settings.items():
        monkeypatch.setenv(key, value)
    with pytest.raises(service.CanonicalV2ServerBitcoinUnavailable):
        service._new_rpc()


def test_server_rpc_factory_uses_loopback_only_and_escapes_credentials(monkeypatch):
    monkeypatch.setenv("RPC_HOST", "127.0.0.1")
    monkeypatch.setenv("RPC_PORT", "8332")
    monkeypatch.setenv("RPC_USER", "core@node")
    monkeypatch.setenv("RPC_PASSWORD", "secret:with/slash")
    called = []

    def factory(url, timeout):
        called.append((url, timeout))
        return object()

    monkeypatch.setattr(service, "AuthServiceProxy", factory)
    service._new_rpc()
    assert called == [("http://core%40node:secret%3Awith%2Fslash@127.0.0.1:8332/", 30)]


def test_malformed_injected_core_cannot_obtain_full(monkeypatch):
    mirror = _bundle()
    _mock_local(monkeypatch, object())
    with pytest.raises(service.CanonicalV2ServerBitcoinUnavailable):
        service.observe_server_bitcoin_collateral_v2(mirror)
