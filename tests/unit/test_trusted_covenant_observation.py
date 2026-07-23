from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import hashlib

import pytest

from app.services.covenant_relation import MAX_BITCOIN_SATS, MAX_VOUT, CovenantDirection
from app.services.trusted_covenant_observation import (
    ADAPTER_VERSION,
    TRUSTED_OUTPOINT_SCHEMA,
    InvalidTrustedCovenantOutpoint,
    TrustedBitcoinCovenantObservationAdapter,
    TrustedCovenantObservationUnavailable,
    TrustedCovenantOutpoint,
)

SUBJECT = "a" * 64
ALICE = "b" * 64
BOB = "c" * 64
BLOCK = "d" * 64
SCRIPT = "5120" + "11" * 32
SCRIPT_HASH = hashlib.sha256(bytes.fromhex(SCRIPT)).hexdigest()
DESC = "raw(5120" + "11" * 32 + ")#exact"
DESC_HASH = hashlib.sha256(DESC.encode()).hexdigest()
NOW = datetime(2026, 7, 23, 12, tzinfo=timezone.utc)


def trusted(**changes):
    values = dict(
        schema=TRUSTED_OUTPOINT_SCHEMA,
        subject_pubkey=SUBJECT,
        counterparty_pubkey=ALICE,
        direction=CovenantDirection.INCOMING,
        txid="1" * 64,
        vout=0,
        amount_sats=100,
        script_sha256=SCRIPT_HASH,
        descriptor_sha256=None,
    )
    values.update(changes)
    return TrustedCovenantOutpoint(**values)


def txout(**changes):
    values = dict(
        bestblock=BLOCK,
        confirmations=3,
        value=Decimal("0.00000100"),
        scriptPubKey={"hex": SCRIPT},
    )
    values.update(changes)
    return values


class RPC:
    def __init__(self, responses=None, heights=(900_000, 900_000), hashes=(BLOCK, BLOCK), error=None):
        self.responses = list(responses or [txout()])
        self.heights = list(heights)
        self.hashes = list(hashes)
        self.error = error
        self.calls = []

    def getblockcount(self):
        self.calls.append(("getblockcount",))
        if self.error and len(self.calls) == 1:
            raise self.error
        return self.heights.pop(0)

    def getbestblockhash(self):
        self.calls.append(("getbestblockhash",))
        return self.hashes.pop(0)

    def gettxout(self, txid, vout, include_mempool):
        self.calls.append(("gettxout", txid, vout, include_mempool))
        return self.responses.pop(0)


def adapter(rpc=None, clock=lambda: NOW):
    return TrustedBitcoinCovenantObservationAdapter(rpc or RPC(), clock=clock)


def test_valid_definition_is_exact_immutable_and_versions_are_exact():
    item = trusted(descriptor_sha256=DESC_HASH)
    assert ADAPTER_VERSION == "hodlxxi.trusted_covenant_observation_adapter.v1"
    assert tuple(item.__dataclass_fields__) == (
        "schema",
        "subject_pubkey",
        "counterparty_pubkey",
        "direction",
        "txid",
        "vout",
        "amount_sats",
        "script_sha256",
        "descriptor_sha256",
    )
    with pytest.raises(FrozenInstanceError):
        item.vout = 2


@pytest.mark.parametrize(
    "changes",
    [
        {"schema": "wrong"},
        {"subject_pubkey": "A" * 64},
        {"subject_pubkey": "a" * 63},
        {"counterparty_pubkey": "B" * 64},
        {"counterparty_pubkey": "b" * 63},
        {"counterparty_pubkey": SUBJECT},
        {"direction": "incoming"},
        {"txid": "A" * 64},
        {"txid": "1" * 63},
        {"vout": True},
        {"vout": -1},
        {"vout": MAX_VOUT + 1},
        {"amount_sats": False},
        {"amount_sats": 0},
        {"amount_sats": MAX_BITCOIN_SATS + 1},
        {"script_sha256": "A" * 64},
        {"script_sha256": "a" * 63},
        {"descriptor_sha256": "D" * 64},
        {"descriptor_sha256": "d" * 63},
    ],
)
def test_definition_rejects_noncanonical_exact_fields(changes):
    with pytest.raises(InvalidTrustedCovenantOutpoint):
        trusted(**changes)


def test_rpc_dependencies_must_expose_callable_exact_methods():
    for rpc in (object(), type("Missing", (), {"getblockcount": 1})()):
        with pytest.raises(InvalidTrustedCovenantOutpoint):
            TrustedBitcoinCovenantObservationAdapter(rpc)


def test_adapter_rejects_bad_container_items_pairs_duplicates_and_subclasses():
    class DefinitionSubclass(TrustedCovenantOutpoint):
        pass

    sub = DefinitionSubclass(**{name: getattr(trusted(), name) for name in trusted().__dataclass_fields__})
    invalid = (
        [],
        (),
        (object(),),
        (sub,),
        (trusted(), trusted(subject_pubkey="e" * 64, txid="2" * 64)),
        (trusted(), trusted(counterparty_pubkey=BOB, txid="2" * 64)),
        (trusted(), trusted(direction=CovenantDirection.OUTGOING)),
    )
    for value in invalid:
        with pytest.raises(InvalidTrustedCovenantOutpoint):
            adapter().observe(value)


def test_stable_snapshot_exact_calls_order_binding_amount_digests_and_utc():
    incoming = trusted(txid="2" * 64, descriptor_sha256=DESC_HASH)
    outgoing = trusted(txid="1" * 64, direction=CovenantDirection.OUTGOING, amount_sats=200)
    rpc = RPC(
        responses=[
            txout(value=Decimal("0.00000200")),
            txout(scriptPubKey={"hex": SCRIPT, "desc": DESC}),
        ]
    )
    local_now = NOW.astimezone(timezone(timedelta(hours=5)))
    result = adapter(rpc, clock=lambda: local_now).observe((incoming, outgoing))
    assert rpc.calls == [
        ("getblockcount",),
        ("getbestblockhash",),
        ("gettxout", "1" * 64, 0, False),
        ("gettxout", "2" * 64, 0, False),
        ("getblockcount",),
        ("getbestblockhash",),
    ]
    assert [item.txid for item in result.observations] == ["1" * 64, "2" * 64]
    assert [item.direction for item in result.observations] == [
        CovenantDirection.OUTGOING,
        CovenantDirection.INCOMING,
    ]
    assert all(item.subject_pubkey == SUBJECT and item.counterparty_pubkey == ALICE for item in result.observations)
    assert result.observed_block_height == 900_000
    assert result.observed_at == NOW and result.observed_at.tzinfo is timezone.utc


def test_null_is_valid_negative_observation_with_expected_source_fields():
    item = trusted(descriptor_sha256=DESC_HASH)
    observed = adapter(RPC(responses=[None])).observe((item,)).observations[0]
    assert observed.unspent is False
    assert observed.confirmations == 0
    assert observed.amount_sats == item.amount_sats
    assert observed.script_sha256 == item.script_sha256
    assert observed.descriptor_sha256 == item.descriptor_sha256


@pytest.mark.parametrize(
    "rpc",
    [
        RPC(heights=(1, 2)),
        RPC(hashes=(BLOCK, "e" * 64)),
        RPC(heights=(True, 1)),
        RPC(heights=(-1, -1)),
        RPC(hashes=("D" * 64, BLOCK)),
        RPC(responses=[txout(bestblock="e" * 64)]),
    ],
)
def test_snapshot_inconsistency_or_malformed_values_are_unavailable(rpc):
    with pytest.raises(TrustedCovenantObservationUnavailable):
        adapter(rpc).observe((trusted(),))


def test_rpc_and_clock_failures_are_sanitized_and_clock_called_once():
    secret = "rpc://user:password@example/wallet/private"
    with pytest.raises(TrustedCovenantObservationUnavailable) as caught:
        adapter(RPC(error=RuntimeError(secret))).observe((trusted(),))
    assert secret not in str(caught.value)
    calls = []

    def naive_clock():
        calls.append(1)
        return NOW.replace(tzinfo=None)

    with pytest.raises(TrustedCovenantObservationUnavailable):
        adapter(clock=naive_clock).observe((trusted(),))
    assert calls == [1]


@pytest.mark.parametrize(
    "response",
    [
        [],
        {},
        txout(confirmations=True),
        txout(confirmations=-1),
        txout(value=0.000001),
        txout(value="0.00000100"),
        txout(value=Decimal("0.000000001")),
        txout(value=Decimal("0")),
        txout(value=Decimal("-1")),
        txout(value=Decimal("NaN")),
        txout(value=Decimal("Infinity")),
        txout(value=Decimal("21000000.00000001")),
        txout(value=Decimal("0.00000101")),
        txout(scriptPubKey=None),
        txout(scriptPubKey={}),
        txout(scriptPubKey={"hex": "AA"}),
        txout(scriptPubKey={"hex": "abc"}),
        txout(scriptPubKey={"hex": "00"}),
    ],
)
def test_malformed_non_null_gettxout_fails_unavailable(response):
    with pytest.raises(TrustedCovenantObservationUnavailable):
        adapter(RPC(responses=[response])).observe((trusted(),))


def test_descriptor_required_exact_and_unexpected_descriptor_ignored():
    required = trusted(descriptor_sha256=DESC_HASH)
    for script_pub_key in ({"hex": SCRIPT}, {"hex": SCRIPT, "desc": 1}, {"hex": SCRIPT, "desc": "different"}):
        with pytest.raises(TrustedCovenantObservationUnavailable):
            adapter(RPC(responses=[txout(scriptPubKey=script_pub_key)])).observe((required,))
    result = adapter(RPC(responses=[txout(scriptPubKey={"hex": SCRIPT, "desc": object()})])).observe((trusted(),))
    assert result.observations[0].descriptor_sha256 is None


def test_exact_integer_whole_bitcoin_is_supported_without_coercion():
    item = trusted(amount_sats=100_000_000)
    assert adapter(RPC(responses=[txout(value=1)])).observe((item,)).observations[0].amount_sats == 100_000_000
