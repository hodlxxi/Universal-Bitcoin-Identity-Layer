"""Dormant mempool-inclusive Bitcoin Core preflight for Canon V2 N+M collateral.

This is a *source-bound* read. An injected RPC can be a synthetic or
malicious stand-in; live use must construct a trusted server-owned Bitcoin
Core client and authenticate the participant/session independently.

No status, sponsorship, EFFECTIVE admission or Full entitlement is issued.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import re

from app.services.canonical_multi_outpoint_mirror_v2 import (
    CanonicalMultiOutpointMirrorV2,
    CanonicalMultiOutpointSnapshotV2,
    validate_canonical_multi_outpoint_snapshot_v2,
)
from app.services.covenant_relation import CovenantRelationEvaluation
from app.services.trusted_covenant_observation import TrustedBitcoinCovenantObservationAdapter

RUNTIME_ENABLED = False
_HEX64 = re.compile(r"[0-9a-f]{64}\\Z")


class CanonicalBitcoinMempoolObservationUnavailableV2(RuntimeError):
    """The exact proposed-only Bitcoin observation could not be established."""

    def __init__(self) -> None:
        super().__init__("canonical bitcoin mempool observation unavailable")


def _fail() -> None:
    raise CanonicalBitcoinMempoolObservationUnavailableV2()


def _tip_hash(value: object) -> str:
    if type(value) is not str or not _HEX64.fullmatch(value):
        _fail()
    return value


def _block_height(value: object) -> int:
    if type(value) is not int or value < 0:
        _fail()
    return value


def _mempool_sequence(value: object) -> int:
    if (
        type(value) is not dict
        or set(value) != {"txids", "mempool_sequence"}
        or type(value["txids"]) is not list
        or type(value["mempool_sequence"]) is not int
        or value["mempool_sequence"] < 0
    ):
        _fail()
    # Do not retain, serialize, or expose the mempool transaction list.
    return value["mempool_sequence"]


class _MempoolInclusiveProxy:
    """Existing verified outpoint parser, with gettxout's flag forced to True."""

    def __init__(self, rpc: object) -> None:
        self._rpc = rpc

    def getblockcount(self) -> int:
        return self._rpc.getblockcount()

    def getbestblockhash(self) -> str:
        return self._rpc.getbestblockhash()

    def gettxout(self, txid: str, vout: int, include_mempool: bool):
        # The legacy adapter explicitly passes False. Reject API drift
        # rather than silently using a caller-chosen flag.
        if include_mempool is not False:
            _fail()
        return self._rpc.gettxout(txid, vout, True)


@dataclass(frozen=True, slots=True)
class MempoolCheckedMultiLegObservationV2:
    """One bounded observation, never an independently authoritative admission."""

    observation: CovenantRelationEvaluation
    snapshot: CanonicalMultiOutpointSnapshotV2
    best_block_hash: str
    mempool_sequence: int

    @property
    def source_is_authoritative(self) -> bool:
        return False

    @property
    def is_effective(self) -> bool:
        return False

    @property
    def grants_full(self) -> bool:
        return False


def observe_multileg_with_mempool_v2(
    bundle: CanonicalMultiOutpointMirrorV2,
    *,
    bitcoin_rpc: object,
    now: datetime,
) -> MempoolCheckedMultiLegObservationV2:
    """Validate 1+1 through N+M outputs under matching tip and mempool sequence.

    gettxout(txid, vout, True) rejects outputs being spent by transactions
    visible in this Bitcoin Core node's mempool. The mempool sequence and
    chain tip are read before/after all outputs; a change fails closed.
    No atomic network-wide mempool snapshot or future chain stability is
    claimed. A later EFFECTIVE transition must check again at its own
    linearization point and must prove RPC and identity provenance.
    """
    try:
        if type(bundle) is not CanonicalMultiOutpointMirrorV2:
            _fail()
        if type(now) is not datetime or now.tzinfo is None or now.utcoffset() is None:
            _fail()
        checked_at = now.astimezone(timezone.utc)
        if checked_at.microsecond:
            _fail()
        for method in ("getblockcount", "getbestblockhash", "gettxout", "getrawmempool"):
            if not callable(getattr(bitcoin_rpc, method, None)):
                _fail()

        height_before = _block_height(bitcoin_rpc.getblockcount())
        hash_before = _tip_hash(bitcoin_rpc.getbestblockhash())
        mempool_before = _mempool_sequence(bitcoin_rpc.getrawmempool(False, True))

        observation = TrustedBitcoinCovenantObservationAdapter(
            _MempoolInclusiveProxy(bitcoin_rpc), clock=lambda: checked_at
        ).observe(bundle.outpoints)
        snapshot = validate_canonical_multi_outpoint_snapshot_v2(
            bundle, observation, now=checked_at
        )

        mempool_after = _mempool_sequence(bitcoin_rpc.getrawmempool(False, True))
        height_after = _block_height(bitcoin_rpc.getblockcount())
        hash_after = _tip_hash(bitcoin_rpc.getbestblockhash())
        if (
            height_before != height_after
            or hash_before != hash_after
            or observation.observed_block_height != height_before
            or mempool_before != mempool_after
        ):
            _fail()

        return MempoolCheckedMultiLegObservationV2(
            observation, snapshot, hash_before, mempool_before
        )
    except CanonicalBitcoinMempoolObservationUnavailableV2:
        raise
    except Exception:
        raise CanonicalBitcoinMempoolObservationUnavailableV2() from None
