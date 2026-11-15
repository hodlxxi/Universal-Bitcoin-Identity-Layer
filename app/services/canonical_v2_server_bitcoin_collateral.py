"""Server-configured Bitcoin Core observation for Canon V2 (Issue #588).

Unlike the source-bound helper, no RPC object, endpoint, credential, chain
or clock is accepted from an HTTP request/caller. This module is an isolated
server-side building block, NOT entitlement authority. It does not authenticate
either signer or commit an EFFECTIVE admission.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import quote

from bitcoinrpc.authproxy import AuthServiceProxy

from app.services.canonical_bitcoin_mempool_observation_v2 import (
    MempoolCheckedMultiLegObservationV2,
    observe_multileg_with_mempool_v2,
)
from app.services.canonical_multi_outpoint_mirror_v2 import CanonicalMultiOutpointMirrorV2

RUNTIME_ENABLED = False
_CHAINS = frozenset(("main", "test", "signet", "regtest"))
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class CanonicalV2ServerBitcoinUnavailable(RuntimeError):
    """Trusted source configuration or a stable Bitcoin scan is unavailable."""

    def __init__(self) -> None:
        super().__init__("canonical v2 server bitcoin observation unavailable")


def _fail() -> None:
    raise CanonicalV2ServerBitcoinUnavailable()


def _clock() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _expected_chain() -> str:
    # Explicit server configuration. No default mainnet vs regtest ambiguity.
    chain = os.environ.get("CANON_V2_BITCOIN_CHAIN")
    if chain not in _CHAINS:
        _fail()
    return chain


def _new_rpc() -> AuthServiceProxy:
    # This service intentionally does NOT reuse get_rpc_connection(), whose
    # legacy defaults permit an empty password and a remote RPC_HOST.
    host = os.environ.get("RPC_HOST")
    port = os.environ.get("RPC_PORT")
    user = os.environ.get("RPC_USER")
    password = os.environ.get("RPC_PASSWORD")
    if (
        host not in ("127.0.0.1", "::1")
        or type(port) is not str
        or not port.isascii()
        or not port.isdecimal()
        or type(user) is not str
        or type(password) is not str
        or not user
        or not password
        or any(ord(c) < 33 or ord(c) > 126 for c in user + password)
    ):
        _fail()
    number = int(port)
    if not 1 <= number <= 65535:
        _fail()
    endpoint = f"[{host}]" if ":" in host else host
    url = f"http://{quote(user, safe='')}:{quote(password, safe='')}@{endpoint}:{number}/"
    return AuthServiceProxy(url, timeout=30)


def _chain_identity(raw: object, expected: str) -> tuple[str, int, int, str]:
    if type(raw) is not dict:
        _fail()
    chain = raw.get("chain")
    height = raw.get("blocks")
    headers = raw.get("headers")
    tip = raw.get("bestblockhash")
    if (
        type(chain) is not str
        or chain != expected
        or type(height) is not int
        or height < 0
        or type(headers) is not int
        or headers < height
        or type(tip) is not str
        or _HEX64.fullmatch(tip) is None
        or raw.get("initialblockdownload") is not False
    ):
        _fail()
    return (chain, height, headers, tip)


@dataclass(frozen=True, slots=True)
class ServerBitcoinCollateralCheckV2:
    """Server-origin scan only. Still no signer or Current-Full authority."""

    scan: MempoolCheckedMultiLegObservationV2
    network: str
    observed_at: datetime

    @property
    def source_is_authoritative(self) -> bool:
        # An RPC source alone cannot authenticate the signer or prove an
        # atomic database transition; never promote this DTO into a Full grant.
        return False

    @property
    def is_effective(self) -> bool:
        return False

    @property
    def grants_full(self) -> bool:
        return False


def observe_server_bitcoin_collateral_v2(
    bundle: CanonicalMultiOutpointMirrorV2,
) -> ServerBitcoinCollateralCheckV2:
    """Read server-owned Core; check chain identity before and after all UTXOs.

    The future EFFECTIVE coordinator must call this again inside its own
    transaction and bind the result to an authenticated exact proposal.
    """
    try:
        if type(bundle) is not CanonicalMultiOutpointMirrorV2:
            _fail()
        expected = _expected_chain()
        rpc = _new_rpc()
        now = _clock()
        if type(now) is not datetime or now.tzinfo is None or now.utcoffset() is None:
            _fail()
        now = now.astimezone(timezone.utc)
        if now.microsecond:
            _fail()
        before = _chain_identity(rpc.getblockchaininfo(), expected)
        observed = observe_multileg_with_mempool_v2(bundle, bitcoin_rpc=rpc, now=now)
        after = _chain_identity(rpc.getblockchaininfo(), expected)
        if (
            before != after
            or observed.best_block_hash != before[3]
            or observed.observation.observed_block_height != before[1]
            or observed.snapshot.observed_at != now
        ):
            _fail()
        return ServerBitcoinCollateralCheckV2(observed, expected, now)
    except CanonicalV2ServerBitcoinUnavailable:
        raise
    except Exception:
        raise CanonicalV2ServerBitcoinUnavailable() from None
