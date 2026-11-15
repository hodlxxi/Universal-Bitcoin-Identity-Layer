# Canon V2 — server-owned Bitcoin Core observation (Issue #588, slice 2)

This module implements a real server-side connection boundary for Bitcoin
Core and reuses the five-outpoint (N+M) mempool-inclusive validator from PR
#587. It is the next dependency for the #589 `EFFECTIVE` database gate.

## Server-controlled input

`observe_server_bitcoin_collateral_v2(bundle)` does not accept an injected
RPC endpoint, RPC object, credentials, expected chain or timestamp from a
caller. A private factory reads the process's `RPC_HOST`, `RPC_PORT`,
`RPC_USER`, and `RPC_PASSWORD` environment and requires explicitly
configured `CANON_V2_BITCOIN_CHAIN`. Only numeric loopback hosts
`127.0.0.1` or `::1` are accepted; absent/blank credentials, invalid ports,
remote hostnames and omitted chain configuration fail closed. The RPC client
is created by the server only, without wallet privileges.

Before and after the Bitcoin scan it reads `getblockchaininfo()` and
checks the expected chain, no initial block download, heights, headers, and
unchanged tip. The inner scan uses `gettxout(txid,vout,true)`, and
checks unchanged mempool sequence, tip, output scripts and amounts, positive
confirmations, both legs and the trust ceiling. Any missing/inconsistent data
aborts without partial success.

The RPC credentials must remain in server-managed configuration; never
pass secrets through a request, log them, or expose the internal factory as
an HTTP endpoint. Enforce least-privilege firewall/RPC user isolation and
authenticate the local bitcoind process independently before activation.
Host loopback alone is not sufficient evidence of host/process identity.

## Absolutely no authority promotion yet

This is **not** the last admission step. The returned typed object still
reports `source_is_authoritative=False`, `is_effective=False`,
`grants_full=False`. Tests inject a deliberately fake RPC **only** by
patching private seams, to test validation logic. They do not verify live
Bitcoin funding, app-session identity or Full status.

The next integration must bind a fresh scan to the **same exact signed N+M
proposal and both authenticated signer identities**, independently confirm
the current sponsor Full / active effective parent in one PostgreSQL
transaction, and atomically write the #589 effective edge plus genuinely
sourced Current-Full evidence. It must cover replay, spent collateral,
reorgs, stale evidence, global child uniqueness, DB role privilege
separation and expiry races. Social must then read the same authoritative
UBID subject. Secure messaging must be verified separately.

## Rollout state

- `RUNTIME_ENABLED=False`; no route, job or enrollment hook.
- No production database migrations, authentication policy changes, Full
  grants, Social status changes, service restarts or deployment.
- Review as a staging-gated source adapter. Never merge/activate on the
  assumption that one server RPC scan independently grants Full.
