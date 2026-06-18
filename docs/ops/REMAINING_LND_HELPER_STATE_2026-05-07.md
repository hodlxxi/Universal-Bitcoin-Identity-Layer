# HODLXXI Remaining LND Helper State — 2026-05-07

> **Status:** Historical checkpoint. This document records deployment, cleanup, planning, or protocol state at the time it was written. Do not treat it as the current runbook or current implementation truth unless it is explicitly linked from `docs/DOCUMENTATION_MAP.md` or `docs/READINESS_EVALUATION.md`.


## Current state

After systemd env cleanup, the remaining active LND-related drop-ins are intentionally retained:

- /etc/systemd/system/hodlxxi.service.d/20-lnd-readonly.conf
- /etc/systemd/system/hodlxxi.service.d/22-home-for-lncli.conf
- /etc/systemd/system/hodlxxi.service.d/23-bind-lncli.conf
- /etc/systemd/system/hodlxxi.service.d/zz-force-lnd-cli-paths.conf

The following LND-related cleanup has already been completed:

- 21-lnd-rpcserver.conf disabled.
- 24-agent-ln-backend.conf reduced to AGENT_PRIVKEY_PATH only.
- override.conf disabled.
- redis-env.conf disabled.
- 25-bitcoin-rpc.conf disabled.

## Why no further drop-ins were disabled

Inspection showed that the remaining files are not obvious duplicates.

20-lnd-readonly.conf provides helper lncli compatibility variables:

- LND_LNCLI_BIN
- LND_DIR
- LND_TLS_CERT
- LND_READONLY_MACAROON

22-home-for-lncli.conf provides:

- HOME

23-bind-lncli.conf provides systemd filesystem binding:

- BindPaths

zz-force-lnd-cli-paths.conf provides the known-good canonical LND runtime variables:

- LN_BACKEND
- LND_RPCSERVER
- LND_TLSCERTPATH
- LND_MACAROONPATH

## Code usage findings

Repository inspection showed legacy/runtime code still reads helper variables including:

- LND_LNCLI_BIN
- LND_DIR
- LND_TLS_CERT
- LND_READONLY_MACAROON
- LND_RPCSERVER

Payment runtime code reads canonical variables including:

- LN_BACKEND
- LND_RPCSERVER
- LND_TLSCERTPATH
- LND_MACAROONPATH

Because both helper and canonical names are still referenced, further systemd cleanup should not happen until code paths are consolidated.

## Hash comparison findings

Live hash comparison showed:

- LND_TLS_CERT matches LND_TLSCERTPATH.
- LND_READONLY_MACAROON differs from LND_MACAROONPATH.
- zz-force-lnd-cli-paths.conf matches the canonical envfile for LN_BACKEND, LND_RPCSERVER, LND_TLSCERTPATH, and LND_MACAROONPATH.

This means zz-force-lnd-cli-paths.conf should remain active for now.

## Current validation

Runtime remained healthy after the previous cleanup steps:

- /health/ready: ready
- /api/public/status: BTC height present, LND active
- /agent/chain/health: chain_ok=true
- OIDC metadata: S256 present

## Decision

Stop systemd LND drop-in removal here.

Next engineering work should migrate remaining legacy/helper LND reads toward canonical names before removing additional drop-ins.

## Safety rule

Only compare variable names or hashes.

Do not print raw secret values, macaroon paths, Redis URLs, database URLs, private keys, or env file contents.
