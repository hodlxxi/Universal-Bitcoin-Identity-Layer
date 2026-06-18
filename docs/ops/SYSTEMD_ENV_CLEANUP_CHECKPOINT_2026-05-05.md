# HODLXXI Systemd Env Cleanup Checkpoint — 2026-05-05

> **Status:** Historical checkpoint. This document records deployment, cleanup, planning, or protocol state at the time it was written. Do not treat it as the current runbook or current implementation truth unless it is explicitly linked from `docs/DOCUMENTATION_MAP.md` or `docs/READINESS_EVALUATION.md`.


## Current state

Production systemd now uses `/etc/hodlxxi/hodlxxi.env` as the only active `EnvironmentFile`.

`/srv/ubid/.env` is no longer an active systemd env source and is retained only as rollback material.

## Completed

- Consolidated working DB env values into `/etc/hodlxxi/hodlxxi.env`.
- Removed `/srv/ubid/.env` from active `EnvironmentFile` references.
- Disabled duplicate Bitcoin RPC systemd drop-in:
  - `/etc/systemd/system/hodlxxi.service.d/25-bitcoin-rpc.conf.DISABLED`
- Confirmed no active direct `RPC_*` systemd `Environment=` lines remain.

## Production validation

- `/health/ready`: ready
- `/api/public/status`: BTC height present, LND active
- `/agent/chain/health`: `chain_ok=true`
- OIDC metadata advertises `S256`
- Recent serious error scan: empty

## LND cleanup note

Attempting to disable `zz-force-lnd-cli-paths.conf` exposed conflicting active LND path values from other drop-ins.

The drop-in was restored and remains active because it currently preserves the intended `lncli` path configuration:

- `LN_BACKEND=lnd_cli`
- `LND_RPCSERVER=127.0.0.1:10009`
- `LND_TLSCERTPATH=/etc/hodlxxi/lncli/tls.cert`
- `LND_MACAROONPATH` points to the intended lncli macaroon path

## Next target

Clean up `override.conf` carefully in a separate operation.

Do not rotate live secrets until remaining drop-in conflicts are resolved and rollback steps are confirmed.
