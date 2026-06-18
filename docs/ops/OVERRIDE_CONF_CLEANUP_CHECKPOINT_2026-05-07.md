# HODLXXI override.conf Cleanup Checkpoint — 2026-05-07

> **Status:** Historical checkpoint. This document records deployment, cleanup, planning, or protocol state at the time it was written. Do not treat it as the current runbook or current implementation truth unless it is explicitly linked from `docs/DOCUMENTATION_MAP.md` or `docs/READINESS_EVALUATION.md`.


## Current state

Production systemd no longer has `override.conf` as an active drop-in.

The file is retained as rollback material:

- `/etc/systemd/system/hodlxxi.service.d/override.conf.DISABLED`

## Completed

- Compared `override.conf` values against `/etc/hodlxxi/hodlxxi.env` using hashes only.
- Identified that live runtime values for `DATABASE_URL`, `LN_BACKEND`, `LND_RPCSERVER`, `LND_TLSCERTPATH`, and `LND_MACAROONPATH` matched canonical env.
- Copied `LNURL_BASE_URL` and `RATELIMIT_STORAGE_URL` into `/etc/hodlxxi/hodlxxi.env` without printing values.
- Verified both copied values matched `override.conf` by hash.
- Disabled `override.conf`.
- Restarted production and verified runtime recovery.

## Production validation

- `/health/ready`: ready
- `/api/public/status`: BTC height present, LND active
- `/agent/chain/health`: `chain_ok=true`
- OIDC metadata advertises `S256`
- Live Gunicorn env includes:
  - `DATABASE_URL`
  - `LNURL_BASE_URL`
  - `RATELIMIT_STORAGE_URL`
  - `LN_BACKEND`
  - `LND_RPCSERVER`
  - `LND_TLSCERTPATH`
  - `LND_MACAROONPATH`
- Safe inventory shows `override.conf` only in disabled/bak drop-ins.

## Startup note

During restart, transient 500s were observed on legacy/bridged routes while the app was still importing. The service recovered and subsequent checks returned expected responses.

This is not treated as an env cleanup failure, but it should be tracked as a separate runtime hardening item.

## Rollback material

- `/root/hodlxxi-before-disable-override-conf-20260506T235300Z`
- `/etc/systemd/system/hodlxxi.service.d/override.conf.DISABLED`

## Next targets

Do not rotate secrets yet.

Next cleanup candidates:

1. `redis-env.conf`
2. LND duplicate/path drop-ins
3. duplicate keys in `/etc/hodlxxi/hodlxxi.env`
4. runtime startup/import hardening for legacy bridged routes
