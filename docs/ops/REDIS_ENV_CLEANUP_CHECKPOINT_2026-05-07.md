# HODLXXI Redis Env Cleanup Checkpoint — 2026-05-07

## Current state

Production systemd no longer has `redis-env.conf` as an active drop-in.

The file is retained as rollback material:

- `/etc/systemd/system/hodlxxi.service.d/redis-env.conf.DISABLED`

## Completed

- Compared live Redis env against `/etc/hodlxxi/hodlxxi.env` and `redis-env.conf` using hashes only.
- Confirmed `REDIS_PASSWORD` already matched canonical env.
- Copied `REDIS_URL` and `REDIS_USERNAME` into `/etc/hodlxxi/hodlxxi.env` without printing values.
- Verified `REDIS_URL`, `REDIS_USERNAME`, and `REDIS_PASSWORD` matched by hash.
- Disabled `redis-env.conf`.
- Restarted production and verified runtime recovery.

## Production validation

- `/health/ready`: ready
- `/api/public/status`: BTC height present, LND active
- `/agent/chain/health`: `chain_ok=true`
- OIDC metadata advertises `S256`
- Live Gunicorn env includes:
  - `REDIS_URL`
  - `REDIS_USERNAME`
  - `REDIS_PASSWORD`
  - `RATELIMIT_STORAGE_URL`
- Redis initialized from `REDIS_URL`.
- Rate limiter initialized with redacted Redis storage URL.
- Safe inventory shows `redis-env.conf` only in disabled/bak drop-ins.

## Rollback material

- `/root/hodlxxi-before-disable-redis-env-20260507T004228Z`
- `/etc/systemd/system/hodlxxi.service.d/redis-env.conf.DISABLED`

## Next targets

Do not rotate secrets yet.

Next cleanup candidates:

1. LND duplicate/path drop-ins
2. duplicate keys in `/etc/hodlxxi/hodlxxi.env`
3. runtime startup/import hardening for legacy bridged routes
4. later: controlled Redis/RPC/Flask secret rotation
