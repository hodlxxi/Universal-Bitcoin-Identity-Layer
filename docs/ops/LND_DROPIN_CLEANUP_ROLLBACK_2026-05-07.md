# HODLXXI LND Drop-in Cleanup Rollback — 2026-05-07

> **Status:** Historical checkpoint. This document records deployment, cleanup, planning, or protocol state at the time it was written. Do not treat it as the current runbook or current implementation truth unless it is explicitly linked from `docs/DOCUMENTATION_MAP.md` or `docs/READINESS_EVALUATION.md`.


## Summary

A cleanup attempt disabled `21-lnd-rpcserver.conf` because `LND_RPCSERVER` appeared redundant by hash comparison.

The change was rolled back because production LND health degraded.

## Attempted change

Disabled:

- `/etc/systemd/system/hodlxxi.service.d/21-lnd-rpcserver.conf`

Rollback restored:

- `/etc/systemd/system/hodlxxi.service.d/21-lnd-rpcserver.conf`

## Result before rollback

After disabling `21-lnd-rpcserver.conf` and restarting production:

- `/health/ready`: ready
- `/agent/chain/health`: `chain_ok=true`
- OIDC metadata: `S256`
- `/api/public/status`: `lnd.active=false`
- LND state: `unknown:TimeoutExpired`

## Result after rollback

After restoring `21-lnd-rpcserver.conf` and restarting production:

- `/health/ready`: ready
- `/api/public/status`: `lnd.active=true`
- `/agent/chain/health`: `chain_ok=true`
- OIDC metadata: `S256`
- Serious LND/error log scan: empty

## Decision

Do not continue LND drop-in cleanup casually.

Keep these active for now:

- `20-lnd-readonly.conf`
- `21-lnd-rpcserver.conf`
- `22-home-for-lncli.conf`
- `24-agent-ln-backend.conf`
- `zz-force-lnd-cli-paths.conf`

The LND env/drop-in group is order-sensitive and requires a separate dedicated cleanup plan.

## Next safer targets

Before further LND cleanup:

1. Clean duplicate keys in `/etc/hodlxxi/hodlxxi.env`
2. Document current active/disabled drop-in state
3. Investigate startup/import transient errors separately
4. Plan LND cleanup with isolated staging validation
