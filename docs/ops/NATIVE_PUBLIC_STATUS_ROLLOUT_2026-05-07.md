# HODLXXI Native Public Status Rollout — 2026-05-07

## Summary

Moved `/api/public/status` off the legacy bridge into a factory-native lightweight blueprint.

## Why

Before this rollout, `/api/public/status` was owned by `app.blueprints.legacy_bridge` and could lazy-import `app.app`.

That violated the factory-first runtime direction and risked monolith import-time side effects from a public status endpoint.

## Change

PR #198 introduced:

- `app/blueprints/public_status.py`
- factory registration before `legacy_bridge`
- route ownership test: `tests/unit/test_public_status_native_route.py`

Route ownership after the change:

- `/api/public/status` → `app.blueprints.public_status`
- `/api/lnd/status` → `app.blueprints.legacy_bridge` for now

## Runtime behavior

The native public status route preserves public-safe response shape:

- top-level `block_height`
- top-level `error`
- nested `btc`
- nested `lnd`
- `online_users`
- `active_sockets`
- `online_roles`
- `uptime_sec`
- `load`

BTC status behavior:

- fast-fails with `rpc_error:missing_env` when RPC env is incomplete
- uses `PUBLIC_STATUS_BTC_RPC_TIMEOUT`, default `2.0`
- caches last-good BTC status

LND status behavior:

- checks `systemctl is-active lnd.service`
- uses `PUBLIC_STATUS_LND_SYSTEMCTL_TIMEOUT`, default `2.0`
- caches last-good LND status

## Validation

Staging:

- route ownership: `/api/public/status` owned by `app.blueprints.public_status`
- `/api/public/status`: 10/10 returned 200
- latency no longer blocked around 20 seconds when staging RPC env was incomplete
- LND active
- `/health/ready`: ready
- `/agent/chain/health`: `chain_ok=true`
- OIDC metadata advertises `S256`
- serious error scan: empty

Production:

- synced to PR #198
- compile checks passed
- route ownership test passed
- restart elapsed: `2.26s`
- `/health/ready`: ready on first check
- `/api/public/status`: BTC height present, BTC error null, LND active
- `/api/public/status`: 20/20 returned 200
- `btc_height_count=20/20`
- `lnd_active_count=20/20`
- critical endpoint smoke passed
- security headers present
- lifecycle/error scan showed no Traceback, critical error, OperationalError, or systemd timeout

## Notes

A SocketIO `Bad file descriptor` message appeared during browser/socket activity after deployment. Runtime stayed green. Track as a later SocketIO/eventlet cleanup item, not a native public status rollback reason.

## Rollback material

- Production pre-restart snapshot:
  `/root/hodlxxi-before-pr198-native-public-status-20260507T094549Z`

Previous known-good commit before PR #198:

- `0d6d70c`
