# HODLXXI Native LND Status Rollout — 2026-05-09

## Summary

Moved `/api/lnd/status` off the legacy bridge into a factory-native lightweight blueprint.

## Why

Before this rollout, `/api/lnd/status` was owned by `app.blueprints.legacy_bridge` and could lazy-import `app.app`.

That violated the factory-first runtime direction and kept a public API route coupled to monolith import-time side effects.

## Change

PR #204 introduced:

- `app/blueprints/lnd_status.py`
- factory registration before `legacy_bridge`
- native route ownership tests
- updated stale route ownership test that previously expected `/api/lnd/status` to remain legacy-bridge owned

Route ownership after the change:

- `/api/lnd/status` → `app.blueprints.lnd_status`
- `/api/public/status` → `app.blueprints.public_status`

## Preserved behavior

Unauthenticated request:

- returns `401`
- body includes `{"error":"Not logged in","ok":false}`

Authenticated non-full user:

- returns `403`
- body includes `{"error":"Full access required","ok":false}`

Full user response shape preserves the legacy structured payload:

- `getinfo`
- `walletbalance`
- `channelbalance`
- `channels_summary`

## LND env behavior

Canonical names are preferred:

- `LND_RPCSERVER`
- `LND_TLSCERTPATH`
- `LND_MACAROONPATH`

Legacy helper fallback is retained:

- `LND_TLS_CERT`
- `LND_READONLY_MACAROON`
- `LND_LNCLI_BIN`

## Validation

Staging:

- `/api/lnd/status` owned by `app.blueprints.lnd_status`
- `/api/public/status` remained owned by `app.blueprints.public_status`
- `app.app_imported_initially=False`
- unauth `/api/lnd/status`: `401`
- `/health/ready`: ready
- `/api/public/status`: green
- `/agent/chain/health`: `chain_ok=true`
- OIDC metadata advertises `S256`
- serious error scan: empty
- targeted tests passed:
  - `tests/unit/test_public_status_native_route.py`
  - `tests/unit/test_lnd_status_native_route.py`

Production:

- synced to PR #204 commit `964a77e`
- compile checks passed
- targeted tests passed: `11 passed`
- route ownership before restart:
  - `/api/lnd/status` → `app.blueprints.lnd_status`
  - `/api/public/status` → `app.blueprints.public_status`
  - `app.app_imported_initially=False`
- restart completed and runtime recovered
- `/health/ready`: ready on first check
- `/api/public/status`: BTC height present, BTC error null, LND active
- `/agent/chain/health`: `chain_ok=true`
- OIDC metadata advertises `S256`
- unauth `/api/lnd/status`: `401`, not `500`

## Known follow-up

The production restart still hit the existing systemd/Gunicorn stop lifecycle issue:

- old Gunicorn processes were killed with `SIGKILL`
- systemd reported `Failed with result 'timeout'`

Runtime recovered immediately and smoke tests passed. Treat this as a separate lifecycle/eventlet shutdown follow-up, not a PR #204 rollback reason.

## Rollback material

Production pre-restart snapshot:

- `/root/hodlxxi-before-pr204-native-lnd-status-20260509T062345Z`

Previous known-good commit before PR #204:

- `2e69238`
