# Runtime Observability (HODLXXI)

This document defines the runtime-observability contract for production/staging health surfaces used by operators, smoke checks, and integrators.

## Canonical health/status endpoints

- `GET /health/ready`
- `GET /api/public/status`
- `GET /agent/chain/health`
- `GET /api/lnd/status` (authenticated, full-access session required)
- `GET /.well-known/agent.json`
- `GET /agent/capabilities`

## Expected HTTP codes

### `GET /health/ready`
- `200` when ready.
- `503` when not ready.
- Must not return `500` for routine dependency outage checks.

Shape:
```json
{
  "status": "ready" | "not_ready",
  "error": "Internal server error" // only when degraded
}
```

### `GET /api/public/status`
- `200` in normal and degraded modes.
- Degradation is represented in JSON fields (not by raising 500).

Shape (stable keys expected by smoke/integrators):
```json
{
  "server_time_epoch": 0,
  "server_time_utc": "... UTC",
  "block_height": 0,
  "error": null,
  "online_users": 0,
  "active_sockets": 0,
  "online_roles": {"full": 0, "limited": 0, "pin": 0, "random": 0, "other": 0},
  "uptime_sec": 0,
  "load": {"1": 0.0, "5": 0.0, "15": 0.0},
  "btc": {"error": null},
  "lnd": {"active": true, "state": "active"}
}
```

### `GET /agent/chain/health`
- `200` for healthy and empty-chain states.

Shape:
```json
{
  "agent_pubkey": "<hex>",
  "count": 0,
  "latest_event_hash": null,
  "latest_prev_event_hash": null,
  "chain_ok": true
}
```

### `GET /api/lnd/status`
- `401` if not logged in.
- `403` for non-full sessions.
- `503` for missing required LND env.
- `200` with structured degraded status on runtime fetch failures.

## Degraded-mode semantics

- Bitcoin RPC unavailable/misconfigured for public status:
  - `/api/public/status` stays `200`.
  - `btc.error` is set (e.g., `rpc_error:missing_env`, `rpc_error:TimeoutError`).
- LND unavailable/timeout for public status:
  - `/api/public/status` stays `200`.
  - `lnd.active=false` and `lnd.state` includes degraded marker.
- LND failures on `/api/lnd/status` (after auth/env pass):
  - returns structured degraded payload with `ok=false`, not a 500.
- Optional/missing env for public status endpoints:
  - endpoint should degrade and return structured JSON.

## Secret leakage policy for public status surfaces

Public health/status responses must not include:
- `RPC_PASSWORD`
- macaroon values
- bearer tokens / raw auth headers
- private key material
- DB URLs with credentials

## Operator first checks

1. `GET /health/ready`
2. `GET /api/public/status`
3. `GET /agent/chain/health`
4. If app session available: `GET /api/lnd/status`
5. Confirm discovery surfaces:
   - `GET /.well-known/agent.json`
   - `GET /agent/capabilities`

## Smoke commands

### Staging smoke

```bash
BASE_URL="https://<staging-host>" ./scripts/hodlxxi_production_smoke_v2_2.sh
```

### Production smoke

```bash
BASE_URL="https://hodlxxi.com" ./scripts/hodlxxi_production_smoke_v2_2.sh
```

## Known warnings

- Eventlet deprecation warnings may appear in Python ecosystem dependency output.
- `datetime.utcnow` deprecation warnings may appear in legacy paths if any still call it.
