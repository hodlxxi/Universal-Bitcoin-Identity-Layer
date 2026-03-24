# API Response Examples

This file contains only examples verified against current route implementations and integration tests.
If an endpoint is not implemented, the example shows the current runtime error response.

## Public Discovery Endpoints

### `GET /health`
**Description:** Application health summary from admin blueprint.
**Auth:** None
**Status:** `200` in testing; `200` or `503` in non-testing depending on RPC health.

**Example response (`200`):**
```json
{
  "timestamp": "2026-03-24T10:00:15.487Z",
  "status": "healthy",
  "version": "1.0.0-beta",
  "ok": true,
  "rpc_ok": true
}
```

---

### `GET /agent/capabilities`
**Description:** Signed machine-readable capabilities document for Agent UBID.
**Auth:** None
**Status:** `200`

**Example response (`200`):**
```json
{
  "agent_pubkey": "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa",
  "version": "0.1",
  "service_name": "HODLXXI Agent UBID",
  "service_description": "Lightning-paid agent with signed receipts, attestations, and reputation",
  "operator": "HODLXXI",
  "network": "bitcoin",
  "supports_payment_settlement_check": true,
  "capability_schema": {
    "version": "1.0",
    "uri": "/agent/capabilities/schema"
  },
  "endpoints": {
    "well_known": "/.well-known/agent.json",
    "capabilities": "/agent/capabilities",
    "capabilities_schema": "/agent/capabilities/schema",
    "request": "/agent/request",
    "job": "/agent/jobs/<job_id>",
    "verify": "/agent/verify/<job_id>",
    "attestations": "/agent/attestations",
    "reputation": "/agent/reputation",
    "chain_health": "/agent/chain/health",
    "marketplace_listing": "/agent/marketplace/listing",
    "skills": "/agent/skills"
  },
  "pricing": {
    "ping_sats": 21,
    "attestation_sats": 1
  },
  "job_types": {
    "ping": {
      "price_sats": 21,
      "memo": "Agent UBID ping job",
      "input_schema": {
        "payload": "object"
      },
      "output_schema": {
        "ok": "boolean",
        "job_type": "string",
        "echo": "object"
      }
    }
  },
  "limits": {
    "max_jobs_per_day": 100
  },
  "skills": {
    "count": 1,
    "endpoint": "/agent/skills",
    "items": []
  },
  "timestamp": "2026-03-24T10:00:15.550101+00:00",
  "sig_scheme": "secp256k1",
  "signature": "3044..."
}
```

## Agent Runtime Examples

### `POST /agent/request`
**Description:** Creates a paid job request and returns an invoice/payment hash.
**Auth:** None
**Status:** `201` on new request, `200` for deduplicated existing request.

**Example request:**
```json
{
  "job_type": "ping",
  "payload": {
    "message": "hello"
  }
}
```

**Example response (`201`):**
```json
{
  "job_id": "0ae001b2-09dd-419e-8abe-0891625836a9",
  "invoice": "ln-invoice",
  "payment_hash": "388dc56cc25cf17d45a56c207679d73578acae01d3f7b9bc068d012e09fdad2a",
  "status": "invoice_pending"
}
```

---

### `GET /agent/jobs/<job_id>`
**Description:** Fetches current job status and receipt (when paid/settled).
**Auth:** None
**Status:** `200` or `404`.

**Example response (`200` with receipt):**
```json
{
  "job_id": "0ae001b2-09dd-419e-8abe-0891625836a9",
  "status": "done",
  "receipt": {
    "event_type": "job_receipt",
    "job_id": "0ae001b2-09dd-419e-8abe-0891625836a9",
    "request_hash": "6cb5e0be948edd6baafbbede4e2158156cb5f4d66e1bceccfefb8ec164a48b67",
    "payment_hash": "388dc56cc25cf17d45a56c207679d73578acae01d3f7b9bc068d012e09fdad2a",
    "result_hash": "29c2121c163670758aec65ad558ce18d8939c722b23bcd138ed4e893207ddee1",
    "timestamp": "2026-03-24T10:00:15.551407+00:00",
    "agent_pubkey": "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa",
    "prev_event_hash": null,
    "signature": "3044..."
  }
}
```

**Example response (`404`):**
```json
{
  "error": "not_found"
}
```

---

### `GET /agent/attestations`
**Description:** Returns latest signed attestation receipts.
**Auth:** None
**Status:** `200`

**Example response (`200`):**
```json
{
  "count": 1,
  "items": [
    {
      "event_type": "job_receipt",
      "job_id": "0ae001b2-09dd-419e-8abe-0891625836a9",
      "request_hash": "6cb5e0be948edd6baafbbede4e2158156cb5f4d66e1bceccfefb8ec164a48b67",
      "payment_hash": "388dc56cc25cf17d45a56c207679d73578acae01d3f7b9bc068d012e09fdad2a",
      "result_hash": "29c2121c163670758aec65ad558ce18d8939c722b23bcd138ed4e893207ddee1",
      "timestamp": "2026-03-24T10:00:15.551407+00:00",
      "agent_pubkey": "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa",
      "prev_event_hash": null,
      "signature": "3044..."
    }
  ]
}
```

---

### `GET /agent/reputation`
**Description:** Public aggregate counters for jobs and attestations.
**Auth:** None
**Status:** `200`

**Example response (`200`):**
```json
{
  "agent_pubkey": "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa",
  "total_jobs": 1,
  "completed_jobs": 1,
  "job_types": {
    "ping": 1
  },
  "attestations_count": 1
}
```

## Bounded Sovereignty Stage 1 Examples

These routes are **not implemented in the current runtime**. Current behavior is standard `404`.

### `GET /agent/policy`
**Status:** `404`

```json
{
  "error": "not_found",
  "message": "Resource not found"
}
```

### `GET /agent/bounded-status`
**Status:** `404`

```json
{
  "error": "not_found",
  "message": "Resource not found"
}
```

### `GET /agent/actions`
**Status:** `404`

```json
{
  "error": "not_found",
  "message": "Resource not found"
}
```

Notes for Stage 1 fields requested by design docs:
- No `policy` document is currently returned by runtime.
- No bounded-status `signature` is currently returned by runtime.
- No action log hash chain is currently exposed at `/agent/actions`.

## Protected Endpoints (Auth Required)

### `POST /agent/bounded/execute`
**Description:** Bounded execution surface is not implemented yet.
**Current behavior:** no route is registered, so requests are denied at routing layer.
**Status:** `404`

**Example request:**
```json
{
  "action": "transfer",
  "amount_sats": 1000
}
```

**Example response (`404`):**
```json
{
  "error": "not_found",
  "message": "Resource not found"
}
```

## Error Responses

### Unsupported job type
**Endpoint:** `POST /agent/request`
**Status:** `400`

```json
{
  "error": "unsupported_job_type"
}
```

### Invalid attestation pagination
**Endpoint:** `GET /agent/attestations?limit=abc`
**Status:** `400`

```json
{
  "error": "invalid_pagination"
}
```

### Rate limit (IP burst)
**Endpoint:** `POST /agent/request`
**Status:** `429`

```json
{
  "error": "ip_rate_limited"
}
```

## Notes on Partial / Experimental Behavior

- `POST /agent/request` success paths depend on Lightning invoice backend availability.
- Job completion/receipt issuance requires invoice settlement (`check_invoice_paid` path).
- Bounded sovereignty endpoints listed above are currently absent; docs intentionally show `404` to avoid implying implemented behavior.
