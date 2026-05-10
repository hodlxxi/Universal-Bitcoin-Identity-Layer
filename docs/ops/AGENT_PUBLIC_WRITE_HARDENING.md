# Agent Public Write Hardening

## Public write surfaces

- `POST /agent/request`
- `POST /agent/message`

Both endpoints return structured JSON error bodies (`{"error": "..."}`) for validation failures and should not return HTTP 500 for malformed client input.

## Payload ceilings

Current guardrails in `app/blueprints/agent.py`:

- Max HTTP request body: `16 KiB` (`AGENT_MAX_BODY_BYTES`)
- Max string field length (recursive): `4096` chars (`AGENT_MAX_STRING_LENGTH`)
- Max nested payload depth (recursive): `12` (`AGENT_MAX_NESTED_DEPTH`)

These limits are tuned to avoid breaking existing smoke payloads while adding abuse resistance on public write surfaces.

## Non-secret logging policy

Audit/log fields must never contain:

- invoices / payment requests
- macaroons
- OAuth/bearer tokens
- secrets / passwords
- raw auth headers
- private keys

Safe metadata includes endpoint/path, HTTP status, `job_type`, `request_id`, and remote address hash if already available.

## Manual smoke command

Run after unit checks pass:

```bash
BASE_URL=https://hodlxxi.com bash scripts/hodlxxi_production_smoke_v2_2.sh
```
