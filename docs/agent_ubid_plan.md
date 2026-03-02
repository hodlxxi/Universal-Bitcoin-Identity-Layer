# Agent UBID MVP Plan

## Minimal API
- `GET /agent/capabilities`: signed capabilities payload (`secp256k1`) with pricing, endpoints, limits, and timestamp.
- `POST /agent/request`: accepts `{ "job_type": "ping", "payload": {...} }`, creates invoice-backed job, returns pending status.
- `GET /agent/jobs/<job_id>`: polls invoice settlement; when paid, creates signed receipt and marks job done.
- `GET /agent/attestations`: returns signed receipt events (latest first, optional limit/offset).

## Data model
- `AgentJob`: stores request payload/hash, invoice fields, payment hash, status, and result hash.
- `AgentEvent`: append-only signed receipt event with `event_hash` and `prev_event_hash` chain.

## Signing and hash strategy
- Canonical JSON uses sorted keys + compact separators.
- Signatures cover canonical JSON excluding `signature` field for both capabilities and receipts.
- `request_hash`, `result_hash`, and `event_hash` use SHA-256 hex over canonical JSON bytes.

## Lightning integration
- Reuse `app.payments.ln.create_invoice` and `check_invoice_paid`.
- Job status endpoint performs polling-based settlement check (no background worker).

## TDD workflow
1. Add failing integration tests for capabilities signature, request creation, paid receipt generation, and attestation listing.
2. Implement signer utility + models + blueprint routes.
3. Register blueprint and verify tests pass.
