# Commerce Runtime State Checkpoint — 2026-06-17

This checkpoint inventories the existing HODLXXI paid agent commerce runtime as of 2026-06-17. It is documentation and protocol-contract state only; it does not request or imply runtime behavior changes.

## What exists now?

HODLXXI has a working invoice-backed paid agent runtime:

- `POST /agent/request` creates paid jobs and returns a Lightning invoice.
- `GET /agent/jobs/<job_id>` is the lifecycle/status endpoint and returns pending or completed job state.
- `GET /agent/verify/<job_id>` is a receipt verifier after a receipt exists.
- `GET /agent/attestations` exposes signed `job_receipt` events.
- `GET /agent/reputation` exposes aggregate operating history.
- `GET /agent/capabilities` and `GET /agent/marketplace/listing` advertise public commerce/discovery surfaces.
- Lightning invoice creation/checking is selected by `LN_BACKEND`; production paid smoke used `LN_BACKEND=lnd_cli`.

## What was verified manually in production?

A live manual production paid smoke verified:

```text
job_id: 47821ab9-c813-4fe7-866b-3ebabef3eece
job_type: ping
payment_hash: eb6cc38493364da21dfb86a1ed2fc40116e4bd7d13106fac4d5e82f3b4e0a8ba
request_hash: 6abebcb952dea20e289208ec7c15c49c387f45bbc0deebf1989562ad1ae4f590
result_hash: 0f8b6a991cf89dd09e4694bb0f4a1e449a0642b336566d28d6d869f5eff0f64d
agent_pubkey: 02019e7a92d22e4467e0afb20ce62976e976d1558e553351e1fb1a886b4a149f92
verify_status: verified
verify_valid: true
attestation_match: true
```

Observed paid flow:

- `POST /agent/request` created a real Lightning invoice-backed `ping` job priced at 21 sats.
- The returned job started as `invoice_pending`.
- After manual payment, `GET /agent/jobs/<job_id>` transitioned to `done`.
- The job returned a `result` and signed `receipt`.
- `GET /agent/verify/<job_id>` returned `status=verified` and `valid=true`.
- `GET /agent/attestations` contained a matching `job_receipt`.

Observed unpaid flow:

- `POST /agent/request` returned `invoice_pending`.
- `GET /agent/jobs/<job_id>` returned `200` with `status=invoice_pending`, `result=null`, and `receipt=null`.
- `GET /agent/verify/<unpaid_job_id>` returned `404` with `verification=unavailable`.
- `GET /agent/attestations` had no event for the unpaid job.

## Which endpoints are public?

Commerce/discovery surfaces include:

- `GET /.well-known/agent.json`
- `GET /agent/capabilities`
- `GET /agent/capabilities/schema`
- `GET /agent/marketplace/listing`
- `GET /agent/reputation`
- `GET /agent/attestations`
- `POST /agent/request`
- `GET /agent/jobs/<job_id>`
- `GET /agent/verify/<job_id>`
- `GET /agent/chain/health`

## Which models/tables support the flow?

- `AgentJob` / `agent_jobs`: stores job id, type, request JSON, `request_hash`, sats, invoice, payment lookup id, `payment_hash`, status, result JSON, `result_hash`, and timestamps.
- `AgentEvent` / `agent_events`: stores signed receipt/attestation events with `event_hash`, `prev_event_hash`, event JSON, signature, job linkage, and timestamps.

## Which docs already existed?

Existing related docs included:

- `docs/AGENT_RECEIPT_QUICKSTART.md`
- `docs/AGENT_RUNTIME.md`
- `docs/RUNTIME_PRODUCT_POSITIONING.md`
- `docs/AGENT_SURFACES.md`
- `docs/EXTERNAL_PAID_CALL_DEMO.md`
- `docs/AGENT_NIP90_COMPATIBILITY.md`
- `docs/AGENT_DVM_COMPATIBILITY.md`
- `docs/ops/RELEASE_GATE_SMOKE_MANUAL.md`
- `AGENT_PROTOCOL.md`

This PR adds `docs/AGENT_RECEIPT_V1.md` and `docs/ops/PAID_EXECUTION_RECEIPT_SMOKE.md` to formalize the observed public receipt contract and safe manual production smoke.

## Which tests already covered paid execution/receipts?

`tests/integration/test_agent_ubid.py` already covers key runtime behavior under deterministic test conditions, including:

- capabilities signature verification,
- `/agent/request` job creation,
- invoice-backed job persistence,
- receipt issuance after a job is marked/observed paid,
- `job_receipt` fields including `payment_hash`, `request_hash`, `result_hash`, `prev_event_hash`, `signature`, and `agent_pubkey`,
- `/agent/attestations` returning receipts,
- `/agent/verify/<job_id>` returning `valid=true` for an issued receipt,
- reputation and marketplace listing surfaces.

This PR adds docs-only marker tests in `tests/unit/test_agent_commerce_docs_contract.py`.

## What public surfaces advertise the commerce runtime?

- `/agent/capabilities` advertises supported job types, pricing, endpoints, schema, and trust surfaces.
- `/agent/marketplace/listing` presents a normalized directory-facing listing.
- `/agent/reputation` presents aggregate completed-job/attestation history.
- `/agent/attestations` exposes signed `job_receipt` events.
- Documentation surfaces now include the quickstart, receipt v1 contract, and paid execution receipt smoke runbook.

## Known semantic gap

`/agent/verify/<unpaid_job_id>` currently returns `404 not_found` / `verification unavailable` even when the job exists and is `invoice_pending`. This is acceptable as current receipt-verifier semantics, but external developers must use `/agent/jobs/<job_id>` for lifecycle state before receipt issuance. A future PR may normalize this into a more explicit pending/no_receipt response.

## What should the next PR be?

The next PR should be a behavior-normalization PR, not bundled with this docs-and-tests audit. Recommended scope:

- Keep `/agent/jobs/<job_id>` as the lifecycle/status endpoint.
- Consider making `/agent/verify/<unpaid_job_id>` return an explicit pending/no-receipt response while preserving backwards compatibility.
- Add runtime tests for unpaid verifier semantics if behavior changes.
- Update SDK helpers to expose pending/no-receipt as a first-class state if the API contract changes.
