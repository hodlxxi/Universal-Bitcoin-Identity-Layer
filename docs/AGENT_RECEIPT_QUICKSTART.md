# Agent Receipt Quickstart

This quickstart shows how an external developer uses the current HODLXXI paid agent runtime:

```text
discover -> inspect capabilities -> create paid job -> manual payment -> poll lifecycle/status -> verify signed receipt -> inspect attestations and reputation
```

The commerce runtime is invoice-backed. Smoke tests and external examples must use manual payment only; they must never auto-pay invoices.

## 1. Discover the agent

Start with the public discovery documents:

```bash
curl -sS https://hodlxxi.com/.well-known/agent.json | jq .
curl -sS https://hodlxxi.com/agent/marketplace/listing | jq .
```

Use these documents to find the agent identity, advertised capabilities, endpoints, pricing, skills, and trust model.

## 2. Inspect capabilities

```bash
curl -sS https://hodlxxi.com/agent/capabilities | jq .
curl -sS https://hodlxxi.com/agent/capabilities/schema | jq .
```

`GET /agent/capabilities` is the main machine-readable capability surface. It advertises supported job types, pricing, and endpoints such as `/agent/request`, `/agent/jobs/<job_id>`, `/agent/verify/<job_id>`, `/agent/attestations`, and `/agent/reputation`.

## 3. Create a paid job

```bash
curl -sS -X POST "https://hodlxxi.com/agent/request" \
  -H 'Content-Type: application/json' \
  -d '{"job_type":"ping","payload":{"message":"hello from external developer"}}' \
  | tee /tmp/hodlxxi-agent-request.json | jq .
```

Expected successful creation may return `HTTP 200 or HTTP 201`, depending on the current endpoint behavior. Treat the JSON lifecycle fields as the success contract:

- `job_id`
- `status=invoice_pending`
- `invoice` present
- `payment_hash` present

Production invoice creation is selected by `LN_BACKEND`; the live production paid smoke used `LN_BACKEND=lnd_cli`. Do not publish invoice strings from live runs. A live production paid smoke on 2026-06-18 produced a verified receipt and attestation; see [`ops/PAID_EXECUTION_RECEIPT_SMOKE.md`](ops/PAID_EXECUTION_RECEIPT_SMOKE.md) for safe evidence fields only.

## 4. Pay manually

Copy the returned Lightning invoice into a wallet and perform manual payment. The quickstart does not auto-pay and must never be changed to auto-pay invoices.

## 5. Poll lifecycle/status

`GET /agent/jobs/<job_id>` is the lifecycle/status endpoint:

```bash
export JOB_ID="$(jq -r .job_id /tmp/hodlxxi-agent-request.json)"
curl -sS "https://hodlxxi.com/agent/jobs/$JOB_ID" | jq .
```

Before settlement, unpaid jobs are expected to return:

- `status=invoice_pending`
- `result=null`
- `receipt=null`

After settlement is observed, completed jobs are expected to return:

- `status=done`
- `result` present
- `receipt` present
- backward-compatible receipt fields such as `job_receipt`, `payment_hash`, `request_hash`, `result_hash`, `signature`, and `agent_pubkey`
- portable receipt fields such as `schema=hodlxxi.receipt.v1`, `receipt_id`, `input_hash`, `amount_sats`, `settled`, `verify_url`, `attestations_url`, `reputation_url`, `chain_health_url`, and `signing_key`

## 6. Verify the signed receipt

For a human-readable verification page, open `GET /agent/verify` and paste a `job_id`, or open `GET /agent/verify?job_id=<job_id>` directly. The page is read-only and displays the raw verifier result.

`GET /agent/verify/<job_id>` is the raw JSON receipt verifier and verification authority after receipt issuance:

```bash
curl -sS "https://hodlxxi.com/agent/verify/$JOB_ID" | jq .
```

For a completed paid job with an issued receipt, expected verifier fields include:

- `job_id`
- `status=verified`
- `valid=true`
- `event_hash`
- `receipt`
- `attestation`
- `agent_pubkey`

Unpaid/no-receipt semantics are intentionally different from lifecycle/status semantics. An unpaid job may exist while `/agent/verify/<job_id>` returns `409 Conflict` with `status=no_receipt`, `valid=false`, `verification=unavailable`, the current `job_status`, `receipt=null`, and `reason=receipt_not_issued` because no receipt has been issued yet. A job id that does not exist still returns `404 not_found`. Use `/agent/jobs/<job_id>` for lifecycle state before receipt issuance.

## 7. Download the receipt JSON

`GET /agent/receipts/<job_id>.json` is the receipt download endpoint. After a receipt exists, download the standalone signed receipt object:

```bash
curl -sS -OJ "https://hodlxxi.com/agent/receipts/$JOB_ID.json"
```

If the job exists but no receipt has been issued yet, this endpoint returns `409 Conflict` with `status=no_receipt` and `reason=receipt_not_issued`. If the job id is unknown, it returns `404 not_found`.

The receipt proves the HODLXXI runtime recorded this invoice-backed job as settled before issuing the result. Independent Lightning settlement verification may require separate payment evidence.

## 8. Inspect factual runtime surfaces

```bash
curl -sS "https://hodlxxi.com/agent/attestations?limit=30" | jq .
curl -sS "https://hodlxxi.com/agent/reputation" | jq .
curl -sS "https://hodlxxi.com/agent/chain/health" | jq .
```

These are factual runtime surfaces, not human trust scores. They help audit runtime receipt context but do not expand what the receipt proves.

`GET /agent/attestations` returns signed runtime events. A completed job should have a matching `job_receipt` attestation. Unpaid jobs should not have a receipt attestation.

`GET /agent/reputation` exposes factual runtime counters/continuity, not a human trust score and not proof of moral trustworthiness.

`GET /agent/chain/health` exposes local append-only continuity, not global consensus.

These surfaces are not KYC, not legal identity, not authority, not consent, not global consensus, not an investment signal, not token ownership, not a guarantee of future performance, and not ownership of a network.

## Receipt contract

See [`AGENT_RECEIPT_V1.md`](AGENT_RECEIPT_V1.md) for the formal public receipt v1 contract, including field definitions for `payment_hash`, `request_hash`, `result_hash`, `signature`, `agent_pubkey`, and unpaid verification semantics. See [`RECEIPT_VERIFICATION.md`](RECEIPT_VERIFICATION.md) for local verification steps and deterministic canonical JSON/hash fixtures.
