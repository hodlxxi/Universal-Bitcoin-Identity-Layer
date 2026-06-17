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

Expected response:

- `job_id`
- `invoice`
- `payment_hash`
- `status=invoice_pending`

Production invoice creation is selected by `LN_BACKEND`; the live production paid smoke used `LN_BACKEND=lnd_cli`. Do not publish invoice strings from live runs.

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
- receipt fields such as `job_receipt`, `payment_hash`, `request_hash`, `result_hash`, `signature`, and `agent_pubkey`

## 6. Verify the signed receipt

`GET /agent/verify/<job_id>` is the receipt verifier after receipt issuance:

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

## 7. Inspect attestations and reputation

```bash
curl -sS "https://hodlxxi.com/agent/attestations?limit=30" | jq .
curl -sS "https://hodlxxi.com/agent/reputation" | jq .
```

`GET /agent/attestations` returns signed receipt events for completed jobs. A completed job should have a matching `job_receipt` attestation. Unpaid jobs should not have a receipt attestation.

`GET /agent/reputation` exposes aggregate operating history that external apps can use as a trust signal alongside receipt verification.

## Receipt contract

See [`AGENT_RECEIPT_V1.md`](AGENT_RECEIPT_V1.md) for the formal public receipt v1 contract, including field definitions for `payment_hash`, `request_hash`, `result_hash`, `signature`, `agent_pubkey`, and unpaid verification semantics.
