# Paid Execution Receipt Smoke Runbook

This runbook documents a safe manual production smoke for the existing HODLXXI paid agent commerce runtime:

```text
discover -> create paid job -> display Lightning invoice -> manually pay -> poll job -> verify receipt -> check attestation
```

The runbook/script must never auto-pay invoices. Payment is manual payment only. Do not include macaroons, certs, private keys, or reusable invoice strings in logs, issues, commits, or PRs.

## Preconditions

- Production runtime is reachable, for example `BASE_URL=https://hodlxxi.com`.
- Production uses a real Lightning backend such as `LN_BACKEND=lnd_cli`.
- You can manually pay the returned Lightning invoice from a wallet you control.
- `jq` is available locally for examples.

```bash
export BASE_URL="https://hodlxxi.com"
```

## 1. Discover

```bash
curl -sS "$BASE_URL/agent/capabilities" | jq .
curl -sS "$BASE_URL/agent/marketplace/listing" | jq .
```

Confirm that the public surfaces advertise `/agent/request`, `/agent/jobs/<job_id>`, `/agent/verify/<job_id>`, `/agent/attestations`, and `/agent/reputation`.

## 2. Create a paid job

```bash
curl -sS -X POST "$BASE_URL/agent/request" \
  -H 'Content-Type: application/json' \
  -d '{"job_type":"ping","payload":{"message":"manual paid receipt smoke"}}' \
  | tee /tmp/hodlxxi-agent-request.json | jq .
```

Expected initial response:

- `job_id` present.
- `invoice` present. Display it for manual payment, but do not commit or publish it.
- `payment_hash` present.
- `status=invoice_pending`.

Set the job id:

```bash
export JOB_ID="$(jq -r .job_id /tmp/hodlxxi-agent-request.json)"
```

## 3. Confirm unpaid state before payment

`/agent/jobs/<job_id>` is the lifecycle/status endpoint:

```bash
curl -sS "$BASE_URL/agent/jobs/$JOB_ID" | jq .
```

Expected unpaid state:

- `status=invoice_pending`
- `result=null`
- `receipt=null`

The verifier is a receipt verifier, not the lifecycle source. Before a receipt exists for an existing job, it returns `409 Conflict` and `verification=unavailable`:

```bash
curl -sS -i "$BASE_URL/agent/verify/$JOB_ID"
```

Expected unpaid verifier behavior:

```json
{"job_id":"...","status":"no_receipt","valid":false,"verification":"unavailable","job_status":"invoice_pending","receipt":null,"reason":"receipt_not_issued"}
```

`/agent/attestations` should not contain a `job_receipt` for the unpaid job:

```bash
curl -sS "$BASE_URL/agent/attestations?limit=30" | jq .
```

## 4. Manually pay the Lightning invoice

Copy the returned `invoice` string into your Lightning wallet and pay it manually. This runbook never auto-pays invoices and must not be changed to auto-pay invoices.

## 5. Poll until completed

```bash
watch -n 3 "curl -sS '$BASE_URL/agent/jobs/$JOB_ID' | jq ."
```

Expected paid state after settlement is observed:

- `status=done`
- `result` present
- `receipt` present
- receipt includes `job_receipt`, `payment_hash`, `request_hash`, `result_hash`, `signature`, and `agent_pubkey`

## 6. Verify the receipt

```bash
curl -sS "$BASE_URL/agent/verify/$JOB_ID" | jq .
```

Expected verified receipt state:

- `status=verified`
- `valid=true`
- `event_hash` present
- `receipt` present
- `attestation` present
- `agent_pubkey` present

## 7. Check attestation

```bash
curl -sS "$BASE_URL/agent/attestations?limit=30" | jq --arg job_id "$JOB_ID" '.items[] | select(.job_id == $job_id)'
```

Expected attestation state:

- matching item exists
- `event_type=job_receipt`
- `payment_hash`, `request_hash`, `result_hash`, `signature`, and `agent_pubkey` match the receipt context

## Live paid smoke evidence

A manual production smoke proved the paid path without publishing a reusable invoice string:

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

Expected unpaid smoke behavior after verifier normalization:

```text
POST /agent/request -> invoice_pending
GET /agent/jobs/<job_id> -> 200 with status=invoice_pending, result=null, receipt=null
GET /agent/verify/<unpaid_job_id> -> 409 with status=no_receipt, verification=unavailable, and reason=receipt_not_issued
GET /agent/attestations -> no event for unpaid job
```
