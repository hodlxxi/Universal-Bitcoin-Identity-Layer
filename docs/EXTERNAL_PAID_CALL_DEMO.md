# External Paid-Call Demo (P6) — HODLXXI

## Purpose
This runbook defines a **safe, manual, external paid-call demo** so one outside Nostr DVM / MCP / Lightning API builder can test HODLXXI end-to-end against live endpoints.

## Current state
HODLXXI production already exposes:

- `/.well-known/agent.json`
- `/agent/discovery`
- `/agent/capabilities`
- `/agent/nostr/announcement`
- `/agent/request`
- `/agent/jobs/<job_id>`
- `/agent/verify/<job_id>`
- `/agent/trust/events`
- `/agent/reputation`
- `/agent/chain/health`

## Target state
A single external builder can complete:

`discover -> inspect -> request -> invoice -> manual payment -> poll -> result -> signed receipt -> trust event`

without custody handoff, auto-payment, outbound spending, or server key disclosure.

## Nostr key and identity rules (critical)
- Public invitation/announcement must be posted from the founder/operator **human Nostr npub**.
- The server agent private key must never be used for posting.
- The machine identity to cite is the public `agent_pubkey` from `/.well-known/agent.json`.

## Step 1 — Discover runtime surfaces
```bash
curl https://hodlxxi.com/.well-known/agent.json | jq .
curl https://hodlxxi.com/agent/discovery | jq .
curl https://hodlxxi.com/agent/capabilities | jq .
curl https://hodlxxi.com/agent/nostr/announcement | jq .
```

## Step 2 — Request a ping job (external builder)
Submit a harmless ping request and save response:

```bash
curl -sS -X POST "https://hodlxxi.com/agent/request" \
  -H 'Content-Type: application/json' \
  -d '{
    "job_type": "ping",
    "payload": {
      "message": "external paid call demo ping",
      "origin": "external-builder"
    }
  }' | tee /tmp/hodlxxi_agent_job.json | jq .
```

Extract identifiers defensively:

```bash
jq -r '
  {
    job_id: (.job_id // .id // .job.id // empty),
    invoice: (
      .invoice
      // .payment_request
      // .payment.payment_request
      // .payment.invoice
      // .bolt11
      // empty
    )
  }
' /tmp/hodlxxi_agent_job.json
```

## Step 3 — Payment model (manual only)
- External builder pays the returned Lightning invoice manually from their own wallet.
- HODLXXI must not auto-pay anything.
- Founder/operator must not pay from server runtime.
- No NWC/NIP-47 spending, no outbound spend automation.

## Step 4 — Poll job status
```bash
curl "https://hodlxxi.com/agent/jobs/<job_id>" | jq .
```

## Step 5 — Verify receipt and trust signals
```bash
curl "https://hodlxxi.com/agent/verify/<job_id>" | jq .
curl "https://hodlxxi.com/agent/trust/events" | jq .
curl "https://hodlxxi.com/agent/reputation" | jq .
```

## Expected successful flow
1. Discover endpoints and inspect machine-readable metadata.
2. Request `job_type=ping`.
3. Receive invoice.
4. External builder pays invoice manually.
5. Poll until job status transitions out of `invoice_pending`.
6. Receive result payload.
7. Verify signed receipt.
8. Confirm trust/reputation surfaces update.

## Failure modes and handling
- **Invoice not paid**: job remains pending.
- **Job remains `invoice_pending`**: continue polling or re-issue test.
- **Expired invoice**: request new job/invoice.
- **Malformed request**: fix JSON shape/content-type and retry.
- **Network failure**: retry with status-code and body logging.
- **Wrong wallet / cannot verify**: confirm paid invoice corresponds to returned invoice and re-check `/agent/verify/<job_id>`.

## Rollback
This is a docs/examples-only change and can be reverted cleanly with:

```bash
git revert HEAD
```

## What founder should send back to developer
Share:
- Curl outputs (with any sensitive fields redacted)
- `job_id` only
- HTTP status codes per endpoint

Do **not** share:
- private keys
- macaroons
- env values
- wallet files
- seed phrases/mnemonics

Invoices are optional to share (founder can omit if preferred).
