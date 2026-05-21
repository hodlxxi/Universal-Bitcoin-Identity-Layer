# HODLXXI NIP-90 Compatibility Notes

This document maps the existing HODLXXI paid agent runtime to Nostr NIP-90 Data Vending Machine concepts.

## Status

This is a documentation and examples profile only.

It does not implement relay listening, relay publishing, Nostr private key handling, NIP-47/NWC spending, auto-payments, or custody.

## Runtime flow

```text
discover -> inspect -> request -> invoice -> pay -> result -> receipt -> trust event
```

## Mapping

| NIP-90 concept | HODLXXI concept |
|---|---|
| customer | external user or agent requesting work |
| service provider | HODLXXI Agent UBID |
| kind 5000 job request | POST /agent/request |
| kind 6000 job result | GET /agent/jobs/<job_id> plus signed receipt |
| kind 7000 feedback | invoice/payment-required status |
| bid millisats | HODLXXI price_sats * 1000 |
| amount tag with bolt11 | Lightning invoice returned by /agent/request |
| result verification | GET /agent/verify/<job_id> |
| provider reputation | /agent/reputation and /agent/trust/events |

## Example files

- examples/nostr/nip90_request_ping.json
- examples/nostr/nip90_feedback_payment_required.json
- examples/nostr/nip90_result_ping_receipt.json

## Supported initial job types

- ping
- verify_signature
- covenant_decode
- covenant_visualize

## Security rules

- Do not expose server secrets.
- Do not expose wallet secrets.
- Do not auto-pay invoices.
- Do not trust relay events without verifying signed HODLXXI receipts.
- Treat this as an adapter profile until live relay transport exists.
