# HODLXXI Receipt Verification

## Purpose

This document is for external verifiers who want to validate HODLXXI agent receipts without trusting Flask internals. `GET /agent/verify` is the human-readable public verification page for entering an arbitrary `job_id`. The `/agent/verify/<job_id>` endpoint is the raw JSON verifier and remains the verification authority for online checks, but independent verifiers should also understand how to verify receipt payloads locally from the JSON they receive.

This document describes current receipt v1 behavior only. For the Human Proof MVP launch boundary and operator checklist, see [`HUMAN_PROOF_MVP.md`](HUMAN_PROOF_MVP.md) and [`ops/HUMAN_PROOF_MVP_RUNBOOK.md`](ops/HUMAN_PROOF_MVP_RUNBOOK.md). Newly issued portable receipts use `schema=hodlxxi.receipt.v1` while older/minimal receipt objects without that additive field remain valid if their signature verifies.

## Verification model

Receipt verification proves:

- the receipt payload was signed by the advertised agent key,
- the `result_hash` and `request_hash` match the canonical payloads available to the verifier,
- the receipt `event_hash` matches the receipt JSON, and
- the receipt is linked to previous local attestation history through `prev_event_hash`.

Receipt verification does not prove legal identity. It also does not prove locked capital, global consensus, external anchoring, or that a Lightning invoice was independently paid unless the verifier also checks payment evidence or trusts the runtime's payment observation. The receipt proves the HODLXXI runtime recorded this invoice-backed job as settled before issuing the result. Independent Lightning settlement verification may require separate payment evidence. A `qr_pointer` returned by the verifier is only a discovery pointer back to the verifier surface; it does not prove receipt validity, payment, consent, approval, delegation, trust, or human presence by itself.

## Canonical JSON

Canonical JSON for receipt v1 means UTF-8 JSON with sorted keys, compact separators, and no extra whitespace. It is the same behavior as Python `json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")`.

```python
import json


def canonical_json_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
```

## Hashes

Receipt v1 hash rules are:

- `request_hash = sha256(canonical_json_bytes({"job_type": job_type, "payload": payload})).hexdigest()`
- `result_hash = sha256(canonical_json_bytes(result)).hexdigest()`
- `event_hash = sha256(canonical_json_bytes(receipt_with_signature)).hexdigest()`

The `event_hash` rule includes the top-level `signature` field because it hashes the signed receipt JSON as stored/published.

## Signature coverage

To verify the receipt signature, copy the receipt, remove the top-level `signature` field, canonicalize the remaining receipt, and verify the hex signature using ECDSA/SHA-256 against `agent_pubkey`. The runtime uses compressed secp256k1 public keys for `agent_pubkey`. For enriched `hodlxxi.receipt.v1` receipts, this means the signature covers the additive fields `schema`, `receipt_id`, `runtime`, `requester_proof`, `input_hash`, `amount_sats`, `invoice_hash`, `settled`, `verify_url`, `attestations_url`, `reputation_url`, `chain_health_url`, and `signing_key`. Older/minimal receipts still verify because verifiers sign the fields present after excluding only `signature`.

Do not overclaim Schnorr/BIP340 verification for receipt v1 unless a future runtime contract explicitly changes the signer.

## Verification algorithm

1. Fetch `/agent/jobs/<job_id>` or receive a receipt from another source.
2. Confirm `status=done` and `receipt` exists.
3. Recompute `request_hash` from the original request envelope if available.
4. Recompute `result_hash` from the result payload.
5. Remove `signature` from receipt and verify the signature over canonical unsigned receipt bytes.
6. Recompute `event_hash` over canonical signed receipt bytes.
7. Compare with `/agent/verify/<job_id>` and `/agent/attestations` if online.
8. Check `prev_event_hash` continuity if replaying attestation history.

## Public verification surfaces

- `GET /agent/verify` renders the read-only human verification page. It accepts an optional `?job_id=<job_id>` query string and fetches the raw verifier for display.
- `GET /agent/verify/<job_id>` is the raw JSON verifier and verification authority.
- `GET /agent/receipts/<job_id>.json` downloads the standalone signed receipt JSON after receipt issuance.

## Runtime context links

Receipt v1 may include `attestations_url`, `reputation_url`, and `chain_health_url`. These links help audit the runtime receipt context but do not expand what the receipt proves. They are factual runtime surfaces, not human trust scores.

- `GET /agent/attestations` returns signed runtime events, including receipt attestations for completed jobs when present.
- `GET /agent/reputation` returns factual runtime counters/continuity, not a human trust score and not proof of moral trustworthiness.
- `GET /agent/chain/health` returns local append-only continuity, not global consensus.

These surfaces are not KYC, not legal identity, not authority, not consent, not global consensus, not an investment signal, not token ownership, not a guarantee of future performance, and not ownership of a network.

## Download endpoint states

`GET /agent/receipts/<job_id>.json` is a download surface for the standalone signed receipt JSON. It does not replace `/agent/verify/<job_id>`.

HTTP 200 issued receipt:

- response body is the signed receipt object itself
- `Content-Type` is `application/json`
- `Content-Disposition` is an attachment filename such as `hodlxxi-receipt-<job_id>.json`

HTTP 409 existing job without a receipt:

- `status=no_receipt`
- `reason=receipt_not_issued`

HTTP 404 missing job:

- `status=not_found`

## Verifier endpoint states

HTTP 200 verified receipt:

- `status=verified`
- `valid=true`
- `receipt` present
- `event_hash` present
- `attestation` present
- `qr_pointer` present as a discovery-only QR Pointer v0 object pointing back to `/agent/verify/<job_id>`

HTTP 409 no receipt:

- `status=no_receipt`
- `valid=false`
- `verification=unavailable`
- `reason=receipt_not_issued`
- `receipt=null`
- `qr_pointer` present as a discovery-only pointer to the same verifier surface, not as proof that a receipt exists

HTTP 404 missing job:

- `error=not_found`
- `verification=unavailable`

## Fixtures

Deterministic external verifier fixtures live in `tests/fixtures/agent_receipt_v1/`. They are docs/test fixtures for canonicalization, hash, and verifier-state examples; they are not runtime configuration and do not change endpoint behavior.

The fixtures include:

- `request_payload.json` for recomputing `request_hash`,
- `result_payload.json` for recomputing `result_hash`,
- `receipt_unsigned.json` for signature-input canonicalization,
- `receipt_signed.json` for signed-receipt canonicalization and `event_hash`,
- `verification_no_receipt_409.json` for the existing-job/no-receipt verifier state, and
- `verification_not_found_404.json` for the missing-job verifier state.

The fixture `receipt_signed.json` intentionally uses a fixed illustrative placeholder signature, not a real production signature vector. Its deterministic `event_hash` is `f32c21837c6810091a3934d5e5c553dfa16190c6f2b62f326f8922569ff91f77` under the canonical JSON rule above, but external clients must verify live signatures cryptographically against the `agent_pubkey` from live receipts.
