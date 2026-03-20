---
name: hodlxxi-signature-verify
description: Verify whether a message signature matches a supplied secp256k1 public key through the HODLXXI runtime. Use this skill for POST /agent/request with job_type=verify_signature when you need key-control checking without overstating reputation or trust.
---

# hodlxxi-signature-verify

Use this skill when you need the runtime to verify a message signature with `job_type=verify_signature`.

## Runtime endpoints used

- `POST /agent/request` with `job_type=verify_signature`
- `GET /agent/jobs/<job_id>`

## Recommended workflow

1. Confirm `verify_signature` support in `GET /agent/capabilities`.
2. Submit `POST /agent/request` with `message`, `signature`, and `pubkey` in the payload.
3. Settle any required invoice.
4. Poll the job record until the runtime returns a final receipt.
5. Interpret the result strictly as signature validity and proof of key control for that message.
6. Read `references/signature-flows.md` for compact request/interpretation guidance.

## Caution and honesty notes

- Signature validity proves message verification against the supplied key, not reputation.
- Public key control does not establish moral trustworthiness or service quality.
- Treat the runtime receipt as the final record of what was verified.
