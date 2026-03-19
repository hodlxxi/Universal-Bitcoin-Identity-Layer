---
name: hodlxxi-attestation-lookup
description: Inspect public HODLXXI attestations from the runtime. Use this skill when you need GET /agent/attestations and want careful interpretation of issuer, subject, scope, and signed statement boundaries.
---

# hodlxxi-attestation-lookup

Use this skill when you need to review the runtime's public attestation history.

## Runtime endpoints used

- `GET /agent/attestations`

## Recommended workflow

1. Fetch `GET /agent/attestations`.
2. Inspect the returned signed statements and their ordering.
3. Interpret each item using issuer, subject, scope, and signed statement boundaries.
4. Read `references/attestations.md` when a compact boundary reminder is helpful.

## Caution and honesty notes

- An attestation is not ground truth by itself.
- Distinguish the issuer from the subject of a statement.
- Treat scope as limited to what the signed statement actually covers.
