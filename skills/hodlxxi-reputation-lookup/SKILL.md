---
name: hodlxxi-reputation-lookup
description: Inspect the public HODLXXI runtime reputation surface. Use this skill when you need aggregate operating history from GET /agent/reputation and need careful trust framing that does not overclaim what the runtime proves.
---

# hodlxxi-reputation-lookup

Use this skill when you need the runtime's public reputation snapshot.

## Runtime endpoints used

- `GET /agent/reputation`

## Recommended workflow

1. Fetch `GET /agent/reputation`.
2. Review aggregate counts, job history, and attestation totals that the runtime actually exposes.
3. Apply the trust framing in `references/trust-model.md` before making any downstream claims.

## Caution and honesty notes

- Reputation is an aggregation surface, not a proof of ground truth.
- Use this trust framing exactly: `public_key + operator_binding + optional_time_locked_capital + signed_behavior + observable_service_history`.
- `optional_time_locked_capital` is optional and must not be treated as proven unless evidence exists.
