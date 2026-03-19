---
name: hodlxxi-covenant-decode
description: Request covenant or script interpretation from the HODLXXI runtime. Use this skill when you need factual decoding through POST /agent/request with job_type=covenant_decode and want a structured result without inventing unsupported covenant claims.
---

# hodlxxi-covenant-decode

Use this skill when you need the runtime to interpret a script payload with `job_type=covenant_decode`.

## Runtime endpoints used

- `POST /agent/request` with `job_type=covenant_decode`
- `GET /agent/jobs/<job_id>`

## Recommended workflow

1. Confirm `covenant_decode` is advertised in `GET /agent/capabilities`.
2. Submit `POST /agent/request` with `job_type=covenant_decode` and the runtime-supported payload.
3. Settle any required invoice.
4. Poll the job record until a final receipt is available.
5. Use the result for parsed script or descriptor data, branches, timelocks, and other structured interpretation the runtime actually returns.
6. Read `references/examples.md` for a compact example.

## Caution and honesty notes

- Keep interpretation factual and limited to what the runtime returns.
- Do not claim legal, financial, or behavioral guarantees from script structure alone.
- Distinguish decoded script structure from broader covenant intent unless the runtime explicitly provides that interpretation.
