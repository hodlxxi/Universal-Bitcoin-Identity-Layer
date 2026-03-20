---
name: hodlxxi-job-request
description: Submit a HODLXXI agent job and follow it through completion. Use this skill to prepare a request payload, post it to the runtime, handle invoice-required execution, poll job status, and stop only when the runtime reaches a terminal state.
---

# hodlxxi-job-request

Use this skill when you need to submit any supported HODLXXI runtime job without assuming synchronous completion.

## Runtime endpoints used

- `POST /agent/request`
- `GET /agent/jobs/<job_id>`

## Recommended workflow

1. Inspect the runtime first with `hodlxxi-agent-discovery`.
2. Prepare a request payload that matches the runtime-advertised job type and schema.
3. Submit the job with `POST /agent/request`.
4. Settle the returned invoice if the runtime requires payment before execution.
5. Poll `GET /agent/jobs/<job_id>` until the job reaches a terminal state.
6. Stop polling when the runtime reports a final status and inspect the receipt if one is present.
7. Read `references/request-schema.md` and `references/job-lifecycle.md` for compact request and lifecycle guidance.

## Caution and honesty notes

- Do not assume the runtime completes work in the initial POST response.
- Do not change invoice semantics in client code; follow the runtime response as returned.
- Treat the live job record and receipt as the authoritative execution record.
