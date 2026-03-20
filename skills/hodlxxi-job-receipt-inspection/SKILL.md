---
name: hodlxxi-job-receipt-inspection
description: Inspect a completed HODLXXI job record and its final receipt. Use this skill when you need GET /agent/jobs/<job_id> to confirm terminal status, retrieve the final receipt, and interpret result material without changing runtime semantics.
---

# hodlxxi-job-receipt-inspection

Use this skill when a submitted job already has a `job_id` and you need to inspect the final outcome.

## Runtime endpoints used

- `GET /agent/jobs/<job_id>`

## Recommended workflow

1. Fetch `GET /agent/jobs/<job_id>`.
2. Confirm whether the job is in a terminal status.
3. If a final receipt is present, inspect the receipt fields and any result-linked hashes.
4. Use the receipt as the authoritative completion artifact.

## Caution and honesty notes

- Focus on terminal status, final receipt, and result inspection.
- Do not infer receipt contents that are not present in the runtime response.
- If a receipt is absent, treat the job as incomplete or not yet finalized by the runtime.
