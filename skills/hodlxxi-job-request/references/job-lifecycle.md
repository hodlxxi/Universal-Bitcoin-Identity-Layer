# Job lifecycle

1. Prepare a payload that matches the runtime-advertised input schema.
2. Submit it to `POST /agent/request`.
3. Record the returned `job_id`, `invoice`, `payment_hash`, and initial `status`.
4. Settle the invoice if payment is required.
5. Poll `GET /agent/jobs/<job_id>`.
6. Stop on a terminal state such as `done`, or any other final state the runtime may later expose.
7. Inspect the final receipt instead of inferring results from intermediate state.

## Operational note

The runtime is authoritative for statuses, receipts, and result availability. Client-side helpers should not guess missing states.
