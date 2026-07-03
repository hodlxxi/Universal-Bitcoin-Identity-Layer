# Human Proof requester proof store

Human Proof v2 requester proof records are created when a requester key signs a challenge for a specific `/agent/request` body. The record is then consumed by `/agent/request` for that same request body. This binding is request-specific: the proof is not a reusable login token, identity credential, or general-purpose session.

## Current MVP storage mode

The current requester proof store is process-local memory with a short TTL. This is acceptable for the Human Proof MVP only when the service runs as a single worker, or when deployment guarantees session affinity so the challenge verification request and later `/agent/request` are handled by the same process.

Current MVP production is expected to run with a single worker. If production moves to multiple workers without session affinity, requester proof records verified by worker A may not be visible to worker B. Before enabling the Human Proof requester proof path at scale in that topology, requester proof records must move to Redis or another shared TTL storage layer.

Stable storage-mode contract:

```json
{
  "storage": "memory",
  "shared_across_workers": false,
  "requires": "single_worker_or_session_affinity",
  "ttl_seconds": 300,
  "multi_worker_safe": false
}
```

The app may emit an operator warning when safe non-secret worker-count signals such as `WEB_CONCURRENCY` or `GUNICORN_WORKERS` indicate more than one worker while the requester proof store remains memory-backed. This warning is diagnostic only and does not crash production by default.

## Receipt and identity boundaries

This storage guard does not change what a receipt proves. Receipts still attest to the paid request, runtime execution, requester proof summary when present, and signed receipt fields already defined by receipt.v1.

This store also does not make HODLXXI any of the following:

- KYC or legal identity infrastructure;
- one-human-one-key enforcement;
- custody infrastructure;
- token, investment, staking, yield, exchange, governance-token, leaderboard, revenue-share, or market mechanics.

## Operator rule

Use the memory requester proof store only for single-worker or session-affine deployments. Use Redis/shared TTL storage before multi-worker Human Proof requester proof deployment at scale.
