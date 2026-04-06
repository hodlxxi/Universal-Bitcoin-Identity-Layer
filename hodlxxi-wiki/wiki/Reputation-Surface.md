# Reputation Surface

## Implemented surfaces
Repository indicates explicit public reputation and history endpoints:
- `/agent/reputation`
- `/agent/attestations`
- `/agent/chain/health`
- Trust summary/report pages that aggregate execution and covenant-state metadata.

## Observable data classes (from code/tests/docs)
- Job receipts and signed attestation items.
- Status-category metrics (`completed_jobs`, `unpaid_or_expired_jobs`, `execution_failed_jobs`, etc.).
- Chain continuity/health summaries.

## Confidence boundaries
- Public observability appears implemented.
- Economic interpretation of reputation (e.g., sustained quality guarantees) remains an inference and should not be overstated without longitudinal runtime evidence.
