# HODLXXI Env Dedupe Checkpoint — 2026-05-07

> **Status:** Historical checkpoint. This document records deployment, cleanup, planning, or protocol state at the time it was written. Do not treat it as the current runbook or current implementation truth unless it is explicitly linked from `docs/DOCUMENTATION_MAP.md` or `docs/READINESS_EVALUATION.md`.


## Summary

Cleaned duplicate keys in the canonical production env file:

- `POF_DB_PATH`
- `TEST_INVOICE_PAID`

## Completed

- Inspected duplicate values by hash only.
- Confirmed duplicate values were identical.
- Kept the last effective occurrence for each key.
- Removed earlier duplicate entries.
- Restarted production and verified runtime recovery.

## Result

- `POF_DB_PATH`: 2 entries reduced to 1
- `TEST_INVOICE_PAID`: 3 entries reduced to 1
- Duplicate key scan: `NO_DUPLICATES`

## Production validation

- `/health/ready`: ready
- `/api/public/status`: BTC height present, LND active
- `/agent/chain/health`: `chain_ok=true`
- OIDC metadata advertises `S256`
- Post-recovery serious error scan: empty

## Note

A systemd restart timeout was observed during restart, but the service recovered and runtime checks passed.

Treat this as a separate service lifecycle hardening item, not an env dedupe failure.

## Rollback material

- `/root/hodlxxi-before-dedupe-env-keys-20260507T020841Z`
