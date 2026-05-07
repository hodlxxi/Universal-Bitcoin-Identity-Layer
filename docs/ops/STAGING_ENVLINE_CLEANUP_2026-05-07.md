# HODLXXI Staging Env-line Cleanup — 2026-05-07

## Summary

Cleaned staging systemd override env handling so `ubid-staging.service` no longer carries direct `Environment=` values in its active override drop-in.

## Current state

- staging canonical env source: `/etc/hodlxxi/ubid-staging.env`
- active direct `Environment=` lines in `ubid-staging.service.d/override.conf`: none
- non-env service behavior remains in override.conf

## Completed

- Took root-only snapshots of staging env and systemd state.
- Built redacted staging inventory.
- Compared live env, canonical env, and override env by hash only.
- Copied missing override-owned keys into `/etc/hodlxxi/ubid-staging.env` without printing values.
- Confirmed required runtime env names remained present after restart.
- Removed 11 direct `Environment=` lines from staging override.conf.

## Validation

- `/health/ready`: ready
- `/api/public/status`: BTC height present, LND active
- `/agent/chain/health`: `chain_ok=true`
- redacted inventory shows no direct Environment keys by active drop-in

## Note

Staging restart recovered and smoke passed, but the stop phase hit the existing 10 second TimeoutStopSec and killed the old Gunicorn process. Treat staging lifecycle tuning as a separate follow-up, not an env cleanup failure.

## Rollback material

- `/root/ubid-staging-before-envline-cleanup-20260507T070332Z`
