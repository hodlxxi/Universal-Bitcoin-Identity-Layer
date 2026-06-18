# HODLXXI Post-RAM Restart Proof — 2026-05-09

> **Status:** Historical checkpoint. This document records deployment, cleanup, planning, or protocol state at the time it was written. Do not treat it as the current runbook or current implementation truth unless it is explicitly linked from `docs/DOCUMENTATION_MAP.md` or `docs/READINESS_EVALUATION.md`.


## Summary

Production RAM was upgraded after diagnosing Gunicorn/eventlet restart timeouts as resource-pressure related.

After the upgrade, a controlled production restart completed cleanly.

## Before RAM upgrade

Observed symptoms:

- production restarts could hit `TimeoutStopSec=10s`
- old Gunicorn/eventlet processes were killed with SIGKILL
- systemd reported `Failed with result 'timeout'`
- standalone `wsgi:app` import could vary up to about `20.7s`
- host had about `961Mi` RAM
- swap was actively used
- LND dominated RAM/swap usage

A production `ExecStop=/bin/kill -s SIGINT $MAINPID` experiment did not fix the issue and was removed.

## After RAM upgrade

Host state:

- total RAM: about `1.9Gi`
- swap used: `0B`
- LND `MemorySwapCurrent=0`
- HODLXXI `MemorySwapCurrent=0`

Standalone import timing stabilized around `1.2s–2.6s`.

## Controlled restart proof

Snapshot:

- `/root/hodlxxi-before-post-ram-restart-proof-20260509T094800Z`

Restart result:

- `restart_elapsed=1.99s`
- Gunicorn master handled SIGINT
- worker exited cleanly
- systemd stopped service cleanly
- systemd started service cleanly
- no SIGKILL
- no `Failed with result 'timeout'`
- app factory completed about 2 seconds after worker boot

## Runtime validation

After restart:

- `/health/ready`: ready
- `/api/public/status`: BTC height present, BTC error null, LND active
- `/agent/chain/health`: `chain_ok=true`
- OIDC metadata advertises `S256`
- unauth `/api/lnd/status`: `401`, not `500`
- serious app log scan: empty

## Conclusion

The restart timeout was caused by resource pressure / swap pressure interacting with Gunicorn/eventlet shutdown and cold startup behavior.

RAM upgrade fixed the operational symptom.

## Current decision

Do not continue systemd signal experiments.

Keep current lifecycle settings:

- `TimeoutStopSec=10s`
- `KillMode=mixed`
- `KillSignal=SIGINT`

Do not re-add the failed `ExecStop` drop-in.
