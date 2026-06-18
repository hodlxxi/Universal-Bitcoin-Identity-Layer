# HODLXXI Gunicorn/Eventlet Shutdown Diagnosis — 2026-05-09

> **Status:** Historical checkpoint. This document records deployment, cleanup, planning, or protocol state at the time it was written. Do not treat it as the current runbook or current implementation truth unless it is explicitly linked from `docs/DOCUMENTATION_MAP.md` or `docs/READINESS_EVALUATION.md`.


## Summary

Production restarts can still hit the systemd stop timeout and kill old Gunicorn/eventlet processes with SIGKILL.

This is not a PR #204 rollback issue. Runtime recovered and smoke tests passed.

## Current runtime state

- `/health/ready`: ready
- `/api/public/status`: BTC height present, BTC error null, LND active
- unauth `/api/lnd/status`: 401, not 500
- failed `31-explicit-gunicorn-stop.conf` experiment was removed
- effective lifecycle returned to:
  - `TimeoutStopSec=10s`
  - `KillMode=mixed`
  - `KillSignal=SIGINT`

## What was tested

A production-only drop-in was tested:

- `ExecStop=/bin/kill -s SIGINT $MAINPID`
- `ExecReload=/bin/kill -s HUP $MAINPID`

Result:

- did not fix shutdown
- old Gunicorn processes were still killed with SIGKILL
- systemd still reported `Failed with result 'timeout'`
- runtime recovered afterward

Decision: remove the drop-in and stop systemd signal experiments.

## Production vs staging comparison

Shared characteristics:

- Python 3.12.3
- Gunicorn 24.1.1
- Eventlet 0.40.4
- `Type=simple`
- `TimeoutStopSec=10s`
- `KillMode=mixed`
- `KillSignal=SIGINT`

Staging restart baseline:

- `restart_elapsed=3.09`
- clean `Worker exiting`
- clean `Stopped`
- no SIGKILL
- no timeout

Production restart behavior:

- old Gunicorn received SIGINT
- worker began exit
- systemd hit stop timeout
- old master/worker were killed with SIGKILL
- service restarted and runtime recovered

## Import timing evidence

Production standalone `wsgi:app` import timing varied:

- first run: about `20.7s`
- later warmed runs: about `1.4s` to `3.2s`

Staging standalone `wsgi:app` import:

- about `3.1s`

Production restart log showed a slow cold startup path:

- Gunicorn worker booted
- app factory completed roughly 40+ seconds later

## Host pressure evidence

Production host is memory constrained:

- total memory: about `961Mi`
- available memory: about `132Mi`
- swap used: about `677Mi`

LND dominates memory and swap:

- LND RSS: about `429Mi`
- LND `MemoryCurrent`: about `460Mi`
- LND `MemorySwapCurrent`: about `543Mi`

TCP checks to Redis, Postgres, Bitcoin RPC, and LND were fast. This points away from network dependency timeouts and toward cold import/page-cache/swap pressure.

## Working diagnosis

The restart problem is likely caused by resource pressure plus Eventlet/Gunicorn shutdown behavior:

1. production memory is tight
2. LND consumes a large fraction of RAM and swap
3. cold Python imports can vary from a few seconds to 20+ seconds
4. old Eventlet/Gunicorn processes do not reliably exit before `TimeoutStopSec=10s`
5. systemd kills the old process after timeout, but runtime recovers

## Do not do next

- do not re-add `ExecStop`
- do not keep changing `KillSignal`
- do not delete LND env/drop-ins
- do not treat this as a PR #204 app regression

## Candidate mitigations

Operational:

- increase server RAM
- reduce resident workload on the same host
- consider raising `TimeoutStopSec` only as a mitigation, not a root fix

Engineering:

- reduce app import/startup cost
- move more routes out of legacy/import-heavy paths
- defer SocketIO/Eventlet modernization as a separate larger project
- eventually migrate away from Eventlet

## Safe next step

Prefer memory/host sizing or startup import hardening before more systemd lifecycle changes.
