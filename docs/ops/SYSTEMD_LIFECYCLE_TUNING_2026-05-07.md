# HODLXXI Systemd Lifecycle Tuning — 2026-05-07

## Summary

Production hodlxxi.service was tuned to stop Gunicorn/eventlet cleanly during restarts.

Before this change, restarts could wait until the default 90 second systemd stop timeout and report:

- Failed with result timeout

## Change

Added production systemd drop-in:

- /etc/systemd/system/hodlxxi.service.d/30-lifecycle-stop-policy.conf

Effective settings:

- TimeoutStopSec=10s
- KillMode=mixed
- KillSignal=SIGINT

## Why

Staging used a similar lifecycle policy and demonstrated clean restart behavior while the service was running.

Production was previously using:

- TimeoutStopUSec=1min 30s
- KillMode=control-group
- KillSignal=SIGTERM

That allowed restart shutdown to stall until timeout.

## Production validation

After applying the drop-in and running daemon-reload:

- production restart elapsed: about 3.5 seconds
- Gunicorn handled SIGINT
- Gunicorn master shut down cleanly
- systemd stopped and started the service without timeout
- /health/ready: ready
- /api/public/status: BTC height present, LND active
- /agent/chain/health: chain_ok=true
- OIDC metadata advertises S256
- Post-restart serious error scan: empty

## Rollback material

Snapshot before change:

- /root/hodlxxi-before-prod-lifecycle-stop-policy-20260507T050816Z

Rollback:

- remove /etc/systemd/system/hodlxxi.service.d/30-lifecycle-stop-policy.conf
- run systemctl daemon-reload
- restart hodlxxi

## Note

This fixes the systemd stop timeout behavior. It does not address unrelated endpoint latency or future app-level startup/import hardening.
