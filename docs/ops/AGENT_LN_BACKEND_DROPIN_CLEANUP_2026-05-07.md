# HODLXXI Agent LND Backend Drop-In Cleanup — 2026-05-07

> **Status:** Historical checkpoint. This document records deployment, cleanup, planning, or protocol state at the time it was written. Do not treat it as the current runbook or current implementation truth unless it is explicitly linked from `docs/DOCUMENTATION_MAP.md` or `docs/READINESS_EVALUATION.md`.


## Current state

Production `24-agent-ln-backend.conf` now only sets:

- `AGENT_PRIVKEY_PATH`

The duplicate/stale LND variables were removed from this drop-in:

- `LN_BACKEND`
- `LND_TLSCERTPATH`
- `LND_MACAROONPATH`

LND runtime configuration remains available through the canonical env file and the forced LND path drop-in.

## Why this was done

`24-agent-ln-backend.conf` mixed the agent private-key path with LND runtime variables.

Hash comparison showed:

- `LN_BACKEND` matched canonical values.
- `LND_TLSCERTPATH` matched canonical values.
- `LND_MACAROONPATH` conflicted with the canonical/forced LND path configuration.

The cleanup keeps `AGENT_PRIVKEY_PATH` in place while removing duplicated/conflicting LND variables.

## Backup

A full backup was created before changing systemd state:

- `/root/hodlxxi-systemd-dropins-before-24-agent-ln-backend-cleanup-20260507T194423Z`

A file-level backup was also created:

- `/etc/systemd/system/hodlxxi.service.d/24-agent-ln-backend.conf.bak.before-lnd-var-cleanup.20260507T194434Z`

## Production validation

Validation after editing `24-agent-ln-backend.conf`:

- `/health/ready`: ready
- `/api/public/status`: BTC height present, LND active
- `/agent/chain/health`: `chain_ok=true`
- OIDC metadata: `S256` present
- Live process still exposes `AGENT_PRIVKEY_PATH`
- Live process still exposes LND env names, including `LN_BACKEND`, `LND_RPCSERVER`, `LND_TLSCERTPATH`, and `LND_MACAROONPATH`
- Recent serious log scan showed no LND, lncli, or agent key traceback after restart

## Rollback

If the app fails to start, LND becomes inactive, or agent key loading breaks, restore the file-level backup:

    sudo cp -a /etc/systemd/system/hodlxxi.service.d/24-agent-ln-backend.conf.bak.before-lnd-var-cleanup.20260507T194434Z /etc/systemd/system/hodlxxi.service.d/24-agent-ln-backend.conf
    sudo systemctl daemon-reload
    sudo systemctl restart hodlxxi
    curl -fsS https://hodlxxi.com/health/ready
    curl -sS https://hodlxxi.com/api/public/status | jq '{btc, lnd}'

## Next target

Do not disable `zz-force-lnd-cli-paths.conf` yet.

The next cleanup should inspect:

- `20-lnd-readonly.conf`
- `22-home-for-lncli.conf`
- `23-bind-lncli.conf`
- `zz-force-lnd-cli-paths.conf`

Only compare variable names or hashes. Do not print secret values.
