# HODLXXI Secret Key Drop-In Cleanup — 2026-05-06

## Current state

Production now sources `FLASK_SECRET_KEY` from the canonical systemd environment file:

- `/etc/hodlxxi/hodlxxi.env`

The duplicate drop-in has been disabled:

- `/etc/systemd/system/hodlxxi.service.d/10-secret-key.conf.DISABLED`

The active drop-in path is absent:

- `/etc/systemd/system/hodlxxi.service.d/10-secret-key.conf`

## Why this was done

`FLASK_SECRET_KEY` was duplicated across systemd config.

The goal is to reduce secret duplication before rotating live credentials.

This is part of the larger env consolidation work:

- one canonical root-owned env file
- fewer active secret-bearing systemd drop-ins
- simpler rollback and rotation procedure

## Backup

A full backup was created before changing systemd state:

- `/root/hodlxxi-systemd-dropins-before-10-secret-key-cleanup-20260506T181933Z`

Backup includes:

- `/etc/systemd/system/hodlxxi.service.d`
- `/etc/hodlxxi/hodlxxi.env`

## Production validation

Validation after disabling `10-secret-key.conf`:

- Commit: `4686d6dc0f9556995aad2bcac8948004a9ae1a15`
- Active `EnvironmentFile`: `/etc/hodlxxi/hodlxxi.env`
- Disabled file exists: `10-secret-key.conf.DISABLED`
- Active file absent: `10-secret-key.conf`
- `/health/ready`: ready
- `/api/public/status`: BTC height present, LND active
- OIDC metadata: `S256` present

## Rollback

If the app fails to start or sessions break, restore the drop-in:

    sudo mv /etc/systemd/system/hodlxxi.service.d/10-secret-key.conf.DISABLED \
            /etc/systemd/system/hodlxxi.service.d/10-secret-key.conf

    sudo systemctl daemon-reload
    sudo systemctl restart hodlxxi

    curl -fsS https://hodlxxi.com/health/ready
    curl -sS https://hodlxxi.com/api/public/status | jq '{btc, lnd}'

## Next target

Do not disable Redis or LND drop-ins yet.

Next cleanup should inspect and resolve duplicate/stale variables in:

- `redis-env.conf`
- `override.conf`
- LND path drop-ins

Only compare variable names or hashes. Do not print secret values.
