# HODLXXI LND RPCSERVER Drop-In Cleanup — 2026-05-07

## Current state

Production now sources LND_RPCSERVER from the canonical systemd env file and the remaining forced LND path drop-in.

The duplicate drop-in has been disabled:

- /etc/systemd/system/hodlxxi.service.d/21-lnd-rpcserver.conf.DISABLED

The active drop-in path is absent:

- /etc/systemd/system/hodlxxi.service.d/21-lnd-rpcserver.conf

## Why this was done

21-lnd-rpcserver.conf only set LND_RPCSERVER.

Hash comparison showed that its value matched the active canonical/forced LND configuration.

Disabling this file removes one duplicate systemd env source while preserving the runtime LND connection.

## Backup

A full backup was created before changing systemd state:

- /root/hodlxxi-systemd-dropins-before-21-lnd-rpcserver-cleanup-20260507T180433Z

Backup includes:

- /etc/systemd/system/hodlxxi.service.d
- /etc/hodlxxi/hodlxxi.env

## Production validation

Validation after disabling 21-lnd-rpcserver.conf:

- /health/ready: ready
- /api/public/status: BTC height present, LND active
- /agent/chain/health: chain_ok=true
- OIDC metadata: S256 present
- Live process still exposes LND env names, including LND_RPCSERVER
- Recent serious log scan showed no LND or lncli traceback after restart

A systemd restart timeout line was observed during restart warmup, but the service recovered and runtime smoke passed.

## Rollback

If the app fails to start or LND becomes inactive, restore the drop-in:

    sudo mv /etc/systemd/system/hodlxxi.service.d/21-lnd-rpcserver.conf.DISABLED /etc/systemd/system/hodlxxi.service.d/21-lnd-rpcserver.conf
    sudo systemctl daemon-reload
    sudo systemctl restart hodlxxi
    curl -fsS https://hodlxxi.com/health/ready
    curl -sS https://hodlxxi.com/api/public/status | jq '{btc, lnd}'

## Next target

Do not disable the remaining LND path drop-ins blindly.

The next cleanup should inspect:

- 20-lnd-readonly.conf
- 24-agent-ln-backend.conf
- zz-force-lnd-cli-paths.conf

Only compare variable names or hashes. Do not print secret values.
