# HODLXXI Secrets Rotation and Env Consolidation Plan — 2026-05-04

## Goal

Consolidate production secrets into root-only environment files and prepare a safe rotation plan for Redis, Flask session signing, Bitcoin RPC, and LND credentials.

This document is planning-only. Do not rotate live secrets until backup and rollback steps are confirmed.

## Current known secret classes

- Flask session secret: FLASK_SECRET_KEY
- Redis URL/password: REDIS_URL
- Bitcoin Core RPC credentials: RPC_USER, RPC_PASSWORD, RPC_HOST, RPC_PORT, RPC_WALLET
- LND backend/path config: LN_BACKEND, LND_RPCSERVER, LND_TLSCERTPATH, LND_MACAROONPATH
- JWT/OIDC signing material if configured outside generated runtime keys
- App-specific API bearer tokens or agent billing credentials

## Desired target state

- One root-owned env file for production app secrets.
- One root-owned env file for staging app secrets.
- Systemd drop-ins reference env files instead of duplicating secrets.
- Diagnostic scripts redact all secret values.
- Rotation procedure is documented before credentials change.
- Rollback procedure is documented before credentials change.

## Safety rules

- Never print secret values into terminal logs, GitHub, docs, or ChatGPT.
- Never commit .env, systemd drop-ins containing raw secrets, macaroon files, TLS certs, wallet files, or RPC credentials.
- Snapshot current systemd drop-in names and variable names only.
- Verify service restart after env-file consolidation before rotating any secret.

## Inventory commands

Run on production, but save only redacted variable names and file paths.

    systemctl cat hodlxxi
    systemctl show hodlxxi -p Environment -p EnvironmentFiles
    find /etc/systemd/system/hodlxxi.service.d -maxdepth 1 -type f -name '*.conf' -print | sort
    find /etc/hodlxxi -maxdepth 2 -type f -print | sort

## Proposed rotation order

1. Inventory and document current env sources.
2. Create root-only canonical env file.
3. Update systemd to load canonical env file.
4. Restart and smoke test without changing secret values.
5. Rotate Redis credential.
6. Rotate Flask secret with session logout window accepted.
7. Rotate Bitcoin RPC password.
8. Verify LND macaroon/TLS paths remain read-only and correct.
9. Run production smoke.
10. Update hardening report.

## Smoke tests after each change

    curl -fsS https://hodlxxi.com/health/ready
    curl -sS https://hodlxxi.com/api/public/status | jq '{btc, lnd}'
    curl -sS https://hodlxxi.com/.well-known/openid-configuration | jq '{issuer, code_challenge_methods_supported}'
    curl -sS https://hodlxxi.com/agent/chain/health | jq .

## Rollback plan

- Restore previous systemd drop-ins or env file from timestamped backup.
- Run systemctl daemon-reload.
- Restart hodlxxi.
- Confirm /health/ready.
- Confirm /api/public/status.
- Do not delete old secrets until new config is confirmed stable.

## Acceptance criteria

- Production and staging env sources are documented.
- No raw secrets are committed.
- Existing runtime stays green.
- Rotation steps and rollback steps are explicit.

## Production consolidation checkpoint — 2026-05-04

Production systemd no longer reads `/srv/ubid/.env` as an `EnvironmentFile`.

Current canonical production env source:

- `/etc/hodlxxi/hodlxxi.env`

Validation:

- `systemctl show hodlxxi -p EnvironmentFiles` shows only `/etc/hodlxxi/hodlxxi.env`
- `/health/ready`: ready
- `/agent/chain/health`: `chain_ok=true`
- `/agent/reputation`: 200
- `/api/public/status`: BTC height present, LND active
- OIDC metadata advertises `S256`
- Recent serious error scan after successful consolidation: empty

Rollback material retained:

- `/srv/ubid/.env`
- timestamped backups of `/etc/hodlxxi/hodlxxi.env`
- timestamped backups of `/srv/ubid/.env`
