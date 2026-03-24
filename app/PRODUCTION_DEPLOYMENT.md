# Production Deployment Guide

## Status Notes

This document is intentionally **current-state only**. It describes how HODLXXI is actually operated today on a single VPS and separates optional future patterns from active reality.

If you see a mismatch between this file and older deployment scripts/docs, trust:
1. Runtime entrypoint in `wsgi.py`
2. Socket.IO/runtime behavior in `app/app.py`
3. Current operator service conventions (`hodlxxi.service`, Nginx -> Gunicorn on `127.0.0.1:5000`)

---

## Current Deployment Reality

### Topology (active today)

- **Single VPS** deployment (Ubuntu family)
- **Nginx** terminates TLS and reverse-proxies to Gunicorn
- **Gunicorn** runs the Flask monolith via `wsgi:app`
- **Flask-SocketIO** is enabled, so worker model stays conservative (single worker)
- **PostgreSQL** is the primary persistent DB for app/OAuth/PoF data
- **Redis** is used for cache/session/presence helpers and related runtime state
- **Bitcoin Core RPC** is expected to be reachable by app config
- **LND integration exists but is conditional/feature-dependent** (not required for every route)

### Monolith vs modular factory

Current public/runtime truth is still centered on the monolith app in `app/app.py` exposed by `wsgi.py`.

- Runtime entrypoint: `from app.app import app` in `wsgi.py`
- `app/factory.py` exists and is useful for modularization/testing paths, but it is **not** the primary production entrypoint documented here.

---

## Runtime Entry Points and Services

### WSGI entrypoint

`wsgi.py` exports:

- `app`
- `application = app`

Gunicorn should point to **`wsgi:app`** (or `wsgi:application`).

### Gunicorn worker model (current)

For Socket.IO compatibility in this repo’s current runtime model, production should use:

- **worker class:** `eventlet`
- **workers:** `1`
- **bind:** `127.0.0.1:5000`

Example:

```bash
gunicorn -k eventlet -w 1 -b 127.0.0.1:5000 wsgi:app
```

Do **not** treat multi-worker generic examples as default truth for current deployment.

### systemd unit naming

Current operator naming is:

- **`hodlxxi.service`** (primary)

Some repository helper scripts/docs still mention `app.service` and `/srv/app`; those are legacy/generic artifacts and should be adapted to your host reality (`hodlxxi.service`, `/srv/ubid` if that is your deployed path).

Recommended service skeleton:

```ini
[Unit]
Description=HODLXXI Flask app (Gunicorn + Socket.IO)
After=network.target postgresql.service redis-server.service
Wants=postgresql.service redis-server.service

[Service]
Type=simple
User=hodlxxi
Group=www-data
WorkingDirectory=/srv/ubid
EnvironmentFile=/etc/hodlxxi/environment
ExecStart=/srv/ubid/venv/bin/gunicorn -k eventlet -w 1 -b 127.0.0.1:5000 wsgi:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

---

## Environment and Secrets

Use an environment file owned by root (or `hodlxxi`) with strict permissions.

```bash
sudo install -m 600 -o root -g root /dev/null /etc/hodlxxi/environment
```

### Minimum production variables

```bash
# Flask/session
FLASK_ENV=production
FLASK_SECRET_KEY=<strong-random>

# Bitcoin RPC
RPC_HOST=127.0.0.1
RPC_PORT=8332
RPC_USER=<rpc-user>
RPC_PASSWORD=<rpc-password>
RPC_WALLET=<wallet-or-empty>

# Database (either DATABASE_URL or DB_* set)
DATABASE_URL=postgresql://hodlxxi:<password>@127.0.0.1:5432/hodlxxi
# optional split form used by code:
# DB_HOST=127.0.0.1
# DB_PORT=5432
# DB_USER=hodlxxi
# DB_PASSWORD=<password>
# DB_NAME=hodlxxi

# Redis
REDIS_HOST=127.0.0.1
REDIS_PORT=6379
REDIS_DB=0
# REDIS_PASSWORD=<optional>

# Runtime behavior
SOCKETIO_ASYNC_MODE=eventlet
SOCKETIO_CORS=https://hodlxxi.com
APP_PORT=5000

# JWT/OIDC
JWT_SECRET=<strong-random>
JWT_ISSUER=https://hodlxxi.com
JWT_AUDIENCE=hodlxxi
```

### Notes

- In production, do not rely on defaults like `RPC_PASSWORD=change-me` or generated ephemeral Flask secret.
- `SECURE_COOKIES=true` is recommended when behind HTTPS.
- If `SOCKETIO_ASYNC_MODE` is misconfigured or backend deps are missing, code falls back to `threading`; treat that as a warning state for prod.

---

## Application Service Configuration

### Deploy/update flow (current style)

```bash
cd /srv/ubid
git fetch --all --prune
git checkout main
git pull --ff-only
source venv/bin/activate
pip install -r requirements.txt
sudo systemctl daemon-reload
sudo systemctl restart hodlxxi.service
```

### Post-deploy checks

```bash
sudo systemctl status hodlxxi.service --no-pager
curl -sf http://127.0.0.1:5000/health
curl -sf http://127.0.0.1:5000/oauthx/status
```

---

## Reverse Proxy / Public Routing

Current external routing is:

- Public: `https://hodlxxi.com`
- Internal upstream: `127.0.0.1:5000`

Nginx must preserve websocket upgrade headers for `/socket.io` and forward standard proxy headers (`X-Forwarded-For`, `X-Forwarded-Proto`, etc.).

Recommended checks:

```bash
sudo nginx -t
sudo systemctl reload nginx
curl -I https://hodlxxi.com
```

---

## Bitcoin / Lightning / Storage Dependencies

### Bitcoin Core

Expected for Bitcoin-facing routes:

- Reachable RPC host/port/user/password via env
- Wallet context optional depending on route

If Bitcoin RPC is unavailable, endpoints that depend on descriptors/chain data will degrade/fail while unrelated UI routes may still work.

### PostgreSQL

Primary system-of-record for:

- users/sessions
- OAuth clients/codes/tokens
- Proof-of-Funds records
- other app domain data

### Redis

Used for runtime acceleration and short-lived state (session/cache/presence helpers). App code is tolerant of Redis outages in some paths but this should still be treated as degraded mode.

### LND

There are LND status/payment integration paths, but LND is not a strict global requirement for baseline web + OAuth availability.

---

## Staging vs Production Notes

Current convention:

- **Production:** real domain + TLS + systemd (`hodlxxi.service`) + Postgres + Redis + Bitcoin RPC
- **Staging/dev:** may run on localhost, alternate env files, weaker cookie/security settings, and non-production secrets

Keep these explicit:

- Never copy staging secrets into prod.
- Keep `FLASK_ENV=production` and HTTPS-aware cookie/security flags in production.
- Keep Gunicorn eventlet/single-worker shape in both environments unless you are deliberately testing an alternative runtime.

---

## Operational Checks and Smoke Tests

Run these after deploy/restart:

```bash
# services
sudo systemctl is-active hodlxxi.service nginx postgresql redis-server

# app liveness
curl -sf https://hodlxxi.com/health
curl -sf https://hodlxxi.com/oauthx/status
curl -sf https://hodlxxi.com/oauthx/docs >/dev/null

# websocket handshake probe (HTTP upgrade path only)
curl -i -N -H "Connection: Upgrade" -H "Upgrade: websocket" https://hodlxxi.com/socket.io/?EIO=4&transport=websocket
```

Log tails during incident triage:

```bash
sudo journalctl -u hodlxxi.service -n 200 --no-pager
sudo tail -n 200 /var/log/nginx/hodlxxi-error.log
```

---

## Known Gaps and Deployment Risks

- Repo still contains mixed deployment naming (`app.service` / `/srv/app`) in some scripts/docs.
- The app is still a large monolith (`app/app.py`) with partial factory modularization.
- Some endpoints/features are intentionally WIP; treat docs/examples around those as development-state.
- Redis/Postgres/Bitcoin dependency health can fail independently; partial uptime does not imply full feature health.

---

## Backup and Recovery (Current Practical Baseline)

For current single-node operation, minimum safe baseline:

1. Daily PostgreSQL dumps
2. Backup `/etc/hodlxxi/environment` (securely) and systemd/nginx config
3. Keep repository revision/commit captured with each backup snapshot

Example DB backup:

```bash
sudo -u postgres pg_dump hodlxxi | gzip > /backup/hodlxxi/hodlxxi_$(date +%F).sql.gz
```

Example restore drill:

```bash
gunzip -c /backup/hodlxxi/<dump>.sql.gz | sudo -u postgres psql hodlxxi
```

Run restore drills periodically; untested backups are not backups.

---

## Optional Future Hardening / Scaling

The following are **not claimed as active today**; they are optional future work:

- Multi-node active/active app tier behind HAProxy/managed LB
- Kubernetes orchestration
- Dedicated Prometheus/Grafana/ELK/SIEM stack
- PostgreSQL replication/failover automation
- Blue/green or canary deployment automation
- Multi-worker horizontal socket architecture with explicit shared message queue tuning

Treat these as roadmap items only until implemented and validated.
