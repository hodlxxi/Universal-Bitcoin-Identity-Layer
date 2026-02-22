# Developer Onboarding & Run-Ready Checklist

This guide is the fastest path for new contributors to fork the repo, boot the stack, and verify the core OAuth2/LNURL functionality locally. Follow the steps in order and you should end up with a running copy of HODLXXI that mirrors the production topology.

## 1) Fork, clone, and copy configuration

1. Fork the repository on GitHub and clone your fork:
   ```bash
git clone https://github.com/<you>/Universal-Bitcoin-Identity-Layer.git
cd Universal-Bitcoin-Identity-Layer
```
2. Seed configuration from the template:
   ```bash
cp env.example .env
```
3. Update secrets in `.env` before exposing the app to the internet:
   - `FLASK_SECRET_KEY` and `JWT_SECRET` must be unique per deployment.
   - `RPC_USER`/`RPC_PASSWORD` should match your Bitcoin Core instance.
   - If you do not want to run Bitcoin locally, keep the defaults and stay on regtest via Docker.

## 2) Recommended: Docker Compose quick start

The repository ships with a Compose stack that spins up Postgres, Redis, Bitcoin Core (regtest), and the Flask app with live reload.

```bash
docker compose up --build
```

What happens:
- Postgres, Redis, and Bitcoin Core wait for health checks before the app starts.
- `./app`, `./logs`, and `./keys` are mounted so code edits and generated keys persist on your host.
- The web app is available at http://localhost:5000.

Useful follow-up commands:
- Tail logs: `docker compose logs -f app`
- Run tests inside the container: `docker compose exec app pytest`
- Reset the stack: `docker compose down -v` (drops volumes for a clean slate)

## 3) Native Python quick start (without Docker)

If you prefer to run locally without containers, mirror these steps:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export FLASK_APP=wsgi:create_app
export FLASK_ENV=development
flask run
```

You will need Postgres and Redis running on your machine and reachable via the settings in `.env` or your shell environment.

## 4) Smoke tests to confirm the app is healthy

Once the app is running (Docker or native), validate the key endpoints:

```bash
curl -f http://localhost:5000/health
curl -f http://localhost:5000/oauthx/status
curl -f http://localhost:5000/metrics/prometheus | head -n 5
```

Expected results:
- `/health` returns `{"status":"ok"}`.
- `/oauthx/status` returns a JSON payload with `status: "ok"` and `provider: "hodlxxi"`.
- `/metrics/prometheus` streams Prometheus-compatible metrics (any output indicates the exporter is live).

## 5) Developer workflows worth knowing

- **Production-style run**: `gunicorn -k gevent -w 1 --bind 0.0.0.0:5000 wsgi:app` (matches the Compose and systemd service configuration).
- **Oauth demo**: run the bundled `HODLXXI OAuth2 Live Demo.sh` script to exercise the Authorization Code flow against your environment.
- **Operational checklist**: the `PRODUCTION VALIDATION.sh` helper script performs Redis persistence checks and a round-trip OAuth flow after a service restart.

## 6) Hand-off expectations for contributors

Before opening a pull request:
- Run `pytest` (inside Docker or your virtualenv) and ensure it passes.
- Document any new environment variables in `env.example` and `README.md` if applicable.
- Include screenshots for visual changes to the web UI.
- Keep changes to deployment scripts (systemd/Nginx) backward-compatible so existing VPS setups keep running.

Completing the steps above ensures any developer can fork, bootstrap, and validate the service with the same defaults used in production.
