# Universal Bitcoin Identity Layer

A production-focused Flask service that bridges OAuth2/OpenID Connect with Lightning Network authentication. The project couples hardened security defaults, Redis-backed rate limiting, RS256 JWT issuance, and Postgres persistence so Bitcoin-enabled applications can expose standards-compliant identity endpoints.

---

## 🚀 Highlights

- **Security-first OAuth2/OIDC core** – RS256 tokens with on-disk JWKS rotation, PKCE validation, HTTPS enforcement through `app.security`, and Redis-powered rate limiting that degrades gracefully to in-memory limits.
- **Lightning-aware identity workflows** – LNURL-auth challenge storage, Bitcoin signature verification helpers, and adapters that keep the legacy authorization views working while the storage layer matured.
- **Persistent storage** – SQLAlchemy models for OAuth clients/codes/tokens, sessions, LNURL challenges, proof-of-funds requests, and audit logs backed by Postgres with Redis coordination for ephemeral state.
- **Operational tooling** – `/metrics/prometheus` endpoint, structured JSON logging, and a reusable `create_app()` factory for WSGI/ASGI containers.
- **Typed configuration surface** – Environment-driven configuration validated by `app.config`, including production guardrails for secrets, Redis, and database connectivity.

---

## 🏗️ Architecture at a Glance

| Layer | Key Modules | Responsibilities |
| --- | --- | --- |
| Web application | [`app/app.py`](app/app.py) | Flask application, OAuth2/LNURL routes, Prometheus metrics, Socket.IO events, and the `create_app()` factory |
| Security | [`app/security.py`](app/security.py) | Proxy/header fixes, HTTPS enforcement, Flask-Limiter setup, logging defaults |
| Identity tokens | [`app/tokens.py`](app/tokens.py), [`app/jwks.py`](app/jwks.py) | RS256 JWT issuance, keypair persistence, JWKS publication |
| Storage | [`app/db_storage.py`](app/db_storage.py), [`app/database.py`](app/database.py), [`app/storage.py`](app/storage.py) | Postgres session helpers, Redis utilities, and in-memory parity for tests |
| Configuration | [`app/config.py`](app/config.py) | Typed env loader, production validation helpers |
| Observability | [`app/app.py`](app/app.py), [`deployment/README.md`](deployment/README.md) | Prometheus counter wiring and deployment guidance |

Further documentation lives in the [`app/`](app/README.md) directory and supporting deployment guides under [`deployment/`](deployment/README.md).

---

## 🧰 Prerequisites

- Python 3.10+
- Postgres 13+
- Redis 6+
- Bitcoin Core 24+ (for RPC-backed features)

For local development you can omit Postgres/Redis by exporting `DATABASE_URL` and `REDIS_URL` pointing to ephemeral services (e.g. docker-compose) or by relying on the in-memory storage adapter for tests.

---

## 🏁 Quick Start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export FLASK_APP=wsgi:create_app
export FLASK_ENV=development
export RPC_USER=bitcoinrpc
export RPC_PASSWORD=change-me
flask run
```

The service exposes:

- `/.well-known/openid-configuration`, `/oauth/token`, `/oauth/authorize`
- `/lnurl/auth` LNURL challenge endpoints
- `/metrics/prometheus` for Prometheus scrapers
- `/health` basic liveness probe

See [`TESTING.md`](TESTING.md) for pytest, mypy, and linting guidance.

---

## ⚙️ Configuration Reference

`app/config.py` documents every supported environment variable. Highlights include:

- `JWT_ALGORITHM=RS256` to force asymmetric signing; JWKS files are stored in `JWKS_DIR`.
- `RATE_LIMIT_ENABLED` / `RATE_LIMIT_DEFAULT` for limiter tuning.
- `DATABASE_URL` or discrete `DB_*` variables for SQLAlchemy.
- `REDIS_URL`/`REDIS_*` for rate limiting and challenge/session TTL handling.
- `FORCE_HTTPS`, `SECURE_COOKIES`, and `CSRF_ENABLED` for deployment hardening.

Run `python -m app.config` (or import `validate_config`) inside your deployment pipeline to fail fast on insecure production settings.

---

## 🧪 Testing

```bash
pytest
```

Unit tests cover configuration parsing/validation along with storage adapters. Integration tests spin up the in-memory backend to exercise OAuth and LNURL flows without external services.

---

## 🤝 Contributing

1. Fork the repository and create a virtual environment.
2. Install dev dependencies with `pip install -r requirements-dev.txt`.
3. Run `pytest` before opening a pull request.
4. Follow the [code of conduct](CODE_OF_CONDUCT.md) and [contribution guidelines](CONTRIBUTING.md).

Bug reports and feature proposals are welcome via [GitHub Issues](https://github.com/hodlxxi/Universal-Bitcoin-Identity-Layer/issues).

---

## 📄 License

Released under the [MIT License](LICENSE).

