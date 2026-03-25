# Production Deployment Guide (Current Ops Reality)

This guide captures the deployment pattern currently aligned with this project’s runtime behavior.

## Baseline deployment pattern

- Ubuntu VPS host
- Nginx reverse proxy terminating TLS
- Gunicorn serving Flask app on loopback
- PostgreSQL for durable data
- Redis for runtime support (real-time/rate-limit/session-adjacent use)
- systemd service management

## What this guide is and is not

- **Is:** pragmatic guidance for current single-node and small-scale deployments.
- **Is not:** a claim that every HA/enterprise pattern is fully implemented in this repository.

## Minimal production checklist

1. Configure TLS and strict proxy forwarding in Nginx.
2. Run application via systemd-managed Gunicorn process.
3. Provide environment variables for Flask, DB, Redis, OAuth, and Bitcoin RPC.
4. Verify health endpoints (`/health`, `/health/live`, `/health/ready`).
5. Confirm DB schema alignment before exposing OAuth and PoF endpoints.
6. Validate log capture and rotation.

## Operational caveats

- OAuth, LNURL, PoF, and Bitcoin-backed behavior are environment-dependent.
- Readiness should be interpreted as operational-with-validation-per-environment, not universal out-of-box readiness.
- If external dependencies (Bitcoin RPC, DB, Redis) are degraded, readiness and endpoint behavior will degrade accordingly.

## Suggested deployment validation sequence

1. Smoke test UI and login endpoints.
2. Validate OAuth register/authorize/token flow in your environment.
3. Validate LNURL challenge creation/check path.
4. Validate PoF pages and `/api/pof/stats`.
5. Validate health and metrics surfaces.

## Related docs

- `docs/SYSTEM_ARCHITECTURE.md`
- `docs/API_REFERENCE.md`
- `app/OAUTH_LNURL_SPECIFICATION.md`
- `app/ERROR_CODE_DOCUMENTATION.md`
