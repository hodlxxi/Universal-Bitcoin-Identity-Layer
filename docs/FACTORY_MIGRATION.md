# Factory Migration

## Previous state

Production still pointed at `app/app.py`, while most tests already booted the service through `app/factory.py`. That created two runtime shapes and left public OAuth, agent, LNURL, billing, and compatibility surfaces split between the monolith and the factory.

## Current state

- `app/factory.py` exports the canonical `create_app(config_object=None)` constructor.
- `wsgi.py` now exposes `app = create_app()` and is the canonical deployment entrypoint.
- `app/app.py` remains only as a compatibility shim for older imports and legacy auth helper coverage.
- Production and tests now use the same constructor path.

## What stayed compatible

The Stage 1 refactor kept the factory runtime reachable at the existing public URLs for:

- `/.well-known/openid-configuration` and `/.well-known/agent.json`
- `/oauth/*` plus `/oauthx/status` and `/oauthx/docs`
- `/api/lnurl-auth/*`
- `/api/billing/agent/*` and `/api/billing/*` compatibility routes
- `/api/account/*` compatibility routes
- `/agent/*` discovery and paid job surfaces

## Operator guidance

Use `wsgi:app` for Gunicorn/systemd/container deployments so production matches tests:

```bash
gunicorn -k gevent -w 4 --bind 0.0.0.0:5000 wsgi:app
```

## Remaining cleanup

Stage 2 can continue extracting leftover monolith-only UI/chat behavior into factory-safe modules, but the real application-construction path now lives in `app/factory.py`.
