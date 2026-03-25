# HODLXXI System Architecture (Current-State Guide)

## Purpose

This document is the system-level companion to `ARCHITECTURE.md`. It focuses on how the current service is put together operationally, without asserting completion of in-progress refactors.

## Current operating model

- **Deployment style:** VPS-hosted application stack.
- **Web tier:** Nginx reverse proxy with TLS termination.
- **App tier:** Gunicorn serving Flask app runtime.
- **State/data:** PostgreSQL for durable data; Redis/ephemeral stores for runtime support.
- **Bitcoin dependency:** Bitcoin RPC integration for signature and descriptor/PoF-adjacent functions.

## Runtime composition

- Flask application contains core routes and blueprint-registered modules.
- Real-time messaging/signaling is implemented through Socket.IO.
- OAuth and LNURL flows are integrated as application endpoints rather than isolated microservices.

## Monolith vs factory status

The repository contains evidence of active architecture evolution. For contributors and reviewers:

- treat the runtime as **monolith-first with partial modularization**;
- do not assume full migration to any factory-only runtime unless explicitly validated in the running environment;
- avoid presenting migration work as already complete.

## Data responsibilities (practical view)

- User/account/session-like identity data is persisted in PostgreSQL models.
- OAuth client/code/token persistence may involve both DB-backed and storage-abstraction-backed paths depending on code path and environment.
- LNURL and challenge-like data may use expiring storage semantics.

## Reliability and readiness framing

Use this language when discussing readiness:

- “running in production-like VPS deployments” is acceptable;
- broad readiness claims are too broad without explicit SLO/SLA evidence;
- “staging-validated” should be used only for behaviors repeatedly verified in staging/demo operations.

## Cross-document consistency notes

To avoid contradictions with `ARCHITECTURE.md`:

- this file stays operational/system-oriented;
- `ARCHITECTURE.md` stays component-and-boundary-oriented;
- protocol details belong in `app/OAUTH_LNURL_SPECIFICATION.md`.
