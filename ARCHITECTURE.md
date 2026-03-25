# HODLXXI Architecture (Current Runtime Truth)

This document describes the runtime architecture that exists in this repository today. It is intentionally conservative and avoids roadmap claims.

## Runtime status snapshot

- **Primary runtime:** Flask monolith with partial blueprint modularization.
- **Primary deployment model:** single VPS, Nginx reverse proxy, Gunicorn, PostgreSQL, Redis.
- **Identity surface:** Bitcoin signature login, guest access modes, OAuth2/OIDC endpoints, LNURL-auth endpoints.
- **PoF surface:** PoF UI and API routes are present; quality and data shape are runtime-defined rather than hard versioned.
- **Covenant/factory split:** this repository contains ongoing evolution; do not assume factory migration is complete.

## High-level component map

1. **Edge / ingress**
   - Nginx handles TLS termination and reverse proxy responsibilities.
2. **Application runtime**
   - Flask app (`app/app.py`) plus blueprints under `app/blueprints/`.
   - Socket.IO is used for real-time presence/chat/video signaling.
3. **Data and state**
   - PostgreSQL for persisted application records.
   - Redis/in-memory storage patterns for transient and rate-limit/session-like data.
4. **Bitcoin integration**
   - Bitcoin RPC-backed features for signature verification, descriptor/covenant operations, and PoF-related flows.

## Authentication and identity modes

Current runtime includes multiple practical login paths:

- Bitcoin challenge/signature verification.
- Guest login paths (PIN and random guest).
- LNURL-auth flow endpoints under `/api/lnurl-auth/*`.
- OAuth2/OIDC provider endpoints under `/oauth/*` and discovery/JWKS endpoints.

Not all login paths have the same assurance level. Contributors should treat guest and convenience flows as lower-assurance compared with signed Bitcoin-key flows.

## OAuth2/OIDC scope and limits

Implemented endpoints support a usable authorization-code-oriented provider flow. Claims of full standards completeness should be avoided unless validated endpoint-by-endpoint against the exact RFC requirements and test matrix.

## LNURL-auth scope and limits

LNURL-auth endpoints exist and are integrated into runtime flows. However, compliance and security posture should be described as **implemented with caveats** rather than “fully complete,” because behavior depends on current verification implementation details.

## PoF and covenant surfaces

- PoF routes currently include landing, leaderboard, verification/certificate views, and stats API.
- Covenant/descriptors functionality exists as part of Bitcoin integration flows.
- Exact production semantics (especially privacy and aggregation behavior) should be treated as current implementation behavior, not as immutable protocol guarantees.

## Architecture boundaries for this repo

When updating docs, keep these boundaries explicit:

- **Current runtime truth:** what exists and is exercised now.
- **Staging-validated behavior:** what has been exercised in staging/demo workflows.
- **Experimental/partial:** features present but not yet hardened as stable contracts.
- **Future work:** ideas or planned refactors (must be labeled as such).

## Related documents

- `docs/SYSTEM_ARCHITECTURE.md` for operational/system-level details.
- `docs/API_REFERENCE.md` for endpoint-level API contract notes.
- `app/OAUTH_LNURL_SPECIFICATION.md` for protocol-specific behavior and caveats.
- `app/PRODUCTION_DEPLOYMENT.md` for deployment guidance aligned to current operations.
