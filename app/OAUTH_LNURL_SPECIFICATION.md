# OAuth2 / OIDC / LNURL-Auth Specification (Current State)

**Status:** Current-state technical reference (not a completeness claim).
**Last Updated:** 2026-03-24
**Source of truth used:** current route code in `app/app.py`, `app/oidc.py`, `app/blueprints/oauth.py`, `app/blueprints/lnurl.py`, and OAuth/LNURL tests.

---

## Status Notes

This document intentionally describes what is **implemented now**, including drift between the production-style monolith runtime (`wsgi.py` -> `app.app`) and the application-factory/blueprint test runtime (`app.factory.create_app`).

Do **not** read this as full RFC-complete OAuth/OIDC/LNURL certification. Several endpoints and claims that existed in older docs are not implemented (or are only partially implemented) in current code.

---

## Current OAuth2 / OIDC Implementation

### Runtime surfaces

There are two active code paths:

1. **Monolith runtime (primary deployment path)**
   - `wsgi.py` imports `app` from `app.app`.
   - OAuth endpoints are implemented directly in `app/app.py` and use `OAuthServer` plus DB-backed storage.

2. **Factory/blueprint runtime (used heavily by tests and modularized app startup)**
   - `create_app()` in `app/factory.py` registers `oauth_bp` (`app/blueprints/oauth.py`) and `oidc_bp` (`app/oidc.py`).

These two paths are similar at high level (authorize, token, register, introspect, discovery, JWKS) but differ in important details (especially token format and supported grants at the `/oauth/token` endpoint).

### Implemented OAuth endpoints (present today)

- `POST /oauth/register`
- `GET /oauth/authorize`
- `POST /oauth/token`
- `POST /oauth/introspect`
- `GET /.well-known/openid-configuration`
- `GET /oauth/jwks.json`
- Operational docs/status helpers:
  - `GET /oauthx/status`
  - `GET /oauthx/docs`

### Endpoints **not currently implemented** as first-class OAuth/OIDC routes

- `GET /oauth/userinfo` (not implemented)
- `POST /oauth/revoke` (not implemented)
- RFC 7592-style client update/delete API under `/oauth/register` (not implemented)

There are separate management routes in monolith runtime (`/oauth/clients`, `/oauth/clients/<id>`, `/oauth/clients/<id>/rotate-secret`) but these are session/admin-style management endpoints, not standards-based OAuth client management endpoints.

---

## Discovery and Metadata Endpoints

### `GET /.well-known/openid-configuration`

Implemented in `app/oidc.py` and available in both runtime styles.

Current behavior:
- Publishes issuer, authorization endpoint, token endpoint, JWKS URI.
- Publishes `response_types_supported: ["code"]`.
- Publishes `id_token_signing_alg_values_supported: ["RS256"]`.
- Publishes `code_challenge_methods_supported: ["S256", "plain"]`.

Important caveat:
- Metadata currently advertises `grant_types_supported` including `refresh_token`, but the factory `oauth_bp /oauth/token` handler only accepts `authorization_code`. The monolith runtime does accept refresh token grant. This is a real drift point.

### `GET /oauth/jwks.json`

Implemented via `app/oidc.py` and backed by key management in `app/jwks.py`.

Current behavior:
- Returns active RSA public signing keys as JWKS.
- Signing algorithm used for OIDC/JWT tokens is RS256.
- Key rotation logic exists in code (`ensure_rsa_keypair`) and is exercised by dedicated tests.

---

## Supported Grant Types

### `authorization_code`

**Implemented** in both runtime styles:
- Authorization code issuance at `GET /oauth/authorize`.
- Code exchange at `POST /oauth/token`.
- PKCE verification is supported when a challenge was provided.

Common enforced checks:
- `response_type` must be `code`.
- Redirect URI must match a registered URI.
- Authorization code is one-time-use.

### `refresh_token`

- **Monolith runtime (`app.app`)**: implemented in `OAuthServer.token_endpoint()` (`grant_type == "refresh_token"`) with refresh token rotation (new refresh token issued, previous one revoked).
- **Factory/blueprint runtime (`app.blueprints.oauth`)**: not implemented at token endpoint (returns `unsupported_grant_type` for anything other than `authorization_code`).

### `client_credentials`

Not implemented in current `/oauth/token` handlers (monolith or blueprint). Any older examples claiming active client credentials support are stale.

---

## Token and Client Behavior

### Token format (current reality)

Token format is **runtime-dependent** right now:

- **Monolith runtime (`app.app`)**
  - Access token: opaque random string (stored server-side in `oauth_tokens`).
  - Refresh token: opaque random string (stored server-side in `oauth_tokens`).
  - ID token: RS256 JWT.

- **Factory/blueprint runtime (`app.blueprints.oauth`)**
  - Access token: RS256 JWT.
  - ID token: RS256 JWT.
  - Refresh token: not currently issued by this path.

So a blanket statement like “all access tokens are JWT” is not currently true across all active runtime paths.

### Token lifetimes and rotation

- Authorization code TTL: 10 minutes.
- Access token TTL:
  - Monolith: `TOKEN_TTL_SECONDS` (defaults to 3600 seconds unless config overrides).
  - Factory: derived from `JWT_EXPIRATION_HOURS` (default config value is 24h).
- Refresh token TTL (monolith path): 30 days.
- Refresh rotation (monolith path): enabled (old refresh token revoked on use).

### Client registration

`POST /oauth/register` exists in both runtime styles but differs:

- **Monolith (`app.app`)**
  - Generates `client_id` prefixed with `anon_`.
  - Returns tier metadata (`client_type`, `rate_limit`, `allowed_scopes`).
  - Applies extra anonymous registration throttling.

- **Factory/blueprint (`app.blueprints.oauth`)**
  - Requires `client_name` and non-empty `redirect_uris` list.
  - Returns OAuth-style registration output (`client_id`, `client_secret`, `grant_types`, `response_types`, `client_id_issued_at`).

Neither path is a complete RFC 7591/7592 lifecycle implementation.

---

## LNURL-Auth Implementation

LNURL-auth is implemented and routable, but there is runtime drift similar to OAuth.

### Implemented routes

- `POST /api/lnurl-auth/create` (monolith also allows GET)
- `GET /api/lnurl-auth/params`
- `GET /api/lnurl-auth/callback/<session_id>`
- `GET /api/lnurl-auth/check/<session_id>`

### Flow (as implemented)

1. Client creates session (`/create`) and receives `session_id`, `lnurl`, and callback metadata.
2. Wallet fetches params (`/params?sid=...`) to obtain `tag=login`, `k1`, and callback.
3. Wallet calls callback with `k1`, `sig`, `key`.
4. Client polls `/check/<session_id>` for verification status.

### Signature verification behavior

- **Monolith (`app.app`)**: performs secp256k1 signature verification using `coincurve` and marks DB challenge verified via `update_lnurl_challenge`.
- **Blueprint path (`app.blueprints.lnurl`)**: endpoint notes signature verification is currently placeholder/trust-based and should be replaced with full cryptographic verification.

This is a significant implementation gap between paths and should be considered before claiming production-grade LNURL-auth parity in all runtimes.

### Status payload differences

- Monolith `/check/<id>` returns `authenticated` and `verified` flags (both set from `is_verified`) plus `pubkey`.
- Blueprint `/check/<id>` returns `verified` and conditionally `pubkey`.

---

## Endpoint Reference (Current)

### OAuth/OIDC public endpoints

- `GET /.well-known/openid-configuration`
- `GET /oauth/jwks.json`
- `POST /oauth/register`
- `GET /oauth/authorize`
- `POST /oauth/token`
- `POST /oauth/introspect`
- `GET /oauthx/status`
- `GET /oauthx/docs`

### OAuth management/UI-oriented routes (monolith)

- `GET /oauth/clients`
- `GET /oauth/clients/<client_id>`
- `POST /oauth/clients/<client_id>/rotate-secret`

### LNURL-auth routes

- `POST /api/lnurl-auth/create` (and GET in monolith)
- `GET /api/lnurl-auth/params`
- `GET /api/lnurl-auth/callback/<session_id>`
- `GET /api/lnurl-auth/check/<session_id>`

---

## Current Limitations and Drift

1. **Dual implementation drift**
   - Monolith and blueprint runtimes differ in grant support, token format, and LNURL signature handling.

2. **Discovery metadata overstates grant support in some contexts**
   - Discovery advertises refresh grant, but blueprint token endpoint currently rejects refresh grant.

3. **No userinfo endpoint**
   - OIDC user profile retrieval endpoint is not available as `/oauth/userinfo`.

4. **No revocation endpoint**
   - OAuth revocation endpoint (`/oauth/revoke`) is not implemented as an HTTP route.

5. **No client credentials grant endpoint behavior**
   - `client_credentials` is not currently accepted at `/oauth/token`.

6. **LNURL callback parity is incomplete across runtimes**
   - Monolith performs signature verification; blueprint includes TODO-level trust behavior.

---

## Compliance Notes

- The project implements useful portions of OAuth 2.0 / OIDC / LNURL-auth flows, but should currently be described as **partially compliant and evolving**.
- Claims of “complete specification”, “full RFC compliance”, or “all grants implemented” are not supported by current route and test reality.
- For integrators, treat this as an implementation reference for currently exposed endpoints, with explicit awareness of runtime-path differences.
