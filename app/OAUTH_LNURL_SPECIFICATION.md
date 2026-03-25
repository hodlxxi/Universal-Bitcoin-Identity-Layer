# OAuth2/OIDC + LNURL-Auth Specification (Current Runtime Scope)

This document defines implemented behavior and known limits for OAuth/OIDC and LNURL-auth in the current HODLXXI runtime.

## Scope and truth model

- This is a **runtime-focused specification**, not a blanket claim of full formal compliance.
- Where behavior is implementation-specific, this document states that explicitly.

## OAuth2/OIDC: implemented endpoints

- `POST /oauth/register`
- `GET /oauth/authorize`
- `POST /oauth/token`
- `POST /oauth/introspect`
- `GET /oauth/jwks.json`
- `GET /.well-known/openid-configuration`

## OAuth flow currently emphasized

The runtime is centered on authorization code flow behavior, including PKCE-related handling in token exchange paths. Additional grant types should be considered unsupported unless directly validated in running code/config.

## OAuth compliance positioning

Safe language for contributors:

- “implements core OAuth2/OIDC provider endpoints used by the current app”
- “includes PKCE-aware authorization-code handling”

Avoid broad claims such as “complete OAuth/OIDC specification compliance” without formal conformance evidence.

## LNURL-auth endpoints

- `POST /api/lnurl-auth/create`
- `GET /api/lnurl-auth/callback/<session_id>`
- `GET /api/lnurl-auth/check/<session_id>`
- `GET /api/lnurl-auth/params`

## LNURL-auth implementation caveat

Current callback verification behavior should be treated as implementation-defined and subject to hardening. Do not describe LNURL-auth security semantics as final/comprehensive unless backed by explicit cryptographic verification and threat-model validation.

## Error behavior

- OAuth errors generally follow OAuth-style fields (`error`, `error_description`).
- LNURL endpoints return LNURL-oriented status/error payloads.
- No single unified error contract spans all identity subsystems today.

## Relationship to other docs

- Endpoint inventory and status labels: `docs/API_REFERENCE.md`
- Example payloads: `app/API_RESPONSE_EXAMPLES.md`
- Runtime/system context: `ARCHITECTURE.md` and `docs/SYSTEM_ARCHITECTURE.md`
