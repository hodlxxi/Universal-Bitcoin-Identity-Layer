# OAuth/OIDC Contract Tests (Current Behavior)

This document describes the **currently supported** OAuth2/OIDC behavior that is contract-tested in unit tests. It is intentionally conservative: it documents what exists today without promising unimplemented flows.

## Supported flows (current)

- OAuth 2.0 Authorization Code flow on `/oauth/authorize` + `/oauth/token`.
- PKCE is required at authorization time and current policy requires `code_challenge_method=S256`.
- OIDC discovery document at `/.well-known/openid-configuration`.
- JWKS public key set at `/oauth/jwks.json`.

## What is contract-tested

- Discovery endpoint returns HTTP 200 and includes required OIDC metadata fields (`issuer`, authorization endpoint, token endpoint, JWKS URI, response/subject type lists).
- Discovery advertises `RS256` ID token signing when implemented.
- JWKS endpoint returns HTTP 200 with a `keys` array.
- Each JWK entry exposes expected public fields (`kid`, `kty`, and `use`/`alg` where present).
- JWKS does **not** expose private key material (`d`, `p`, `q`, etc.).
- Authorization errors are stable and non-500 for:
  - missing `client_id` / malformed requests,
  - invalid `redirect_uri`,
  - unsupported `response_type`.
- PKCE behavior is stable and non-500 for:
  - S256 challenge accepted,
  - plain or missing challenge rejected under S256-only policy,
  - bad verifier rejected at token exchange.

## Beta / experimental / out of scope

These are not guaranteed by this contract set yet:

- Additional grant types beyond authorization code.
- Dynamic client management UX beyond base registration API semantics.
- Rich OIDC claim profiles or advanced federation metadata.
- Any non-S256 PKCE modes (current policy rejects them).

## Runtime constraints

- Runtime remains factory-first with `wsgi:app`.
- Tests are additive and focused on contract hardening.
- No secrets handling is changed by this work.
