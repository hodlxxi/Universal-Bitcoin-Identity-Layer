# Sign in with HODLXXI Integration Guide

## Purpose

HODLXXI can be used as a Bitcoin/public-key-oriented OAuth2/OIDC identity provider for controlled third-party integrations. This guide gives relying-party developers a conservative, implementation-focused path for adding a **Sign in with HODLXXI** button and validating the resulting tokens.

Use this guide for practical login integration. Do not treat it as a certification statement, a legal identity product brief, a custody claim, or a proof-of-funds/paid-receipt verification protocol.

## Current status

This guide documents current implemented behavior and public metadata surfaces. It does not promise future features, full OpenID Connect certification, mature consent/admin UX, legal identity verification, KYC, custody, paid receipt verification through login alone, locked-capital proof through OAuth login, or universal wallet compatibility.

Related current-runtime references:

- [`docs/ops/OAUTH_OIDC_CONTRACTS.md`](ops/OAUTH_OIDC_CONTRACTS.md)
- [`docs/API_REFERENCE.md`](API_REFERENCE.md)
- [`docs/READINESS_EVALUATION.md`](READINESS_EVALUATION.md)
- [`docs/AGENT_SURFACES.md`](AGENT_SURFACES.md)

## Discovery

Inspect the public metadata before configuring a relying party:

```bash
curl -sS https://hodlxxi.com/.well-known/openid-configuration | jq .
curl -sS https://hodlxxi.com/.well-known/oauth-authorization-server | jq .
curl -sS https://hodlxxi.com/.well-known/oauth-protected-resource | jq .
curl -sS https://hodlxxi.com/oauth/jwks.json | jq .
```

Expected fields include:

- `issuer`: `https://hodlxxi.com`
- `authorization_endpoint`: `https://hodlxxi.com/oauth/authorize`
- `token_endpoint`: `https://hodlxxi.com/oauth/token`
- `jwks_uri`: `https://hodlxxi.com/oauth/jwks.json`
- `response_types_supported`: includes `code`
- `grant_types_supported`: includes `authorization_code`
- `scopes_supported`: includes the currently advertised scopes listed below
- `code_challenge_methods_supported`: includes `S256`

The protected-resource metadata is expected to describe:

- `resource`: `https://hodlxxi.com`
- `bearer_methods_supported`: includes `header`

## Minimal relying-party configuration

A minimal relying-party configuration should use the discovered metadata and placeholders for client-specific values:

```json
{
  "issuer": "https://hodlxxi.com",
  "authorization_endpoint": "https://hodlxxi.com/oauth/authorize",
  "token_endpoint": "https://hodlxxi.com/oauth/token",
  "jwks_uri": "https://hodlxxi.com/oauth/jwks.json",
  "response_type": "code",
  "pkce": "S256",
  "client_id": "<CLIENT_ID>",
  "client_secret": "<CLIENT_SECRET_IF_CONFIDENTIAL_CLIENT>",
  "redirect_uri": "<REDIRECT_URI>",
  "scope": "read"
}
```

Do not hard-code example secrets. Register and store your real `client_id`, any current-behavior-dependent confidential-client secret, and allowed `redirect_uri` values using your normal secret-management process.

## Authorization request

Build an authorization URL in this shape:

```text
https://hodlxxi.com/oauth/authorize?response_type=code&client_id=<CLIENT_ID>&redirect_uri=<REDIRECT_URI>&scope=read&state=<STATE>&code_challenge=<CODE_CHALLENGE>&code_challenge_method=S256
```

Relying parties should:

- Generate and validate a high-entropy `state` value for CSRF protection.
- Use PKCE with `code_challenge_method=S256`.
- Register and validate exact redirect URI values.
- Treat the authorization response as a short-lived code returned to the `redirect_uri`, not as proof of identity by itself.

## Token exchange

Exchange the authorization code at `/oauth/token` with `authorization_code` and the original PKCE verifier:

```bash
curl -sS -X POST "https://hodlxxi.com/oauth/token" \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=authorization_code' \
  --data-urlencode 'client_id=<CLIENT_ID>' \
  --data-urlencode 'code=<AUTHORIZATION_CODE>' \
  --data-urlencode 'redirect_uri=<REDIRECT_URI>' \
  --data-urlencode 'code_verifier=<CODE_VERIFIER>' \
  | jq .
```

If your current deployment and registered client type require confidential-client authentication, send `<CLIENT_SECRET_IF_CONFIDENTIAL_CLIENT>` only through the token endpoint mechanism documented for that client. Do not place secrets in browser URLs, static front-end bundles, logs, or documentation examples.

## JWKS and token validation

Fetch signing keys from `/oauth/jwks.json` and validate tokens using standard JWT/OAuth relying-party checks:

- Validate the RS256 signature against the published JWKS.
- Validate `iss` against `https://hodlxxi.com`.
- Validate `exp` and reject expired tokens.
- Validate audience or `client_id` if present in the current token contract for the token you receive.
- Cache JWKS carefully, honor reasonable cache lifetimes, and refetch after key-rotation validation failures.
- Do not over-specify or depend on claims that are not part of a published contract.

## Subject and claims model

HODLXXI identity is public-key oriented. Where token claims provide a subject, relying parties should treat `sub` as a pseudonymous stable identifier for application login and account linking.

Do not treat `sub`, profile-like claims, or successful OAuth login as any of the following:

- a legal name or residential identity;
- KYC identity;
- custody of funds;
- proof of locked capital;
- paid job receipt validity;
- application-specific authorization or risk approval.

Unless a future claim contract is published, relying parties should inspect token claims and treat only `iss`, `sub`, `exp`, and other standard validated fields as stable for conservative login purposes.

## Scopes

Currently advertised scopes include:

- `read`
- `write`
- `covenant_read`
- `covenant_create`
- `read_limited`

Request the minimum scope needed by your application. Scope semantics are current-runtime permissions and are not a broad legal authorization model.

## Public metadata smoke

Use this smoke check to review public metadata without sending secrets:

```bash
BASE=https://hodlxxi.com
curl -sS "$BASE/.well-known/openid-configuration" | jq '{issuer, authorization_endpoint, token_endpoint, jwks_uri, response_types_supported, grant_types_supported, scopes_supported, code_challenge_methods_supported}'
curl -sS "$BASE/.well-known/oauth-authorization-server" | jq '{issuer, authorization_endpoint, token_endpoint, jwks_uri, grant_types_supported, scopes_supported, code_challenge_methods_supported}'
curl -sS "$BASE/.well-known/oauth-protected-resource" | jq '{resource, authorization_servers, jwks_uri, bearer_methods_supported, scopes_supported}'
curl -sS "$BASE/oauth/jwks.json" | jq '{key_count:(.keys | length), keys:[.keys[]? | {kty, use, kid, alg}]}'
```

## Non-claims

Sign in with HODLXXI has explicit boundaries:

- Sign in with HODLXXI does not prove legal identity.
- It does not prove KYC.
- It does not prove custody of funds.
- It does not prove locked capital.
- It does not prove paid job receipt validity; use the paid receipt verifier for receipt evidence.
- It does not replace application-specific authorization and risk checks.
- It is not a guarantee of full OIDC certification.

## Related docs

- [`docs/ops/OAUTH_OIDC_CONTRACTS.md`](ops/OAUTH_OIDC_CONTRACTS.md)
- [`docs/API_REFERENCE.md`](API_REFERENCE.md)
- [`docs/READINESS_EVALUATION.md`](READINESS_EVALUATION.md)
- [`scripts/smoke_public_agent_contract.sh`](../scripts/smoke_public_agent_contract.sh)
- [`scripts/verify_paid_receipt_evidence.sh`](../scripts/verify_paid_receipt_evidence.sh)
