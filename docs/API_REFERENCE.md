# API Reference (Current Runtime Truth)

This reference lists major API surfaces that are currently implemented in this repository. It prioritizes practical endpoint reality over aspirational completeness claims.

## Status labels used in this file

- **Implemented:** endpoint exists in runtime code.
- **Implemented (partial contract):** endpoint exists, but payload shape/semantics should be treated as evolving.
- **Environment-dependent:** behavior depends on external services/configuration.

## Health and operational endpoints

- `GET /health` (Implemented)
- `GET /health/live` (Implemented)
- `GET /health/ready` (Implemented)
- `GET /metrics` and `GET /metrics/prometheus` (Implemented)

## OAuth2/OIDC endpoints

Base path: `/oauth`

- `POST /oauth/register` — dynamic client registration (Implemented)
- `GET /oauth/authorize` — authorization code initiation (Implemented)
- `POST /oauth/token` — code exchange/token issuance (Implemented)
- `POST /oauth/introspect` — token introspection (Implemented)
- `GET /oauth/jwks.json` — JWKS (Implemented)
- `GET /.well-known/openid-configuration` — OIDC discovery (Implemented)

Notes:
- Current runtime behavior is authorization-code focused.
- Treat standards compliance as implemented with caveats until verified against full RFC/OIDC conformance matrix.

## LNURL-auth endpoints

Base path: `/api/lnurl-auth`

- `POST /api/lnurl-auth/create` (Implemented)
- `GET /api/lnurl-auth/callback/<session_id>` (Implemented)
- `GET /api/lnurl-auth/check/<session_id>` (Implemented)
- `GET /api/lnurl-auth/params` (Implemented)

Notes:
- Verification and callback semantics depend on current runtime implementation details.

## Proof-of-Funds (PoF) endpoints

- `GET /pof/` (Implemented)
- `GET /pof/leaderboard` (Implemented)
- `GET /pof/verify` (Implemented)
- `GET /pof/certificate/<cert_id>` (Implemented)
- `GET /api/pof/stats` (Implemented)

Notes:
- Some PoF payloads and aggregation behavior are implementation-defined and may evolve.

## Bitcoin utility/API endpoints

Base path: `/api/bitcoin`

- `GET /api/bitcoin/rpc/<cmd>` (Implemented; command allowlist behavior applies)
- `POST /api/bitcoin/verify` (Implemented)
- `POST /api/bitcoin/decode_raw_script` (Implemented)
- `GET /api/bitcoin/descriptors` (Implemented)
- `POST /api/bitcoin/challenge` (Implemented)

## Error model note

The runtime returns mixed error shapes across subsystems (some OAuth-standard forms, some `{ok:false,error:...}` forms, and subsystem-specific variants). Consumers should not assume a single global error envelope today.
