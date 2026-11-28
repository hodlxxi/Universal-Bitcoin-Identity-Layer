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

## Ordinary token response and rollout

For an ordinary authorization code request with `openid`, an optional nonce
is a single non-empty string of at most 256 UTF-8 bytes after query decoding.
C0 and C1 controls and DEL are rejected. Accepted values keep their exact case,
whitespace and punctuation. The server takes the claim from the stored code and
includes it in the ID token only. Requests without a nonce continue to work.
The token endpoint sets `Cache-Control: no-store` and `Pragma: no-cache` on
success and error responses. Ordinary `expires_in` reports the remaining
lifetime of the signed access token in seconds.

Before any separately authorized rollout, apply
`migrations/2026-11-28_oauth_code_nonce.sql` once in a database transaction,
then start the new runtime. It adds one nullable column without a backfill.
Existing codes remain valid under their original expiry and binding checks.
To roll back, return to the previous runtime and retain the column and its
data. The configured Social lifecycle keeps its existing protocol.

### Disposable PostgreSQL rehearsal

From a checkout with test dependencies installed, run as an unprivileged
user with PostgreSQL 16 binaries on PATH. Use a fresh scratch directory and
database for each run. The fixture verifies the server identity and empty schema
before writing, then compares the old row, keys and indexes and exchanges the
old code through the factory-owned token endpoint.

```sh
pg_root=$(mktemp -d /tmp/hodlxxi-b02a-pg.XXXXXXXX)
mkdir -m 700 "$pg_root/socket"
initdb -D "$pg_root/data" --encoding=UTF8 --auth-local=trust --auth-host=reject --username=b02a_test
pg_ctl -D "$pg_root/data" -l "$pg_root/server.log" \
  -o "-c listen_addresses= -k $pg_root/socket -p 55491" -w start
createdb -h "$pg_root/socket" -p 55491 -U b02a_test hodlxxi_b02a_test
HODLXXI_B02A_PG_ROOT="$pg_root" FLASK_SKIP_DOTENV=1 PYTHON_DOTENV_DISABLED=1 \
  REDIS_URL="unix://$pg_root/no-redis.sock" \
  python -m pytest -q -ra tests/integration/test_oauth_code_nonce_migration.py
pg_ctl -D "$pg_root/data" -m fast -w stop
```
