# API Reference

## Status Notes

- This document is grounded in **current registered routes in the Flask factory runtime** (`app.factory.create_app`) and integration tests that exercise those routes.
- Labels used in this file:
  - **Confirmed**: route exists in the factory runtime today.
  - **Protected**: route enforces auth and/or billing requirements.
  - **Staging-validated**: route behavior is covered by current tests.
  - **Partial**: route exists but implementation is intentionally limited or placeholder.
  - **Monolith-only**: route exists in `app/app.py` but is **not** part of the factory-registered route map used by current tests.
- Bounded sovereignty Stage 1 routes requested in this audit (`/agent/policy`, `/agent/bounded-status`, `/agent/actions`, `/agent/bounded/execute`) are **not present** in current Python route definitions.

## Public Discovery and Status Endpoints

| Method | Path | Status | Auth | Notes |
|---|---|---|---|---|
| GET | `/.well-known/agent.json` | Confirmed + Staging-validated | Public | Agent discovery doc (identity, capabilities, trust model, discovery links). |
| GET | `/agent/capabilities` | Confirmed + Staging-validated | Public | Signed capability payload including endpoints, job types, pricing. |
| GET | `/agent/capabilities/schema` | Confirmed + Staging-validated | Public | JSON Schema for capability payload. |
| GET | `/agent/skills` | Confirmed + Staging-validated | Public | Enumerates skills from `skills/public/*/SKILL.md`. |
| GET | `/agent/marketplace/listing` | Confirmed | Public | Marketplace-friendly composite listing (discovery + reputation + chain health). |
| GET | `/agent/reputation` | Confirmed | Public | Aggregate totals by job type/completion. |
| GET | `/agent/attestations` | Confirmed + Staging-validated | Public | Signed receipt events with pagination (`limit`, `offset`). |
| GET | `/agent/chain/health` | Confirmed | Public | Receipt chain integrity summary (`chain_ok`, latest hash, count). |
| GET | `/health` | Confirmed + Staging-validated | Public | App health. Returns `503` when unhealthy outside testing mode. |
| GET | `/health/live` | Confirmed | Public | Liveness probe (`alive`). |
| GET | `/health/ready` | Confirmed | Public | Readiness probe (`ready`/`not_ready`). |
| GET | `/metrics` | Confirmed + Staging-validated | Public | JSON metrics payload. |
| GET | `/metrics/prometheus` | Confirmed | Public | Prometheus text format metrics. |

## Agent Runtime Endpoints

| Method | Path | Status | Auth | Request / Response Notes |
|---|---|---|---|---|
| POST | `/agent/request` | Confirmed + Staging-validated | Public | Body: `job_type`, `payload`. Returns `job_id`, Lightning invoice, `payment_hash`, status `invoice_pending`. Deduplicates identical recent requests. |
| GET | `/agent/jobs/<job_id>` | Confirmed + Staging-validated | Public | Returns job status and receipt (once invoice marked paid / detected paid). |
| GET | `/agent/verify/<job_id>` | Confirmed + Staging-validated | Public | Verifies stored receipt signature and returns `valid` + receipt hash. |
| POST | `/agent/jobs/<job_id>/dev/mark_paid` | Confirmed | Protected (dev token) | Dev-only helper to simulate payment and mint receipt. Disabled in production-like mode; requires `Authorization: Bearer <DEV_AGENT_ADMIN_TOKEN>`. |

### Supported `job_type` values (current)

- `ping` (Confirmed)
- `verify_signature` (Confirmed + Staging-validated)
- `covenant_decode` (Confirmed + Staging-validated, **Partial** decode semantics)

## Agent Job Payment and Receipt Endpoints

| Method | Path | Status | Auth | Notes |
|---|---|---|---|---|
| POST | `/api/billing/agent/create-invoice` | Confirmed | Protected | Requires OAuth Bearer token with `read_limited`; creates PAYG top-up invoice for OAuth client. |
| POST | `/api/billing/agent/check-invoice` | Confirmed | Protected | Requires OAuth Bearer token with `read_limited`; checks invoice/crediting status. |

Both endpoints return JSON and are tied to `request.oauth_client_id` resolved from the bearer token.

## Bounded Sovereignty Stage 1 Endpoints

The following routes are **not currently implemented** in the repo route surfaces audited for this refresh:

- `GET /agent/policy` — **Planned / missing**
- `GET /agent/bounded-status` — **Planned / missing**
- `GET /agent/actions` — **Planned / missing**
- `POST /agent/bounded/execute` — **Planned / missing**

No active route-level evidence currently supports documenting bounded sovereignty execution APIs as live.

## Authentication and Identity Endpoints

| Method | Path | Status | Auth | Notes |
|---|---|---|---|---|
| GET | `/login` | Confirmed + Staging-validated | Public | Login UI endpoint. |
| POST | `/verify_signature` | Confirmed | Public | Verifies Bitcoin signature against session challenge; sets session on success. |
| POST | `/guest_login` | Confirmed | Public | Guest/PIN login, sets guest session state. |
| GET | `/logout` | Confirmed + Staging-validated | Session | Clears session and redirects to login. |

## OAuth / OIDC Endpoints

| Method | Path | Status | Auth | Notes |
|---|---|---|---|---|
| GET | `/.well-known/openid-configuration` | Confirmed + Staging-validated | Public | OIDC discovery metadata. |
| GET | `/oauth/jwks.json` | Confirmed + Staging-validated | Public | RS256 JWKS document. |
| POST | `/oauth/register` | Confirmed + Staging-validated | Public | Dynamic client registration (requires `client_name`, `redirect_uris`). |
| GET | `/oauth/authorize` | Confirmed + Staging-validated | Session required to complete | If no session user, redirects to `/login`; supports code flow with optional PKCE. |
| POST | `/oauth/token` | Confirmed + Staging-validated | Client credentials | Authorization code exchange; validates redirect URI and PKCE when present. |
| POST | `/oauth/introspect` | Confirmed | Client credentials | Returns OAuth introspection response shape (`active` true/false). |

### OAuthx status/docs compatibility surfaces

- `GET /oauthx/status` — **Monolith-only** (present in `app/app.py`, not in factory route map).
- `GET /oauthx/docs` — **Monolith-only** (present in `app/app.py`, not in factory route map).

These should not be treated as factory-runtime guaranteed surfaces without deployment-specific confirmation.

## Lightning / LNURL Endpoints

| Method | Path | Status | Auth | Notes |
|---|---|---|---|---|
| POST | `/api/lnurl-auth/create` | Confirmed + Staging-validated | Public | Creates session/challenge and returns `session_id`, `k1`, callback URL. |
| GET | `/api/lnurl-auth/params` | Confirmed | Public | Returns LNURL login params for a `session_id`. |
| GET | `/api/lnurl-auth/callback/<session_id>` | Confirmed | Public | Callback endpoint for wallet auth response. |
| GET | `/api/lnurl-auth/check/<session_id>` | Confirmed + Staging-validated | Public | Poll session verification state. |

**Current limitation:** callback flow marks verification state but contains placeholder signature-validation behavior (not full cryptographic verification), so treat as **Partial**.

## Proof-of-Funds Endpoints

| Method | Path | Status | Auth | Notes |
|---|---|---|---|---|
| POST | `/api/challenge` | Confirmed + Staging-validated | Public | PoF challenge creation compatibility endpoint. Requires `pubkey`. |
| POST | `/api/verify` | Confirmed | Public | PSBT-based proof verification endpoint. |
| GET | `/api/pof/stats` | Confirmed | Public | Aggregated PoF stats from DB (`verified_users`, `total_btc`, `addresses_verified`). |
| GET | `/pof/` | Confirmed | Public | PoF landing page. |
| GET | `/pof/verify` | Confirmed | Public | PoF verification UI. |
| GET | `/pof/leaderboard` | Confirmed | Public | PoF leaderboard UI from verified records. |
| GET | `/pof/certificate/<cert_id>` | Confirmed | Public | Shareable verified certificate page. |

## Covenant / Descriptor / Script Endpoints

| Method | Path | Status | Auth | Notes |
|---|---|---|---|---|
| POST | `/api/decode_raw_script` | Confirmed | Public | Decodes provided script via Bitcoin Core `decodescript`. |
| GET | `/api/descriptors` | Confirmed | Protected | Requires OAuth token + PAYG enforcement; returns wallet descriptors. |
| GET | `/api/rpc/<cmd>` | Confirmed | Protected | Requires OAuth token + PAYG enforcement; command allowlist enforced. |

### Monolith-only covenant/descriptor surfaces

The following legacy routes exist in `app/app.py` but are not factory-runtime guaranteed:

- `GET /verify_pubkey_and_list`
- `POST /decode_raw_script` (non-`/api` form)
- `POST /import_descriptor`
- `GET /export_descriptors`
- `GET /export_wallet`
- `GET /rpc/<cmd>` (non-`/api` form)

Document or rely on these only when deployment is explicitly monolith-driven.

## Capabilities / Skills / Attestations / Reputation / Chain Health

These surfaces are active and public in current factory runtime:

- Capabilities: `/agent/capabilities`, `/agent/capabilities/schema`
- Skills catalog: `/agent/skills`
- Attestations: `/agent/attestations`
- Reputation: `/agent/reputation`
- Chain health: `/agent/chain/health`

All are confirmed by code; key portions are staging-validated via `tests/integration/test_agent_ubid.py`.

## Public Status / Docs Endpoints

| Method | Path | Status | Auth | Notes |
|---|---|---|---|---|
| GET | `/` | Confirmed + Staging-validated | Public | Agent-first homepage listing core public surfaces. |
| GET | `/screensaver` | Confirmed | Public | Public UI route. |
| GET | `/playground` | Confirmed | Public | Lightweight API playground page. |

Monolith-only docs endpoints (not factory-guaranteed): `/oauthx/docs`, `/docs.json` aliasing, and rich `/docs` handlers in `app/app.py`.

## Protected / Operator-Oriented Endpoints

| Method | Path | Status | Auth | Notes |
|---|---|---|---|---|
| GET | `/api/demo/protected` | Confirmed + Staging-validated | OAuth + PAYG | Requires `read_limited` scope and sufficient free quota / sats balance. |
| POST | `/api/billing/agent/create-invoice` | Confirmed | OAuth | Top-up invoice creation for OAuth client billing. |
| POST | `/api/billing/agent/check-invoice` | Confirmed | OAuth | Invoice status/credit polling. |
| GET | `/dev/dashboard` | Confirmed | Session (full access) | Developer dashboard HTML. |
| POST | `/dev/billing/create-invoice` | Confirmed | Session (limited access policy) | Session-based billing top-up flow. |
| POST | `/dev/billing/check-invoice` | Confirmed | Session (limited access policy) | Session-based billing status flow. |

## Known Gaps and Partial Surfaces

1. **Bounded sovereignty Stage 1 endpoints are missing** (not implemented as routes).
2. **LNURL callback verification is partial** (placeholder verification path in callback handler).
3. **Runtime split exists**:
   - Factory runtime (`app.factory`) is test-covered and has the routes documented as confirmed above.
   - Monolith runtime (`wsgi.py` importing `app.app`) exposes additional legacy routes not currently staging-validated through factory tests.
4. **Do not assume full autonomous spending/control surfaces** from current code; no active bounded-execute API is present.

---

Last refreshed: 2026-03-24 (UTC)
