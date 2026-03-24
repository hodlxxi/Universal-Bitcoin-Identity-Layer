# HODLXXI System Architecture

**Status:** Current-state architecture (repo/runtime truth as of 2026-03-24)
**Scope:** Detailed architecture and drift map for contributors/reviewers

## Executive Summary

HODLXXI is currently a **hybrid architecture**:

- **Production runtime entrypoint is monolith-first**: `wsgi.py` imports `app.app:app` directly.
- A **factory runtime exists** (`app/factory.py`) and is actively used by tests, but it is **not the current WSGI entrypoint**.
- Agent, OAuth, PoF, LNURL, and admin surfaces exist both as modern blueprints and/or legacy monolith routes, creating overlap.

This document is the canonical detailed architecture reference. `ARCHITECTURE.md` is now a short top-level overview and pointer.

---

## Status Legend

- **Confirmed**: Implemented in current repo and exercised by tests and/or active route wiring.
- **Partial**: Implemented but incomplete, compatibility-heavy, or environment-dependent.
- **Planned**: Mentioned goals/surfaces not present in current route/runtime wiring.

---

## Current Runtime Truth

## Runtime entrypoint and app construction

- `wsgi.py` imports `app` from `app/app.py` and exposes it as `application`; Gunicorn/uWSGI run this monolith object directly. **(Confirmed)**
- `app/factory.py` exposes `create_app()` and registers modular blueprints, but this is currently the test/default factory path, not the production WSGI path in this repo snapshot. **(Confirmed, secondary runtime)**

## Monolith vs factory drift

- `app/app.py` remains large (`~12.5k` lines), with direct `@app.route` endpoints and its own blueprint registrations. **(Confirmed)**
- `create_app()` also registers many of the same logical surfaces (auth, OAuth, LNURL, PoF, admin, agent), and includes explicit legacy overrides for `/login` and `/playground` to old monolith handlers. **(Confirmed)**
- Result: architecture is not yet a completed migration; it is a **hybrid monolith + incremental factory extraction**. **(Confirmed)**

## Production vs staging/test truth

- **Production/runtime truth (repo entrypoint):** monolith-first via `wsgi:app`.
- **Staging/test-validated behavior:** factory app (`create_app`) is validated through integration/unit tests.
- **Planned direction:** further decomposition toward fully factory-driven modular runtime, but not complete in current code.

---

## High-Level Architecture

1. **Edge/Web tier:** Flask HTTP + Socket.IO surfaces (WebRTC signaling included in monolith UI flow).
2. **Identity/Auth tier:** Bitcoin signature login, guest login, OAuth2/OIDC issuance and discovery.
3. **Agent UBID tier:** paid jobs, signed receipts, attestations, reputation, and chain-health verification.
4. **Bitcoin integration tier:** Bitcoin RPC usage for descriptor/covenant and verification surfaces.
5. **Persistence tier:** SQLAlchemy models for users/OAuth/LNURL/PoF/agent/payment artifacts; optional Redis support in surrounding infrastructure.

---

## Core Components

## 1) Web runtime

- Monolith Flask app: `app/app.py`.
- Factory Flask app creator: `app/factory.py`.
- WSGI entrypoint: `wsgi.py` -> `app.app:app`.
- Operational endpoints exist in both monolith and admin blueprint paths (`/health`, `/metrics`, `/metrics/prometheus`).

## 2) Authentication and identity

- Bitcoin-signature verification (`/verify_signature`) with session challenge checks and RPC-backed verification path.
- Guest/PIN login (`/guest_login`) supported.
- Session identity fields (`logged_in_pubkey`, access levels) drive downstream access behavior.

## 3) OAuth2/OIDC

- OAuth blueprint (`/oauth/register`, `/oauth/authorize`, `/oauth/token`, `/oauth/introspect`).
- OIDC discovery + JWKS (`/.well-known/openid-configuration`, `/oauth/jwks.json`).
- Additional monolith diagnostics/docs surface (`/oauthx/status`, `/oauthx/docs`).
- Compatibility adapters remain in monolith for legacy object/storage expectations (not fully cleaned up).

## 4) LNURL and Lightning payment surfaces

- LNURL auth blueprint under `/api/lnurl-auth/*` (create/callback/check/params).
- LNURL callback currently marks verification based on challenge matching and records supplied key; the signature-verification step is noted in code as a future hardening point. **(Partial)**
- Lightning invoice module supports `lnd_rest`, `lnd_cli`, and `stub` backend controlled by `LN_BACKEND`; production guard rejects stub/testing mode when production flags are set. **(Partial)**

## 5) Proof-of-Funds and Bitcoin/covenant surfaces

- PoF web/API blueprints under `/pof/*` and `/api/pof/*` with DB-backed stats route (`/api/pof/stats`).
- Monolith includes descriptor/covenant explorer routes such as `/verify_pubkey_and_list` and decode/import flows.
- Agent job type `covenant_decode` exists, but currently returns a lightweight decoded placeholder (`script(<hex>)`) + CLTV heuristic, not a full script interpreter. **(Partial)**

## 6) Agent UBID runtime surfaces

- Discovery/capabilities: `/.well-known/agent.json`, `/agent/capabilities`, `/agent/capabilities/schema`, `/agent/skills`.
- Paid job flow: `/agent/request` -> invoice -> `/agent/jobs/<job_id>` settlement/status.
- Verification/reputation: `/agent/verify/<job_id>`, `/agent/attestations`, `/agent/reputation`, `/agent/chain/health`, `/agent/marketplace/listing`.
- Signed receipt chain: receipts are signed, hashed, and linked through `prev_event_hash`.

---

## Authentication and Authorization Model

- Browser/session model: Flask sessions with pubkey/access-level markers.
- API auth model: OAuth bearer token checks via decorators (e.g., `require_oauth_token`).
- Billing gate model: some protected API surfaces can return 402 (`payment_required`) and use invoice top-up endpoints.

---

## Agent Runtime and Verification Surfaces

## Confirmed

- Capability documents are signed and verifiable.
- Jobs persist request hash + payment hash and produce signed receipts after paid status.
- Attestation feed and per-job verification endpoints expose the proof artifacts.
- Reputation and chain-health endpoints summarize continuity and chain-link integrity.

## Partial

- Payment settlement depends on configured LN backend (or stub mode in non-production/testing).
- Trust-model metadata correctly distinguishes optional/not-verified time-locked-capital proof instead of claiming on-chain proof exposure.

---

## Bounded Sovereignty Stage 1 (Current Truth)

The following distinction is intentional to avoid overstating maturity.

## Confirmed in current repo

- Public agent trust/pay surfaces listed above (`/agent/request`, `/agent/attestations`, `/agent/reputation`, receipt verification, chain health).
- Economic gating and “pay before work” behavior at the agent job interface.
- Signed receipt/attestation chain for completed jobs.

## Not present as routes in current snapshot (therefore not claimed as active Stage 1 runtime)

- `/agent/policy`
- `/agent/bounded-status`
- `/agent/actions`
- dedicated protected executor route for bounded actions

## Consequence

- **Observe-only spending policy** and **signed manifest / signed action-log executor workflow** are not exposed as first-class runtime routes in current code.
- These should be treated as **planned Stage 1 bounded sovereignty surfaces**, not current production/runtime truth.

---

## Bitcoin, Lightning, and Covenant-Related Surfaces

- Bitcoin RPC is used for identity and descriptor/covenant-related operations (including `listdescriptors` path in explorer/API functionality).
- Covenant-related UX/API exists, but implementation depth varies by endpoint (some are strong runtime utilities, others are simplified helpers).
- Lightning is integrated enough for invoice-driven job/billing flows but remains backend-configuration dependent; production safety checks exist, full operational hardening is still ongoing.

---

## Deployment and Environment Model

## Confirmed in repo/runtime wiring

- WSGI entrypoint contract: `wsgi:app`.
- Gunicorn-compatible app export in `wsgi.py` (`application = app`).

## Common deployment shape (documented in repo, environment-dependent)

- Reverse proxy + Gunicorn + Flask app, with Postgres and optional Redis services.
- Test/development frequently runs factory-based app initialization and in-memory/testing fallbacks.

## Not claimed as active baseline

- Kubernetes horizontal scaling as an active, validated production default.
- Full observability stack (e.g., ELK/Sentry) as guaranteed active deployment truth.

---

## Known Drift, Gaps, and Limitations

1. **Runtime split-brain risk:** monolith entrypoint vs factory migration can cause behavior divergence.
2. **Route overlap:** some surfaces exist in both monolith and blueprint versions, plus legacy compatibility shims.
3. **LNURL security depth:** callback path currently does not enforce full cryptographic signature verification hardening.
4. **Covenant decode depth:** agent `covenant_decode` is intentionally lightweight.
5. **Bounded sovereignty Stage 1 routes:** policy/status/actions/executor surfaces are not yet present as concrete endpoints.

---

## Near-Term Architecture Priorities

1. **Choose one canonical runtime path** (prefer factory or monolith, but remove ambiguity).
2. **Unify duplicate routes and compatibility shims** to reduce drift.
3. **Implement/ship bounded sovereignty Stage 1 HTTP surfaces** (`/agent/policy`, `/agent/bounded-status`, `/agent/actions`, executor route) with explicit observe-only guarantees.
4. **Harden LNURL verification logic** to full signature validation guarantees.
5. **Formalize covenant tooling boundaries** (what is full decode vs heuristic convenience).
