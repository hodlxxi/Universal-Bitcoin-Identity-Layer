# STATE_OF_PRODUCT_AND_RUNTIME

_Last updated: April 14, 2026_

This document is the **runtime-truth snapshot** for HODLXXI in the current branch state. It intentionally separates what is live now from what is staging-confirmed and what is still transitional.

## What HODLXXI is

HODLXXI is a Bitcoin-native identity/runtime service that combines:

- browser login and account surfaces,
- OAuth/OIDC identity-provider surfaces,
- Proof-of-Funds (PoF) pages and APIs,
- and an agent runtime that supports paid job execution with signed receipts.

The current codebase supports both a factory-based Flask app (`app/factory.py`) and a legacy monolith runtime (`app/app.py`), with active route migration to blueprints.

## What works end-to-end today

### Live now

1. **Agent paid job flow**
   - `POST /agent/request` creates a job and returns invoice details.
   - `GET /agent/jobs/<job_id>` checks payment status and, once paid, returns result + receipt.
   - `GET /agent/verify/<job_id>` verifies receipt signature.
   - `GET /agent/attestations` exposes receipt history.

2. **Signed discovery + capability handshake**
   - `/.well-known/agent.json`
   - `/agent/capabilities`
   - `/agent/capabilities/schema`
   - `/agent/skills`

3. **Covenant visualization as paid capability**
   - `job_type: covenant_visualize` is present in the agent runtime and emits structured output including confidence/trust/pattern fields where available.

4. **PoF stats endpoint and PoF pages**
   - `/api/pof/stats` returns live aggregate counts.
   - `/pof`, `/pof/leaderboard`, and PoF certificate/verify routes are wired.

### Staging-confirmed (documented as done on staging; do not assume full parity everywhere)

- Browser route ownership has moved toward blueprints.
- Auth extraction has been completed on staging.
- Browser shell extraction has been completed on staging.

### Transitional / pending

- Some browser and panel routes still call into `app.app` for compatibility.
- Runtime guards and bootstrap side effects still exist in `app.app` and can influence behavior depending on deployment entrypoint.

## Public machine-readable surfaces

### Live now

- `GET /.well-known/agent.json`
- `GET /agent/capabilities`
- `GET /agent/capabilities/schema`
- `POST /agent/request`
- `GET /agent/jobs/<job_id>`
- `GET /agent/verify/<job_id>`
- `GET /agent/attestations`
- `GET /agent/reputation`
- `GET /agent/skills`

These are implemented in `app/blueprints/agent.py` and exposed via blueprint registration.

## Human-facing surfaces

### Live now

- `/` (agent-first home)
- `/login`
- `/logout`
- `/home`
- `/playground`
- `/app` (legacy chat path)
- `/pof`, `/pof/leaderboard`, `/pof/verify`, `/pof/certificate/<id>`

### Transitional notes

- `/account`, `/explorer`, `/onboard`, `/oneword`, `/upgrade` currently resolve through blueprint wrappers that delegate into legacy `app.app` handlers.

## Paid execution and signed receipt flow

### Live now

1. Client submits `POST /agent/request` with `job_type` + payload/input.
2. Service returns `invoice`, `payment_hash`, and `invoice_pending` status.
3. On settlement, `GET /agent/jobs/<job_id>` finalizes execution and stores signed receipt data.
4. Receipt chain is visible in `/agent/attestations`.
5. Receipt signature can be checked via `/agent/verify/<job_id>`.

### Transitional/pending caveat

- Dev-only mark-paid route exists for non-production simulation (`/agent/jobs/<job_id>/dev/mark_paid`).

## Covenant decode / covenant visualize current state

### Live now

- `covenant_decode` and `covenant_visualize` are listed job types.
- `covenant_visualize` validates input and returns a structured result object designed to separate observed data from heuristic interpretation.

### Conservative boundary

- Interpretation remains heuristic by design; this is not a claim of complete Miniscript/formal script intent verification.

## Reputation / attestation current state

### Live now

- `/agent/reputation` reports totals, completed/evidenced counts, and trust-style aggregates where result fields exist.
- `/agent/attestations` returns append-only-style receipt records.
- `/agent/chain/health` exists and reports continuity checks.

### Conservative boundary

- Reputation/trust values are derived from recorded runtime outputs, not external on-chain proof of economic backing.

## What is still transitional / legacy

1. **Monolith coexistence**
   - `app.app` still defines many routes, guards, aliases, and bootstrap/runtime side effects.

2. **Blueprint wrappers that still delegate to `app.app`**
   - UI blueprint routes for account/explorer/onboard/oneword/upgrade import legacy handlers from `app.app`.

3. **Browser route compatibility globals**
   - Browser route handler registration remains partly dependent on shared runtime globals.

## Current runtime/deployment truth

### Live now

- Factory runtime exists (`create_app` in `app/factory.py`) and registers core blueprints.
- Agent APIs are blueprint-owned and registered in both modern and legacy app paths.
- PoF blueprints are registered in factory runtime.

### Transitional truth

- `app.app` is still present and active as a runtime/bootstrap source for some deployments and compatibility paths.
- Do **not** treat factory-only behavior as universal without deployment-specific verification.

## Immediate next architectural steps

1. Remove remaining UI blueprint delegation into `app.app` (account/explorer/onboard/oneword/upgrade).
2. Isolate and migrate legacy `before_request` login/redirect gates from monolith into explicit blueprint middleware.
3. Consolidate browser handler registration so `/app` does not depend on hidden global registration state.
4. Keep one canonical endpoint contract per surface and document runtime-level auth policy per endpoint.
5. After extraction, make `app.app` a minimal bootstrap shim and then retire it.
