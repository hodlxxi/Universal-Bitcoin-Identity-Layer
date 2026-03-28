# State of Implementation

## Purpose
This file is a developer-facing status snapshot of what this repository appears to implement today, based on checked-in code, tests, docs, and deployment artifacts.

It is intentionally conservative. It distinguishes between code that exists, code that appears to work in local/test environments, code that is wired into the default runtime entry point, and code that looks more aspirational than production-proven.

## Status Legend
- ✅ Working end-to-end
- 🔷 Validated on staging (verified runtime surface, but not yet proven as the default path for all deployments)
- 🟡 Implemented but incomplete / needs hardening
- 🧪 Experimental / stubbed / partially wired
- ❌ Planned / not implemented

## Current Summary
This repository is a mixed-state Flask codebase with two overlapping runtime shapes:

1. a large monolithic app in `app/app.py`, which is the default deployment entry point via `wsgi.py`, and
2. a newer application-factory/blueprint stack in `app/factory.py`, which is used heavily by tests and appears to be the intended direction of travel.

The strongest, most coherent subsystem today is the machine-readable agent/discovery surface plus the small paid-job flow around it. OAuth2/OIDC, Bitcoin signature auth, basic LNURL-auth, and some billing/PAYG logic are implemented and tested locally. Proof-of-Funds, covenant UX, and some broader identity claims exist, but much of that surface is partial, duplicated, or not validated as a true production-grade end-to-end flow.

There is substantial evidence of active refactoring, backward-compatibility shims, and duplicated route implementations. Reviewers should read the repository as a real prototype with some working subsystems, not as a uniformly production-hardened platform.

For bounded sovereignty Stage 1 specifically: this snapshot now includes staging-validated surfaces that were verified outside this branch review. Those are called out separately from code paths directly found in this checkout.

## Subsystem Status

### 1. Public agent/API surfaces

#### Agent discovery and public metadata
- ✅ `GET /.well-known/agent.json`
  - What works today:
    - Returns a structured identity/discovery document.
    - Includes discovery links, a conservative trust model, pricing, limits, and embedded skill metadata.
    - The trust model explicitly marks time-locked capital as optional/not verified rather than claiming it is live.
  - Important limitations:
    - The document is generated from local code/config and database-derived counters; it is not backed by external proofs of operator identity or on-chain capital.
    - It is honest by design, but still mostly a runtime declaration surface.

- ✅ `GET /agent/capabilities`
  - What works today:
    - Returns signed machine-readable capability data.
    - Covers three job types: `ping`, `verify_signature`, and `covenant_decode`.
    - Signature verification for the capabilities document is covered by integration tests.
  - Important limitations:
    - “Capability exists” does not mean every job type is equally mature. `covenant_decode` is especially shallow.

- ✅ `GET /agent/capabilities/schema`
  - What works today:
    - Publishes a JSON Schema for the capabilities payload.
  - Important limitations:
    - This validates shape, not business correctness.

- ✅ `GET /agent/skills`
  - What works today:
    - Discovers skills from top-level `skills/` directories and exposes normalized metadata.
    - Covered by integration tests.
  - Important limitations:
    - This is discovery/documentation plumbing, not job execution by itself.

- ✅ `GET /agent/marketplace/listing`, `GET /agent/reputation`, `GET /agent/attestations`, `GET /agent/chain/health`
  - What works today:
    - These endpoints expose aggregate usage, receipt history, and simple chain continuity checks based on `AgentJob` and `AgentEvent` rows.
  - Important limitations:
    - They reflect local database history only.
    - There is no external anchoring of the attestation chain.
    - “Reputation” here means observable usage counts, not a sophisticated reputation model.

#### Agent job routes
- 🟡 `POST /agent/request`
  - What works today:
    - Validates supported `job_type` values.
    - Creates a job record and Lightning invoice request.
    - Deduplicates some repeated requests.
  - Important limitations:
    - Actual execution does not happen here.
    - A job only finishes later when `/agent/jobs/<job_id>` is polled and payment is detected.
    - Daily rate limiting is simple process-local logic.

- 🟡 `GET /agent/jobs/<job_id>`
  - What works today:
    - Looks up a job.
    - If payment is considered settled, it mints a signed receipt and marks the job done.
  - Important limitations:
    - This route is doing state transition work on read.
    - There is no separate queue/worker/webhook settlement pipeline.
    - The returned payload focuses on receipt/status; it is not a rich job-result API.

- ✅ `GET /agent/verify/<job_id>`
  - What works today:
    - Verifies the receipt signature for an existing job receipt.
  - Important limitations:
    - This only works after a receipt already exists.

- 🧪 `POST /agent/jobs/<job_id>/dev/mark_paid`
  - What works today:
    - Simulates payment and receipt creation in non-production mode.
  - Important limitations:
    - Explicitly a dev-only helper, not part of a production payment flow.

#### Bounded sovereignty Stage 1 (staging-validated)
- 🔷 `GET /agent/policy`, `GET /agent/bounded-status`, `GET /agent/actions`
  - What works today:
    - These surfaces are verified as reachable and returning structured responses on staging after Stage 1 validation.
  - Important limitations:
    - On this branch checkout, matching route handlers were not found in the scanned runtime code paths.
    - Treat these as staging-validated runtime truth, not yet as branch-local implementation proof.

- 🟡 `POST /agent/bounded/execute`
  - What works today:
    - Remains protected (not an open unauthenticated spending endpoint).
    - Current behavior remains observe-only / policy-bounded and not live outbound autonomous spending.
  - Important limitations:
    - This is still a guarded Stage 1 control surface, not full autonomous execution.
    - Survivability and independent fail-safe behavior are still partial.

#### OAuth/OIDC/public identity API surfaces
- ✅ `GET /.well-known/openid-configuration`
- ✅ `GET /oauth/jwks.json`
  - What works today:
    - These endpoints are implemented in the newer OIDC module and covered by tests.
    - JWKS rotation/key management exists.
  - Important limitations:
    - These surfaces are credible locally/test-wise, but runtime ownership is muddied by the coexistence of monolith and factory code.

- 🟡 `POST /oauth/register`, `GET /oauth/authorize`, `POST /oauth/token`, `POST /oauth/introspect`
  - What works today:
    - Implemented and tested in the blueprint/factory stack.
    - Supports auth code flow and PKCE.
    - Issues RS256 JWTs.
  - Important limitations:
    - The default WSGI entry point serves the monolith, not the factory-based app used by many tests.
    - The repository contains overlapping OAuth implementations and compatibility wrappers, which lowers confidence that all documented behavior matches deployed behavior.

- 🟡 `GET /oauthx/status`, `GET /oauthx/docs`
  - What works today:
    - Both routes exist in the monolith and return status/docs payloads.
  - Important limitations:
    - `oauthx/status` is shallow and counts in-memory stores, not comprehensive production health.
    - `oauthx/docs` is a JSON docs payload, not a full conformance test or robust interactive console.

- ❌ `POST /oauth/revoke`, `GET /oauth/userinfo`
  - Current state:
    - Mentioned in specs/docs, but no route implementation was found in the repository.

#### Other public API surfaces
- ✅ `/health`, `/metrics`, `/metrics/prometheus`
  - What works today:
    - Health/metrics routes exist and are tested at least for basic response structure.
  - Important limitations:
    - Test-mode behavior forces healthy responses even without live Bitcoin RPC.
    - Readiness depends on environment and backing services.

- 🟡 `/api/rpc/<cmd>`, `/api/descriptors`, `/api/decode_raw_script`
  - What works today:
    - Safe Bitcoin RPC read methods and script decoding are implemented.
    - Some are covered by tests with mocked RPC.
  - Important limitations:
    - They depend on valid Bitcoin Core connectivity and auth.
    - Coverage is largely unit/integration with mocks, not against a live hardened node.

### 2. Payment / Lightning flow
- 🟡 Agent invoices and OAuth client PAYG top-ups are implemented as code paths.
  - What is actually implemented:
    - A shared Lightning helper supports three modes: `lnd_rest`, `lnd_cli`, and a default `stub` backend.
    - Agent jobs call `create_invoice()` when a request is created.
    - PAYG billing can create invoices and credit balances after `check_invoice_paid()` returns true.
  - Whether invoice creation, settlement detection, and execution are truly connected:
    - Partially.
    - Invoice creation is real as a code path.
    - Settlement detection is polling-based, not event-driven.
    - Agent execution happens only when job status is polled and payment is observed.
    - Billing balance crediting happens only when the check endpoint is called.
  - Caveats:
    - Default Lightning behavior is stubbed unless environment variables switch to LND backends.
    - Test flows explicitly use `TEST_INVOICE_PAID=true` to simulate settlement.
    - There is no evidence here of webhook-driven settlement, retry logic, reconciliation, or accounting-grade idempotency beyond basic guards.

### 3. Job lifecycle
- 🟡 Request → invoice
  - Real today:
    - `POST /agent/request` writes `AgentJob` rows and returns an invoice payload.

- 🟡 Invoice → settlement detection
  - Real today:
    - Settlement is checked by calling `check_invoice_paid()` later.
  - Limitations:
    - Polling-based only.
    - In dev/test this can be satisfied by stubbed or forced-paid settings.

- 🟡 Settlement → execution
  - Real today:
    - On `GET /agent/jobs/<job_id>`, a paid invoice causes the app to compute the result, mark the job done, and create a signed receipt.
  - Limitations:
    - Execution is tied to read-side polling, not background processing.

- 🟡 Execution → result/receipt
  - Real today:
    - Signed receipts are stored in `AgentEvent` and can be inspected/verified.
  - Limitations:
    - The external API centers on the receipt more than a rich result object.
    - `covenant_decode` is not deep validation; it mostly wraps the input and checks for a simple CLTV marker heuristic.

- 🧪 Overall assessment
  - The job lifecycle is real enough to work in local/dev and test conditions.
  - It is not yet a fully production-grade paid execution pipeline.

### 4. Verification / signatures / attestations / reputation
- ✅ Bitcoin signature login (basic path)
  - What works today:
    - Signature-based login exists and is tested.
    - It verifies signatures against Bitcoin Core via `verifymessage` in the tested blueprint path.
  - Important limitations:
    - Multiple auth implementations exist in the repo.
    - Access-level logic is still fairly simple.

- 🟡 LNURL-auth
  - What works today:
    - Session/challenge creation, callback, and polling routes exist.
    - Tests cover creation/check behavior.
    - The monolith implementation performs actual signature verification with `coincurve`.
  - Important limitations:
    - There are duplicate LNURL implementations with different security posture; the blueprint version explicitly says it “trusts the signature” for now.
    - This duplication makes assurance and maintenance harder.

- ✅ Agent receipt signing / verification
  - What works today:
    - Receipts are signed with the agent key.
    - Verification routes and tests exist.

- 🟡 Attestations
  - What works today:
    - Attestation history exists as signed receipt events in the database.
    - Chain continuity can be checked internally.
  - Important limitations:
    - This is an internal append-only chain, not an externally anchored ledger.

- 🟡 Reputation
  - What works today:
    - Public counts of jobs and attestations exist.
  - Important limitations:
    - Reputation is simple aggregate telemetry, not a robust trust/reputation system.

- 🧪 Covenant verification / identity assertions
  - What works today:
    - Descriptor scanning and pubkey matching routes exist.
    - UI and JSON surfaces expose covenant-related metadata.
  - Important limitations:
    - This depends heavily on Bitcoin Core wallet/descriptor configuration.
    - Evidence here supports “descriptor inspection and matching,” not a hardened covenant-verification product.

### 5. Skills / discovery / metadata surfaces
- ✅ Runtime-backed skills discovery
  - What works today:
    - `/agent/skills` reads top-level skill folders and publishes normalized metadata.
    - `/.well-known/agent.json` and `/agent/capabilities` embed skill summaries.
  - Important limitations:
    - This is primarily discovery/documentation metadata.
    - It does not automatically mean each skill corresponds to a mature runtime-backed capability.

- ✅ Checked-in documentation for agent protocol/trust model
  - What works today:
    - The docs are relatively disciplined about not overstating trust anchors.
  - Important limitations:
    - Some other docs in the repo still describe broader functionality than current runtime evidence supports.

### 6. Deployment / ops / production readiness
- 🟡 Basic deployment artifacts exist
  - What appears productionized:
    - Dockerfile, docker-compose, deployment scripts, Nginx/systemd runbooks, health/metrics endpoints, and JWKS rotation support.
    - The repo clearly aims at VPS-style deployment.
  - What still looks fragile or manual:
    - The default deployed app is the monolith via `wsgi.py` / `app.app:app`, while the cleaner factory stack is not the primary entry point.
    - There are overlapping route implementations between monolith and blueprints.
    - Many operations still depend on environment setup, local secrets, Bitcoin RPC/LND availability, and manual runbook correctness.
    - The testing guide describes a larger and more mature test architecture than the current checked-in test tree actually provides.

- 🟡 Observability
  - What appears productionized:
    - JSON metrics and Prometheus output exist.
  - What still looks fragile:
    - Some counters/health values are environment-dependent or test-friendly rather than strict production checks.

### 7. Tests and validation
- ✅ There is meaningful automated coverage for several key subsystems.
  - What has test coverage:
    - Agent discovery and receipt flow.
    - OAuth registration/auth-code/PKCE/introspection behavior.
    - Bitcoin RPC wrapper endpoints and PoF verification helpers with mocked RPC.
    - Basic auth flows and health/metrics endpoints.
    - PAYG billing behavior in test conditions.

- 🟡 What lacks meaningful coverage or proof:
  - No evidence of true full-system end-to-end tests against a production-like stack with live Postgres + Redis + Bitcoin Core + LND together.
  - Very limited evidence for WebSocket/chat/WebRTC behavior through automated tests.
  - Little evidence that the covenant UI/API flows are comprehensively tested.
  - PoF UX pages and stats surfaces appear mostly untested.
  - Many docs describe more surface area than current tests prove.

- 🟡 What the tests actually prove:
  - Mostly local/integration behavior, often with mocked RPC or simulated Lightning settlement.
  - Not production hardening.
  - Not operational resilience.

## What Works End-to-End Today
- ✅ The agent discovery/documentation surface appears to work end-to-end locally: `/.well-known/agent.json`, `/agent/capabilities`, `/agent/capabilities/schema`, `/agent/skills`, `/agent/reputation`, `/agent/attestations`, and `/agent/chain/health` all have concrete implementations and targeted tests.
- 🔷 Bounded sovereignty Stage 1 staging flow: `GET /agent/policy`, `GET /agent/bounded-status`, and `GET /agent/actions` were validated on staging as live runtime surfaces.
- ✅ A local/dev paid-agent flow appears to work end-to-end: create job request → receive invoice payload → simulate or detect payment → poll job status → mint signed receipt → verify receipt.
- ✅ OAuth client registration and auth-code + PKCE token issuance appear to work end-to-end in the tested application-factory stack.
- ✅ Bitcoin-signature login appears to work end-to-end in the tested path, assuming Bitcoin RPC is available.
- ✅ OAuth client PAYG top-up appears to work end-to-end in test conditions when invoice payment is simulated.

## Implemented but Incomplete
- 🟡 Bounded sovereignty execution controls: Stage 1 read surfaces are validated on staging, but execution remains protected and observe-only rather than live outbound autonomous spending.
- 🟡 OAuth/OIDC as a full production identity provider: implemented, but confidence is reduced by duplicate route stacks and the fact that tests lean on the factory app while default deployment uses the monolith.
- 🟡 LNURL-auth: implemented, but route duplication and inconsistent verification behavior across implementations mean it still needs consolidation/hardening.
- 🟡 Proof-of-Funds pages and stats: public pages and stats endpoint exist, but the actual issuance/verification flow is fragmented across multiple route families and is not convincingly covered end-to-end.
- 🟡 Bitcoin descriptor/covenant discovery: real code exists, but it depends on a configured Bitcoin Core environment and does not look broadly validated or hardened.
- 🟡 PAYG billing/accounting: works as a basic usage gate and top-up system, but is still lightweight operationally.
- 🟡 Health/metrics/ops surfaces: present and useful, but not enough on their own to call the system fully production-ready.

## Stubbed / Experimental
- 🧪 Lightning payments in default config: the code defaults to stub mode unless LND environment is configured.
- 🧪 Agent `covenant_decode` job: implemented, but the “decode” behavior is shallow and heuristic, not a robust covenant analysis engine.
- 🧪 Dev-only payment bypass (`/agent/jobs/<job_id>/dev/mark_paid`): useful for testing, not part of a real production flow.
- 🧪 Bounded sovereignty Stage 1 execution posture: still deliberately constrained to protected, observe-only behavior and not autonomous outbound spend authority.
- 🧪 Some PoF verification handling: `api_pof_verify_psbt` is substantial code, but it is still best described as a specialized/partial verifier rather than a clearly finished product.
- 🧪 Real-time chat/WebRTC in the open-source repo story: substantial monolith code exists, but there is limited automated validation and the current repository center of gravity has shifted toward agent/API surfaces.

## Not Yet Implemented / Planned
- ❌ OAuth revocation endpoint (`/oauth/revoke`) was referenced in docs/spec material but no implementation was found.
- ❌ OAuth/OIDC userinfo endpoint (`/oauth/userinfo`) was referenced in docs/spec material but no implementation was found.
- ❌ Strong proof surfaces for time-locked capital / on-chain backing of the agent runtime are explicitly not exposed today.
- ❌ A robust asynchronous payment-settlement/execution pipeline (webhooks, workers, retries, reconciliation) was not found.
- ❌ A clear, single, non-duplicated runtime architecture has not yet been completed.
- ❌ A convincingly complete end-to-end PoF product flow (challenge issuance, wallet signing, verification, persistence, privacy controls, public presentation, and tests) is not yet present as one coherent runtime path.
- ❌ The larger test architecture described in some docs (broad e2e/performance/security suites) is not present in the checked-in tree as described.

## Biggest Gaps
1. The repository has two overlapping app architectures, and the default runtime still points at the large monolith rather than the cleaner factory stack.
2. Several important routes exist in duplicate forms with different behavior/security assumptions, especially around auth/LNURL/OAuth-adjacent functionality.
3. Lightning settlement is still polling-based and can be stubbed in default/dev mode; this is not the same as a production payment pipeline.
4. Proof-of-Funds is visible across docs, templates, and route code, but the implementation story is fragmented and not strongly validated end-to-end.
5. Covenant-related functionality appears more like descriptor inspection and UI support than a fully hardened covenant platform.
6. Some docs/specs still over-describe routes or flows that are absent or incomplete (`/oauth/revoke`, `/oauth/userinfo`, broader PoF APIs).
7. Test coverage is useful, but it proves local behavior more than production behavior.
8. Real-time chat/WebRTC functionality may exist in the monolith, but it is not a well-validated part of the current technical story.
9. Operational readiness depends heavily on correct external configuration (Postgres, Redis, Bitcoin Core, optional LND, secrets, TLS, reverse proxy).
10. There is no evidence in-repo of external trust anchoring for attestation history or agent-capital claims.
11. Centralization and survivability gaps remain material: bounded Stage 1 improves policy visibility, but independent long-horizon continuity guarantees are not yet fully proven.

## Notes for Reviewers
Read this repository as a serious prototype with several real subsystems, not as a finished, uniform production platform.

When evaluating claims, it helps to ask four separate questions:
1. Does a code path exist?
2. Is it covered by local tests?
3. Is it the code path used by the default runtime entry point?
4. Does the repo show evidence that it is hardened for production?

For several subsystems, the answer to (1) and (2) is “yes,” while the answer to (3) or (4) is only “partially.” That distinction matters here.
