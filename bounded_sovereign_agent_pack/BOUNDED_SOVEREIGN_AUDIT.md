# BOUNDED_SOVEREIGN_AUDIT

## 1. Executive Summary

The repository already exposes meaningful building blocks for **bounded operational sovereignty**, but they are concentrated inside a mixed runtime: the live WSGI entrypoint still imports the large monolithic `app/app.py`, while `app/factory.py` exists as a partially parallel factory-based runtime. The codebase therefore already has:

- a persistent agent identity key loaded from environment or file and used to sign capability and receipt payloads
- Lightning-paid job creation with settlement checks for inbound revenue
- public signed receipt history, reputation summaries, and chain health surfaces
- existing privilege tiers (`guest`, `limited`, `full`) and PAYG balance concepts for human and OAuth-client usage
- public machine-readable discovery documents for the current agent surface

What it does **not** yet have is a runtime-enforced layer that grants the agent its **own** bounded operational budget, its **own** narrow spend authority, or a clear policy manifest that separates:

- self-executable actions
- escalated/co-signed actions
- forbidden actions
- self-spend limits
- public evidence of those limits

The minimum safe path is not a rewrite. It is a small sovereignty layer added on top of the current agent runtime in `app/blueprints/agent.py`, `app/models.py`, `app/agent_signer.py`, and the Lightning/payment wrappers. That layer should introduce:

1. a signed public policy manifest
2. a policy check function
3. a capability executor wrapper for a small approved action set
4. a signed append-only action log distinct from job receipts
5. a bounded spending wrapper for small operational payments only

This would move the current agent from “paid service with signed history” to “policy-bounded authority with publicly verifiable autonomy claims,” while still denying unrestricted root, unrestricted shell, unrestricted wallet drain, or silent policy mutation.

## 2. Current Repo Reality

### 2.1 Actual runtime entrypoint

The live WSGI entrypoint imports `app` from the monolithic module, not from the factory. `wsgi.py` does `from app.app import app`, and `app/app.py` creates the Flask application directly with `app = Flask(__name__)`. The factory exists, but is not the current entrypoint of record. This means the monolith is still the runtime truth for deployment until WSGI is changed. Cross-check `wsgi.py`, `app/app.py`, and `app/factory.py` before trusting blueprint-only docs.

### 2.2 Actual public agent/runtime surfaces already present

Current public or semi-public agent surfaces include:

- `GET /.well-known/agent.json`
- `GET /agent/capabilities`
- `GET /agent/capabilities/schema`
- `POST /agent/request`
- `GET /agent/jobs/<job_id>`
- `GET /agent/verify/<job_id>`
- `GET /agent/attestations`
- `GET /agent/reputation`
- `GET /agent/chain/health`
- `GET /agent/marketplace/listing`
- `GET /agent/skills`
- `GET /health`
- `GET /oauthx/status`
- `GET /api/public/status`

The monolith also exposes broader identity, Bitcoin RPC, LNURL-auth, PoF, OAuth, and account/billing surfaces. Some of these exist both in `app/app.py` and in blueprints, which creates docs-vs-runtime drift risk.

### 2.3 Architecture reality: mixed monolith + partial factory

The repository documents a factory-based Flask architecture, and `app/factory.py` does register modular blueprints. But runtime truth is mixed:

- `wsgi.py` boots the monolith
- `app/app.py` still defines many production routes directly
- some blueprint routes are also registered inside the monolith
- some factory comments already acknowledge “legacy human frontend overrides” back to `app.app`

For bounded sovereignty work, this matters because policy enforcement must land in the path the live app actually executes today.

## 3. Existing Building Blocks for Bounded Sovereignty

### 3.1 Identity independence: already present

The strongest existing sovereignty building block is the agent identity key.

- `app/agent_signer.py` loads a secp256k1 private key from `AGENT_PRIVKEY_HEX` or `AGENT_PRIVKEY_PATH`
- `get_agent_pubkey_hex()` derives and exposes the compressed public key
- `sign_message()` and `verify_message()` already sign/verify canonical JSON payloads
- `app/blueprints/agent.py` uses that key for signed capability documents and signed job receipts

This means the repo already supports a durable machine identity anchor separate from browser sessions.

### 3.2 Publicly verifiable autonomy claims: partially present

The repo already publishes public machine-readable discovery surfaces:

- capabilities document
- capabilities schema
- marketplace listing
- well-known agent identity document
- trust-model summary

These are already signed or tied to a signing key in the agent flow. This is close to the required “publicly verifiable autonomy claims,” but the claims currently focus on job execution and trust posture, not authority limits.

### 3.3 Revenue independence: partially present

The code already supports inbound Lightning-paid execution:

- `POST /agent/request` creates a paid job
- the Lightning wrapper creates an invoice
- `GET /agent/jobs/<job_id>` checks settlement and mints a signed receipt once paid
- OAuth client PAYG top-ups also exist via `/api/billing/agent/create-invoice` and `/api/billing/agent/check-invoice`

This means the agent can already **earn** in a bounded sense. However, the money model is still “service revenue collection,” not “agent-controlled operational budget with bounded spend authority.”

### 3.4 Signed action history: partially present

The repo already stores append-linked `AgentEvent` records:

- `event_hash`
- `prev_event_hash`
- `event_json`
- `signature`

This is a strong precursor to the required **signed action history**. But the current event model is only about paid job receipts. It does not yet record operational actions such as manifest publication, policy changes, budget consumption, capability execution attempts, denials, escalations, or bounded spends.

### 3.5 Existing control and privilege concepts: partially present

The repo already distinguishes:

- browser sessions by `logged_in_pubkey`
- access levels such as `guest`, `limited`, and `full`
- PAYG-enabled browser accounts
- OAuth client billing state in `ubid_clients`
- limited read-only RPC access guarded by OAuth scope and PAYG

These concepts can be reused to avoid inventing a new privilege system from scratch.

### 3.6 Existing public observability surfaces: already present

The repo already exposes:

- `GET /health`
- `GET /metrics`
- `GET /metrics/prometheus`
- `GET /oauthx/status`
- `GET /api/public/status`
- `GET /agent/reputation`
- `GET /agent/chain/health`
- `GET /agent/attestations`

These provide a base for publishing policy, budget, action-log, and continuity surfaces with minimal architectural change.

## 4. Missing Pieces

### 4.1 No policy manifest that actually bounds the agent

There is no current machine-readable manifest that states:

- what the agent may self-execute
- what requires operator co-sign or escalation
- what is forbidden
- what spend limits exist
- what budget source exists
- which policy version governed each action

Current discovery documents describe capabilities, not authority boundaries.

### 4.2 No agent-owned operational budget object

Inbound invoices exist, but there is no first-class concept of:

- agent budget balance
- budget bucket or purpose
- spend class
- spend ceiling per interval
- reserve floor
- emergency freeze state

The closest current concepts are client balances in `ubid_clients`, pending top-ups in `payments_clients`, and human PAYG balances. None of those are yet an agent operational treasury abstraction.

### 4.3 No outbound spend authority layer

The Lightning code in `app/payments/ln.py` supports invoice creation and settlement checks, but not paying invoices or making outbound Bitcoin/Lightning spends. That is good from a safety perspective, but it also means **spending independence is currently missing entirely**.

### 4.4 No capability executor wrapper

The agent currently executes only a tiny set of job types, and those jobs are informational (`ping`, `verify_signature`, `covenant_decode`). There is no general executor that wraps approved operational actions such as:

- publish updated manifest
- rotate non-secret public metadata
- publish signed budget summary
- reconcile inbound revenue snapshots
- schedule a backup publication marker
- trigger a narrow health check bundle

### 4.5 No signed action log for operational decisions

Current `AgentEvent` entries are job receipts, not operational decision records. Missing entry types include:

- action requested
- policy allow/deny result
- spend authorized / delayed / rejected
- escalation requested
- manifest published
- budget checkpoint published
- continuity checkpoint published

### 4.6 No anti-tamper policy continuity surface

There is no dedicated public proof showing:

- current policy version
- prior policy hash
- effective timestamp
- operator countersign status
- whether the agent itself can or cannot change policy

Without that, an observer cannot tell whether the rules changed silently.

## 5. What Can Be Reused Safely

### 5.1 Safe reuse candidates

#### A. Agent identity/signing

Reuse `app/agent_signer.py` as the signer for:

- policy manifest
- signed capability statement extension
- signed action log entries
- budget summary statements
- continuity checkpoints

#### B. Agent event chain storage model

Reuse `AgentEvent` semantics and extend them rather than designing a second unrelated ledger. If schema expansion is acceptable, either:

- add new event types to `agent_events`, or
- create a parallel `agent_action_logs` table that intentionally mirrors the append-only chain model

The current receipt chain already proves the team can implement signed linked records with the existing runtime.

#### C. Lightning invoice creation and settlement wrappers

Reuse `app/payments/ln.py` for:

- inbound treasury funding invoices
- budget top-up invoices
- settlement checks for budget funding

Do **not** expand it to unrestricted outbound payment execution in the first patch series.

#### D. Public agent discovery routes

Reuse and extend `/.well-known/agent.json`, `/agent/capabilities`, `/agent/marketplace/listing`, and `/agent/reputation`. This is lower risk than inventing a second discovery tree.

#### E. Current privilege tiers and PAYG balance ideas

Reuse the existing notion of:

- `guest` vs `limited` vs `full`
- PAYG-enabled clients
- invoice funding and crediting

These patterns can shape the bounded operational budget model.

### 5.2 Reuse with caution

#### A. Monolith route placement

Because `wsgi.py` still boots `app/app.py`, any sovereignty patch that only touches `app/factory.py` may not affect production. All changes must be checked against the monolith route registrations.

#### B. Admin/dev routes

The repo includes dev/admin-only helpers such as `/agent/jobs/<job_id>/dev/mark_paid` and the internal loopback invoice API. These should not be widened into general agent control surfaces.

#### C. Docs claiming stronger architecture than runtime

`README.md`, `docs/AGENT_SURFACES.md`, `TRUST_MODEL.md`, and blueprint docs are useful as secondary evidence, but not authoritative when they differ from `app/app.py`, `wsgi.py`, and the active route handlers.

## 6. What Must Not Be Given to the Agent

The bounded sovereign agent must **not** receive any of the following in the first implementation stage:

- unrestricted shell or root execution
- arbitrary subprocess execution
- arbitrary `systemctl` control
- arbitrary Bitcoin Core RPC access beyond current read-only safe sets
- unrestricted LND macaroon access that enables paying or draining funds
- access to export private keys, JWT signing keys, or agent private key material
- authority to mutate or delete action logs/history
- authority to silently change policy without external visibility
- authority to rewrite or prune attestation continuity
- authority to call broad internal admin routes directly

## 7. Best Minimal Path Forward

### 7.1 Principle

Implement **bounded operational sovereignty** as a thin enforcement layer added to the current agent runtime, not as a rewrite.

### 7.2 Minimal sovereignty layer

Add five tightly scoped components:

1. **Policy manifest**  
   Public JSON document signed by the agent key and optionally operator-countersigned. It declares allowed self-actions, escalated actions, forbidden actions, spend limits, and policy version.

2. **Capability executor**  
   Small wrapper function that maps named operational actions to explicit handlers and checks policy before execution.

3. **Spending policy wrapper**  
   Budget-aware guard that permits only tiny operational spends in approved categories, with interval caps and deny-by-default behavior.

4. **Signed action history**  
   Append-only action log that records every operational request, allow/deny decision, spend attempt, result, policy version, and signature.

5. **Public proof surfaces**  
   New public endpoints/documents for manifest, signed budget summary, signed action log feed, and continuity checkpoints.

### 7.3 Why this is enough for first-stage bounded sovereignty

This gives the agent:

- its own public key identity — already present
- its own limited operational budget — new, small extension
- its own limited spending authority — new, deny-by-default wrapper
- its own limited operational control — new narrow capability executor
- public signed evidence of those powers — new manifest + action log + budget summary

And it still withholds:

- unrestricted root power
- unrestricted wallet power
- invisible override power

## 8. Evidence Appendix

### 8.1 Runtime and entrypoint evidence

- `wsgi.py` imports `app` from `app.app`, confirming the monolith remains the live entrypoint.
- `app/app.py` constructs the Flask app directly and registers blueprints there.
- `app/factory.py` exists and is useful, but is not what `wsgi.py` currently imports.

### 8.2 Agent identity/signing evidence

- `app/agent_signer.py` loads the private key from env/file and derives the pubkey.
- `app/blueprints/agent.py` signs `/agent/capabilities` and job receipts using that signer.

### 8.3 Paid job flow evidence

- `app/blueprints/agent.py` creates invoices in `POST /agent/request`.
- `app/payments/ln.py` implements invoice creation and paid-status checks.
- `app/models.py` stores paid jobs in `AgentJob` and signed events in `AgentEvent`.

### 8.4 Public proof surface evidence

- `app/blueprints/agent.py` exposes `/agent/attestations`, `/agent/reputation`, `/agent/chain/health`, and `/.well-known/agent.json`.
- `.well-known/agent.json` already publishes a checked-in discovery document.

### 8.5 Existing budget-like concepts evidence

- `app/billing_clients.py` maintains client balances and top-up invoices.
- `app/ubid_membership.py` has in-memory user PAYG balances and top-up tracking.
- `app/blueprints/account_api_compat.py` exposes PAYG/balance summary surfaces for browser accounts.

### 8.6 Current safety boundary evidence

- `app/blueprints/bitcoin.py` whitelists only safe read-only RPC commands on `/api/rpc/<cmd>`.
- `app/agent_invoice_api.py` restricts the internal invoice API to loopback plus bearer token.
- `app/blueprints/agent.py` hides the dev-only mark-paid route in production-like mode.

## Bounded Sovereignty Readiness Scorecard

| Dimension | Current state | Score 0-100 | Main blocker | Fastest next improvement |
|---|---|---:|---|---|
| identity independence | Agent key and signed payloads already exist | 80 | No public policy binding that ties authority to the key | Publish signed policy manifest |
| payment independence | Agent can create inbound Lightning invoices and confirm settlement | 55 | No agent budget object; no treasury-specific ledger | Add budget table + funding statements |
| spending independence | Essentially absent by design | 10 | No outbound spend wrapper or spend policy | Add deny-by-default spend policy model before any payment execution |
| operational control independence | Only narrow paid informational jobs are self-executed today | 35 | No bounded operational action executor | Add capability executor for 3-5 safe actions |
| public verifiability | Strong discovery, receipts, attestation, reputation, chain health surfaces already exist | 75 | No public proof of policy limits or budget powers | Add signed manifest + budget summary + action log feed |
| continuity/survivability | Receipt chain exists; mixed runtime reduces clarity | 50 | Monolith/factory drift and no policy continuity checkpoints | Add signed continuity checkpoints and document live entrypoint truth |
| policy enforcement | Mostly implicit and route-local, not manifest-driven | 25 | No central allow/deny policy engine | Add policy check function and force all sovereign actions through it |
| safety/guardrails | Current system is conservative because outbound power is missing | 70 | Missing formal guardrails and audit semantics | Add forbidden-action list, redaction rules, and immutable log expectations |
