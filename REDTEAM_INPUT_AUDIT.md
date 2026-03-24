# Executive Summary

HODLXXI currently contains **two materially different Flask application shapes**: a large monolithic runtime in `app/app.py` and a cleaner factory/blueprint app in `app/factory.py`. The production WSGI entrypoint points to the **monolith**, not the factory. That means the repo’s real runtime truth is a hybrid: monolithic routes plus a subset of blueprints registered inside the monolith. Tests, however, primarily exercise the **factory app**, which exposes a different route surface and omits several monolith-only routes. Evidence: `wsgi.py`, `app/app.py`, `app/factory.py`, `tests/conftest.py`.

The implemented “agent” story is real but narrow:
- There is a public discovery surface at `/.well-known/agent.json`, `/agent/capabilities`, `/agent/capabilities/schema`, `/agent/skills`, `/agent/marketplace/listing`, `/agent/reputation`, `/agent/attestations`, and `/agent/chain/health`.
- There is a public job submission surface at `POST /agent/request`.
- Jobs are Lightning-priced, persisted, and can mint signed receipts once invoice settlement is detected.
- There is a public verification endpoint for receipts.

But the implementation is **partial and operationally fragile**:
- The runtime requires a server-held `AGENT_PRIVKEY_HEX` or file to derive the agent pubkey and sign receipts. There is **no formal linkage** between that agent key and any human/operator login identity.
- Job settlement is polling-based only; there is no background worker or webhook.
- `GET /agent/jobs/<job_id>` returns **status + receipt only**, not the actual job result payload, even though `result_json` is computed and stored in the database.
- Deduplication is request-hash based and not requester-bound, so a later caller can get an existing paid receipt for the same payload without paying again.
- The public receipt chain is only database-backed; it is not anchored on-chain, not replicated, and not survivable if the operator disappears.

The “covenant” story is where the biggest docs/runtime gap exists. The repo does contain **real Bitcoin descriptor/script inspection code** and watch-only import/label tooling in the monolith. It can list descriptors, decode scripts, extract visible pubkeys from script ASM, derive addresses, and show balances/groupings. But it does **not** implement on-chain covenant creation, covenant enforcement automation, miniscript compilation, taproot covenant tooling, or the broader 21-year contract lifecycle claimed in several docs. The agent-side `covenant_decode` job is especially limited: it returns `decoded: "script(<hex>)"` and treats `"b1" in script_hex` as CLTV presence.

The economics that are actually enforced today split into two separate systems:
1. **Agent jobs**: fixed 21-sat pricing per supported job type.
2. **OAuth client PAYG**: OAuth clients can hit protected endpoints, receive 402 responses, top up via Lightning invoices, and spend a sats balance or free quota.

There is also a **staging-validated bounded sovereignty Stage 1 update** that needs to be treated carefully:
- public GET surfaces now work for `/agent/policy`, `/agent/bounded-status`, and `/agent/actions`
- `/agent/bounded/execute` remains protected
- current spending posture is still `observe_only`, not live outbound autonomous spending

That is a meaningful runtime change, but it does **not** convert the system into a fully autonomous or decentralized spending agent. It adds bounded-policy disclosure and bounded-status visibility, not sovereign outbound financial autonomy.

The repo therefore supports the thesis only **partially**:
- “agent with its own pubkey” — yes.
- “agent can be paid” — yes, via Lightning invoice flow.
- “agent can sign outputs / produce verifiable receipts” — yes, but receipts omit the actual result payload.
- “agent can accumulate machine-verifiable history” — yes, but only as DB-local signed events with no external anchoring.
- “agent can act as a durable trust actor” — only weakly; durability depends almost entirely on one operator-controlled server, one signing key, and one database.

# What Exists Today (Confirmed)

## Runtime architecture actually used

### Confirmed runtime entrypoint
- `wsgi.py` imports `app` from `app.app` and exposes it as both `app` and `application`. That makes the monolith the deployed WSGI target.
- The monolith registers the agent blueprint, PoF blueprints, OIDC blueprint, dev blueprint, and an internal agent invoice blueprint directly.
- The monolith also defines many routes inline that do not exist in the factory app.

### Factory app also exists, but is not the WSGI runtime
- `app/factory.py` builds a cleaner blueprint app with auth, bitcoin, demo, LNURL, OAuth, admin, PoF, UI, dev, billing-agent, and agent blueprints.
- Pytest fixtures instantiate `create_app()` from the factory, so most automated tests validate the factory route map, not the monolith route map.
- This is a major source of drift: production runtime truth and test/runtime truth are not the same app object.

## Confirmed public route surface in the monolith runtime

### Public discovery / agent routes
- `GET /.well-known/agent.json`
- `GET /agent/capabilities`
- `GET /agent/capabilities/schema`
- `GET /agent/policy` *(staging-validated Stage 1 public surface)*
- `GET /agent/bounded-status` *(staging-validated Stage 1 public surface)*
- `GET /agent/actions` *(staging-validated Stage 1 public surface)*
- `GET /agent/skills`
- `POST /agent/request`
- `GET /agent/jobs/<job_id>`
- `GET /agent/verify/<job_id>`
- `GET /agent/attestations`
- `GET /agent/reputation`
- `GET /agent/chain/health`
- `GET /agent/marketplace/listing`

These are explicitly exempted from session auth in the monolith request guard.

### Other confirmed public runtime-facing routes
- `GET /.well-known/openid-configuration`
- `GET /oauth/jwks.json`
- `POST /oauth/register`
- `GET /oauth/authorize`
- `POST /oauth/token`
- `POST /oauth/introspect`
- `GET /oauthx/status`
- `GET /oauthx/docs`
- `GET /health`
- `GET /metrics`
- `GET /api/public/status`
- `GET /login`
- `GET /logout`
- `GET /pof/`
- `GET /pof/leaderboard`
- `GET /pof/verify`
- `GET /verify_pubkey_and_list`
- `POST /decode_raw_script`
- `POST /api/challenge`
- `POST /api/verify`
- `GET,POST /api/lnurl-auth/create`
- `GET /api/lnurl-auth/params`
- `GET /api/lnurl-auth/callback/<session_id>`
- `GET /api/lnurl-auth/check/<session_id>`

### Public but operationally sensitive routes
- `GET /api/public/status` exposes aggregated online user counts, bitcoind health, and LND service state.
- `GET /verify_pubkey_and_list` exposes covenant/descriptor-derived metadata for a queried pubkey or npub.
- `POST /decode_raw_script` can derive descriptor and QR outputs for submitted script hex.
- `GET /agent/policy`, `GET /agent/bounded-status`, and `GET /agent/actions` now add staging-validated bounded-sovereignty disclosure surfaces. These improve visibility into bounded runtime posture, but they also give hostile reviewers more policy and action-surface material to inspect.

## Confirmed protected route classes

### OAuth-token + PAYG protected (factory app)
- `GET /api/demo/protected`
- `GET /api/rpc/<cmd>`
- `GET /api/descriptors`
- `POST /api/billing/agent/create-invoice`
- `POST /api/billing/agent/check-invoice`

These require a bearer token through `require_oauth_token(...)`, and some also require `require_paid_client(...)` billing.

### Session/full-access protected (monolith)
- `POST /import_descriptor` requires `require_full_access()`.
- `GET /export_descriptors` requires `session['access_level'] == 'full'`.
- `POST /set_labels_from_zpub` requires full access JSON guard.
- `GET /api/lnd/status` requires a logged-in full-access session.
- `GET /rpc/<cmd>` in the monolith requires full access.
- `POST /agent/bounded/execute` remains protected in the bounded-sovereignty Stage 1 runtime and should not be treated as a public autonomous spending endpoint.

## Confirmed identity/auth surfaces

### Bitcoin signature login
- `POST /verify_signature` verifies a session challenge by deriving a legacy address from a provided pubkey and calling Bitcoin Core `verifymessage`.
- If the request omits a pubkey, the handler loops through `SPECIAL_USERS` and grants `full` access if one of those pubkeys matches the signature.
- If the request includes a specific pubkey, successful verification grants only `limited` access.

### Guest login
- `POST /guest_login` accepts an optional PIN and creates session identities like `guest_<pin>` or `anon_<uuid8>` with `access_level='guest'`.

### LNURL-auth
- `POST /api/lnurl-auth/create` creates a challenge/session record.
- `GET /api/lnurl-auth/callback/<session_id>` marks the session verified if `k1` matches, but **does not cryptographically verify the signature**; the code explicitly says “For now, we trust the signature (this should be replaced).”
- `GET /api/lnurl-auth/check/<session_id>` only reports stored verification state.

### OAuth2/OIDC
- Dynamic client registration exists.
- Authorization Code + PKCE flow exists.
- Token issuance exists and produces RS256 JWTs.
- Token introspection exists and performs actual JWT signature verification against JWKS.

## Confirmed PoF surface

### Real, implemented now
- `GET /pof/` renders live DB-backed PoF stats.
- `GET /pof/leaderboard` renders DB-backed leaderboard rows from `proof_of_funds` where status is `verified` and privacy level is in `threshold|aggregate|exact`.
- `GET /pof/certificate/<cert_id>` renders a shareable certificate page from DB data.
- `GET /pof/verify` renders a verification page shell.
- `GET /api/pof/stats` returns live counts/sums from the `proof_of_funds` table.
- `POST /api/challenge` returns a compatibility challenge payload even without RPC.
- `POST /api/verify` verifies PSBT structure against RPC by checking UTXOs and searching for the challenge in an OP_RETURN.

### Not confirmed in runtime today
- No implemented `/pof/api/generate-challenge` or `/pof/api/verify-signatures` flow matching the architecture docs.
- No confirmed runtime path that writes fresh PoF attestations into `proof_of_funds` from a complete user-facing verification flow.

# Public Agent Surface

## Discovery documents

### Staging-validated bounded sovereignty Stage 1 read surfaces
**Implemented on staging:** yes.

The current bounded-sovereignty Stage 1 runtime now exposes these additional public GET surfaces:
- `/agent/policy`
- `/agent/bounded-status`
- `/agent/actions`

What that changes:
- outsiders can inspect more of the bounded operating posture
- the runtime now discloses a more explicit bounded-control layer than the earlier audit captured

What it does **not** change:
- it does not make spending autonomous
- it does not make outbound spend authority public
- it does not reduce operator dependency
- it does not improve survivability in any meaningful decentralized sense

### `GET /.well-known/agent.json`
**Implemented:** yes.

Returns an unsigned discovery/identity document containing:
- service name/version/operator/network
- `agent_pubkey`
- capability schema reference
- job types and pricing summary
- discovery links
- signed-surface trust summary
- skills summary

Important reality:
- The document itself is **not signed**.
- It embeds the runtime trust model, but the operator binding is only a hardcoded string (`"HODLXXI"`).
- It explicitly labels time-locked capital as `optional_not_verified` and states `on_chain_proof_exposed: false`.

### `GET /agent/capabilities`
**Implemented:** yes.

Returns a signed JSON payload with:
- `agent_pubkey`
- version/name/operator/network
- endpoint map
- pricing
- job registry
- limits
- skills summary
- timestamp
- signature scheme (`secp256k1`)
- signature over canonical JSON

Important reality:
- This is the only agent discovery surface that is actually signed.
- The signing scheme is raw secp256k1 ECDSA over canonical JSON bytes, not BIP-322, not JOSE/JWS, not Nostr events.

### `GET /agent/capabilities/schema`
**Implemented:** yes.

Publishes a JSON Schema describing the capabilities payload.

### `GET /agent/skills`
**Implemented:** yes.

Builds a catalog from `skills/public/*/SKILL.md` by parsing lightweight front matter and exposing install metadata, including a raw GitHub URL.

Current confirmed behavior:
- It only reflects checked-in public skills in the local repo.
- It is not independently signed.
- A signed summary of the skills catalog is embedded in `/agent/capabilities`.

### `GET /agent/marketplace/listing`
**Implemented:** yes.

Returns a compact directory-facing record combining:
- discovery links
- capabilities schema reference
- skills summary
- trust model summary
- pricing
- reputation counts
- chain health summary

Important reality:
- This is custom JSON, not a known external marketplace standard.

## Request/execution surfaces

### `POST /agent/request`
**Implemented:** yes, public.

Accepts:
- `job_type`
- `payload`

Current protections:
- in-memory per-process IP rate limit: 20 requests per 60 seconds
- global DB job cap: 100 jobs per day across all callers
- payload size cap: stringified payload length <= 10,000 chars
- supported job type check only

Current supported job types:
- `ping`
- `verify_signature`
- `covenant_decode`

### `GET /agent/jobs/<job_id>`
**Implemented:** yes, public.

Current behavior:
- looks up persisted `AgentJob`
- if invoice not yet settled: returns `job_id`, `status`, `receipt: null`
- if invoice is settled and no receipt exists yet: computes result, stores it, creates a signed receipt event, links it to previous event hash, marks job done
- returns only `job_id`, `status`, and `receipt`

Critical reality:
- It does **not** return `result_json`, even after execution.
- That means the public caller cannot fetch the actual job result payload through the documented job retrieval route.

### `GET /agent/verify/<job_id>`
**Implemented:** yes, public.

Current behavior:
- loads the stored receipt event for the job
- removes `signature`
- verifies the signature against `agent_pubkey`
- returns `valid`, `agent_pubkey`, `event_hash`, and the full receipt

Critical limitation:
- It verifies the receipt signature only.
- It does not prove the result payload to the caller because the result payload is not returned here either.

### `POST /agent/bounded/execute`
**Implemented at Stage 1, but protected:** yes.

Current bounded-sovereignty reality:
- this route should be treated as protected, not public
- current runtime posture remains `observe_only`
- the system still does not expose live outbound autonomous spending

Red-team implication:
- Stage 1 bounded execution narrows the gap between “agent with policies” and “agent with guarded action paths”
- but it is still materially different from a self-authorizing spend agent
- operator/server controls remain the decisive choke point

## History/continuity surfaces

### `GET /agent/attestations`
**Implemented:** yes, public.

Returns paginated receipt events from `agent_events`, latest first.

### `GET /agent/reputation`
**Implemented:** yes, public.

Returns only aggregate counts:
- `agent_pubkey`
- `total_jobs`
- `completed_jobs`
- `job_types`
- `attestations_count`

This is not a reputation score. It is a counter surface.

### `GET /agent/chain/health`
**Implemented:** yes, public.

Checks whether the `prev_event_hash` chain is internally consistent across stored events and returns:
- `agent_pubkey`
- count
- latest event hash
- latest previous event hash
- boolean `chain_ok`

Critical limitation:
- It checks DB ordering/linkage only.
- It does not re-verify signatures, prove external publication, or prove survivability.

## Internal/local-only billing helper surface

### `/api/internal/agent/invoice` and `/api/internal/agent/invoice/<rhash>`
**Implemented:** yes.

These routes are loopback-only and bearer-token protected for internal agent→web-app calls. They shell out to `lncli` and are explicitly intended to be callable only from localhost without proxy headers.

# Agent Job / Payment / Receipt Loop

## Stage 1 — discovery

### What exists
- `/.well-known/agent.json`
- `/agent/capabilities`
- `/agent/capabilities/schema`
- `/agent/skills`
- `/agent/marketplace/listing`

### Status
**Implemented.**

### Caveat
- Only `/agent/capabilities` is signed.
- The discovery formats are custom to this repo.

## Stage 2 — capability read

### What exists
- `/agent/capabilities` returns job registry entries with `price_sats`, `memo`, input schema, and output schema.

### Current job types
- `ping`: 21 sats
- `verify_signature`: 21 sats
- `covenant_decode`: 21 sats

### Status
**Implemented.**

### Caveat
- Output schemas are not fully honored by retrieval routes because results are not returned to the client from `/agent/jobs/<job_id>`.

## Stage 3 — request creation

### Flow
1. Caller `POST`s JSON to `/agent/request`.
2. Server rate-limits and validates job type.
3. Server hashes `{job_type, payload}` with SHA-256 over canonical JSON.
4. Server deduplicates by `request_hash` against existing jobs.
5. Server creates a Lightning invoice and persists an `AgentJob` with `invoice_pending`.

### Status
**Implemented.**

### Critical caveats
- Deduplication is **not caller-bound**. If an identical request was already completed, a later caller gets that old job/receipt without proving payment.
- The per-IP limiter is process-local memory, not distributed and not durable.
- The daily job cap is global, not per caller.

## Stage 4 — payment requirement

### Flow
- The job is always invoice-backed for the current supported job types.
- The `create_invoice(...)` helper chooses backend from `LN_BACKEND`.

### Backends
- `lnd_rest`
- `lnd_cli`
- `stub` (default outside production)

### Status
**Implemented, but environment-dependent.**

### Caveats
- In non-production, default behavior is stub invoice generation.
- In production (or `FORCE_HTTPS=true`), stub/testing modes are rejected.
- The job API itself does not prove an invoice was genuinely created by LND unless the environment is configured that way.

## Stage 5 — invoice generation

### What is generated
- `payment_request`
- `invoice_id` / `payment_lookup_id`
- synthetic or real `payment_hash`

### Status
**Implemented.**

### Caveat
- If the lookup ID is not already a 64-char hex string, the code hashes it with SHA-256 to produce `payment_hash`. That means `payment_hash` may be a derived correlation token rather than the native Lightning payment hash.

## Stage 6 — settlement check

### Flow
- Caller polls `GET /agent/jobs/<job_id>`.
- Route calls `check_invoice_paid(job.payment_lookup_id)`.
- If paid and no receipt yet, the route executes the job and mints the receipt.

### Status
**Implemented.**

### Caveats
- No asynchronous worker.
- No push callback or webhook.
- No execution occurs until someone polls the job endpoint.

## Stage 7 — job execution

### `ping`
- Returns `{ok: true, job_type: "ping", echo: payload}`.
- Status: **implemented**.

### `verify_signature`
- Calls `verify_message(message.encode('utf-8'), signature_hex, pubkey_hex)`.
- Status: **implemented, but custom**.
- Caveat: this is not Bitcoin message signature verification (`verifymessage`) and not BIP-322; it is raw secp256k1 ECDSA verification over UTF-8 bytes.

### `covenant_decode`
- Returns `decoded: f"script({script_hex})"` and `has_cltv: 'b1' in script_hex.lower()`.
- Status: **stubbed / heuristic only**.
- Caveat: it does not actually decode Bitcoin script semantics.

## Stage 8 — signed result or receipt generation

### Flow
- `_build_receipt(...)` computes `result_json`, `result_hash`, and job status.
- Receipt includes:
  - `event_type`
  - `job_id`
  - `request_hash`
  - `payment_hash`
  - `result_hash`
  - `timestamp`
  - `agent_pubkey`
  - `prev_event_hash`
  - `signature`

### Status
**Implemented.**

### Critical caveat
- The receipt does **not** include the actual result payload.
- The public API therefore exposes a signed hash of a result that the caller cannot fetch from the agent job endpoint.

## Stage 9 — job retrieval

### What the public caller gets
- `job_id`
- `status`
- `receipt`

### Status
**Partial.**

### Why partial
- The repo computes results and stores them, but the public retrieval route omits them.
- This undermines the documented “returns signed results” claim.

## Stage 10 — attestation/history publication

### What exists
- `AgentEvent` append-only DB records
- `GET /agent/attestations`
- `GET /agent/reputation`
- `GET /agent/chain/health`
- `GET /agent/verify/<job_id>`

### Status
**Implemented, local-only.**

### Caveats
- History is only in the application database.
- No external replication, no Bitcoin anchoring, no immutable log backend, no remote witness.
- If the operator loses or resets the DB, continuity can be lost.

# Identity and Trust Model

## Identity anchors that actually exist

### 1. Agent runtime key
**Confirmed:** yes.

- The agent pubkey is derived from a server-held secp256k1 private key loaded from `AGENT_PRIVKEY_HEX` or `AGENT_PRIVKEY_PATH`.
- This key signs capabilities and receipts.
- This is the strongest implemented machine-verifiable identity anchor for the agent surface.

### 2. Human/user pubkeys
**Confirmed:** yes.

- The application has a `users` table keyed by Bitcoin pubkey.
- Web sessions store `session['logged_in_pubkey']` and `session['access_level']`.
- OAuth tokens and sessions are tied to user identities.
- Special-user signature login can grant `full` access; explicit-pubkey signature login grants `limited` access.

### 3. Guest pseudo-identities
**Confirmed:** yes.

- Guest/PIN logins create fake local identifiers like `guest_<pin>` and `anon_<uuid8>`.
- These are session identities, not cryptographic identities.

## What can be cryptographically verified today

### Verifiable
- The agent capabilities payload signature.
- Receipt signatures from `/agent/verify/<job_id>`.
- OAuth JWT signatures via JWKS / introspection.
- Bitcoin signature login, but only through Bitcoin Core `verifymessage` during auth flow.

### Not verifiable from public runtime alone
- Legal or organizational control behind operator string `HODLXXI`.
- Linkage between human/operator login keys and the agent runtime key.
- On-chain reserves or capital backing.
- Time-locked capital backing.
- Persistence beyond the current server/database.
- Any claim that bounded-sovereignty Stage 1 has crossed into autonomous spending rather than guarded observe-only execution.

## What is merely asserted

- `operator: "HODLXXI"` in discovery surfaces.
- The broader “durable trust actor” thesis beyond current server continuity.
- Any 21-year covenant claim not backed by current route behavior.
- Marketplace/interoperability readiness beyond custom JSON docs.

## What depends on operator honesty

- Preserving the signing key and not misusing it.
- Preserving the event database and not resetting it.
- Publishing honest operator metadata.
- Returning honest job results before hashing/signing them.
- Proper Lightning backend configuration in production.

## What depends on server availability

Everything material in the current design:
- discovery documents
- job acceptance
- payment checking
- receipt retrieval
- attestation history
- chain health checks
- OAuth token issuance/introspection

If the server goes offline, counterparties lose access to all live verification surfaces except previously saved artifacts.

## What survives operator disappearance

### Survives weakly
- Previously saved capabilities payloads and receipts can still be locally verified if the verifier already has them and knows/pins the agent pubkey.

### Does not survive cleanly
- Public attestation history.
- Chain health endpoint.
- Job lookup.
- Discovery documents.
- Any claim of durable continuity.

There is no independent witness or anchored ledger for the receipt chain.

## What the agent pubkey actually controls or proves today

### It proves
- The holder of the server-side private key signed the capabilities document.
- The holder of the server-side private key signed a specific receipt payload.

### It does not prove
- Ownership of Lightning funds.
- Ownership of any covenant or Bitcoin UTXO.
- Organizational control of HODLXXI.
- Relationship to logged-in human keys.
- That the result payload is available to counterparties through the public API.
- That the bounded Stage 1 execution surface has autonomous spending authority; current validated posture remains observe-only.

## Is there a formal linkage between operator identity and agent identity?

**No formal linkage is implemented.**

Current reality:
- Human/operator login identity is one system (`users`, sessions, OAuth subjects).
- Agent runtime identity is another system (`AGENT_PRIVKEY_HEX`-derived secp256k1 key).
- The discovery docs place them side by side, but the binding is declarative, not cryptographic.

# Covenant-Related Reality in the Repo

## A. Real code paths that construct / decode / verify Bitcoin scripts or descriptors

### Implemented now

#### Descriptor/script inspection in monolith
- `GET /verify_pubkey_and_list`
  - lists descriptors from Bitcoin Core
  - extracts raw script hex from descriptors
  - decodes script via `decodescript`
  - scans ASM for matching pubkeys/npubs
  - derives addresses and address balances via `listaddressgroupings`
  - extracts OP_IF / OP_ELSE pubkeys
  - computes “incoming/outgoing” totals based on heuristic role assignment
  - returns masked descriptor metadata and optional full-access-only onboarding fields

#### Script decode helper route
- `POST /decode_raw_script` (monolith)
  - expects `raw_script`
  - calls `decodescript` and `getdescriptorinfo(raw(...))`
  - extracts pubkeys / ELSE branches / early/late locks
  - builds QR payloads for descriptor, segwit address, pubkeys, and raw script

#### Descriptor import + watch-only label workflow
- `POST /import_descriptor` (monolith, full access required)
  - calls `importdescriptors`
  - if `raw(...)`, decodes script and imports an address descriptor labeled by script hex

#### Label derivation from zpub
- `POST /set_labels_from_zpub` (monolith, full access required)
  - converts zpub to xpub
  - imports/derives `wpkh(xpub/0/*)` range
  - attempts to match an existing covenant descriptor by script hex or derived pubkeys
  - labels first 20 addresses as `<script_hex> [i]`

#### Descriptor export
- `GET /export_descriptors` (monolith, full access required)
  - exports only descriptors beginning with `raw(` or `wpkh(`

#### Factory bitcoin API helpers
- `POST /api/decode_raw_script` decodes arbitrary script hex.
- `GET /api/descriptors` lists descriptors through OAuth+PAYG.
- Utility functions exist for extracting raw script and pubkeys from descriptors/ASM.

## B. Wallet/UI/explorer surfaces for covenant-related data

### Implemented now
- The monolith root and legacy UI reference an explorer/home experience centered on descriptors and covenant participants.
- `GET /verify_pubkey_and_list` is the main public JSON surface for inspecting descriptor-associated participants, balances, online status, QR codes, and masked script/address data.
- `POST /decode_raw_script`, `POST /import_descriptor`, and `POST /set_labels_from_zpub` support watch-only inspection and labeling workflows.
- The monolith links to `/export_descriptors`, not `/export_wallet`.

### Important caveat
- These are inspection/import/labeling surfaces, not covenant execution or enforcement automation.

## C. Conceptual/philosophical/docs-only covenant claims

### Docs-only or overstated relative to code
- “21-year Bitcoin contracts” as a core production-ready feature.
- Miniscript usage.
- Taproot-based covenant privacy.
- A covenant lifecycle with PSBT creation/broadcast endpoints.
- `/export_wallet` as the exported runtime endpoint.
- A PoF+covenant integrated API flow using `/pof/api/generate-challenge` and `/pof/api/verify-signatures`.

These are discussed in `docs/COVENANT_SYSTEM.md`, `docs/SYSTEM_ARCHITECTURE.md`, and other static docs, but corresponding automated runtime paths are not confirmed in the current app.

## D. Not present in repo (as actual runtime logic)

### Not found as implemented runtime features
- Miniscript compiler or policy tooling.
- Taproot covenant construction.
- Bitcoin transaction or PSBT builder for covenant creation.
- Broadcast endpoint for covenant transactions.
- On-chain covenant verification service.
- 21-year covenant state machine with maturity/unlock enforcement.
- Reciprocal/mirror covenant engine beyond descriptive text and UI language.

## Bottom-line covenant assessment

### What is real
- Descriptor import, export, decode, masking, labeling, participant extraction, and watch-only balance inspection.

### What is not real
- Automated covenant contract creation/execution system.
- On-chain proof-backed “21-year covenant” lifecycle.
- Miniscript/taproot production implementation.

### Agent-specific covenant support
- The agent advertises `covenant_decode`, but that job is a **stub**: it wraps the submitted hex in `script(...)` and flags CLTV by substring check.

# Economics / Access Model

## Runtime-enforced economics

### 1. Agent job pricing
- `ping`: 21 sats
- `verify_signature`: 21 sats
- `covenant_decode`: 21 sats

This is runtime-enforced in the agent job registry and invoice creation path.

### 2. OAuth client PAYG
**Implemented and enforced.**

Mechanism:
- OAuth bearer token establishes `client_id`.
- Protected endpoints call `require_paid_client(cost_sats=...)`.
- Billing layer creates/ensures a `ubid_clients` record.
- It first tries free quota (`HODLXXI_FREE_QUOTA_CALLS`), then sats balance.
- If neither is available, it returns HTTP 402 with `create_invoice_endpoint`.
- Top-up invoice creation/check routes create invoices in `payments_clients` and credit `sats_balance` upon settlement.

### 3. Bitcoin API pricing
- `/api/rpc/<cmd>` and `/api/descriptors` both use OAuth + PAYG, default cost 1 sat via env.

### 4. Demo protected endpoint pricing
- `/api/demo/protected` uses OAuth + PAYG with env-driven cost.

## UI wording only / partial economics

### Human developer plans (`/dev` billing)
- `free`, `builder`, and `pro` plans are defined in `app/dev_routes.py`.
- These look like session-based human developer billing/plan metadata.
- They are not the same as the OAuth client PAYG system.
- They are operationally tied to monolith session access levels and DB tables outside the cleaner factory app.

### PoF leaderboard “whale tiers”
- This is real UI and real DB-backed categorization, but it is display logic rather than payment logic.

## Documentation/proposal language only

### Not confirmed as runtime-enforced now
- membership tiers for covenant participants with unlimited usage
- covenant-based fee waivers
- durable reputation-backed pricing models
- machine-verifiable trust scores

## Reputation / trust score economics

### Actually implemented
- `reputation` is just counts of jobs and attestations.
- There is no scalar trust score or price modulation from history.

# Discovery / Interoperability Readiness

## What is already sufficient for third-party agent integration

A third-party agent can, in principle:
1. fetch `/.well-known/agent.json`
2. fetch `/agent/capabilities`
3. validate the capabilities signature with the published `agent_pubkey`
4. inspect supported jobs and pricing
5. submit a job to `/agent/request`
6. pay the Lightning invoice
7. poll `/agent/jobs/<job_id>`
8. verify the receipt via `/agent/verify/<job_id>`
9. inspect public history through `/agent/attestations`, `/agent/reputation`, and `/agent/chain/health`

That is enough for a custom integration.

## What is custom/proprietary

- Canonical JSON signing scheme for capabilities/receipts.
- Receipt payload format.
- Marketplace listing format.
- Skills catalog format.
- Job type registry format.
- `covenant_decode` job semantics.
- Payment/result polling contract.

There is no evidence of conformance to an existing standard agent protocol.

## What would block outside agents from using it today

### 1. Job retrieval omits results
This is the biggest practical blocker. The public caller gets a receipt hash, not the actual result payload.

### 2. Signature scheme is custom
An external agent needs repo-specific code to verify signed JSON receipts/capabilities.

### 3. Payment flow is custom
The repo exposes Lightning invoices, but not a standard L402 or similar machine-payment negotiation format.

### 4. Deduplication semantics are odd
Identical payloads can resolve to old jobs/receipts, which may confuse outside callers and allow unpaid reuse.

### 5. Settlement is polling-only
There is no async callback/subscription model.

### 6. `verify_signature` is not Bitcoin-message verification
It uses raw ECDSA over UTF-8 message bytes, which many Bitcoin-native counterparties will not assume.

### 7. `covenant_decode` is not a real decoder
Outside agents expecting actual script semantics will get a placeholder result.

# Centralization and Survivability Analysis

## Centralization points

### Single signing key
- Agent identity depends on one private key loaded from env/file on the server.

### Single database
- Agent jobs, receipt events, OAuth state, PoF data, and LNURL state all depend on the app database.

### Single operator-controlled web server
- Discovery, execution, billing, and verification are all server-hosted.

### Single Lightning backend configuration
- Payment realism depends on correct env configuration of LND REST or lncli.

## Hidden assumptions

- The operator will preserve the receipt DB indefinitely.
- The operator will not silently rotate or lose the agent key.
- The runtime environment will not fall back to stub Lightning in unsafe ways.
- Counterparties will understand the repo-specific signature scheme.
- Clients will treat the operator field as descriptive, not authoritative.

## Survivability if operator/server disappears

### What remains
- Any previously downloaded signed capabilities payloads and receipts.
- The pinned agent pubkey.

### What disappears
- Public discovery surface.
- Public receipt history.
- Chain-health endpoint.
- Marketplace listing.
- Job lookup.
- Any ability to prove continuity after disappearance.

## Net survivability judgment

**Low.**

The system can produce cryptographically signed artifacts, but continuity and history availability are still centrally hosted and operator-controlled.

# Contradictions / Drift

1. **Runtime entrypoint drift:** production WSGI uses `app.app`, while tests use `app.factory.create_app()`. Many tests therefore validate a different route map than the deployed runtime.

2. **Route drift: LNURL docs/README vs runtime path names:** README says `/lnurl/auth` endpoints, but actual implemented paths are under `/api/lnurl-auth/...`.

3. **Route drift: covenant export endpoint:** docs repeatedly reference `GET /export_wallet`, but the implemented monolith route is `GET /export_descriptors`.

4. **Route drift: script decode request shape:** docs show `POST /decode_raw_script` with `{"script_hex": ...}`, factory API expects `{"script": ...}`, and monolith route expects `{"raw_script": ...}`.

5. **Protocol drift: AGENT_PROTOCOL says `GET /agent/jobs/<job_id>` returns the current state and, once complete, the job result. The implementation returns only `status` and `receipt`, not the result payload.**

6. **Trust-doc drift vs actual durability:** trust docs correctly disclaim on-chain proof, but the broader narrative around durable trust actors still overstates what a single DB-backed receipt chain can deliver.

7. **Covenant docs overstate implementation:** docs claim core production-ready 21-year covenant contracts, miniscript, taproot, and a broader covenant system. Code confirms descriptor/script inspection tooling, not a production covenant execution system.

8. **PoF architecture doc drift:** docs describe challenge/signature endpoints and a full verification flow not confirmed in the actual current routes.

9. **Agent protocol/result claim drift:** repo language says “returns signed results,” but the public API exposes only signed receipts containing hashes.

10. **Marketplace/discovery readiness drift:** docs present a coherent agent surface, which is true, but external usability is limited by custom formats and missing result retrieval.

11. **LNURL-auth security drift:** code comments admit signature verification is not implemented, but the feature exists as if it were a normal auth surface.

12. **Monolith vs factory billing routes differ:** monolith logs expose compatibility routes like `/api/billing/check-invoice` and `/api/billing/create-invoice` plus monolith aliases; factory app uses only the cleaner blueprint routes. This increases operational ambiguity.

13. **Public auth exemption drift:** monolith request guard treats `/agent/jobs/<job_id>` as public GET even though comments say “Keep write or paid flows protected.” In practice, anyone with a job ID can poll it.

14. **Docs mention `/.well-known/agent.json` trust model as compact runtime summary, but the document is unsigned. The signed trust signal is really `/agent/capabilities`, not `agent.json` itself.**

# Real vs Aspirational Matrix

| Topic | Reality today | Status |
|---|---|---|
| Agent pubkey | Server-held secp256k1 key signs capabilities and receipts | Real |
| Public discovery | Custom well-known/capabilities/schema/skills/marketplace endpoints exist | Real |
| Paid agent jobs | Invoice-backed job creation exists | Real |
| Signed receipts | Receipt signatures exist and can be verified | Real |
| Public attestation history | DB-backed event log exposed over HTTP | Real |
| Public reputation | Aggregate counters only | Real but minimal |
| Chain health | Linear prev-hash integrity check only | Real but shallow |
| Agent-to-agent market readiness | Enough for custom integrations, not standard-ready | Partial |
| Bounded sovereignty Stage 1 | Public policy/status/actions surfaces exist; execute path remains protected | Partial / staging-validated |
| Return signed job results to caller | Result hashes exist; result payload not returned publicly | Partial / broken for external use |
| Verify Bitcoin signatures as agent job | Generic secp256k1 verification over message bytes | Real but custom |
| Covenant decode as agent job | Placeholder string + substring CLTV heuristic | Stubbed |
| Descriptor/covenant inspection tooling | Descriptor/script decode/import/label/export exist in monolith | Real |
| 21-year covenant system | Strongly described in docs, not fully automated in code | Docs-heavy / aspirational |
| Miniscript / Taproot covenant implementation | No concrete runtime implementation found | Docs-only / not present |
| On-chain trust anchor for agent | Explicitly not exposed | Not implemented |
| Formal human/operator ↔ agent key linkage | No cryptographic binding | Not implemented |
| Durable survivability after operator disappearance | No external anchoring/replication | Not implemented |
| OAuth2/OIDC provider | Dynamic registration + auth code + PKCE + RS256 tokens exist | Real |
| LNURL-auth | Challenge flow exists; signature verification is missing | Partial and security-weak |
| Proof-of-Funds stats/leaderboard/certificates | DB-backed read surfaces exist | Real |
| End-to-end PoF attestation issuance flow | Not clearly present in current runtime | Partial / unclear |

# Highest-Risk Assumptions

1. That a DB-local receipt chain meaningfully supports “durable trust actor” claims without external anchoring.
2. That counterparties will accept a custom secp256k1-over-canonical-JSON signature scheme.
3. That exposing a signed `result_hash` is enough even when the result payload is not public.
4. That deduplication by request hash without payer binding is acceptable.
5. That one operator-controlled server is a sufficient trust substrate for long-horizon claims.
6. That the unsigned `/.well-known/agent.json` can safely carry important discovery metadata.
7. That the `verify_signature` job’s semantics will match Bitcoin-native expectations.
8. That the `covenant_decode` job can be advertised as meaningful covenant support in its current stubbed form.
9. That production will never accidentally drift into stub/test Lightning mode.
10. That LNURL-auth is acceptable before real signature verification is implemented.
11. That tests validating the factory app are a reliable proxy for the monolith runtime.
12. That public `/agent/jobs/<job_id>` access is safe once a UUID leaks.
13. That `/api/public/status` is an acceptable amount of operational exposure for a live service.
14. That “operator” metadata will be interpreted conservatively by integrators.
15. That job/day limits implemented globally will not create trivial denial-of-service conditions.
16. That readers will not overread Stage 1 bounded sovereignty as evidence of live autonomous outbound spending when the runtime remains `observe_only`.

# Questions a Hostile Reviewer Will Ask

## Product / market
1. Why should another agent integrate this instead of directly using Lightning + a normal signed API?
2. What problem does the custom agent protocol solve that existing API auth/payment patterns do not?
3. If the public API does not return job results, what is the practical product value of the agent job loop?
4. Is the “agent marketplace” anything more than a custom listing JSON file?
5. Why is the covenant narrative so much larger than the currently automated covenant functionality?

## Trust / security
6. What exactly does the agent pubkey prove beyond “this server held a private key at some time”? 
7. Where is the cryptographic proof that the human/operator behind HODLXXI controls the agent key?
8. Why is `/.well-known/agent.json` unsigned if it is meant to be a trust-critical discovery surface?
9. Why should anyone trust LNURL-auth when the callback explicitly skips signature verification?
10. What prevents a compromised server key from rewriting the agent’s entire history?
11. How does a verifier obtain and verify the actual result payload if only its hash is exposed?
12. Why is `verify_signature` using a custom ECDSA message format instead of a Bitcoin-native standard?

## Decentralization
13. In what sense is this decentralized if discovery, history, billing, and continuity all depend on one server and one DB?
14. What part of the trust model survives without the operator’s infrastructure?
15. If the operator resets the database, how would an outside party detect a selective history rewrite?
16. Why is the “covenant-linked trust actor” thesis meaningful when no on-chain proof is published on the agent surface?

## Survivability
17. If the VPS disappears tomorrow, what evidence remains publicly available?
18. How does the system preserve attestation continuity across migrations or key rotations?
19. Is there any external witness, anchoring, or replication of receipts?
20. Can a verifier distinguish “fresh agent with empty DB” from “operator wiped bad history”?

## Economics
21. Why are all current agent jobs fixed at 21 sats regardless of complexity?
22. What prevents free-riding on deduplicated completed jobs?
23. Why is the daily job cap global instead of per user/client/IP?
24. Are the advertised agent payments real Lightning payments in all environments, or can they silently degrade to stub mode?
25. What economic penalty exists for failing to return a valid result after taking payment?

## Protocol clarity
26. Which app is actually canonical: the monolith used by WSGI or the factory used by tests?
27. What is the canonical request shape for script decode: `raw_script`, `script`, or `script_hex`?
28. Which covenant export endpoint is canonical: `/export_wallet` or `/export_descriptors`?
29. Is `/.well-known/agent.json` or `/agent/capabilities` the canonical trust source?
30. Are result payloads supposed to be public, or are hashes-only the intended design?
31. Why is the marketplace listing not versioned against an external spec?

## Adoption / interoperability
32. What existing third-party agent/tooling stack can consume this protocol without repo-specific code?
33. How would a third-party marketplace compare agents if “reputation” is only raw counters?
34. How would a third-party payer reconcile invoices/payments/results without a standard payment API contract?
35. What prevents outside integrators from misunderstanding `verify_signature` as Bitcoin-message verification?
36. Why would external agents trust covenant-related claims when the agent covenant job is plainly stubbed?

# Evidence Appendix

## Runtime entrypoint and app-shape evidence
- `wsgi.py` — WSGI entrypoint imports `app.app:app`.
- `app/app.py` — monolith app object, blueprint registration, many inline routes.
- `app/factory.py` — separate factory app used in tests.
- `tests/conftest.py` — pytest fixture constructs `create_app()` rather than importing `app.app`.

## Agent surface evidence
- `app/blueprints/agent.py` — capabilities, skills, agent discovery, request, jobs, verify, attestations, chain health, marketplace listing, reputation.
- `app/agent_signer.py` — canonical JSON signing and pubkey derivation.
- `app/models.py` — `AgentJob`, `AgentEvent` persistence model.
- `tests/integration/test_agent_ubid.py` — confirms capabilities signature, job creation, receipt minting, verify endpoint, attestation listing, marketplace listing, and stub covenant job behavior.
- **Staging-validated bounded Stage 1 runtime note:** public GET surfaces `/agent/policy`, `/agent/bounded-status`, and `/agent/actions` are now treated as working on staging; `/agent/bounded/execute` remains protected; spending posture remains `observe_only`, not live outbound autonomous spending. This refresh captures validated runtime reality without upgrading the decentralization/survivability assessment.

## Lightning/payment evidence
- `app/payments/ln.py` — LND REST, lncli, and stub backends; production guard against stub/testing modes.
- `app/billing_clients.py` — OAuth client PAYG enforcement, invoice creation, settlement crediting.
- `app/blueprints/billing_agent.py` — OAuth-protected billing endpoints.
- `tests/integration/test_billing_payg.py` — confirms 402 path, invoice top-up, and successful access after payment.

## OAuth/OIDC evidence
- `app/oidc.py` — discovery + JWKS endpoints.
- `app/blueprints/oauth.py` — client registration, authorize, token, introspection.
- `app/oauth_utils.py` — bearer token extraction and scope enforcement.
- `tests/integration/test_api_endpoints.py` — confirms OIDC discovery, JWKS, OAuth endpoint existence.

## Human identity/auth evidence
- `app/blueprints/auth.py` — Bitcoin signature login, guest login, access-level assignment.
- `app/blueprints/lnurl.py` — LNURL-auth flow with TODO-level signature trust.
- `tests/test_auth_flows.py` — confirms expected auth/guest behavior.

## PoF evidence
- `app/pof_routes.py` — PoF stats, leaderboard, certificate, verify page.
- `app/blueprints/bitcoin.py` — challenge compatibility endpoint, PSBT verification endpoint, decode script, descriptor listing.
- `app/models.py` — `ProofOfFunds`, `ProofOfFundsChallenge`.
- `tests/test_bitcoin_flows.py` — confirms PSBT verification, descriptor listing, script decode behavior.

## Covenant/tooling evidence
- `app/app.py` — `verify_pubkey_and_list`, `decode_raw_script`, `import_descriptor`, `set_labels_from_zpub`, `export_descriptors`.
- `app/utils.py` — raw script extraction and ASM pubkey helpers.
- `app/blueprints/bitcoin.py` — factory-side descriptor/script read APIs.
- `tests/test_bitcoin_flows.py` — descriptor and script utility coverage.

## Trust-model and drift evidence
- `TRUST_MODEL.md` — conservative trust language and explicit non-claims.
- `AGENT_PROTOCOL.md` — protocol claims; specifically note result-return claim drift.
- `docs/AGENT_SURFACES.md` — machine-readable discovery narrative.
- `docs/COVENANT_SYSTEM.md` — overstates covenant maturity relative to code.
- `docs/SYSTEM_ARCHITECTURE.md` — references routes/flows not fully present today.
- `README.md` — mixes accurate agent-surface claims with some path/documentation drift.

## Red-Team Input Snapshot

| Topic | Confirmed reality | Confidence (High/Medium/Low) | Evidence files | Main caveat |
|---|---|---|---|---|
| agent identity | Agent has a stable server-side secp256k1 pubkey derived from env/file and exposed publicly | High | `app/agent_signer.py`, `app/blueprints/agent.py`, `tests/integration/test_agent_ubid.py` | No formal binding to human/operator identity |
| agent pubkey | Used to sign capabilities and receipts | High | `app/agent_signer.py`, `app/blueprints/agent.py` | Custom signature format |
| Lightning payment loop | Invoice-backed agent jobs and OAuth PAYG billing both exist | High | `app/payments/ln.py`, `app/blueprints/agent.py`, `app/billing_clients.py`, `tests/integration/test_billing_payg.py` | Stub backend exists outside production |
| signed receipts | Receipts are signed and publicly verifiable | High | `app/blueprints/agent.py`, `tests/integration/test_agent_ubid.py` | Receipt omits actual result payload |
| attestations | Public DB-backed append-only receipt events exist | High | `app/models.py`, `app/blueprints/agent.py` | No external anchoring or replication |
| public discovery | Well-known, capabilities, schema, skills, listing, reputation, attestations, chain health all exist | High | `app/blueprints/agent.py`, `README.md`, `docs/AGENT_SURFACES.md` | Mostly custom/proprietary formats |
| bounded sovereignty Stage 1 | Public policy/status/actions surfaces now work on staging; execute remains protected | Medium | staging-validated runtime update captured in this audit refresh | Still observe_only; not autonomous spend |
| covenant support | Real descriptor/script inspection tooling exists; agent covenant job is stubbed | High | `app/app.py`, `app/utils.py`, `app/blueprints/bitcoin.py`, `tests/test_bitcoin_flows.py`, `tests/integration/test_agent_ubid.py` | Docs heavily overstate end-to-end covenant system maturity |
| survivability | Very low beyond saved signed artifacts | High | `TRUST_MODEL.md`, `app/blueprints/agent.py`, `app/models.py` | History is DB-local and operator-controlled |
| operator dependency | Operator/server controls key, DB, billing, discovery, and continuity | High | `wsgi.py`, `app/app.py`, `app/agent_signer.py`, `app/models.py` | No external witness or federation |
| third-party agent usability | Possible for custom integrators using repo-specific logic | Medium | `app/blueprints/agent.py`, `AGENT_PROTOCOL.md`, `docs/AGENT_SURFACES.md` | Public job retrieval does not return result payload |
