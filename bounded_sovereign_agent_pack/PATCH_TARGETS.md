# PATCH_TARGETS

| File | Current role | Proposed change | Why needed | Risk | Depends on |
|---|---|---|---|---|---|
| `wsgi.py` | Live WSGI entrypoint imports `app.app` | Add runtime-truth note or switch only if explicitly planned later | Prevent sovereignty patches from landing in a dead path | Medium | None |
| `app/app.py` | Monolithic live runtime and route registration hub | Ensure new policy/action/budget routes are actually registered in live runtime | Current production truth lives here | High | Step 1 |
| `app/factory.py` | Partial modular runtime path | Mirror new sovereignty routes/helpers for parity, but only after monolith path works | Reduces future drift | Medium | Step 1 |
| `app/blueprints/agent.py` | Existing agent discovery, paid jobs, receipts, reputation, chain health | Add policy publication, action log routes, capability executor, budget/public proof routes, and policy enforcement hooks | This is the natural place to extend bounded sovereignty with minimal invasiveness | High | Steps 2-7 |
| `app/agent_signer.py` | Agent pubkey derivation and secp256k1 signing | Reuse for policy manifest, action log entries, budget summaries, continuity checkpoints | Current signer already anchors agent identity | Low | Step 2 |
| `app/models.py` | SQLAlchemy persistence for jobs, events, PoF, OAuth, billing | Add policy manifest table and action-log / budget tables or extend `AgentEvent` safely | Need durable storage for policy versions, action history, and budget checkpoints | High | Steps 2-6 |
| `app/payments/ln.py` | Lightning invoice create/check wrapper | Add budget-funding wrapper and, only if later approved, tiny outbound-pay interface behind strict policy checks | Needed for treasury funding and bounded spend enforcement | High | Step 6 |
| `app/agent_invoice_api.py` | Loopback-only internal invoice creation via lncli + invoice macaroon | Keep invoice-only scope; optionally reuse for treasury funding endpoints; do not widen to outbound pay | Useful safe primitive, but dangerous if expanded casually | Medium | Step 6 |
| `app/billing_clients.py` | OAuth client PAYG balances and top-up handling | Reuse balance/invoice patterns conceptually; do not overload client billing as agent treasury | Existing model informs minimal budget design | Low | Step 6 |
| `app/ubid_membership.py` | In-memory browser-user PAYG logic | Use only as conceptual reference for small balance semantics; avoid using as sovereign treasury backend | Too ephemeral for durable sovereign budget state | Medium | None |
| `.well-known/agent.json` | Checked-in discovery document/example | Update or regenerate to include policy and proof surface references once runtime routes exist | Public discovery should advertise the new proof surfaces | Medium | Steps 2, 7 |
| `docs/AGENT_SURFACES.md` | Secondary docs for current agent discovery surfaces | Document new policy/budget/action-log endpoints and privacy boundaries | Needed to reduce docs-vs-runtime drift | Low | Step 7 |
| `TRUST_MODEL.md` | Trust language and assurance boundaries | Add bounded sovereignty wording and explicit non-claims | Align published claims with runtime truth | Low | Step 8 |
| `AGENT_PROTOCOL.md` | Agent discovery/job/receipt protocol description | Extend with policy manifest and action-log verification model | Keeps counterparties aligned with runtime changes | Low | Step 8 |
| `tests/` | Existing auth, OAuth, and some runtime tests | Add tests for policy signature verification, continuity, deny-by-default behavior, and budget limits | Prevent silent regression into over-broad authority | Medium | Steps 2-8 |
