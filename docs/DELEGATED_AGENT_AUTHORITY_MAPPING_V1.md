# Delegated Agent Authority Mapping V1

Status: **PROPOSED V1 NORMATIVE CONTRACT — DOCUMENTATION ONLY — NOT CURRENT
RUNTIME STATE**

Repository evidence basis: commit
`a189eb3e8f3ffc33b0c028b2de31a622419b81ee`, inspected 2026-08-14.
No production service was queried. A source implementation described below is not
therefore a claim that the same code is deployed.

## 1. Purpose and reading rule

This document defines the canonical accountability chain:

```text
principal key
 -> delegated agent key
 -> authority scope
 -> spending limit
 -> revocation
 -> signed receipt
```

It deliberately separates four kinds of statement:

1. **Current repository truth** describes executable source, checked-in data,
 migrations, routes, and tests that exist at the evidence-basis commit.
2. **Proposed V1 normative contract** uses MUST, MUST NOT, SHOULD, and MAY to
 specify a future contract. These requirements are not implemented merely by
 appearing in this document.
3. **Future implementation work** lists code, schema, storage, and operational
 work still needed.
4. **Non-claims** state what neither current artifacts nor the proposed contract
 prove.

Documentation is not implementation evidence. In particular,
`docs/AGENT_DELEGATION_V0.md` and
`docs/schemas/agent_delegation_v0.schema.json` are planning artifacts, not a
live delegation service.

## 2. Product and trust boundaries

- HODLXXI is the identity, runtime, discovery, trust, and integration layer.
 Current project positioning calls it a public-key trust runtime and lists
 identity, capabilities, paid jobs, signed receipts, attestations, reputation,
 health, and messaging policy in `docs/RUNTIME_PRODUCT_POSITIONING.md`.
- Keymarket is a separate key-only commerce, marketplace, attestation, and
 settlement product. It is not part of this V1 runtime contract. The only
 Keymarket reference in this repository describes it as a consumer application
 built over the HODLXXI runtime idea, not the core product:
 `docs/RUNTIME_PRODUCT_POSITIONING.md`, section 5.
- Identity remains public-key-only. The canonical user record is
 `app/models.py::User`, whose identity field is `pubkey` and which has no email
 or phone field. The signature challenge entry points are
 `app/blueprints/api_auth.py::api_challenge` and `::api_verify`; supported key
 normalization is `app/auth_api_core.py::canonical_xonly_pubkey`.
- A public key is a pseudonymous cryptographic identifier, not a legal name,
 human identity, email address, phone number, KYC result, or proof of human
 presence.
- The public MCP boundary remains conservative and read-only.
 `packages/hodlxxi_mcp/src/hodlxxi_mcp/client.py::Endpoint` is a fixed endpoint
 enum and `HODLXXIReadOnlyClient.get_json` always uses GET.
 `packages/hodlxxi_mcp/src/hodlxxi_mcp/server.py::build_server` expressly
 exposes no writes, keys, wallet access, or payment action. This V1 contract
 does not add an MCP tool.
- No principal or agent receives custody, wallet control, or financial authority
 by identity, discovery, continuity, OAuth, QR, receipt, attestation, or
 reputation alone. Spending authority defaults to exactly zero and denied.
 Only a valid, current, explicit delegation may make a non-zero amount eligible,
 and even then a separately reviewed enforcement adapter is required.
- Missing, stale, contradictory, malformed, over-limit, or unavailable
 delegation, limit, or revocation state MUST fail closed.

## 3. Precise definitions

### 3.1 Principal key

The **principal key** is the root identity and authority key for one delegation.
It authorizes the immutable delegation grant by signing it. It is not inferred
from a display name, session, OAuth client, agent receipt, continuity page,
payment, CRT membership, or possession of another key.

The principal key has two distinct representations:

- `principal_key_id`: a stable, scheme-qualified identifier for key lookup and
 rotation history; and
- `principal_public_key`: the exact public key bytes used to verify the
 delegation signature.

For this proposed V1 profile, the public key is lowercase compressed secp256k1
hex (`02` or `03` followed by 64 hex characters). The identifier MUST resolve to
exactly those key bytes and the declared signature scheme. A verifier MUST NOT
silently substitute an operator key, current login key, receipt signer, CRT root
key, or similarly named record.

“Root” here means root of the delegation's authority chain. It does not mean the
CRT graph root selected by
`app/models.py::CanonicalRootRegistrationBindingRow`, and it does not confer
Bitcoin spending rights.

### 3.2 Delegated agent key

The **delegated agent key** is a separate operational key that signs each
authority-bearing operation request. It is represented by
`delegated_agent_key_id` and `delegated_agent_public_key`.

After canonical key decoding, it MUST differ from the principal key. A runtime
MUST keep the roles separate in policy decisions, storage, logs, receipts, and
user interfaces. It MUST NOT relabel the delegated key as the principal, accept
the principal's session as proof of delegated request signing, or treat a
receipt signed by the agent as a principal-signed delegation.

The static operator/agent pair in
`app/data/trust/agent_binding_hodlxxi-herald-01.json` demonstrates distinct
declared keys, but it is not a V1 delegation grant: it has no principal
signature, delegation ID, spend ledger, validity enforcement, or revocation
record.

### 3.3 Authority scope

The **authority scope** is a closed allowlist, never an open-ended capability.
It MUST bind all of the following:

- exact action names;
- exact resource identifiers or bounded resource patterns whose grammar is part
 of the schema;
- exact job types;
- exact endpoint method and normalized path pairs;
- one environment identifier, such as `development`, `staging`, or a named
 production environment;
- one or more exact audiences, normally service origins or service identifiers;
 and
- an inclusive `valid_from` and exclusive `expires_at` validity interval.

`allowed_operations` is the positive allowlist. `prohibited_operations` is an
explicit deny list for high-risk or contextually forbidden actions. The deny
list and platform-wide safety policy override the allowlist. Unknown actions,
wildcards, an empty allowlist, ambiguous path matching, method changes,
environment mismatch, audience mismatch, and anything not listed are denied.

Current adjacent code has exact action/scope matching in
`app/services/action_authorization.py::ACTION_REQUIREMENTS` and
`::authorize_action`, plus a finite OAuth scope registry in
`app/services/oauth_scope_policy.py`. Neither consumes a delegation record.

### 3.4 Spending limit

The **spending limit** is an explicit, integer-valued ceiling in one exact
currency or unit. It consists of:

- `spending_unit`, for example `sat`;
- `per_operation_limit`, the maximum amount one operation may commit;
- `period_limit`, the maximum cumulative committed amount in one period;
- `period`, a fixed-duration ISO 8601 value whose window is anchored at
 `valid_from`;
- a spending-limit `expires_at`, which may be earlier than authority expiry; and
- `enforcement_point`, the reviewed component that atomically reserves budget
 immediately before the irreversible side-effect boundary.

Amounts MUST be non-negative integers; binary floating point is forbidden. The
effective limit expiry is the earlier of authority expiry and spending-limit
expiry. A spend-capable request MUST declare its amount and unit before
authorization. Unit mismatch, absent amount, absent limit, unavailable counter,
counter overflow, or inability to reserve the amount is a denial.

For a fixed period of duration `D`, window `n` is
`[valid_from + nD, valid_from + (n + 1)D)`. Calendar months and years are not
allowed in V1 because their duration is ambiguous. A period counter includes
reserved, completed, and indeterminate amounts until a deterministic release
rule proves that no spend occurred. Concurrent checks MUST use one atomic
compare-and-reserve transaction:

```text
requested_amount <= per_operation_limit
and committed_in_window + requested_amount <= period_limit
```

The current repository's invoice prices, top-up cap, and PAYG balance debits are
commercial controls, not delegated spending authority. In particular,
`app/payments/ln.py::create_invoice` creates invoices and
`::check_invoice_paid` observes them; neither is an outgoing-payment function.

### 3.5 Revocation

**Revocation** is an append-preserved, signed decision that a named
`delegation_id` is no longer usable. It MUST identify:

- the exact delegation ID;
- the revoking authority key and its authorization basis;
- the effective `revoked_at` time;
- a monotonically ordered event or checkpoint reference;
- any successor delegation or rotated key, without mutating the old grant; and
- a signature over the complete revocation record.

The principal key is the default revoking authority. A distinct recovery or
revocation key is valid only when its key ID was explicitly authorized in the
original principal-signed grant. Key rotation creates a new key ID and new
delegation ID. It MUST NOT silently replace either public key in an existing
grant.

A verifier MUST resolve current revocation state, not trust a copied
`status=active` field. `unknown`, unreachable, stale, contradictory, or
signature-invalid revocation state is denied. Revocation MUST be rechecked with
the spending reservation immediately before execution so a prior successful
check cannot be replayed across a revocation race.

### 3.6 Signed receipt

The **signed receipt** is cryptographic evidence of the authority decision and
operation outcome. It MUST bind at least:

- principal and delegated key IDs;
- `delegation_id` and a digest of the verified grant;
- the exact operation, resource, endpoint, environment, audience, and scope
 actually used;
- the nonce and delegated request hash;
- the amount requested, reserved, and actually spent, including unit and limit
 window;
- the revocation status/reference checked at the enforcement point;
- result state and `result_hash`;
- start, completion, and issuance times;
- receipt ID, signer key, signature scheme, canonicalization, and verification
 endpoint.

The receipt signer is an explicitly registered runtime receipt key. It is not
silently the principal and need not be the delegated agent. A valid signature
proves only that this signer attested to the signed fields. It does not by itself
prove legal authority, external settlement, absence of side effects, global
consensus, or truth of an omitted request/result body.

## 4. Current repository truth

### 4.1 Evidence inventory

| Area | Executable or checked-in evidence | What exists now | Boundary |
| --- | --- | --- | --- |
| Public-key identity | `app/models.py::User`; `app/auth_api_core.py::canonical_xonly_pubkey`; `app/auth_api_core.py::verify_nostr_login_event`; `app/blueprints/api_auth.py::api_challenge`, `::api_verify` | Pubkey records, key normalization, challenges, and signature verification. | No principal-signed delegation issuance or principal/delegate role binding. |
| Operator continuity | `app/blueprints/agent.py::_operator_continuity_payload`, `::operator_continuity`; route `GET /.well-known/hodlxxi-operator.json`; `tests/integration/test_operator_continuity_surface.py::test_operator_continuity_endpoint_contract` | Declares distinct operator and runtime agent keys, `key_status=active`, unfunded covenant status, and a documented rotation policy. | Payload is a declaration, not a signed delegation, revocation ledger, or authority enforcement input. |
| Static operator/agent binding | `app/data/trust/agent_binding_hodlxxi-herald-01.json`; `app/services/trust_surface.py::load_agent_binding` | Static pair and `authority.may_publish` descriptions. | Loader reads/falls back to JSON; it does not verify a principal signature or enforce operations. |
| Existing delegation contract | `docs/AGENT_DELEGATION_V0.md`; `docs/schemas/agent_delegation_v0.schema.json`; `tests/unit/test_agent_delegation_v0_contract.py` | Documentation-phase schema with issuer, subject, scopes, limits, status, verification metadata, non-claims, and a placeholder/future signature. | The document explicitly says no route, table, migration, runtime verification, or enforcement exists. |
| Delegation route absence | `tests/integration/test_agent_surface_machine_readable_contract.py::test_capabilities_do_not_advertise_qr_or_delegation_runtime_endpoints`; `app/contracts/qr_pointer_v0.py::FUTURE_DELEGATION_TARGET_PREFIXES` | Tests keep delegation paths out of capabilities; QR boundary code rejects future delegation paths. | `/.well-known/agent-delegation.json` and `/agent/delegations...` are not current runtime surfaces. |
| Exact action policy | `app/services/action_authorization.py::ACTION_REQUIREMENTS`, `::authorize_action`; `tests/unit/test_action_authorization_policy.py::test_missing_exact_scope_and_broad_scope_are_denied`, `::test_operator_has_no_implicit_bypass` | Fail-closed exact action, scope, identity, ownership, and step-up decisions. | Module describes itself as future policy and has no delegation input. |
| OAuth scope/token checks | `app/services/oauth_scope_policy.py::KNOWN_SCOPES`; `app/services/oauth_bearer_validation.py::validate_canonical_access_token_with_config`; `app/models.py::OAuthToken`; `tests/unit/test_oauth_bearer_validation.py::test_rejects_issuance_record_disagreement` | Finite scopes and checks for issuer, audience, subject, expiry, JTI, stored digest, user state, and token revocation. | An OAuth bearer principal is not a delegation and the canonical bearer decorator is not used by a route at this commit. |
| Fresh key-possession proof | `app/services/action_step_up.py::StepUpChallenge`, `::ActionStepUpService`; `app/models.py::ActionStepUpChallenge`; `migrations/2026-07-20_action_step_up_challenges.sql` | Domain-separated, request-bound BIP-340 proof with random nonce, short expiry, and one-time consumption. | It proves one actor's fresh key possession; it does not prove a principal delegated authority or spending approval. |
| Replay/idempotency storage | `app/services/action_idempotency.py`; `app/services/action_operation_storage.py::SqlAlchemyActionOperationRepository`; `app/services/action_step_up_operation_storage.py::SqlAlchemyAtomicStepUpOperationRepository`; `migrations/2026-07-20_action_operations.sql`; `migrations/2026-07-21_action_step_up_operation_binding.sql` | Durable idempotency namespace, request fingerprint, state transitions, and atomic step-up-consume/operation-reserve primitive. | Components are for dormant internal actions and have no delegation or spending counter fields. |
| Internal action orchestration | `app/services/internal_action_gateway.py::InternalActionGateway`; `tests/integration/test_internal_action_gateway.py::test_real_atomic_step_up_gateway_consumes_reserves_receipts_and_replays` | Source/test composition of bearer validation, entitlement, scope, atomic replay control, dispatch, and action receipts. | No Flask route, MCP tool, production handler registry, delegation validator, revocation resolver, or spend adapter constructs it. |
| Strict action receipts | `app/services/action_receipt.py::create_action_receipt`, `::verify_action_receipt`; `app/models.py::ActionOperation`; `tests/unit/test_action_receipt.py::test_real_der_signature_and_every_security_mutation_fails` | Strict domain-separated ECDSA action receipt with actor, action, request/result hashes, policy decision, signer, and timestamps. | It has no principal key, delegation ID, authority-scope snapshot, revocation evidence, or amount fields. It is not exposed by a route. |
| Paid agent jobs | `app/models.py::AgentJob`; `app/blueprints/agent.py::JOB_REGISTRY`, `::create_job_request`, `::get_job`; routes `POST /agent/request` and `GET /agent/jobs/<job_id>` | Fixed priced jobs, inbound invoice creation/checking, request/result hashes, and daily global job cap. | A requester paying an invoice is not the agent spending funds and is not delegated financial authority. |
| Paid-job receipts | `app/models.py::AgentEvent`; `app/blueprints/agent.py::_build_receipt`, `::verify_job_receipt`, `::download_job_receipt_json`; `tests/unit/test_agent_receipt_requester_pubkey.py::test_new_receipt_v1_additive_fields_are_signed`, `::test_receipt_json_download_endpoint_returns_standalone_receipt` | Signed `hodlxxi.receipt.v1` paid-job receipts include request/result/payment hashes, amount in sats, signer, and verifier URL. | They do not identify a principal-signed delegation, limit reservation, or revocation check. |
| Attestations and continuity | `app/blueprints/agent.py::_event_attestation`, `::attestations`, `::trust_events`, `::chain_health`; `app/models.py::AgentEvent` | Public receipt-event views and local `prev_event_hash` continuity. | This is a local log, not global consensus, a revocation registry, or delegated authority. |
| Payment controls | `app/blueprints/billing_agent.py::_agent_billing_max_amount_sats`, `::create_agent_invoice`; `app/billing_clients.py::_debit_balance`, `::require_paid_client`; `migrations/2026-02-10_client_billing.sql`; `tests/integration/test_billing_payg.py` | Per-top-up invoice cap, zero-default client balance/quota, conditional balance debit, and 402 on insufficient balance. | These meter incoming PAYG service use. They are not per-delegation outgoing spend limits or custody. |
| Lightning boundary | `app/payments/ln.py::_create_invoice_lnd_rest`, `::_create_invoice_lnd_cli`, `::check_invoice_paid`; `app/agent_invoice_api.py::agent_create_invoice`, `::agent_lookup_invoice` | Invoice creation and settlement observation. The internal helper is loopback/token guarded and caps invoice amount. | No application function in these paths pays an invoice. No current agent-spend authority is established. |
| Read-only Bitcoin/MCP boundaries | `app/blueprints/bitcoin.py::SAFE_RPC_METHODS`, `::rpc_command`; `tests/test_bitcoin_flows.py::TestBitcoinRPC::test_rpc_dangerous_command_blocked`; `packages/hodlxxi_mcp/src/hodlxxi_mcp/client.py::HODLXXIReadOnlyClient`; `packages/hodlxxi_mcp/tests/test_allowlist.py::test_exact_endpoint_inventory` | Feature-gated read-only Bitcoin RPC allowlist and fixed-origin GET-only MCP allowlist. | No wallet send, arbitrary RPC, generic URL, MCP write, or payment action is authorized. |
| CRT root/continuity lifecycle | `app/models.py::CanonicalRootRegistrationBindingRow`; `app/services/canonical_root_registration_binding.py::CanonicalRootRegistrationBinding`; `migrations/2026-08-11_canonical_root_registration_binding_v1.sql` | Dormant append-preserved root-registration selection with lifecycle states including revoked/superseded. | This is CRT graph selection, not agent delegation and not a substitute for a principal-signed grant. |

### 4.2 Current conclusions

The repository does **not** currently implement the complete mapping in this
document. A repository-wide `rg` search for `delegation_id`,
`principal_key_id`, and `delegated_agent_key_id` finds no application model,
migration, service, or route using those V1 fields. The only non-documentation
references to future delegation routes are guards/tests that reject or omit
them.

Two existing documents lag later source and must not be used alone as status
evidence:

- `docs/MCP_READONLY_WRAPPER.md` calls the wrapper documentation-only, while the
 implemented package and tests now live under `packages/hodlxxi_mcp/`.
- `docs/INTERNAL_ACTION_GATEWAY_V1.md` describes a missing atomic step-up reserve
 primitive, while
 `app/services/action_step_up_operation_storage.py::SqlAlchemyAtomicStepUpOperationRepository`
 and its integration tests now implement that primitive. The gateway is still
 dormant and unrouted.

The present paid-agent receipt route is real source behavior, but it proves a
runtime-signed job record, not delegated authority. The present billing code
meters service consumption and receives Lightning payments; it does not prove
that the agent can pay, hold funds, or exercise financial authority.

## 5. Proposed V1 normative contract

### 5.1 Artifacts

The complete contract consists of four independently parseable artifacts and a
read-only verification bundle:

1. `hodlxxi.delegation_grant.v1`: immutable principal-signed grant.
2. `hodlxxi.delegated_operation_request.v1`: delegated-agent-signed request for
 one operation.
3. `hodlxxi.delegation_revocation.v1`: append-only revocation or rotation event,
 when one exists.
4. `hodlxxi.delegated_authority_receipt.v1`: runtime-signed outcome and authority
 evidence.
5. `hodlxxi.delegated_agent_authority_mapping.v1`: a read-only bundle that
 carries or references the artifacts needed for independent verification.

The grant, operation request, revocation record, and receipt MUST each reject
unknown fields in V1. An implementation MUST NOT merge them into a mutable row
whose history can be overwritten. Storage projections MAY cache current state,
but the signed source artifacts and transition history remain authoritative.

### 5.2 Canonical key, signature, time, and hash rules

- V1 public keys are lowercase 33-byte compressed secp256k1 hex.
- V1 `signature_scheme` is exactly
 `secp256k1_ecdsa_sha256_der_hex`. Signatures are strict DER, lowercase hex,
 and low-S. Other schemes require a new contract version.
- V1 `canonicalization` is exactly `rfc8785_jcs`. Signing implementations MUST
 implement RFC 8785 rather than assume that one language's sorted JSON is
 equivalent.
- A grant signs JCS bytes of
 `{"domain":"HODLXXI_DELEGATION_GRANT_V1","payload":<unsigned-grant>}`.
- A request signs JCS bytes of
 `{"domain":"HODLXXI_DELEGATED_OPERATION_REQUEST_V1","payload":<unsigned-request>}`.
- A revocation signs JCS bytes of
 `{"domain":"HODLXXI_DELEGATION_REVOCATION_V1","payload":<unsigned-revocation>}`.
- A receipt signs JCS bytes of
 `{"domain":"HODLXXI_DELEGATED_AUTHORITY_RECEIPT_V1","payload":<unsigned-receipt>}`.
- `request_hash`, `result_hash`, grant hashes, and receipt hashes are lowercase
 SHA-256 hex over the applicable domain-separated canonical bytes. A hash of an
 omitted body proves only commitment to the bytes available to the hasher.
- Timestamps are UTC RFC 3339 strings in the single form
 `YYYY-MM-DDTHH:MM:SSZ`. `valid_from` is inclusive and `expires_at` is
 exclusive. Verifiers MUST use a bounded, configured clock-skew policy and MUST
 NOT extend expiry because a client clock is wrong.
- IDs are opaque, stable, case-sensitive strings with schema-defined length and
 character ceilings. V1 examples use UUID URNs; an implementation MUST reject
 aliases that resolve ambiguously.

### 5.3 Canonical field-level mapping

This is the canonical field mapping across the four artifacts. “Copied into
receipt” means the receipt either carries the exact value or a signed digest of
the complete source object as stated; it never means the runtime may reinterpret
the value.

| Field | Canonical artifact / JSON location | Required type and meaning | Normative verification rule | Current repository correspondence |
| --- | --- | --- | --- | --- |
| `principal_key_id` | grant `/principal_key_id`; receipt `/principal_key_id` | Stable scheme-qualified ID of the delegation root authority key. | Resolve to exactly `principal_public_key`; verify grant signature; never infer from operator/session/receipt signer. | Static operator ID/key exists in `app/blueprints/agent.py::_operator_continuity_payload`; no delegation key ID exists. |
| `principal_public_key` | grant `/principal_public_key` | Lowercase compressed secp256k1 key that signs the grant. | Validate curve point and declared format; MUST differ canonically from delegated key. | Pubkeys exist in `app/models.py::User` and continuity data; not principal-role bound. |
| `delegated_agent_key_id` | grant and request `/delegated_agent_key_id`; receipt `/delegated_agent_key_id` | Stable ID for the operational signer. | Resolve to the exact delegated public key and match request signer. | Static agent key is declared, but no delegation key ID exists. |
| `delegated_agent_public_key` | grant `/delegated_agent_public_key` | Lowercase compressed secp256k1 operational key. | Verify every delegated request; MUST NOT be treated as principal. | Runtime agent signing key is exposed by `app/agent_signer.py::get_agent_pubkey_hex`; no delegation binding. |
| `delegation_id` | every artifact `/delegation_id` | Unique immutable grant identifier. | Exact equality across grant, request, revocation resolution, limit ledger, and receipt. | No application field or migration. |
| `authority_scope` | grant `/authority_scope` | Closed object containing operations, resources, job types, endpoints, environment, audience, and validity. | Reject unknown/empty/ambiguous members; hash the entire object into the receipt. | v0 docs schema has `authority.scopes/resources`; current action policy has narrower adjacent pieces only. |
| `allowed_operations` | grant `/authority_scope/allowed_operations` | Non-empty unique array of exact action names. | Requested operation MUST appear exactly once; no wildcard or prefix implication. | `app/services/action_authorization.py::ACTION_REQUIREMENTS` is an exact registry but is not grant-derived. |
| `prohibited_operations` | grant `/authority_scope/prohibited_operations` | Unique explicit deny array. | A match denies even if also allowed; platform denies also apply. | Delegation v0 non-claims forbid raw execution conceptually; no runtime field. |
| `resources` | grant `/authority_scope/resources` | Exact IDs or schema-defined bounded patterns. | Requested resource MUST match one rule under one normalization algorithm. | `ActionRequest.resource_owner_pubkey` and step-up `resource_id` are adjacent, not delegation scope. |
| `job_types` | grant `/authority_scope/job_types` | Exact allowed job types. | Requested job type MUST be present and registered; unknown means deny. | `app/blueprints/agent.py::JOB_REGISTRY` registers runtime jobs; it is not per principal/delegate. |
| `endpoints` | grant `/authority_scope/endpoints` | Array of exact `{method,path}` pairs. | Normalize once; method and path must both match; redirects do not widen authority. | Current MCP uses a fixed GET endpoint enum; no delegated endpoint list. |
| `environment` | grant `/authority_scope/environment`; request/receipt same field | Exact named runtime environment. | Runtime-configured environment MUST equal it; no fallback between staging and production. | Feature gates distinguish production, but no delegation environment binding exists. |
| `audience` | grant `/authority_scope/audience`; request/receipt same field | Non-empty exact service identifier/origin array. | Executing service MUST be an exact member; do not trust Host alone. | OAuth tokens validate `aud`; delegation records do not. |
| `spending_unit` | grant `/spending_limit/spending_unit`; request and receipt corresponding fields | Registered unit such as `sat`. | Exact equality across request, ledger, adapter, and receipt. | Agent jobs store `sats`; no delegated unit field. |
| `per_operation_limit` | grant `/spending_limit/per_operation_limit`; receipt `/limit_snapshot/per_operation_limit` | Non-negative integer maximum per operation. | Requested and committed amounts MUST be less than or equal; absent means zero/deny. | Billing top-up cap is unrelated; v0 docs-only schema has `max_sats_per_request`. |
| `period_limit` | grant `/spending_limit/period_limit`; receipt `/limit_snapshot/period_limit` | Non-negative integer cumulative ceiling. | Atomic committed total including this request MUST not exceed it. | No per-delegation cumulative ledger. |
| `period` | grant `/spending_limit/period`; receipt `/limit_snapshot/period` | Fixed ISO 8601 duration anchored at `valid_from`. | Reject calendar-variable or unsupported duration; derive one deterministic window. | No per-delegation period counter. |
| `valid_from` | grant `/authority_scope/valid_from`; receipt `/authority_snapshot/valid_from` | Inclusive authority start. | `decision_time >= valid_from`; not-yet-valid grants deny. | Step-up challenges have adjacent issued/expiry checks; no delegation validity. |
| `expires_at` | grant `/authority_scope/expires_at` and `/spending_limit/expires_at`; receipt snapshots both | Exclusive authority and limit expiry. | Decision and atomic pre-execution recheck must precede both expiries. | OAuth, step-up, and invoice artifacts expire separately; no delegation expiry enforcement. |
| `enforcement_point` | grant `/spending_limit/enforcement_point`; receipt `/limit_snapshot/enforcement_point` | Exact reviewed adapter/service identifier. | Runtime component must equal it and atomically reserve before side effect. | No delegated spend adapter. |
| `revocation_status` | resolver result and receipt `/revocation_status` | `not_revoked`, `revoked`, or `unknown`. | Only fresh, authenticated `not_revoked` can proceed; `unknown` denies. | Other domains have revocation fields; delegation does not. |
| `revoked_at` | revocation `/revoked_at`; receipt `/revoked_at` nullable | Effective UTC instant, null only when freshly resolved not revoked. | At or after this instant, unexecuted authority is invalid. | Continuity rotation is documented only; no delegation revocation record. |
| `revocation_reference` | resolver result and receipt `/revocation_reference` | Immutable event/checkpoint ID or digest plus resolvable read-only reference. | Verify signature, authority, delegation ID, ordering, and freshness. | No delegation status endpoint or checkpoint. |
| `revoking_authority_key_id` | grant policy, revocation, receipt when revoked | Principal or pre-authorized recovery/revocation key ID. | Must be authorized by original grant and verify revocation signature. | No delegation revoker registry. |
| `successor_delegation_id` | revocation optional field | New grant created for rotation; never an in-place key replacement. | Resolve independently; old grant remains revoked and historical. | Operator rotation policy is narrative only. |
| `nonce` | request `/nonce`; receipt `/nonce` | Unique random 32-byte lowercase hex value per delegation. | Atomically reserve once; any reuse denies or returns the exact prior receipt without re-execution. | Step-up nonce/consumption is reusable design evidence, not delegation-bound. |
| `request_hash` | request and receipt `/request_hash` | SHA-256 commitment to the full domain-separated canonical request. | Recompute; request includes delegation, scope selectors, amount, nonce, audience, and environment. | Paid jobs and action operations already store request hashes. |
| `request_signature` | request `/request_signature` | Delegated-agent signature over the complete unsigned request envelope. | Verify with the grant's delegated key before any reservation. | Agent messages and step-up proofs sign requests; delegation requests do not exist. |
| `result_hash` | receipt `/result_hash` | SHA-256 commitment to exact canonical result bytes; null only for a defined explicit failure. | Recompute when result is available and enforce state/null conditional rules. | `AgentJob.result_hash` and action receipts implement adjacent result hashes. |
| `amount_requested` | request and receipt `/amount_requested` | Non-negative integer proposed amount. | Required for any spend-capable operation and included in budget reservation. | No delegated request amount. |
| `amount_reserved` | receipt `/amount_reserved` | Amount held against the limit at dispatch. | Must equal the ledger reservation and be at least actual spend. | No delegated ledger. |
| `amount_spent` | receipt `/amount_spent` | Actual amount committed/settled by the operation; zero for no spend. | Same unit; `0 <= spent <= reserved <= limits`; external settlement may need separate evidence. | Paid-job receipt has `amount_sats`, but that is incoming job price, not agent spend. |
| `receipt_id` | receipt `/receipt_id` | Globally unique immutable receipt identifier. | Must map to one exact canonical signed receipt and idempotency namespace. | Paid receipt uses `hodlxxi-receipt-v1:<job_id>`; action receipt uses UUID. |
| `receipt_signer_key` | receipt `/receipt_signer_key` | Exact compressed public key for the registered receipt signer. | Validate registration for audience/environment/time; never assume it is principal. | Paid receipts expose `signing_key`; action receipts use `signer_public_key`. |
| `receipt_signature` | receipt `/receipt_signature` | Strict DER low-S ECDSA signature as lowercase hex. | Verify over domain-separated canonical unsigned receipt; any mutation invalidates it. | Current paid receipt calls it `signature`; strict action receipt has `signature`. |
| `signature_scheme` | each signed artifact `/signature_scheme` | Exact algorithm identifier; V1 value fixed above. | Algorithm/key-format mismatch or unknown value denies; no downgrade. | Strict action receipts declare this exact scheme; paid receipts do not carry the full identifier. |
| `canonicalization` | each signed artifact `/canonicalization` | Exact canonical JSON identifier; V1 is `rfc8785_jcs`. | Reproduce exact bytes; unsupported value denies. | Current code uses sorted compact Python JSON, not RFC 8785. |
| `issued_at` | grant and receipt `/issued_at`; request uses its own issue time | UTC time the signer issued that artifact. | Must be canonical, within validity, and consistent with execution ordering. | Current receipts have `timestamp`; action receipts have start/completion times. |
| `verification_endpoint` | receipt `/verification_endpoint` | Same-origin or explicitly allowlisted HTTPS read-only verifier URL/path. | Endpoint must return exact bytes/status evidence and must not mutate, execute, delegate, revoke, or pay. | Current paid receipt uses `/agent/verify/<job_id>`; no delegated-authority verifier exists. |

### 5.4 Authority and spending snapshots in receipts

The receipt MUST include `delegation_grant_hash`, `authority_scope_hash`, and the
exact `limit_snapshot` used. A verifier MUST obtain the matching immutable grant
and request, not accept receipt copies as a replacement for the principal and
delegated signatures. Snapshot fields make the decision auditable; the original
signed artifacts establish authority.

For a non-spending operation, all of `amount_requested`, `amount_reserved`, and
`amount_spent` MUST be zero. A non-zero amount is invalid when the action is not
declared spend-capable. An implementation MUST NOT reinterpret invoice price,
account credit, a Bitcoin balance, covenant amount, or proof-of-funds value as a
delegated spending limit.

## 6. Complete verification and execution flow

The required order is:

```text
principal authorization
 -> delegation validation
 -> scope validation
 -> spending-limit validation
 -> revocation check
 -> operation execution
 -> signed receipt creation
 -> independent verification
```

### 6.1 Principal authorization

1. Parse the exact grant schema and reject duplicate or unknown fields.
2. Resolve `principal_key_id` to the exact declared key bytes and key state.
3. Recompute the domain-separated canonical grant bytes.
4. Verify the principal signature with the declared scheme.
5. Confirm the principal and delegated keys are distinct and role-bound.
6. Reject any attempt to derive principal authorization from OAuth, a session,
 the continuity declaration, a receipt signer, CRT state, or payment.

### 6.2 Delegation validation

1. Validate `delegation_id`, key IDs, schema version, timestamps, audience,
 environment, canonicalization, and algorithm.
2. Require `valid_from <= decision_time < expires_at`.
3. Verify the delegated operation request signature with the exact delegated
 key from the grant.
4. Recompute `request_hash` and bind the delegation ID, operation, resource, job
 type, endpoint, amount/unit, audience, environment, nonce, and request time.
5. Reject nested delegation in V1. Only the principal may issue the one-hop
 grant; the delegated agent may not subdelegate.

### 6.3 Scope validation

1. Match the exact operation against `allowed_operations`.
2. Apply `prohibited_operations` and platform deny policy first.
3. Match exact resource, job type, endpoint method/path, environment, and
 audience.
4. Reject wildcard, ambiguous normalization, redirect expansion, alternate
 environment, and unregistered job/action values.

### 6.4 Spending-limit validation

1. Determine whether the action can spend. If it can, require exact integer
 amount and unit; otherwise require all amounts to be zero.
2. Load the delegation's current period window and committed total.
3. Validate per-operation, period, and expiry ceilings.
4. Prepare an atomic reservation, but do not execute yet.
5. Treat absent or unavailable limit state as zero/denied.

### 6.5 Revocation check and atomic authorization boundary

1. Resolve a fresh signed revocation status for the exact delegation.
2. Validate revoker authority, effective time, sequence/checkpoint, signature,
 and freshness.
3. In one transaction, require `not_revoked`, recheck validity/limit expiry,
 reserve the nonce, reserve the idempotency namespace, and reserve the amount.
4. The successful transaction is the authorization boundary. A failed or
 ambiguous transaction executes nothing.
5. Immediately before dispatch, compare the persisted request and decision
 digests. No caller-supplied `revocation_status`, spend counter, or
 “already_verified” boolean is authoritative.

### 6.6 Operation execution

Only a new, committed authorization reservation may cross the dispatch boundary.
The handler receives the immutable canonical request bytes or a trusted parsed
view of exactly those bytes. It cannot widen scope, change amount, choose another
audience/environment, or replace keys. Retries return prior state and MUST NOT
blindly re-execute. An uncertain side effect becomes `indeterminate`; its amount
remains committed until reconciliation proves otherwise.

### 6.7 Signed receipt creation

After a deterministic success or explicit deterministic failure, the runtime
constructs the receipt from persisted trusted evidence, not handler-supplied
authority fields. It computes the result hash, records actual amount and state,
copies the limit/revocation decision references, signs once, verifies its own
signature, and stores the exact canonical bytes. A signing or finalization
failure after dispatch yields `indeterminate`, not an unsigned success and not
an automatic retry.

### 6.8 Independent verification

An independent verifier:

1. parses all artifacts strictly;
2. verifies principal, delegated-request, revocation/checkpoint, and receipt
 signatures under their distinct roles;
3. recomputes the grant, scope, request, result, and receipt hashes;
4. checks time, environment, audience, endpoint, resource, job type, operation,
 prohibited-operation, and amount bindings;
5. validates the receipt's limit window/counter reference and
 `amount_spent <= amount_reserved <= limits`;
6. resolves current revocation state as well as the historical state referenced
 by the receipt;
7. confirms the receipt ID returns the same canonical bytes from the read-only
 verification endpoint; and
8. reports each dimension separately. A valid receipt signature MUST NOT be
 summarized as “all authority and settlement verified” when a grant,
 revocation, limit, result, or external settlement check is missing.

## 7. Delegation lifecycle behavior

### 7.1 Issuance

- The principal constructs a complete grant with zero spending by default.
- The issuer validates that the delegated key is separate, scopes are finite,
 forbidden actions are denied, validity is bounded, and revocation lookup is
 configured.
- The principal signs the immutable grant. Publication and activation are
 separate: an unpublished or unresolvable grant cannot be consumed.
- A runtime may require an additional human/operator approval artifact, but
 MUST NOT claim the delegation itself proves human consent.

### 7.2 Consumption

- The delegated key signs one complete operation request.
- One nonce is usable once within one delegation.
- Scope, limit, expiry, and revocation checks occur for every operation, not only
 at session or token issuance.
- The amount and nonce reservation is atomic with the final pre-dispatch
 revocation check.
- Exact replay returns the stored receipt/state. A changed payload with the same
 nonce or idempotency key is a conflict and never executes.

### 7.3 Rotation

- Principal rotation and delegated-key rotation both create new key IDs and a
 new principal-signed delegation ID.
- Normal rotation SHOULD be cross-signed by the old principal key and MUST be
 signed by the new principal key. Emergency recovery uses only a recovery key
 explicitly named in the old grant and is visibly labeled.
- The old delegation is revoked with a successor reference. History and prior
 receipts remain verifiable; the old grant is never rewritten.
- A receipt signer rotates through a separate signed signer registry. Receipt
 signer rotation does not rotate the principal or delegated key.

### 7.4 Expiry

- Authority is not valid before `valid_from` and is invalid at
 `decision_time >= expires_at`.
- There is no automatic renewal, grace period, session carry-over, or legacy
 fallback.
- In-flight work that has not crossed dispatch stops. Work already dispatched
 follows the indeterminate/reconciliation rules and the receipt records the
 exact authorization and dispatch times.

### 7.5 Revocation

- Revocation is append-only and effective at `revoked_at`.
- The resolver retains all prior grant, rotation, status, and receipt evidence.
- Cached “not revoked” answers have a short explicit freshness bound. Cache
 expiry, resolver failure, fork/sequence conflict, or missing record denies.
- An old delegated request cannot be replayed after revocation even if its
 request signature and original validity interval are otherwise valid.

## 8. Security invariants

1. Principal and delegated keys are cryptographically distinct and never
 interchangeable.
2. Only a principal-signed immutable grant creates delegation authority.
3. Authority is the intersection of all allowlists, validity, platform policy,
 spending limits, and fresh non-revocation state; no source broadens another.
4. Anything not explicitly allowed is denied.
5. Explicit prohibitions override allowances.
6. Spending authority is zero unless every required non-zero limit field is
 present, current, same-unit, and atomically enforceable.
7. Limit and revocation storage failure denies; it never falls back to cached
 unlimited authority or a legacy path.
8. One nonce and idempotency namespace can dispatch at most once.
9. Authorization checks and spend reservation precede side effects; ambiguous
 post-dispatch state is never automatically replayed.
10. Receipt fields come from persisted trusted evidence, not caller or handler
 claims.
11. Receipt signing keys, delegated keys, and principal keys have separate roles
 and rotation histories.
12. Canonicalization and signature schemes are explicit and downgrade-resistant.
13. Revocation and rotation preserve historical grants and receipts.
14. Read-only discovery, verification, QR, attestation, and MCP surfaces never
 create authority or execute operations.
15. OAuth scopes, CRT membership/entitlement, billing balance, payment, and
 operator status are independent predicates and never implicit delegation.

## 9. Threat model and defenses

| Threat | Attack | Required defense |
| --- | --- | --- |
| Principal/delegate confusion | Present the operational key, agent receipt signer, or current session as the principal. | Role-specific fields, distinct keys, principal grant signature, and no implicit key substitution. |
| Forged or widened grant | Add an operation, endpoint, audience, time, or limit after signing. | Strict schema, domain-separated signature, complete canonical coverage, and immutable grant hash. |
| Confused deputy | Use a valid request against another service, environment, resource, endpoint, job type, or method. | Bind exact audience, environment, operation, resource, job type, endpoint method/path, delegation ID, and amount in both request and receipt. |
| Replay | Reuse a signed request or race the same nonce concurrently. | Random per-delegation nonce, durable uniqueness, atomic nonce/idempotency/amount reservation, and exact stored-receipt replay. |
| Revocation race | Pass a stale status check, then execute after revocation. | Fresh signed status and atomic recheck with final reservation immediately before dispatch. |
| Limit race | Concurrent requests each observe budget below the ceiling. | One transactional compare-and-reserve counter including reserved/indeterminate amounts. |
| Unit confusion | Treat sats as msats, fiat minor units, account credits, or BTC. | Registered exact unit, integer values, and unit equality across grant, request, adapter, ledger, and receipt. |
| Expiry bypass | Continue using a session/token after delegation expiry. | Per-operation grant/limit expiry checks with no session carry-over or grace fallback. |
| Key rotation rollback | Serve an old key/grant as current or silently replace key bytes under one ID. | Append-only key/grant history, monotonic checkpoints, successor references, and immutable key-ID resolution. |
| Algorithm/canonicalization confusion | Verify different bytes or downgrade to a permissive algorithm. | Contract-fixed scheme/canonicalization, domain separation, strict DER/low-S, duplicate-field rejection, no fallback. |
| Receipt laundering | Show a valid runtime receipt as proof of principal authority, consent, or external settlement. | Verify the entire artifact chain and present granular verification results/non-claims. |
| Result substitution | Pair a receipt with a different result or omit a failure. | Canonical result hash, conditional state rules, and exact receipt bytes. |
| Handler authority injection | Handler supplies its own principal, scope, amount, revocation, or receipt fields. | Construct receipts only from persisted gateway evidence; handler returns result or bounded failure only. |
| Availability downgrade | Revocation/limit/signature service fails and legacy behavior permits execution. | Fail closed with stable unavailable state; no legacy or documentation fallback. |
| Metadata correlation | Public keys, amounts, resources, and timestamps link activity across contexts. | Data minimization, audience-specific delegated keys, hashed bounded references, retention limits, and no contact-identifier collection. |

### 9.1 Replay and confused-deputy details

The delegated request signature MUST cover the complete request, including the
nonce. The `request_hash` alone is not an authentication credential. Nonce
uniqueness is scoped to `delegation_id`, while idempotency uniqueness SHOULD be
scoped to `(delegation_id, delegated_agent_key_id, idempotency_key_hash)`.

Exact replay after completion returns byte-identical stored receipt content and
does not sign again. Replay while reserved/executing returns in-progress;
indeterminate returns indeterminate. Same nonce/idempotency key with any changed
request binding returns conflict without revealing the old body.

An endpoint path is matched only after one specified normalization pass. Query
parameters that affect authority are part of the signed resource/request and
cannot be added by a redirect or proxy. The service derives its own audience and
environment from trusted configuration; caller headers are not authoritative.

## 10. Receipt verification rules

A receipt is valid only when all of these are true:

- exact schema and field set;
- supported canonicalization and signature scheme;
- valid registered receipt signer for the receipt's audience, environment, and
 issuance time;
- valid receipt signature over the exact unsigned receipt;
- exact match to one verified principal-signed grant and delegated-signed
 request;
- correct grant, scope, request, result, authorization-decision, limit-window,
 and revocation-reference hashes;
- valid ordering
 `grant.issued_at <= valid_from <= request.issued_at <= dispatch_at <= completed_at <= receipt.issued_at`,
 subject to explicit failure/indeterminate rules;
- dispatch before authority and limit expiry;
- operation/resource/job/endpoint/environment/audience within scope and absent
 from prohibitions;
- nonce/idempotency evidence consistent with one execution;
- amount/unit arithmetic valid and within both limits; and
- historical revocation state permits the recorded dispatch time, while current
 revocation state is reported separately.

The verification response SHOULD expose separate booleans or reason codes for
grant signature, request signature, scope, limits, historical revocation,
current revocation, receipt signature, result hash, and external settlement.
It MUST NOT collapse unknown external settlement into success.

The verification endpoint is read-only. A GET or verification request MUST NOT
consume a nonce, reserve budget, execute an operation, create a receipt, change
revocation, rotate a key, create/pay an invoice, or mutate trust/reputation.

## 11. Failure behavior

| Condition | Required behavior |
| --- | --- |
| Missing grant, principal key, delegated key, delegation ID, signature, scope, limit, nonce, request hash, or revocation reference | Deny before reservation and execution. Missing spending fields mean zero, not unlimited. |
| Malformed JSON, duplicate/unknown field, invalid key/ID/time/amount, unsupported scheme or canonicalization | Deny as malformed; do not attempt a permissive parser or legacy format. |
| Invalid principal signature | Deny as unauthorized; do not treat continuity, OAuth, or an agent signature as replacement proof. |
| Invalid delegated request signature or key mismatch | Deny as unauthorized; do not reserve nonce or budget unless the transaction can roll back completely. |
| Not yet valid or expired authority/limit | Deny; no grace period, session carry-over, renewal assumption, or fallback. |
| Scope, resource, job type, endpoint, method, environment, or audience mismatch | Deny with a bounded reason that does not echo secrets. |
| Prohibited operation | Deny even if also allowlisted. |
| Missing amount/unit for a spend-capable action, unit mismatch, negative/overflow value, per-operation overage, period overage, or unavailable counter | Deny; default effective authority is zero. |
| Revoked delegation | Deny at or after the effective time and return the verified revocation reference when disclosure is safe. |
| Unknown, stale, contradictory, unreachable, or invalidly signed revocation state | Deny as authorization unavailable; never assume not revoked. |
| Nonce replay or idempotency conflict | Return exact prior state/receipt for an exact replay, otherwise conflict; never redispatch. |
| Execution fails explicitly before an irreversible side effect | Release reservation only under an atomic deterministic rule; a signed failure receipt MAY be issued. |
| Side-effect outcome is uncertain | Mark indeterminate, retain committed budget, issue no fabricated success/failure receipt, and require explicit reconciliation. |
| Receipt signing/finalization fails after dispatch | Mark indeterminate and do not retry automatically. |
| Receipt missing, malformed, signature-invalid, hash-mismatched, or signer unregistered | Report invalid/unverifiable; never infer success from job state, payment, QR, or attestation alone. |
| Verification endpoint unavailable | Local cryptographic checks MAY still be reported individually, but current revocation and online consistency remain unknown and authority MUST NOT be reused. |

## 12. Privacy for public-key-only identity

V1 requires no email address or phone number. Implementations MUST NOT introduce
either as a hidden prerequisite, recovery shortcut, correlation key, delegation
identifier, or public receipt field. Recovery uses explicitly declared
cryptographic recovery/revocation keys, not contact identifiers.

Public-key-only does not mean anonymous. Stable keys, key IDs, delegation IDs,
audiences, resources, exact amounts, timestamps, endpoints, and receipt chains
can be highly linkable. Implementations SHOULD:

- use audience- or purpose-specific delegated keys where accountability permits;
- publish public keys and hashes, never private keys, seeds, macaroons, bearer
 tokens, raw idempotency keys, or wallet metadata;
- keep raw request/result bodies out of public receipts and use hashes only when
 verifiers have an authorized way to obtain the corresponding bytes;
- recognize that hashes of low-entropy payloads can be guessed and therefore are
 not automatic redaction;
- minimize public resource identifiers and use opaque IDs rather than human
 labels;
- disclose exact amount/time only when accountability needs them, while never
 omitting them from the protected audit record;
- define retention for grants, revocations, nonce records, limit ledgers, and
 receipts; and
- preserve revocation and accountability history without publishing unnecessary
 contact or behavioral metadata.

Loss of a key has no email/phone recovery path by design. The grant must name a
cryptographic recovery/revocation mechanism in advance or authority remains
unrecoverable until a separately trusted principal transition is established.

## 13. NON-NORMATIVE EXAMPLE — NOT PRODUCTION STATE

The following JSON is illustrative only. It uses `example.invalid`, example IDs,
zero spending authority, and placeholder signatures/hashes. It is not a valid
signature vector, current delegation, route response, configuration, database
row, operator approval, or production state.

```json
{
 "schema": "hodlxxi.delegated_agent_authority_mapping.v1",
 "delegation": {
 "schema": "hodlxxi.delegation_grant.v1",
 "delegation_id": "urn:uuid:11111111-1111-4111-8111-111111111111",
 "principal_key_id": "urn:hodlxxi:key:example:principal-01",
 "principal_public_key": "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
 "delegated_agent_key_id": "urn:hodlxxi:key:example:agent-01",
 "delegated_agent_public_key": "02c6047f9441ed7d6d3045406e95c07cd85a200ce959f2815b16f817984cfe",
 "authority_scope": {
 "allowed_operations": [
 "job.propose"
 ],
 "prohibited_operations": [
 "wallet.pay_invoice",
 "wallet.send",
 "shell.execute"
 ],
 "resources": [
 "urn:hodlxxi:job-type:ping"
 ],
 "job_types": [
 "ping"
 ],
 "endpoints": [
 {
 "method": "POST",
 "path": "/agent/request"
 }
 ],
 "environment": "example",
 "audience": [
 "https://authority.example.invalid"
 ],
 "valid_from": "2026-08-14T00:00:00Z",
 "expires_at": "2026-08-15T00:00:00Z"
 },
 "spending_limit": {
 "spending_unit": "sat",
 "per_operation_limit": 0,
 "period_limit": 0,
 "period": "P1D",
 "expires_at": "2026-08-15T00:00:00Z",
 "enforcement_point": "hodlxxi.example.no-spend-gateway.v1"
 },
 "revocation_policy": {
 "revoking_authority_key_ids": [
 "urn:hodlxxi:key:example:principal-01"
 ],
 "status_endpoint": "https://authority.example.invalid/delegations/urn%3Auuid%3A11111111-1111-4111-8111-111111111111/status"
 },
 "issued_at": "2026-08-14T00:00:00Z",
 "signature_scheme": "secp256k1_ecdsa_sha256_der_hex",
 "canonicalization": "rfc8785_jcs",
 "delegation_signature": "PLACEHOLDER_NOT_A_VALID_SIGNATURE"
 },
 "operation_request": {
 "schema": "hodlxxi.delegated_operation_request.v1",
 "delegation_id": "urn:uuid:11111111-1111-4111-8111-111111111111",
 "delegated_agent_key_id": "urn:hodlxxi:key:example:agent-01",
 "operation": "job.propose",
 "resource": "urn:hodlxxi:job-type:ping",
 "job_type": "ping",
 "endpoint": {
 "method": "POST",
 "path": "/agent/request"
 },
 "environment": "example",
 "audience": "https://authority.example.invalid",
 "spending_unit": "sat",
 "amount_requested": 0,
 "nonce": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
 "issued_at": "2026-08-14T00:01:00Z",
 "request_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
 "signature_scheme": "secp256k1_ecdsa_sha256_der_hex",
 "canonicalization": "rfc8785_jcs",
 "request_signature": "PLACEHOLDER_NOT_A_VALID_SIGNATURE"
 },
 "revocation_resolution": {
 "delegation_id": "urn:uuid:11111111-1111-4111-8111-111111111111",
 "revocation_status": "not_revoked",
 "revoked_at": null,
 "revocation_reference": "urn:hodlxxi:revocation-checkpoint:example:42",
 "checked_at": "2026-08-14T00:01:01Z"
 },
 "receipt": {
 "schema": "hodlxxi.delegated_authority_receipt.v1",
 "receipt_id": "urn:uuid:22222222-2222-4222-8222-222222222222",
 "delegation_id": "urn:uuid:11111111-1111-4111-8111-111111111111",
 "principal_key_id": "urn:hodlxxi:key:example:principal-01",
 "delegated_agent_key_id": "urn:hodlxxi:key:example:agent-01",
 "delegation_grant_hash": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
 "authority_scope_hash": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
 "operation": "job.propose",
 "resource": "urn:hodlxxi:job-type:ping",
 "job_type": "ping",
 "endpoint": {
 "method": "POST",
 "path": "/agent/request"
 },
 "environment": "example",
 "audience": "https://authority.example.invalid",
 "nonce": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
 "request_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
 "result_hash": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
 "state": "completed",
 "spending_unit": "sat",
 "amount_requested": 0,
 "amount_reserved": 0,
 "amount_spent": 0,
 "limit_snapshot": {
 "per_operation_limit": 0,
 "period_limit": 0,
 "period": "P1D",
 "window_started_at": "2026-08-14T00:00:00Z",
 "committed_before": 0,
 "committed_after": 0,
 "enforcement_point": "hodlxxi.example.no-spend-gateway.v1"
 },
 "revocation_status": "not_revoked",
 "revoked_at": null,
 "revocation_reference": "urn:hodlxxi:revocation-checkpoint:example:42",
 "started_at": "2026-08-14T00:01:01Z",
 "completed_at": "2026-08-14T00:01:02Z",
 "issued_at": "2026-08-14T00:01:02Z",
 "receipt_signer_key": "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
 "receipt_signature": "PLACEHOLDER_NOT_A_VALID_SIGNATURE",
 "signature_scheme": "secp256k1_ecdsa_sha256_der_hex",
 "canonicalization": "rfc8785_jcs",
 "verification_endpoint": "https://authority.example.invalid/delegated-authority/receipts/urn%3Auuid%3A22222222-2222-4222-8222-222222222222/verify"
 }
}
```

## 14. Implementation-status matrix

The status values in this matrix are exhaustive. `IMPLEMENTED` means present in
repository source with direct tests or executable contract evidence; it does not
mean deployed. `PARTIAL` means a cited component exists but does not satisfy the
complete V1 capability. Documentation never upgrades a row to implemented.

| Capability | Status | Exact repository evidence and boundary |
| --- | --- | --- |
| Pubkey user record and signature-auth entry points | PARTIAL | `app/models.py::User`; `app/blueprints/api_auth.py::api_challenge`, `::api_verify`; `app/auth_api_core.py::verify_nostr_login_event`. These authenticate/control one key but do not issue a principal-to-delegate grant. |
| No-email/no-phone user identity record | IMPLEMENTED | `app/models.py::User` stores `id`, `pubkey`, timestamps, metadata, and active state, with no email or phone column; `app/blueprints/api_auth.py::api_challenge` accepts a pubkey. This claim is limited to the canonical repository user/auth path. |
| Distinct operator and agent continuity declaration | PARTIAL | `app/blueprints/agent.py::_operator_continuity_payload`, route `::operator_continuity`; `app/data/trust/agent_binding_hodlxxi-herald-01.json`; `tests/integration/test_operator_continuity_surface.py::test_operator_continuity_endpoint_contract`. It is a declaration, not a signed grant. |
| Delegation v0 canon and schema | DOCUMENTED_ONLY | `docs/AGENT_DELEGATION_V0.md`; `docs/schemas/agent_delegation_v0.schema.json`; `tests/unit/test_agent_delegation_v0_contract.py`. |
| Delegation discovery/index/detail routes | MISSING | The intended paths are reserved only in `docs/AGENT_DELEGATION_V0.md`; `tests/integration/test_agent_surface_machine_readable_contract.py::test_capabilities_do_not_advertise_qr_or_delegation_runtime_endpoints` asserts they are absent from capabilities. |
| Principal-signed delegation issuance and verification | MISSING | No application service, model, migration, route, or test consumes a principal-signed delegation grant. |
| Delegation persistence and append-only lifecycle | MISSING | No delegation table/migration exists. Existing lifecycle tables are CRT/current-entitlement domains and cannot substitute. |
| Delegation revocation resolver/checkpoint | MISSING | `status=revoked` exists only in the documentation schema; no delegation revocation route, signed record, or resolver exists. |
| Operator/delegated key rotation enforcement | DOCUMENTED_ONLY | `docs/OPERATOR_CONTINUITY_E923.md`, section “Rotation policy,” and `app/blueprints/agent.py::_operator_continuity_payload` describe policy but implement no signed transition verification. |
| Exact finite action/scope policy | PARTIAL | `app/services/action_authorization.py::ACTION_REQUIREMENTS`, `::authorize_action`; tests `test_missing_exact_scope_and_broad_scope_are_denied`, `test_operator_has_no_implicit_bypass`. It is fail-closed but not delegation-driven or route-wired. |
| OAuth audience, expiry, issuance-record, and token-revocation checks | PARTIAL | `app/services/oauth_bearer_validation.py::validate_canonical_access_token_with_config`; `app/models.py::OAuthToken`; `tests/unit/test_oauth_bearer_validation.py::test_valid_real_canonical_jwt_and_exact_principal`, `::test_rejects_issuance_record_disagreement`. These are OAuth checks, not delegation checks. |
| Request-bound nonce and one-time key-possession proof | PARTIAL | `app/services/action_step_up.py::ActionStepUpService`; `app/services/action_step_up_storage.py::SqlAlchemyActionStepUpRepository.consume`; `migrations/2026-07-20_action_step_up_challenges.sql`; `tests/unit/test_action_step_up.py`. It is not bound to a principal-signed delegation. |
| Atomic step-up consumption and action reservation | PARTIAL | `app/services/action_step_up_operation_storage.py::SqlAlchemyAtomicStepUpOperationRepository.reserve_with_step_up`; `migrations/2026-07-21_action_step_up_operation_binding.sql`; `tests/integration/test_action_step_up_operation_storage.py::test_concurrent_identical_requests_resolve_new_and_replay`. It has no limit/revocation transaction. |
| Durable action idempotency and no blind replay | PARTIAL | `app/services/action_operation_storage.py::SqlAlchemyActionOperationRepository`; `app/services/internal_action_gateway.py::InternalActionGateway`; `tests/unit/test_internal_action_gateway.py::test_completed_once_persists_only_hashes_and_valid_receipt_then_exact_replays`. Gateway is dormant and lacks delegation. |
| Per-delegation spending unit/per-operation/period limit ledger | MISSING | No grant-linked amount, unit, period-window, or cumulative counter exists in application models or migrations. |
| Inbound paid-job pricing and invoice lifecycle | IMPLEMENTED | `app/blueprints/agent.py::JOB_REGISTRY`, `::create_job_request`, `::get_job`; `app/models.py::AgentJob`; `app/payments/ln.py::create_invoice`, `::check_invoice_paid`; route tests in `tests/unit/test_agent_receipt_requester_pubkey.py`. This is inbound commerce, not agent spend. |
| OAuth client PAYG balance debit and top-up cap | IMPLEMENTED | `app/billing_clients.py::_debit_balance`, `::require_paid_client`; `app/blueprints/billing_agent.py::_agent_billing_max_amount_sats`; `migrations/2026-02-10_client_billing.sql`; `tests/integration/test_billing_payg.py`. This is account metering, not delegated financial authority. |
| Outgoing Lightning payment/custody adapter for an agent | MISSING | Invoice modules expose creation/lookup only. This document makes no claim that any current agent can pay or hold funds. |
| Current paid-job signed receipt creation | IMPLEMENTED | `app/blueprints/agent.py::_build_receipt`; `app/agent_signer.py::sign_message`; `app/models.py::AgentEvent`; `tests/unit/test_agent_receipt_requester_pubkey.py::test_new_receipt_v1_additive_fields_are_signed`. |
| Current paid-job receipt signature verification route | IMPLEMENTED | Route `GET /agent/verify/<job_id>` in `app/blueprints/agent.py::verify_job_receipt`; `app/agent_signer.py::verify_message`; `tests/unit/test_agent_receipt_requester_pubkey.py::test_receipt_json_download_endpoint_returns_standalone_receipt`. |
| Full independent paid-job semantic verification | PARTIAL | The route verifies the stored receipt signature and computes event hash in `verify_job_receipt`; request/result recomputation and independent Lightning settlement remain verifier responsibilities in `docs/RECEIPT_VERIFICATION.md`. |
| Strict domain-separated action receipt component | PARTIAL | `app/services/action_receipt.py::create_action_receipt`, `::verify_action_receipt`; `tests/unit/test_action_receipt.py::test_real_der_signature_and_every_security_mutation_fails`. It is unrouted and lacks delegation/amount/revocation fields. |
| Delegation-aware signed authority-use receipt | MISSING | Neither current receipt shape contains `delegation_id`, principal authority, scope/limit snapshot, or revocation evidence. |
| Receipt attestation list and local hash continuity | IMPLEMENTED | `app/models.py::AgentEvent`; routes/functions `app/blueprints/agent.py::attestations`, `::trust_events`, `::chain_health`; `tests/integration/test_agent_surface_machine_readable_contract.py::test_agent_trust_events_shape_contract`, `::test_chain_health_shape_contract`. |
| Complete ordered V1 verification/execution flow | MISSING | Adjacent components are not composed with a delegation validator, revocation resolver, or spending ledger. |
| Conservative fixed-origin GET-only MCP boundary | IMPLEMENTED | `packages/hodlxxi_mcp/src/hodlxxi_mcp/client.py::Endpoint`, `::HODLXXIReadOnlyClient.get_json`; `packages/hodlxxi_mcp/src/hodlxxi_mcp/server.py::build_server`; `packages/hodlxxi_mcp/tests/test_allowlist.py::test_exact_endpoint_inventory`; `packages/hodlxxi_mcp/tests/test_tool_inventory.py::test_server_registers_exactly_26_tools`. |
| Deployment of this proposed V1 contract | UNKNOWN | Production was intentionally not accessed, and no repository route/storage implementation for this V1 exists to deploy. |

## 15. Explicit non-claims

- This document does not activate delegation, change authorization, create a
 route, migrate a database, configure production, or grant anyone authority.
- The current HODLXXI agent is not shown by repository evidence to spend funds,
 pay invoices, hold custody, or exercise delegated financial authority.
- An inbound Lightning invoice, paid job, PAYG balance, receipt amount, Bitcoin
 balance, proof of funds, or declared covenant amount is not a spending
 delegation.
- The operator continuity endpoint and Herald binding are public declarations,
 not principal-signed V1 grants.
- OAuth bearer possession and scope are not proof that a principal delegated an
 agent key.
- A fresh step-up signature proves bounded key possession, not delegation,
 consent, ownership, spending approval, or execution.
- CRT genesis, membership, root-registration binding, FULL/LIMITED entitlement,
 sponsor lineage, and `current_144` continuity are distinct domains and do not
 substitute for this contract.
- A signed receipt proves that the receipt signer signed the included fields. It
 does not alone prove legal authority, human identity, human consent, external
 settlement, locked capital, custody, correctness, global consensus, or future
 behavior.
- A receipt, attestation, QR pointer, discovery document, marketplace listing,
 reputation surface, or MCP response does not create or expand authority.
- Keymarket is not implemented or governed by this document. Future Keymarket
 integration must consume verified HODLXXI evidence across an explicit product
 boundary and apply its own commerce/settlement policy.
- No statement here is a legal conclusion or a claim that public-key control
 proves authority recognized by a third party or jurisdiction.

## 16. Prioritized future implementation gaps

1. **P0 — Freeze exact schemas and vectors.** Create separately reviewed JSON
 Schemas for grant, request, revocation, receipt, and verification bundle;
 specify RFC 8785, domain separation, strict key/signature rules, duplicate
 rejection, test vectors, and stable reason codes.
2. **P0 — Implement principal issuance and delegated request verification.** Add
 explicit key-role resolution, principal-signed issuance, delegated request
 signing, one-hop-only policy, and negative tests proving neither key is
 silently substituted.
3. **P0 — Add append-only delegation/revocation storage.** Use additive
 migrations, immutable grants/events, signed revoker authority, monotonic
 checkpoints, exact effective times, historical retention, and fail-closed
 current-state resolution.
4. **P0 — Add atomic nonce, revocation, and spending enforcement.** Extend the
 existing action reservation pattern with per-delegation nonce uniqueness,
 fixed-window integer counters, zero defaults, reserved/indeterminate
 accounting, and one transaction immediately before dispatch.
5. **P0 — Extend strict receipts for authority evidence.** Bind grant/scope,
 delegated request signature, amount/unit/limit window, historical revocation,
 result, and exact signer registry; store and replay byte-identical receipts.
6. **P0 — Keep all spend adapters absent by default.** Any future outgoing
 Lightning or wallet adapter requires a separate security review, explicit
 enablement, least-privilege credentials, staging proof, kill switch,
 reconciliation, and no MCP exposure by implication.
7. **P1 — Add read-only publication and verification routes.** Only after P0,
 publish a delegation index/detail/status and receipt verifier with strict
 privacy, caching, freshness, and non-mutation tests. Do not add write-capable
 MCP tools in the same change.
8. **P1 — Add rotation and recovery operations.** Implement old/new key
 cross-signing, pre-authorized emergency recovery, successor links, signer
 registry rotation, rollback/fork detection, and operator runbooks.
9. **P1 — Add end-to-end adversarial tests.** Cover malformed and duplicate JSON,
 signature/canonicalization confusion, scope and audience confusion, concurrent
 limit races, revocation races, replay, expiry boundaries, storage outage,
 indeterminate side effects, privacy leakage, and exact receipt retrieval.
10. **P2 — Define the separate Keymarket integration contract.** After HODLXXI V1
 is implemented and reviewed, define how Keymarket consumes grants,
 attestations, receipts, and settlement evidence without moving marketplace,
 custody, or settlement policy into the HODLXXI core.

No item in this gap list is implemented by this documentation change.
