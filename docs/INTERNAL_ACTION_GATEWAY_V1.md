# Internal Action Gateway v1

## Purpose and dormant boundary

`InternalActionGateway` is an endpoint-independent Python orchestrator for the authenticated-action contracts delivered in PR1–PR5. It is deliberately dormant. This change registers no production handler and adds no Flask route or blueprint, MCP tool/resource/prompt, discovery record, well-known document, runtime service, deployment configuration, or application-factory wiring.

The only actions structurally eligible for an injected test or future internal handler are `self_read` and `job_create`. Neither has a production handler. In particular, `job_create` is not connected to the paid-job `/agent/request`, invoice, Lightning, payment, or paid-job receipt flow.

## Trusted dependency boundary

Construction requires an injected canonical bearer validator, current-entitlement resolver, `ActionOperation` repository, immutable `ActionName`-keyed handler mapping, receipt signer callback, compressed signer public key, timezone-aware clock, and optionally an authoritative ownership resolver. The gateway does not construct applications, database engines, keys, wallets, LND or Bitcoin clients, paid-job services, or MCP servers. Caller-supplied identity, scopes, JTI, digests, decisions, policy versions, ownership, or step-up status are not accepted.

The internal invocation contains an encoded bearer, expected OAuth client ID, action, nullable resource ID, raw idempotency key, JSON-compatible payload, and optional non-authoritative step-up proof. Identifiers are bounded. Payloads accept only exact JSON value types: null, booleans, integers, finite floats, strings, lists, and dictionaries with exact string keys. Python-only containers, binary values, custom mappings or sequences, non-finite numbers, and cycles are rejected rather than normalized. Payloads use UTF-8 canonical JSON with `sort_keys=True`, `separators=(",", ":")`, and `ensure_ascii=True`. Canonical requests are limited to 65,536 bytes. The request SHA-256 is computed internally from those canonical bytes.

## Invocation and authorization order

For a new invocation the gateway:

1. Validates the invocation shape, identifiers, idempotency key, action name, and canonical payload.
2. Calls the injected canonical bearer validator and requires its `BearerPrincipal.client_id` to equal the expected client ID.
3. Resolves current entitlement from persisted state.
4. Rejects step-up-required, non-LIMITED/FULL-only, ownership-unresolved, structurally ineligible, and unregistered actions before reservation.
5. Calls `authorize_action` with the principal subject and scopes, current entitlement evidence, only authoritative ownership evidence, and `step_up_verified=False`.
6. Requires `ActionDecision.allowed=True`.
7. Hashes the full `ActionDecision.to_dict()` as SHA-256 over the same canonical JSON convention. This binds `allowed`, `reason_code`, `actor_pubkey`, `identity_class`, `action`, `required_scope`, `current_access_level`, `resource_owner_pubkey`, `ownership_required`, `step_up_required`, and `policy_version`; there is no second policy representation.
8. Internally derives the idempotency-key hash, token-reference hash, request hash, and request fingerprint, then reserves the operation.

Authorization always precedes durable reservation.

## Reservation, dispatch, and terminal receipts

Only a `new` reservation may proceed. The successful `reserved -> executing` compare-and-set transition is the dispatch boundary; the handler cannot run if that transition fails. A handler receives only the immutable canonical JSON request bytes used for `request_sha256`; it never receives or re-reads the caller-owned Python object. A handler must return either a completed result with a JSON-compatible payload or an explicit failed result with a bounded stable failure code. Arbitrary exceptions are not a normal handler protocol.

For completion, the gateway canonicalizes the result exactly once and hashes those exact bytes without persisting its body. For explicit failure, it accepts no result bytes or digest. It builds receipts exclusively with `create_action_receipt`, using the persisted operation ID and execution boundary plus trusted principal, request, policy, decision, clock, and signer evidence. Step-up receipt fields are always `None` in v1. Handlers cannot override receipt evidence.

The gateway does not persist the raw bearer, raw idempotency key, raw request body, raw result body, or step-up signature. The PR5 operation schema necessarily stores the validated token JTI and derived token-reference hash; it never stores the encoded token.

## Replay and uncertainty

An exact retry reserves no second namespace and never dispatches or signs again. A persisted `completed` or `failed` operation returns `stored_receipt_bytes` unchanged and is labeled `replay`; no receipt is reconstructed. A conflicting payload returns `idempotency_conflict` without disclosing the prior payload. Existing `reserved` or `executing` operations return `operation_in_progress`. Existing `indeterminate` operations return `operation_indeterminate`.

After execution begins, unexpected handler exceptions, signing/receipt-validation failures, and terminal finalization failure or uncertainty attempt `executing -> indeterminate`. They do not fabricate a failed receipt and never automatically redispatch. Confirmed marking returns `operation_indeterminate`; if indeterminate state cannot be confirmed, the gateway returns `gateway_internal_failure` and remains fail-closed. Only an explicit structured handler failure can create a normal failed receipt.

## Receipt retrieval

Retrieval is an internal Python method, not an endpoint. It validates a fresh bearer and current entitlement, loads the operation, and authorizes `action_receipt_read_self`. The persisted operation `actor_pubkey` is the authoritative resource owner; caller-provided ownership is neither requested nor trusted. A different actor is denied. Nonterminal operations do not produce reconstructed receipts, and terminal stored bytes are returned unchanged.

## Current limitations and PR6.1

Current persisted active users resolve only to `IdentityClass.LIMITED` with `current_full_relation_satisfied=False`. Consequently FULL-only and covenant actions remain unavailable, including `covenant_draft_create` and `covenant_draft_read_self`. There is also no generic authoritative ownership resolver registered for production actions.

Most importantly, the repository has no transaction that atomically combines step-up challenge verification/consumption with `ActionOperation` reservation. `ActionStepUpService` consumes through its challenge repository while `SqlAlchemyActionOperationRepository` reserves through a separate session and transaction. All step-up-required actions therefore fail before reservation and dispatch as `gateway_action_unavailable`; an optional proof cannot change that result. PR6.1 may introduce a single atomic consume-and-reserve primitive. It must not be approximated or hidden by orchestration.

Later work may add separately reviewed real action adapters and rollout. This v1 makes no claim of wallet control, Bitcoin transaction creation, LND payment, covenant construction or execution, filesystem or shell mutation, paid-job activation, or any production action activation.
