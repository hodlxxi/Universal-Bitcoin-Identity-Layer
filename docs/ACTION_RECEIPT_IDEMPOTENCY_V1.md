# Canonical Action Receipts and Durable Idempotency v1

This document defines a dormant internal foundation. It registers no route, blueprint, MCP tool, resource, or prompt; performs no authorization; and executes no action. The repository APIs are unsafe to expose directly. Authorization denial must occur before a future reservation.

## Constants and canonical receipt

- receipt schema: `hodlxxi.action-receipt.v1`
- signature domain: `HODLXXI_ACTION_RECEIPT_V1`
- signature scheme: `secp256k1_ecdsa_sha256_der_hex`
- idempotency digest domain: `HODLXXI_ACTION_IDEMPOTENCY_KEY_V1`
- operation contract: `hodlxxi.action-operation.v1`

The exact receipt fields are `schema`, `receipt_id`, `operation_id`, `idempotency_key_sha256`, `actor_pubkey`, `oauth_client_id`, `token_reference_sha256`, `action`, `resource_id`, `request_sha256`, `policy_version`, `authorization_decision_sha256`, `step_up_challenge_id`, `step_up_verification_sha256`, `state`, `started_at`, `completed_at`, `failure_code`, `result_sha256`, `signer_public_key`, `signature_domain`, `signature_scheme`, and `signature`. Extra and missing fields are rejected. `created_at`, `verifier_url`, and `previous_receipt_hash` are not fields.

Canonical JSON is UTF-8 JSON with `sort_keys=True`, `separators=(",", ":")`, `ensure_ascii=True`, and no whitespace. UTC timestamps use six fractional digits and `Z`. The signed bytes are the canonical object `{"domain":"HODLXXI_ACTION_RECEIPT_V1","receipt":<the exact receipt without signature>}`. Verification uses SHA-256, strict DER ECDSA, secp256k1, and the compressed `signer_public_key` embedded in that receipt. Unknown schemas, states, keys, encodings, and malformed signatures fail closed. Runtime key wiring is absent; callers inject a signer callback and its public identity.

Only `completed` and `failed` are final receipt states. Completed requires `result_sha256` and forbids `failure_code`. Failed requires `failure_code` and forbids `result_sha256`; v1 defines no meaningful partial-result digest. Step-up challenge and verification digests are paired. A stored terminal retry returns canonical bytes from the persisted receipt and never reconstructs or re-signs it.

## Idempotency and state

Keys are strings of 8–200 ASCII characters from letters, digits, `.`, `_`, `~`, `:`, `+`, `/`, `=`, and `-`. They are not trimmed or normalized; whitespace, Unicode, and controls are rejected. Plaintext is never persisted. The digest is `sha256(UTF8("HODLXXI_ACTION_IDEMPOTENCY_KEY_V1") || 0x00 || UTF8(raw_key))`.

The unique namespace is `(actor_pubkey, oauth_client_id, idempotency_key_sha256)`. The request fingerprint is SHA-256 over canonical JSON binding the operation contract version, actor x-only public key, OAuth client ID, raw internal token JTI, action, nullable resource ID, request SHA-256, and nullable step-up challenge ID. The public receipt contains only a token-reference digest.

The states are `reserved`, `executing`, `completed`, `failed`, and `indeterminate`. Allowed transitions are:

- `reserved -> executing`
- `reserved -> failed`
- `executing -> completed`
- `executing -> failed`
- `executing -> indeterminate`

Every transition is a conditional compare-and-set. Completed and failed rows are immutable. Reservation relies on the database unique constraint plus insert, `IntegrityError` rollback, reload, and fingerprint comparison—not SELECT then INSERT. Identical concurrent callers converge on one operation ID; a different fingerprint returns stable `idempotency_conflict`. PostgreSQL supplies the production uniqueness semantics. SQLite file-backed tests exercise the same races, although SQLite serializes writers differently.

`reserved` is a durable reservation with no receipt. `executing` means the dispatch boundary was entered and automatic blind replay is forbidden. `indeterminate` means the side-effect outcome cannot be proven: there is no automatic execution and no final receipt until a later explicit reconciliation contract. Crashes before dispatch can leave a reserved row; crashes after dispatch may require indeterminate recovery. PR5 provides no automatic reconciliation and no automatic deletion or retention cleanup.

## Security boundary and protocol separation

No bearer token, OAuth client secret, raw key, private key, wallet seed, macaroon, raw request or result body, proof signature, step-up nonce, payment credential, or database exception is persisted or emitted. The raw token JTI is internal only. client-supplied `step_up_verified` is never authoritative; a reconstructed `VerifiedStepUp` object is never authoritative. PR5 does not decide whether an operation is authorized. Payment success is not authorization success.

This protocol is separate from the paid-job `hodlxxi.receipt.v1` protocol. Paid-job receipts cannot satisfy OAuth, scope, entitlement, ownership, step-up, action authorization, or action idempotency. Action receipts have no invoice, settlement, Lightning, or payment fields.

## PR5 / PR6 split

PR5 owns data contracts, canonicalization, hashing, the strict receipt parser/verifier, injected signer interface, key digest, request fingerprint, state machine, model and migration, atomic repository primitives, tests, and this documentation.

PR6 owns the trusted internal action entrypoint, bearer validation, scope enforcement, current entitlement, resource ownership, direct step-up verification and consumption, authorization-policy invocation, reservation sequencing, dispatch, wallet/LND/Bitcoin adapters, finalization orchestration, signer/key-provider runtime wiring, reconciliation and recovery, and receipt retrieval authorization.

Therefore this dormant foundation must not be called from routes or MCP. There is no action gateway, runtime signer wiring, action dispatch, public verifier, retention cleanup, automatic reconciliation, migration application, or secure covenant ownership activation in PR5.
