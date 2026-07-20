# HODLXXI Action Step-Up Proof v1

## Purpose and status

This document defines the canonical cryptographic step-up foundation for future sensitive authenticated actions. The implementation has no HTTP endpoint and executes no action. A verified step-up proof is evidence of fresh key possession for one bounded intent. It is not authorization, consent to unrelated actions, resource ownership, action execution, payment approval, legal identity, or KYC.

The exact identifiers are:

- challenge schema: `hodlxxi.action-step-up.challenge.v1`
- proof schema: `hodlxxi.action-step-up.proof.v1`
- verification evidence schema: `hodlxxi.action-step-up.verification.v1`
- signature domain: `HODLXXI_ACTION_STEP_UP_V1`
- signature format: `bip340_schnorr_sha256`

## Challenge contract

A challenge contains `schema`, `challenge_id`, the canonical lowercase 64-hex x-only `actor_pubkey`, `oauth_client_id`, canonical access-token `token_jti`, exact action-policy `action`, nullable `resource_id`, lowercase 64-hex `request_sha256`, a random 32-byte hex `nonce`, UTC `issued_at` and `expires_at`, and `signature_domain`.

`resource_id: null` is the only representation of no resource. A present resource identifier, client ID, and token JTI must be nonempty, have no surrounding whitespace or control characters, and fit their declared ceilings. The request digest is mandatory even for create operations and is the SHA-256 digest of the exact canonical future action request; the raw request is not stored.

The default lifetime is 300 seconds and the hard maximum is 600 seconds. Service clocks are injected and must return timezone-aware UTC-compatible values. Expiration is exclusive: `now >= expires_at` is expired, and atomic consumption requires `expires_at > consumed_at`. Verification rejects expired state, invalid time ordering, lifetime over 600 seconds, issuance more than 60 seconds in the future, malformed persisted bindings, and invalid or already-consumed state.

Issuance accepts only an `ActionName` from the immutable `hodlxxi.action-policy.v1` requirement table whose `step_up_required` value is true. It does not maintain a second action registry. At present, only `covenant_draft_create` qualifies.

## Proof and canonical signature

A proof contains `schema`, `challenge_id`, `signature`, and `signature_format`. The signature is exactly 64 bytes encoded as 128 lowercase hexadecimal characters. Syntax and size checks happen before cryptographic verification.

The canonical signed representation is compact UTF-8 JSON with keys sorted lexicographically and ASCII escaping enabled:

```json
{"challenge":{...all public challenge fields...},"domain":"HODLXXI_ACTION_STEP_UP_V1"}
```

The verifier computes SHA-256 over those canonical bytes and verifies the digest with BIP-340 Schnorr. It uses the repository's existing `coincurve.PublicKeyXOnly.verify` primitive, already used for x-only Nostr-controlled proofs. The public key comes only from the persisted challenge. No compressed-key parity is reconstructed and no caller-supplied replacement key is trusted. Every security-relevant challenge field is inside the signed representation.

## Durable one-time consumption

`action_step_up_challenges` stores only the challenge contract version, domain, exact bindings, nonce, issue/expiry times, and nullable consumption time. It stores no bearer token, OAuth client secret, private key, arbitrary request body, or proof signature.

After signature verification, one conditional database update matches the challenge ID, every persisted binding, both timestamps, nonce, contract identifiers, unexpired state, and `consumed_at IS NULL`. Success requires exactly one affected row. Concurrent valid attempts therefore yield one verified result and one consumed/replay denial. Invalid signatures and binding mismatches do not update state. Database read, insert, update, commit, or ambiguous-result failures fail closed as `storage_unavailable`; database exception text is never included in evidence.

The repository-native migration is the dated SQL artifact `migrations/2026-07-20_action_step_up_challenges.sql`. Like the repository's existing production migrations, operators apply it directly with `psql -f migrations/2026-07-20_action_step_up_challenges.sql` during the database-migration deployment step. It creates only this table, portable integrity constraints, and its lookup/uniqueness indexes. The repository has no executable Alembic environment or supported automatic downgrade mechanism, so PR4 does not invent one. Operational rollback is to revert the application release while retaining this additive, inert table; destructive table removal requires a separately reviewed data-removal operation.

## Verification evidence and authorization boundary

The immutable verification result contains `verified`, stable `reason_code`, verification schema, challenge ID, actor, OAuth client ID, token JTI, action, nullable resource ID, request digest, issue/expiry/verification/consumption times, and evidence source/version. Its deterministic dictionary contains no nonce, signature, bearer token, client secret, or arbitrary exception.

Stable reason codes are:

- `verified`
- `invalid_request`
- `invalid_actor`
- `unknown_action`
- `step_up_not_required`
- `challenge_not_found`
- `challenge_expired`
- `challenge_consumed`
- `binding_mismatch`
- `invalid_signature`
- `storage_unavailable`

PR4 does not integrate step-up proof into action authorization. `VerifiedStepUp` is audit and application data, not an unforgeable credential: it is a publicly constructible result dataclass and must never establish authorization provenance by itself.

A future trusted orchestration layer must call `verify_and_consume()` directly and keep proof verification, binding checks, and policy invocation in one trusted control flow. Callers must not accept a client-supplied boolean or reconstructed result object as proof. This PR therefore exposes no helper that converts `VerifiedStepUp` into the policy model's `step_up_verified` boolean and makes no authorization claim.

## Boundary from later roadmap work

One-time challenge consumption prevents reuse of this proof. It is not action-level idempotency: PR5 remains responsible for receipts and replay-safe action idempotency. PR6 remains responsible for internal action dispatch, PR7 for Authenticated Action MCP, and PR8 for covenant drafts and ownership.

This version deliberately has no route, blueprint, action execution, job or action receipt, idempotency key, gateway authentication, wallet/LND/Bitcoin adapter, covenant draft, resource-ownership migration, operator/admin OAuth, or authoritative persisted FULL entitlement.

The public `/agent/mcp` sidecar remains separate, unauthenticated, read-only, and fixed at 26 tools. This contract adds no MCP package dependency and no OAuth challenge behavior to MCP. The Flask monolith's fail-closed fallback is unchanged. Operator identity remains a separate control plane and receives no implicit proof or policy bypass.
