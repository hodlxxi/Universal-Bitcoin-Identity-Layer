# OAuth Bearer and Entitlement Contract V1

Canonical bearer authorization has three independent gates: authentication,
an exact finite scope check, and current entitlement evaluation. Passing one
gate does not imply that another gate passes.

## Canonical access-token validation

Canonical access tokens are compact RS256 JWTs with a bounded credential size.
The validator uses unverified `jti` and single-string `aud` only to locate a
candidate issuance record. It then derives the expected audience from the
persisted record's `client_id`, loads a trusted local key by `kid`, and performs
normal signature, issuer, audience, time, and required-claim verification.
The client-bound audience contract is therefore `aud == record.client_id`.

The signed subject must already be the lowercase 64-character x-only public
key. The scope claim must be the exact canonical serialization of the finite
issuable registry. Token purpose, contract version, digest, user relationship,
expiry, revocation state, and all canonical issuance metadata must agree with
the persisted record. Digest comparison is constant-time. Missing, malformed,
or unavailable state fails closed.

JWT-looking credentials are handled only by the canonical validator. Any JWT
failure is `invalid_token`; there is no opaque-token fallback. Non-JWT
credentials use only the legacy opaque validator. Canonical issuance records
and stored JWT digests are rejected by that path.

## Current entitlement

Entitlement is resolved from the active persisted canonical user record only.
An active canonical user receives the interim `LIMITED` identity class.
Unknown, inactive, malformed, guest-like, and operator identities are denied.
`FULL` is never inferred from browser session state, request context, wallet
state, Bitcoin RPC, LND, Redis, or any request-time external call. Operator
identity remains outside OAuth; an `operator_managed` client is only a client
trust class.

## Protected resources and deferrals

Canonical resources return `invalid_token` (401), `insufficient_scope` (403),
`insufficient_entitlement` (403), or `authorization_unavailable` (503), without
revealing internal state. Introspection authenticates the client first and
uses the same validator with the expected client ID.

This version adds no database migration and no production self-resource route.
Jobs, receipts, reports, covenant drafts, action execution, durable requester
ownership, step-up proof, and MCP actions remain deferred. Public
`/agent/mcp` behavior is unchanged. Future work must define authoritative
fresh persisted full-entitlement evidence and durable resource ownership
before either can be enforced.
