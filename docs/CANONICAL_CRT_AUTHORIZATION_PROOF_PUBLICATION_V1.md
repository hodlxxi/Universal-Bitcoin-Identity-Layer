# Canonical CRT Authorization Proof Publication V1

**Status:** `IMPLEMENTED_SOURCE_ONLY` · `READ_ONLY_REFERENCE_SURFACE` ·
`NOT_DEPLOYED` · `NOT_LIVE_MEMBERSHIP`

PR6.15 exposes three source-controlled deterministic examples of the PR6.14
canonical proof and a stateless verifier for caller-supplied canonical bytes.
They are reference artifacts, not live membership state, not current participant
authorization, and not signed or issuer-attested.

PR6.14 remains the sole parsing and validation authority. The publication layer
loads each file read-only, requires the authoritative parser to accept it,
requires parse/serialize byte identity, and checks both its pinned canonical
proof digest and file SHA-256. Verification passes the exact HTTP body bytes to
that parser, so duplicate keys and noncanonical JSON remain invalid.

## Source-implemented HTTP contract

- `GET /.well-known/crt-authorization-proof.json`
- `GET /agent/crt/authorization-proofs`
- `GET /agent/crt/authorization-proofs/<artifact_id>.json`
- `POST /agent/crt/authorization-proofs/verify`

The reference IDs are `e923-full`, `depth-3-full`, and
`unknown-ordinary-limited`. Downloads are the exact checked-in bytes. The POST
body must be `application/json` and no larger than 262144 bytes. A successful
result has schema
`hodlxxi.canonical_crt_authorization_proof_verification_result.v1`; it confirms
only that the submitted bytes satisfy the PR6.14 V1 canonical, nested-binding,
digest, conclusion, and basis contract.

SHA-256 identifies exact bytes and provides change detection. It is not a
signature and does not authenticate an issuer. The unsigned discovery document
is likewise not authenticated.

## Explicit non-claims

This surface makes:

- no live Bitcoin evidence lookup
- no live admission registry lookup
- no automatic sponsor-lineage lookup
- no automatic membership evaluation
- no automatic authorization evaluation
- no action authorization grant
- no session or role mutation
- no entitlement write
- no administrator or operator status grant
- no invite or sponsor permission grant
- no proof of private-key possession
- no signature or issuer-attestation claim
- no authenticity claim from SHA-256 alone
- no claim that evidence remains current after evaluated_at
- no replacement of active legacy authorization
- no MCP publication in PR6.15
- no production deployment claim

It also performs no billing, payment, storage mutation, RPC/LND call, external
network request, live source composition, or current proof generation. It does
not prove legal identity, ownership, custody, guardianship, fairness, informed
consent, reputation, rank, trustworthiness, or production enforcement.

## Version boundary

PR6.14 is the pure, deterministic canonical proof domain artifact. PR6.15 is
only the source-implemented read-only reference publication and stateless
verification surface. Still not implemented are live source composition, live
current proof generation, signature or attestation, runtime authorization
enforcement, an MCP wrapper, a human HTML verifier, and production deployment.
