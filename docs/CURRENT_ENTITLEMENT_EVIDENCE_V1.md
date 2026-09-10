# Persisted Current Entitlement Evidence V1

> **Status: IMPLEMENTED_RUNTIME_READ.** Synchronization basis: Canon commit `152c87522a7d89cd5c0e7014d7915a19bf074e1a`; runtime base `7df976c59742aa84fd79cfd41f12a34a33915259`.

This layer supplies an append-only, read-only-at-resolution source for a subject's current covenant-relation entitlement. The canonical runtime resolver reuses the application's initialized SQLAlchemy session factory, checks the active persisted-user LIMITED baseline, and then reads the latest evidence. It closes the gap between an active local account and authoritative, time-bounded FULL evidence without consulting browser state or a wallet RPC.

FULL/LIMITED in this document are runtime authorization evidence outcomes, not CRT membership states. No Canon membership-state evaluator, lineage evaluator, or Canon-conformant policy mapping is wired. A current FULL evidence record must not be described as proof of CRT membership. The human `legacy_777` and operator-agent `current_144` profiles remain separate.

## Distinct concepts

An **active persisted user** proves only that the local account exists and is enabled; it remains the prerequisite and LIMITED baseline. **ProofOfFunds** is a separate proof and is not current covenant-relation evidence. A **BitcoinWallet/watch-only descriptor** describes wallet observation capability and neither proves ownership nor a current relation. Only a valid record under `hodlxxi.current_entitlement_evidence.v1` represents the current FULL covenant relation used by this dormant resolver.

## Evidence and latest-state semantics

Each immutable observation contains `evidence_id`, `contract_version`, `subject_pubkey`, `identity_class`, `current_full_relation_satisfied`, `evidence_source`, `evidence_version`, `source_evidence_sha256`, `observed_at`, `valid_until`, optional `revoked_at`, and `created_at`. It stores only a hash reference to source evidence, not descriptors, addresses, UTXOs, balances, credentials, signatures, keys, session data, or RPC responses.

For one subject, latest means `observed_at DESC, created_at DESC, evidence_id DESC`. Selection happens before validation and state evaluation. A newer LIMITED, revoked, expired, future, or malformed record therefore blocks use of every older FULL record. Falling back would erase the meaning of a newer negative observation and could restore access that was deliberately withdrawn.

Validity starts at `observed_at` and expires exclusively at `valid_until`; windows are at most 900 seconds. Evidence is never activated before `observed_at`. More than 60 seconds of future structural skew is malformed; smaller future skew is tolerated structurally but remains inactive. Revoked evidence is LIMITED from the resolver's perspective. Malformed or contradictory persisted state and storage failures fail closed as unavailable.

## Runtime boundary and status

`resolve_runtime_current_entitlement` is the canonical runtime read seam. It constructs the existing SQLAlchemy evidence repository with the existing application session factory and invokes only `get_latest`; the read session is closed without commit. Missing, LIMITED, revoked, expired, or not-yet-active evidence remains LIMITED. Valid current FULL evidence upgrades the result to FULL. Malformed or subject-mismatched evidence and storage failures fail closed as unavailable.

A future offline materializer may verify covenant state and append observations, and a future public assertion consumer may call this resolver. Both are outside this change. This layer performs no CRT evaluation or evidence materialization and adds no route, MCP surface, background job, configuration flag, or independent database infrastructure.

## Transaction-bound Current-Full authority

The standalone runtime resolver above is intentionally detached: its active-user
lookup and evidence lookup own their sessions and cannot authorize a later write
atomically. It must not be injected into an authorization-storage transaction.
The source-only `SqlAlchemyTransactionBoundCurrentFullVerifier` instead accepts
an already-active caller-owned PostgreSQL session and exposes only
`verify_in_transaction(subject, now=...)`. It never begins, commits, rolls back,
or closes that transaction. A verifier exposing only detached `verify(...)` does
not satisfy the Social legacy-adoption atomic port.

For one subject the PostgreSQL lock order is: transaction-level advisory subject
lock, exact `users` row `FOR UPDATE`, then the latest
`current_entitlement_evidence` rows `FOR UPDATE`. The advisory key is derived
from SHA-256 of the ASCII domain
`HODLXXI_CURRENT_FULL_ENTITLEMENT_SUBJECT_LOCK_V1` plus a NUL byte plus the
canonical subject. Both evidence writer methods acquire the same advisory lock;
the two-subject writer acquires keys in ascending canonical-subject order.
Consequently an append that replaces current evidence conflicts with the read.
PostgreSQL updates or deletes of the locked user or evidence rows inherently
conflict with `FOR UPDATE`. No application writer updates `revoked_at` in place;
the current materializers invalidate state by appending a newer Limited or
otherwise newer record, and the repository can append an immutable record whose
`revoked_at` is already set. Expiry needs no writer lock because the returned
authority interval ends exclusively at `validUntil`.

The transaction-bound reader requires exactly one active `users` row whose
`pubkey` is the canonical subject, and one unambiguous logical latest evidence
row. It rejects a tie at the latest `observed_at` and `created_at`, a missing or
inactive user, missing or malformed evidence, Limited, future, expired, revoked,
subject-mismatched, or superseded Full evidence. SQLite is used only for
unrelated offline storage semantics and is not accepted by this atomic verifier;
PostgreSQL concurrency remains a separate disposable rehearsal.

## Canonical Current-Full proof content identity

The trusted transaction-bound producer hashes compact, sorted-key ASCII JSON
with exact schema `hodlxxi.full_entitlement_proof.v1`, integer version `1`, and
domain `HODLXXI_FULL_ENTITLEMENT_V1`. The exact preimage shape is:

```json
{"domain":"HODLXXI_FULL_ENTITLEMENT_V1","proof":{"evidence":{"contractVersion":"hodlxxi.current_entitlement_evidence.v1","createdAt":"<UTC-Z second>","currentFullRelationSatisfied":true,"evidenceId":"<canonical UUID>","evidenceSource":"<bounded source>","evidenceVersion":"<bounded version>","identityClass":"full","observedAt":"<UTC-Z second>","revokedAt":null,"sourceEvidenceSha256":"<64 lowercase hex>","subject":"<canonical x-only subject>","validUntil":"<UTC-Z second>"},"schema":"hodlxxi.full_entitlement_proof.v1","user":{"id":"<canonical UUID>","isActive":true,"subject":"<same canonical x-only subject>"},"version":1}}
```

Every listed member is required and no other member exists. Object keys are
sorted lexicographically by the canonical JSON serializer; strings, booleans,
integers, and null retain their JSON types. All timestamps are whole-second
UTC-Z values. The producer accepts only exact immutable domain record types,
not subclasses, mappings, inherited fields, properties, accessors, or
caller-shaped objects. Persisted timestamps with subsecond precision are not
rounded and fail closed at this proof boundary.

The identifier is
`hodlxxi-full-entitlement-v1-sha256:` plus lowercase SHA-256 of those exact
bytes. The fixed test vector is
`hodlxxi-full-entitlement-v1-sha256:b4ac158d3851b0d0dde4f76f290e89d8da3b81aef080ff8994dd781bda945b76`.
This digest is only a deterministic content identity for the exact active-user
and latest-evidence state. It is not a signature, credential, bearer proof, or
independent authority. Authority comes only from the trusted transaction-bound
producer after its locked reads. A caller-supplied string remains untrusted even
when it matches the identifier regex; consumers continue to require the exact
typed verifier result, matching subject, and covering validity interval.

See [CRT Runtime Bridge](CRT_RUNTIME_BRIDGE.md) and [CRT Membership Implementation Status](CRT_MEMBERSHIP_IMPLEMENTATION_STATUS.md).

## Non-claims

This layer does not provide KYC or legal identity; proof of ownership merely from a stored descriptor; proof of current funds merely from `BitcoinWallet.balance`; automatic covenant verification; public action execution; wallet custody; transaction creation, signing, funding, or broadcast; deployment; or migration application.
