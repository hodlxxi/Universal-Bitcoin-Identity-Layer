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

See [CRT Runtime Bridge](CRT_RUNTIME_BRIDGE.md) and [CRT Membership Implementation Status](CRT_MEMBERSHIP_IMPLEMENTATION_STATUS.md).

## Non-claims

This layer does not provide KYC or legal identity; proof of ownership merely from a stored descriptor; proof of current funds merely from `BitcoinWallet.balance`; automatic covenant verification; public action execution; wallet custody; transaction creation, signing, funding, or broadcast; deployment; or migration application.
