# Persisted Current Entitlement Evidence V1

This dormant layer supplies an append-only, read-only-at-resolution source for a subject's current covenant-relation entitlement. It closes the gap between an active local account and authoritative, time-bounded FULL evidence without consulting browser state or a wallet RPC.

## Distinct concepts

An **active persisted user** proves only that the local account exists and is enabled; it remains the prerequisite and LIMITED baseline. **ProofOfFunds** is a separate proof and is not current covenant-relation evidence. A **BitcoinWallet/watch-only descriptor** describes wallet observation capability and neither proves ownership nor a current relation. Only a valid record under `hodlxxi.current_entitlement_evidence.v1` represents the current FULL covenant relation used by this dormant resolver.

## Evidence and latest-state semantics

Each immutable observation contains `evidence_id`, `contract_version`, `subject_pubkey`, `identity_class`, `current_full_relation_satisfied`, `evidence_source`, `evidence_version`, `source_evidence_sha256`, `observed_at`, `valid_until`, optional `revoked_at`, and `created_at`. It stores only a hash reference to source evidence, not descriptors, addresses, UTXOs, balances, credentials, signatures, keys, session data, or RPC responses.

For one subject, latest means `observed_at DESC, created_at DESC, evidence_id DESC`. Selection happens before validation and state evaluation. A newer LIMITED, revoked, expired, future, or malformed record therefore blocks use of every older FULL record. Falling back would erase the meaning of a newer negative observation and could restore access that was deliberately withdrawn.

Validity starts at `observed_at` and expires exclusively at `valid_until`; windows are at most 900 seconds. Evidence is never activated before `observed_at`. More than 60 seconds of future structural skew is malformed; smaller future skew is tolerated structurally but remains inactive. Revoked evidence is LIMITED from the resolver's perspective. Malformed or contradictory persisted state and storage failures fail closed as unavailable.

## Boundary and status

A future offline materializer may verify covenant state and append observations. That verifier is outside this PR. This PR adds no materializer, application-factory construction, route, MCP surface, background job, configuration flag, or production dependency wiring; the resolver is independently constructible and dormant.

## Non-claims

This layer does not provide KYC or legal identity; proof of ownership merely from a stored descriptor; proof of current funds merely from `BitcoinWallet.balance`; automatic covenant verification; public action execution; wallet custody; transaction creation, signing, funding, or broadcast; deployment; or migration application.
