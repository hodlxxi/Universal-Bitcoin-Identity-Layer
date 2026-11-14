# Canon V2 multileg candidate atomic intake — dormant

**Stacked on PR #583 → #582 → #581 → #580 → #579 → #578.**

A new, independent, proposed-only PostgreSQL 16 registry provides an
atomic composition for **all N+M outputs**, not just one output per
mirrored script. This does not modify the legacy two-output candidate
registry, and is deliberately unwired from HODLXXI Runtime.

## One caller-owned database transaction

\`SqlAlchemyCanonicalMultiLegCandidateRegistryV2\` rejects SQLite,
missing Postgres transactions, unexpected isolation or pending ORM
mutations. For one exact proposal it:

1. Re-evaluates typed multileg script, mirror UTXOs, sponsor/child key
   bindings, parent/genesis proposal identity and current observation.
   This is structural **input validation**, not independent Bitcoin
   Core provenance, effective ancestor verification or network consensus.
2. For non-genesis depth, confirms the exact parent **candidate** row,
   locked under \`FOR SHARE\`, including parent digest, depth and child key.
   Proposed parent existence is not parent authority.
3. Uses existing \`SqlAlchemyTransactionBoundCurrentFullVerifier\` on the
   sponsor's current active User and latest locked Current-Full
   evidence. No claimed Full or parent proposal can substitute.
4. Consumes the previously PostgreSQL-issued Canon V2 *multileg* nonce,
   validating sponsor and child Bitcoin message signatures on the exact
   hash of every UTXO. It marks the nonce consumed within this same
   transaction, without committing it.
5. Writes an immutable candidate header and **every** (txid,vout),
   P2WSH script hash, amount and leg. PostgreSQL uniquely indexes
   child and outpoint, verifies the consumed nonce and exact proposal
   and verification hash, and at **COMMIT** a deferred constraint checks
   that the number and both aggregate sums exactly match the signed
   snapshot. Any failed write causes caller rollback, including nonce
   consumption.

The returned receipt is always \`durable=False\` (the method does not
commit), \`is_effective=False\` and \`grants_full=False\`. Even after
a successful external COMMIT, this registry records **only a candidate**.

## Regression coverage

Real, disposable PostgreSQL 16 tests exercise:
- Alice→Bob 3+2 P2WSH UTXOs, 300,000/300,000 sats and 300,000 trust ceiling
- Current sponsor Full required, even for recorded candidate ancestors
- Bob→Charlie only when Bob separately has current Full; no root monopoly
- Single-use nonce + all outputs atomic rollback on abort or conflicts
- Exact parent candidate digest and subject; missing parent refused
- No duplicated child or reused (txid,vout) within this new registry
- Stale/spent observations rejected before nonce consumption
- Immutable candidate header and outpoint evidence
- No SQLite or production target allowed

These fixtures use fake Bitcoin verifymessage and **synthetically seeded
current Full**. They do not demonstrate real-world Bitcoin signatures,
validated independent current Full source provenance or a live on-chain
connection.

## Critical remaining production blockers

- Caller inputs \`authenticated_...pubkey\` are compared for equality,
  NOT authenticated by the service. Live session authentication must be
  independently enforced before invoking any write.
- Observations and parent/genesis basis are caller-provided. A malicious
  caller can fake recent UTXO observations; current effective ancestry,
  independent Bitcoin Core RPC and mempool-aware/reorg-safe snapshots
  must be established by a trusted server-owned dependency.
- Unlike a production admission registry, candidate rows are immutable
  forever. There is no cancel, supersede, expiry-release, dispute or
  re-registration policy. **Do not deploy until lifecycle is specified.**
- UTXO uniqueness here covers only this NEW multileg table. The older
  strict two-output registry has a separate unique index. Concurrent
  cross-version writes are NOT globally protected. A single cross-version
  claim registry/locking policy is required before integration.
- There is no transition to EFFECTIVE, durable per-ancestor effective
  proof verification, Full materialization, Social membership bridge or
  encrypted message delivery.
- No migration applied outside disposable CI; no routes, startup flags,
  active service changes, merge to main, server restart or production
  deployment.

**A green pytest is not an end-to-end HODLXXI membership release.**
