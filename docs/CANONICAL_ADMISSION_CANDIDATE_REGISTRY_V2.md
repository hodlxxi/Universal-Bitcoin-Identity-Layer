# Canon V2 signed candidate ledger — dormant PostgreSQL stage

**Scope:** isolated Draft PR stacked on PR #579 (itself stacked on #578).

**Status:** Proposed-only database contract. Not deployed, not a grant, not an
effective admission, not a replacement for current Full validation.

## What the ledger verifies

The dormant service app/services/canonical_admission_candidate_registry_v2.py
requires one caller-owned PostgreSQL READ COMMITTED transaction. Within
that transaction it:

1. Rechecks the exact Canon V2 root-to-target proposed edge chain, including
   each historical script/registration/funding binding, current caller-supplied
   two-UTXO observation, 777-block depth ordering and no same-chain outpoint
   reuse.
2. Calls the existing actual
   SqlAlchemyTransactionBoundCurrentFullVerifier on the **sponsor's** x-only
   key. This reads and locks the authoritative latest current-entitlement
   evidence for the sponsor; it does not accept a caller-shaped Full proof.
   Bob can use the exact same check to sponsor Charlie *only after Bob has
   a separate, actual, current Full evidence row*.
3. Consumes one database-issued challenge through the existing trusted
   Canon V2 challenge ledger, performing the two Bitcoin Core
   verifymessage calls over the exact sponsor/child role and proposal digest.
4. Inserts an immutable proposed-only candidate and **two** exact P2WSH
   UTXO claim rows in the SAME transaction. The SQL insertion rechecks
   the consumed challenge's proposal/verification digest. Unique indexes
   prevent duplicate child, proposal, registration, verification receipt,
   or global (txid,vout) in candidate rows. A composite FK ties child
   candidates to exactly one existing parent candidate's edge ID and
   proposal digest. The caller explicitly commits or rolls everything back.

A returned PendingCanonicalAdmissionCandidateV2 is **not durable until
the caller commits**; its durable, is_effective and grants_full properties
are always False. A committed candidate is still not Full. The database
schema has no Full or effective state to switch on.

## Deliberate hard blockers for production

- Caller-provided session keys must be independently authenticated by the
  outer route/service. Mere equality to a supplied pubkey is not
  authentication; this module is not connected to any route.
- Current genesis evaluation and per-node on-chain observations are passed
  as typed data, not fetched from a trusted database/RPC under one
  independently verified chain snapshot. The preflight does not prove
  effective V2 ancestor registrations or mempool/reorg safety. A recent
  unspent snapshot can be stale before commit.
- This ledger is **immutable and exclusive while still proposed**. It
  intentionally has no cancellation, succession, dispute/revocation,
  expiry or reissue mechanism. As currently designed it can permanently
  occupy a child/outpoint claim; do not deploy without an audited lifecycle
  and authorization policy.
- A sponsor being current Full is required, but that alone does not prove
  the particular proposed ancestor edge became EFFECTIVE. An authenticated
  effective-edge registry and per-ancestor locked authority revalidation
  are still required.
- Current entitlement rows must only be created from trusted effective
  evidence with bounded lifetime, never from these candidate rows.
  No direct Social role issuance or messaging changes are in this PR.
- No transaction boundaries, job runners, backend startup wiring, schema
  application to Runtime, or special root bypass were added.

## Verification

The dedicated Canon V2 Candidate PostgreSQL workflow provisions disposable
PostgreSQL 16 and executes the SQL migrations only there. Tests cover
real signed-message **stubbed** Bitcoin RPC calls, actual locked current
Full verifier, transaction rollback of candidate + nonce, uniqueness,
child-only conflict, immutable rows and Bob/Charlie authorization gating.
The stubbed signatures are not real cryptographic proofs; actual BTC Core
integration and production authority tests remain necessary.

The destructive test fixture refuses any database other than
postgresql+psycopg2://canonv2test@localhost:5432/canonv2test with explicit
CANON_V2_DISPOSABLE_PG_ACK=1 and refuses any preexisting target table
before creating and cleaning its own schema.

**Deployment prohibition:** Neither PR #578, #579 nor this PR authorizes
a merge, database migration, startup/restart, Full grant or production
runtime modification.
