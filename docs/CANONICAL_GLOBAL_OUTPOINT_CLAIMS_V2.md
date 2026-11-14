# Canon V2 shared UTXO reservations — dormant, proposed-only

**Draft stacked on #585 → #584 → #583 → #582 → #581 → #580 → #579 → #578.**
No production database migration, runtime wiring, EFFECTIVE promotion, Full grant or Social action.

## Exact invariant

For each canonical Bitcoin outpoint `(txid, vout)`, the two dormant
PostgreSQL 16 intake formats must share **one unique live reservation**:

- Strict-two V2 candidates from #580 reserve both of their historical
  outpoints permanently (no validated strict-two expiration transition).
- N+M V2 candidates from #584/#585 reserve every **live** outpoint, one
  per pair of immutable signed mirrored evidence and the active candidate.
- A strict-two and multileg candidate cannot claim the same outpoint in
  either order. Concurrent transactions serialize on one PostgreSQL primary
  key; a rejected transaction rolls back its previously consumed nonce.
- A seven-day expired, never-effective **multileg** candidate may release
  only its own global reservations. Its signed proposal, output evidence
  and consumed nonce are still immutable. Re-enrollment still requires a
  new signed proposal and a new server-issued challenge.

## Migration / rollback boundary

`migrations/2026-11-13_canonical_global_outpoint_claims_v2.sql` runs
**after** both V2 candidate migrations and the #585 expiration migration.
It locks both source reservation tables, backfills strict-two historical
claims plus *only currently live* multileg claims, then enables triggers
that mirror subsequent inserts and audited multileg releases atomically.

Any cross-version collision already present causes the migration to
**ABORT**, leaving source schemas and data unchanged when executed in
a single migration transaction. Do **not** arbitrarily choose a winner
or automatically release a UTXO during remediation.

A deferred constraint trigger requires the matching immutable expiry event
at commit for each deleted multileg live outpoint. A separate global guard
rejects updates, permanent strict-two deletes and deletion of an active
multileg claim. There is no route, scheduler, background actor or Full
transition. Execute permission on new trigger functions and global table
DML are not granted to PUBLIC.

## Test coverage and known limitations

A new dedicated disposable PostgreSQL 16 CI workflow tests:
1. Non-overlapping 2+5 claims coexist.
2. Existing strict-two rejects a signed N+M duplicate UTXO.
3. Existing N+M rejects a signed strict-two duplicate UTXO.
4. Global uniqueness denial rolls back the failed challenge receipt.
5. Seven-day candidate expiry releases matching N+M global claims but
   retains five historical outpoints and permits later strict-two claim.
6. Manual live-claim deletion without a terminal expiry event rolls back.
7. Direct modification/deletion of permanent global claims is rejected.

Fixtures use synthetic Bitcoin-message signature acceptance, fake Bitcoin
observations, and artificially seeded Current Full. These are **not**
live-chain or real-identity tests.

**DO NOT DEPLOY OR MERGE STRAIGHT TO MAIN.** Remaining blockers:

- Migration-owner/superuser can bypass table privilege policy, and
  `TRUNCATE` is not protected by row triggers. Dedicated non-owner
  read/write roles, restricted migration authority, explicit function
  ownership and privilege verification must precede live activation.
- Strict-two candidate expiry/re-enrollment and **global child-identity
  uniqueness** are not implemented. Shared UTXO uniqueness alone does not
  prove identity uniqueness or grant Full.
- Nothing validates actual Bitcoin Core-confirmed UTXO/mempool state,
  reorg-safe snapshot, independently authenticated keys or session binding.
- No current effective ancestor chain, entitlement materialization,
  UBID-to-Social role reconciliation, or encrypted delivery is wired.
- Claims associated with any future EFFECTIVE admission must become
  permanent and never be released by the candidate TTL mechanism. This
  migration intentionally has no EFFECTIVE admission path.

The implementation remains an isolated prerequisite, not a verified
membership release.
