# Canon V2 candidate-only expiration and reusable reservations

**Draft, stacked on PR #584. No deployment or Full authorization.**

The #584 candidate header and UTXO records are immutable. The original
UNIQUE(child) and UNIQUE(txid,vout) on these historical records mean that
even a permanently failed proposed admission could never be retried.

This stage separates **historical signed evidence** from **live proposed
reservations**, with a deliberately conservative seven-day TTL and
server-database-clock check. It does not create EFFECTIVE registration,
grant or revoke Full, or make a spendable Bitcoin covenant.

## Data model

- Both historical candidate and outpoint tables remain append-only.
- New live child and live outpoint claim tables own exclusive reservations.
  Migration transaction backfills all existing candidates before dropping
  historical uniqueness constraints. Missing or duplicate constraints fail.
- PostgreSQL AFTER INSERT triggers reserve the exact child and each UTXO,
  and check the parent candidate still has a live reservation.
- An output insertion trigger locks its candidate and prevents any extra
  sixth output after a complete 3+2 registration. Existing COMMIT-time
  deferred completeness checks still enforce both side sums and count.
- An immutable expiration-event table preserves an audit record after the
  live claims have been released. No original evidence or nonce is erased.

The privileged internal PostgreSQL function
\`expire_canonical_multileg_candidate_v2\` checks its own database time
(\`clock_timestamp()\`). Only a **proposed-only** candidate older than
seven days and without ANY active descendant may release its live child
claim and ALL exact N UTXO reservations. The release, event and previous
nonce receipt are transactionally consistent. Rollback restores claims.
Expiry is objective and does not require human signing: this is
permissible ONLY because these are not effective grants and cannot
become Full through this registry. It never expires an effective grant.

A new candidate using released UTXOs must present a **new proposal ID,
canonical signed SHA, freshly issued PostgreSQL nonce and two fresh
Bitcoin message signatures**, with current Full sponsor and fresh
observation revalidated by the #584 intake service. An expired parent
is unavailable as a basis for a child (candidate SQL joins live
reservations).

## Strict limitations / deployment prohibition

- This is an *optional, explicitly invoked internal operation*, not a
  scheduler, HTTP route or automatic expiration job.
- Candidate ages in the original #584 registration remain caller-clock
  stamped and observations caller-provided. No trusted server-only clock
  or Bitcoin Core RPC binding is implemented there; do not expose it.
- A candidate can still sponsor a proposed child after its nominal TTL
  if not yet explicitly expired: parent *reservation* is checked, but
  expired eligibility is not independently enforced by a root policy.
- No effective-edge registry, on-chain source-of-truth, mempool/reorg
  evidence, authenticated session route, or Full materializer exists.
- **Important:** the new live claim index protects only THIS multileg
  V2 table. It does not arbitrate the separate 2-UTXO candidate table
  from #580. Cross-version collateral double-use remains unaddressed.
- The tables/functions are owned by the migration principal. A future
  production migration requires a dedicated least-privilege internal
  role; database owner/superuser bypass is not prevented by GRANTs.
  SQL function execution is revoked from PUBLIC; no runtime grants
  or routes have been created.
- Once any candidate can become EFFECTIVE, its claims must be transferred
  to a shared permanent global collateral registry *before* expiry can
  be enabled. Otherwise an active participant could lose reservations.
- Database schema and test fixtures are for disposable PostgreSQL 16
  only. No live migration, main merge, backend restart or deploy.

## Verification

New and inherited PostgreSQL tests cover all original atomic 3+2
registration behavior plus seven-day refusal, historical expiry,
re-enrollment with a newly signed proposal, parent-with-active-child
denial, child-then-parent expiry, rollback, immutable audit and
post-commit output immutability. Bitcoin verifymessage is synthetic.
Full pytest and all style checks are separate required CI gates.

**This is a proposed-only lifecycle prerequisite, not membership release.**
