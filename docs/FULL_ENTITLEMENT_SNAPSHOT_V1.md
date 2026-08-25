# Full Entitlement Snapshot V1

## Authority and boundary

This source-only boundary reads the complete current subject population from
the existing append-only `current_entitlement_evidence` repository and active
persisted-user proof from the existing `users` table in one explicit database
transaction. Callers do not supply subjects, entitlement records, user
prerequisites, Full claims, or completeness claims. The repository identifies
the logical latest record for every subject by `observed_at DESC, created_at
DESC`; if more than one record shares that latest logical time, the complete
population is unavailable. `evidence_id` ordering may only make the SQL carrier
deterministic after the tie has been detected and rejected. Selection is bounded
by requesting one subject beyond the limit; an over-limit read fails instead of
truncating.

The reader revalidates every selected latest record with the same canonical
semantics used by the per-subject resolver. A current, non-revoked Full record
is included only when the same complete population proves that the subject is an
active persisted user. A latest Limited, revoked, expired, or not-yet-active
record does not grant authority and suppresses any older Full record. Current
Full evidence for an inactive, deleted, nonexistent, malformed, mismatched, or
uncertain user, plus malformed, unknown, duplicated, inconsistently ordered,
ambiguous, partial, or unavailable state, makes the complete snapshot
generically unavailable. The read performs no write, commit, repair, refresh,
retry, fallback, or per-subject user lookup.

## Contract

Successful output has schema `hodlxxi.full_entitlement_snapshot.v1`, version
`1`, source `hodlxxi-crt`, `complete: true`, a deterministic SHA-256 snapshot
identifier, integer-millisecond issue and expiry times, and a strictly
subject-ordered `entitlements` array. Every record has exact Full status,
`revoked: false`, and an evidence interval covering the snapshot interval.

The interval starts at the trusted reader time and lasts no more than 300
seconds. It never extends beyond the earliest included Full evidence expiry. A
proven complete empty population is valid for the same bounded lifetime. The
digest identifies normalized snapshot evidence; it is not a signature or an
independent authenticity proof.

All malformed, stale, ambiguous, partial, unbounded, storage, clock, and
internal failures are reported only as `full entitlement snapshot unavailable`.

## Unavailable capabilities

This adds no database table or migration, HTTP route, OAuth or Social policy,
caller authorization, public Runtime disclosure, live directory delivery,
cache, refresh, repair, retry, scheduler, background job, network access, or
deployment. It preserves the existing per-subject entitlement behavior and
remains dormant until a separately reviewed delivery boundary exists.
