# Staging import recovery continuation for #595 / #588

This branch remains incomplete and must not be activated. Automatic imports
still produce pending candidates, never EFFECTIVE admissions or Current Full.
The signed admission path retains its original consent checks.

The authenticated ordinary import route now commits sponsor provenance before
the first Core mutation when `AUTO_SPONSORED_IMPORT_ENABLED=true`. It reads the
subject from the server-side login session, locks and verifies current Full,
records its evidence reference and the structural sponsor depth, and reuses an
unexpired intent on exact retries. A failed intent transaction prevents the
Core call. The post-import journal requires that provenance and rechecks Full
and depth. The feature-off endpoint behavior remains unchanged.

`recover_authenticated_sponsored_imports` is a bounded server composition
primitive, not an HTTP endpoint or an installed worker. It requires a
descriptor wallet with private keys disabled, finds both exact imported
descriptors, derives native P2WSH locally, and journals only a matching live
authenticated intent. Wallet labels and balances supply no sponsor authority.
An intent expires after seven days; recovery cannot revive an expired or
revoked sponsor. The automatic Full coordinator and recurring funding worker
still need implementation and runtime composition.

Apply these journal migrations in order, after current-entitlement evidence:

1. `2026-11-15_canonical_auto_sponsored_import_v1.sql`
2. `2026-11-15_canonical_auto_sponsored_import_v1_intents.sql`

The script checks use explicit lengths because PostgreSQL does not accept the
draft's `{2,2048}` repetition bound at insert time. Both tables also check the
exact witness-script SHA-256. Intent and import history reject UPDATE/DELETE;
PUBLIC receives no privileges. Migration ownership and the future runtime
writer must be separate. The PG16 regression exercises an unprivileged role
without UPDATE, DELETE, TRUNCATE or schema ownership. It does not install any
role or grant in an existing database.

The destructive Canon V2 fixtures support the existing CI port 5432 and an
explicit alternate loopback port. Alternate instances require
`CANON_V2_DISPOSABLE_PG_PORT`, the existing acknowledgement, the exact test
database/role, PostgreSQL 16, no connection-option overrides, and database
comment `hodlxxi-canon-v2-disposable-pg16-v1`. The target is checked read-only
before any DDL. Never use the shared staging or production instance.

The VPS audit found no deployed automatic journal schema. No earlier durable
authenticated Alice import record has been established by this run. Existing
funded outputs alone cannot recover authenticated
sponsorship. Once the full coordinator and isolated runtime are ready, Alice
must perform the ordinary first import in a dedicated staging watch-only
wallet using the same existing outputs. Do not synthesize her consent or
infer provenance from their scripts.

Remaining release gates include automatic atomic EFFECTIVE plus short-lived
evidence, global conflicts shared with signed admission, active ancestry,
pre-login eligibility, spend/reorg/expiry refresh, Bob-to-Charlie admission,
and the paired Social runtime. Tests of the existing signed EFFECTIVE
transition do not establish these automatic-path gates.
