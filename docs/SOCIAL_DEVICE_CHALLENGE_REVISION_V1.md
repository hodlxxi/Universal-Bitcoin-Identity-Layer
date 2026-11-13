# Native issued device challenge revision V1

Status: **dormant source-only prerequisite; bounded disposable PostgreSQL 16
verification completed**. PostgreSQL 13..16 remains the source support boundary;
only 16 has execution evidence. Lock-wait acceptance and runtime orchestration
remain unverified. The implementation is
`app/services/social_device_challenge_revision_storage.py`. The additive source
is `migrations/2026-10-09_social_device_challenge_revision_v1.sql`; its presence
does not mean that it has been applied. No route, factory registration,
configuration, signer, transport or runtime caller is supplied.

## Issuance provenance

The explicitly qualified `public.social_device_admission_challenge_revisions`
companion holds exactly `challenge_id` and `revision`. Its primary key and
canonical lowercase 64-hex check bind one exact challenge ID; the foreign key
references the actual `public.social_device_admission_challenges` relation.
Only revision **1** is supported. This is an immutable first issuance
generation, never a state-transition counter. Future reissue/version semantics
require a separately reviewed contract. Existing positive-revision V2 parsers
and fixed wire vectors remain unchanged.

The guarded `AFTER INSERT FOR EACH ROW` producer inserts the companion for
every new parent challenge kind in the parent's transaction. Insert failure
aborts challenge creation. Rollback must discard both rows. The bounded
PostgreSQL 16 rehearsal demonstrated same-transaction enrollment-v2 companion
creation and root rollback of both rows. Forced companion-insert failure and
execution for every challenge kind were not separately demonstrated.
There is no backfill, creation-on-read, synthetic default, adopted caller
revision, late-attachment writer or update-based provenance. A pre-migration
row without a companion fails the new reader; legacy V1 history remains
readable. Existing five-column metadata, dataclass, decoder and store entry
points are unchanged. The new relation is not registered on shared Base.

## Schema and role boundary

The applying, separately trusted DDL principal owns the new relation and both
functions. The source creates no role and grants no runtime privileges.
Installation pins the canonical public parent and the exact current legacy
guard source and trigger configuration, rejecting incompatible installations;
it does not replace those guards or apply earlier migrations.

The future runtime must be a distinct direct login with schema USAGE and
companion SELECT ONLY, including no column-level write grants. It must have
parent SELECT/UPDATE to acquire the legacy state lock. Parent DELETE/TRUNCATE/
TRIGGER, companion INSERT/UPDATE/DELETE/TRUNCATE/REFERENCES/TRIGGER and new
function EXECUTE are denied. Public companion/function privileges are revoked
by the source. Runtime ownership, owner membership, schema CREATE, superuser,
CREATEROLE/CREATEDB, replication, row-security bypass and guard-bypass
capabilities deny. Only optional `pg_read_all_settings` membership is accepted
for the separately guarded disposable target identity inspection. That exception
never waives ownership or membership in an **actual** parent, companion, TOAST,
attested function (including the legacy guard), or public-schema owner. These
actual owners are enumerated independently of effective grants and CREATE.
The legacy function must share the trusted parent owner; new functions share
the trusted companion owner. The unchanged legacy API/source receives no ALTER.


The producer is a narrowly scoped SECURITY DEFINER function with
`search_path=pg_catalog`, qualified relation names, no dynamic SQL and no
caller-selected object. Companion UPDATE/DELETE and TRUNCATE triggers always
raise. Trusted DDL owners remain an explicit administrative boundary; these
guards do not protect against a malicious owner rewriting history.

The reader checks qualified catalog lookups before and after observations,
source-pinned stable function and trigger fields, parent/companion structure,
both relations' exact native constraints and supporting indexes, owners and effective runtime privileges. It also pins
relation/row-type/TOAST/function/trigger identities and rejects subsequent
identity changes. Function cost and row estimates use float4send bytes.
PostgreSQL 13 lacks prosqlbody; where present it must be NULL for these
PL/pgSQL functions. Names/counts alone are not definition authentication.
The canonical parent has eight constraint rows: its PRIMARY KEY, six CHECKs,
and only the named deferred `trg_social_enrollment_challenge_atomic` type-t
constraint. The installer and reader authenticate its exact parent, namespace,
NULL column binding, local/non-inherited flags, validation and deferred flags,
and its one named AFTER UPDATE row-trigger binding. Constraint and trigger
identities are pinned on repeat observations. Unexpected names, kinds or
bindings deny. The legacy atomic predicate, function and acceptance effects
remain outside this issuance guard set; recognizing its structural binding
is not acceptance-effect attestation.
The canonical parent PRIMARY KEY and all six named CHECK definitions come from
`2026-09-21_social_device_challenge_store_v1.sql`; its current legacy guard
comes from `2026-09-23_social_device_admission_receipt_consumption_v1.sql`.
Both files remain unchanged. Closed explicit expected `pg_get_constraintdef`
renderings are checked without cast stripping, wildcard comparison or adoption
of the initially observed expression. The FK allows exactly qualified/unqualified
public-parent rendering while independently binding its actual relation OID.
Constraint relation/namespace/column arrays, type, validation, deferral and
local/inheritance fields are checked completely. PK and FK bind to the exact
validated primary btree index on the authoritative challenge column; constraint,
index and expression identities are pinned and rechecked.

Inheritance metadata is type-specific: default CHECK has `connoinherit=false`;
ordinary non-partitioned PK, FK and the known atomic constraint-trigger have
`connoinherit=true`. This is independent
of `conislocal=true`, `coninhcount=0` and `conparentid=0`.
The PK rule follows PostgreSQL's
[index_constraint_create source](https://doxygen.postgresql.org/index_8c.html).
A separately stopped and removed disposable PostgreSQL 16 cluster supplied
synthetic prerequisite catalog metadata for review. The exact CHECK renderings
retain the nested AND groups produced by BETWEEN; the wire-ID column binding
is `[2, 1, 3]`. These observations correct the expectations without changing
canonical prerequisite SQL or adopting arbitrary first-observed definitions.
The complete two-table metadata capture established installation in an
empty disposable prerequisite schema, with verified teardown. That capture
alone did not establish reader execution or concurrency; the subsequent native
rehearsal described below supplied bounded execution evidence.
PostgreSQL 15/16's optional FK deletion-column list and NULLS-NOT-DISTINCT
index field must retain their canonical NULL/false defaults. New catalog
fields or constraint kinds outside the reviewed 13..16 boundary are unsupported.

Installation checks the parent columns, exact constraints/index and current
legacy guard before producer attachment, taking a parent structural lock in
the unapplied source. A subsequent disposable PostgreSQL 16 rehearsal
established bounded native reader execution, catalog and role checks, and
parent-lock waiting with rejection. It did not establish fresh lock-wait
acceptance or runtime orchestration. Deployment readiness is **NO**.

Native catalog composite JSON uses decimal strings for OIDs, integer arrays
for int2vector and decimal-string arrays for oidvector/OID arrays. A closed
field-aware decoder checks canonical unsigned 32-bit OIDs and bounded int2
array elements, preserves ordering, NULL and empty vectors, and leaves bytea
and expression bytes exact. It never coerces numeric-looking strings in other
fields. Relation, namespace, TOAST, attribute, constraint, index, function,
trigger and runtime-role owner fields all cross this boundary; outer bigint
projections remain integers. Unknown layouts deny. Maintenance estimates,
vacuum horizons and physical storage locators are observations, not fixed
provenance identifiers. Shadow parent lookup through the legacy store's
unqualified mapping denies, rather than redirecting its query.

`pg_proc.prosupport` is a `regproc`, rather than an ordinary OID field.
Its native absent-support representation is exactly `"-"`; only that value
decodes to the internal no-support value 0. Named support, numeric strings,
numbers, booleans, NULL, missing fields and whitespace variants deny. The
function-definition guard still requires no planner support. See the
[PostgreSQL pg_proc catalog](https://www.postgresql.org/docs/16/catalog-pg-proc.html)
and [OID alias types](https://www.postgresql.org/docs/16/datatype-oid.html).
Complete synthetic parent and companion metadata and effective privileges
captured under distinct DDL/runtime roles informed this bounded native decoding
correction. This does not change schema source, ownership authority, issuance,
transaction semantics or runtime composition. The decoding correction alone
is not execution evidence; the subsequent outer rehearsal established the
bounded native reader behavior described below.

## Caller transaction contract

The internal supported caller exclusively manages the root transaction and
all savepoints with SQLAlchemy Session/Connection/Transaction APIs. Direct
BEGIN/COMMIT/ROLLBACK/SAVEPOINT/RELEASE/ROLLBACK TO SQL, cursor/driver
transaction control, driver autocommit changes, and concurrent or reentrant
use of the same Session/connection are outside this port's caller contract.
There is no claim of protection against arbitrary callers bypassing
SQLAlchemy savepoint bookkeeping.

The reader requires a clean active caller-owned PostgreSQL READ COMMITTED
transaction. It pins original active Session root/nested objects, Connection
RootTransaction/NestedTransaction objects, and the physical DBAPI connection.
It denies replacement, inactive savepoints, invalid/closed connections,
autocommit and pending ORM work. It never begins, commits, rolls back or
closes the caller's transaction. Core legacy reads avoid cached ORM state.
Any failure poisons the reader and requires caller rollback, with the sole
non-sensitive exception `social device challenge revision unavailable`.

Independently, the explicitly qualified
`pg_catalog.pg_current_xact_id()::text` must return the same canonical nonzero
unsigned xid8 decimal at establishment and before/after the parent lock/read,
companion SELECT and catalog/security checks. PostgreSQL **13 through 16 only** is the source-reviewed catalog boundary;
other major versions deny, including 17 and later. Within that boundary, unavailable, malformed or changed identity denies without fallback.
The call may allocate an XID even for read-only observation. XIDs stay private:
they are not logged, returned, serialized, used in errors, or used with xmin
to manufacture challenge issuance. This detects backend root replacement
even when all original SQLAlchemy/DBAPI objects remain identical.

PostgreSQL returns the **top-level** XID within subtransactions too. It does
not authenticate an individual savepoint. Savepoint continuity is strictly
the original SQLAlchemy object identity under the supported caller contract.
The bounded native rehearsal observed top-level XIDs and exercised raw-root
replacement denial. Its old-row cases lack a companion, so generic denial alone
does not isolate continuity enforcement. Valid-row offline regressions provide
separate adapter evidence; unsupported raw savepoint management remains outside
the caller contract.

## Locked observation and later orchestration

`read_issued_with_revision_in_transaction(challenge_id, *, observed_at)` composes
the real unchanged legacy store on the same guarded connection. It locks and
reparses the canonical parent first, then reads exactly one immutable native
companion for that same confidential internal selector. Missing, duplicate,
mismatched or corrupt evidence and unsupported revisions, including booleans,
deny. There is no companion FOR UPDATE: its immutability plus the parent's
state lock supplies the causal observation, without granting companion UPDATE.

Only enrollment-v2, issued state and current exclusive deadline are accepted.
The actual existing verification-context and Enrollment V2 wire parsers enforce
canonical whole-millisecond/safe-integer semantics. Future, expired and every
terminal state deny. Returned `VerifiedIssuedDeviceChallengeRevisionV1` and
its already-parsed challenge are frozen and suppress sensitive repr fields.

The seam orders parent challenge before companion and independently takes no
Full, OAuth, binding or association locks. Later composition must preserve
reservation -> current authorities -> binding -> challenge -> association.
`observed_at` remains explicit caller time; this reader cannot prove it was
resampled after a wait. Orchestration must resample and recheck after waits and
before effects. A successful result is transaction-scoped history, never a
detached current-authority grant, acceptance, consumption, signature or Send
permission. Lock-wait acceptance is not established.

This prerequisite links to the unchanged
[admission contract](SOCIAL_DEVICE_ADMISSION_V1.md),
[V2 handoff](SOCIAL_PREACCEPTANCE_ED25519_HANDOFF_V2.md),
[deadline evidence](SOCIAL_MESSAGING_DEVICE_VERIFICATION_DEADLINE_EVIDENCE_V1.md)
and [atomic acceptance contract](SOCIAL_PREACCEPTED_ENROLLMENT_V2_ATOMIC_ACCEPTANCE_AND_CAS_V1.md).
Native V2 child/session issuance, dedicated signers, reservation orchestration
and atomic effects remain separate prerequisites. This source grants no Full,
enables no Send and does not fix directory503.

## PostgreSQL verification and rehearsal boundary

The separately guarded integration source is
`tests/integration/test_social_device_challenge_revision_storage_postgresql.py`.
The source-only CLI did not execute it. A subsequent separately authorized
outer runner executed it on a disposable PostgreSQL 16 cluster and verified
teardown. PostgreSQL 13..15 execution remains unverified. Future rehearsals
require a separately authorized outer runner; that runner alone manages clusters. An
operator must explicitly authorize and
provision a uniquely named disposable cluster, exact ACK/DSNs/data path and
high loopback-only port, no Unix sockets, distinct DDL/runtime roles and the
exact empty legacy schema. No inherited DATABASE_URL/default5432 fallback is
accepted. Role provisioning and cluster lifecycle are external to the tests.
The prerequisite public schema must contain exactly the four empty canonical
challenge, enrollment receipt and Ed25519 chain/event relations; tests generate
all later rows synthetically. Ownership/membership alteration cases additionally
require the trusted DDL principal's explicitly provisioned ability to
assign schema/function ownership to the restricted role and grant its own role.
Those grants are transactional test alterations and are rolled back, not
runtime provisioning. Failure to supply those prerequisites is a rehearsal
blocker, not a skipped security assertion.

Bounded SQL/lock/connect timeouts, synthetic rows and identity rechecks precede
targeted verified teardown. The ACK explicitly includes dropping the disposable
synthetic challenge tables. It is never a live-data authorization.

Coverage includes a complete native-reader positive with exact parent atomic
constraint, OID/vector/bytea JSON shapes, index and FK bindings, as well as
same-transaction production and rollback, old-row denial,
runtime mutation/EXECUTE denial, guards, shadows, duplicate issuance, terminal
generation persistence, root replacement, supported savepoint replacement,
top-level XID limitation, physical invalidation and bounded parent waits.
The duplicate test constructs the legacy store within the chosen SQLAlchemy
savepoint and asserts its actual generic storage exception, then proves both
rows disappear on root rollback. Guard/parent/owner tampering tests feed actual
uncommitted native catalog rows and native effective privileges to the complete
validator on an established restricted reader, restoring definitions/OIDs with
owner rollback and verifying restoration. This is bounded native-catalog-to-
validator coverage, not restricted reader lock acquisition against uncommitted
DDL. The wait's expiry branch supplies an already-expired `observed_at`: it
proves exclusive rejection after a bounded wait, not a crossing deadline or
automatic clock resampling. Resampling remains a later caller obligation.

Offline syntax inspection and interim lint/test results do not prove SQL
execution, native role enforcement, catalog rendering or concurrency. Final
offline verification additionally requires all outer-runner checks passing in
`external-checks.json`; those checks still do not constitute a database rehearsal.

The first revision installation attempt failed before any PostgreSQL test body;
passing offline doubles did not establish native compatibility. Subsequent
independent original-source red regressions, corrected-source offline checks
and a fresh disposable PostgreSQL 16 native rehearsal passed within the coverage
and limitations above. This establishes bounded source evidence, not future
acceptance effects or runtime readiness. Source remains dormant/default-off;
**DEPLOYMENT_READY=NO**.
