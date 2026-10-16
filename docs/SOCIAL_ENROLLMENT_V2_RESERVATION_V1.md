# UBID Enrollment V2 reservation V1


Freshness policy: [server-selected signed freshness profiles](SOCIAL_ENROLLMENT_V2_FINALIZATION_V1.md#server-selected-signed-freshness-profiles). Legacy closed payload field sets and fixed
vectors remain exact; the separately selected new contract requires its signed
marker. Default configuration remains disabled and legacy ten seconds.
Status: **dormant source-only reservation owner and dedicated evidence signer**.
`RUNTIME_ENABLED` remains false; default configuration is disabled. Offline
verification uses synthetic in-memory SQLite and catalog doubles. Bounded
disposable PostgreSQL 16 verification additionally covers native catalog/role
composition, rollback, exact pending retry, concurrent reservations and completed
lock waits with fresh-clock success and expiry rejection. These results establish
the tested synthetic target only; live schema/role compatibility and general
finalization remain separate obligations. No key is operationally provisioned.
This source is not deployment-ready.

The source API is `V2ReservationOwner` in
[`social_enrollment_v2_reservation.py`](../app/services/social_enrollment_v2_reservation.py),
with configuration/result contract, dedicated signer and native authority owner
in the adjacent `social_enrollment_v2_reservation_contract.py`,
`social_enrollment_v2_reservation_signer.py` and
`social_enrollment_v2_reservation_authority.py` modules.

## Exact API and authority

An internal server composition may explicitly construct the owner with one
already-active caller SQLAlchemy Session, trusted aware UTC clock, server
`ReservationConfig` and `DedicatedRS256EvidenceSigner`. `reserve` accepts only
an exact canonical V2 verification-input wire and a native issuance ID lookup
selector. It accepts no caller evidence, deadlines, observation, authority
records, current/verified/reserved booleans, callbacks granting authority or
signature substitutes. No runtime composition is supplied here.

Configuration fixes the native issuer, client, backend, service principal,
verification audience, dedicated evidence audience/purpose and exact selected
kid/trust revision. The existing strict public trust configuration remains the
canonical shape/lifecycle implementation. Independent server `trust_pins`
bind each retained kid to one immutable revision and complete trust-record ID;
selection of a new issuance key does not change any retained registration.
For this new owner's registrations the operational kid policy is
`ubid-v2-reservation-r<revision>-<existing-SPKI-sha256-hex>-<notBefore>-<notAfter>`.
`dedicated_reservation_key_id` validates these values using existing helpers;
configuration enforces that exact ID for every selected and retained record.
This uses the existing public fingerprint, with no new digest domain or wire.
The canonical signed protected header therefore also binds original revision,
public key and immutable validity bounds. Opaque arbitrary registrations remain
valid under the unchanged general canonical verifier, but cannot enter this
new owner. Server configuration/public trust is reparsed and frozen at owner
and signer construction rather than trusting mutable cached key objects.
The dedicated signer receives an explicit already-held RSA private-key object.
Its public parameters must match the selected registered JWK exactly. It has
no provider, file, environment, generic OAuth key discovery or fallback.

Only a private registry-backed immutable `LockedReservationCandidate` from
this native owner in this guarded transaction may enter signing. The registry
binds exact owner, guard, canonical input, immutable native facts, challenge
revision, payload, trust identity and interval. It rejects forged/copy/lookalike
objects, another owner's candidate, superseded candidates and repeated signing.
Candidates expose no writable authority fields. Serialization alone never
registers one. Rechecks before and after the real private-key operation and
persistence reject expired, changed or disconnected authority. Any failure
poisons the owner and candidate and requires caller rollback. The poison
also fences the original Session and physical Connection roots against a new
reservation owner until caller rollback replaces those roots. Public failures
have only `social enrollment v2 reservation denied`, without sensitive chained
cause or context.

The actual `NativeV2AuthorityReader` and its exact `validated_facts` registration
supply native birth provenance, genuine BIP340 approval/acceptance, operation,
child/parent/approver token and durable browser/session generations, exact
binding, Full evidence ID/version/source hash/proof and independent effective
deadlines. Reads use the exact verification input. The owner cross-checks the
approval and acceptance bytes, authorization and pre-enrollment digests,
operation/pairing/request/subject/device identities, binding tuple and public
commitment, context/enrollment audience and identities, both role-separated
session commitments and both Full proof commitments. Shape-valid phone proof
bytes are preserved; this owner claims no Ed25519 verification.

The exact `SqlAlchemyTransactionBoundIssuedChallengeRevisionReader` then locks
and reparses the genuinely issued enrollment-v2 challenge and immutable native
revision. The context and Enrollment V2 bytes must equal the input exactly;
revision must be supported, state issued and deadline current. There is no new
challenge producer or old-revision backfill. The real guarded Ed25519 history
reader requires no chain/event/current/history and authority epoch zero. A
revoked/historical chain or `current=None` alone is insufficient. Relevant
legacy enrollment receipt/effect history also denies; the canonical reservation
collision set excludes accepted or terminal reuse. History relation identities
and unqualified public resolution are checked and pinned. Enabled or forced
row-level security and runtime ownership or inherited owner privileges on any
of the three history/receipt relations deny before absence is interpreted.
An empty SELECT is not complete absence when the database can hide matching
rows from this role. These checks are repeated with the pinned identities;
the existing readers' guards remain in force.

## Caller transaction and combined locks

PostgreSQL 16 READ COMMITTED is the combined source boundary. The owner reuses
`TransactionGuard` and `BoundSession`: one caller Session, physical guarded
Connection, original Session/Connection root and nested objects, clean ORM
state, non-autocommit driver and private native root XID. Core stored reads
avoid the identity map; native ORM reads refresh and bind to that Connection.
Snapshots freeze native fields before validation. Swapped/reconnected binds,
root XID replacement even with unchanged Python objects, inactive/replaced
savepoints and pending ORM work deny. Supported callers use SQLAlchemy
transaction APIs exclusively; raw driver/SQL savepoint control and concurrent
or reentrant use of the same Session are unsupported. XID authenticates only
the root, not individual savepoints.

The actual combined order is:

1. canonical reservation table serialization, then all existing collision rows
   in reservation-ID order;
2. native V2 operation lock and immutable offer/parent/acceptance observations;
3. the native reader's shared request, Full subject/User, device and global/sorted
   public-key mutation locks, then client/issuer/original browser/parent
   token/durable Session locks;
4. exact X25519 binding, the native reader's Current-Full evidence evaluation
   under the already-held subject/User locks, and child token;
5. exact issued challenge/state lock and immutable revision read; and
6. subject/device Ed25519 pair advisory lock, chain and complete event history,
   followed by relevant receipt absence inspection.

The native reader owns its internal order, including the later evidence
validation; this owner does not substitute the old transition orchestrator.
Rechecks revisit already-held owners in that same order. See the
[native issuance contract](SOCIAL_SESSION_ISSUANCE_V2_PROVENANCE_V1.md) and
[issued revision contract](SOCIAL_DEVICE_CHALLENGE_REVISION_V1.md).

A missing `FOR UPDATE` row locks no gap. Before authority/signing the new owner
executes a fixed `LOCK TABLE` in `SHARE ROW EXCLUSIVE` mode on the canonical
reservation table. This transaction-held lock conflicts with all existing
INSERT/UPDATE writers' `ROW EXCLUSIVE` locks, including the frozen old raw
storage owner. It serializes all first reservations, at a deliberate throughput
cost, covers even evidence identities not yet calculable before signing and
permits complete collision-set rechecks after waits. No in-process mutex is
claimed as PostgreSQL proof. Existing external writers must preserve the global
reservation-before-authority order; writers that instead hold authority locks
before inserting may deadlock and must roll back. No timeout/deadlock authorizes
a grant. Bounded disposable verification covers this composition, privileges
and completed waits; every intended runtime target requires its own verification.

The additive discovery adapter intentionally uses the frozen canonical store's
checked Connection, table mapping and `parse_stored_atomic_acceptance_v1`.
This is a narrow private-source coupling because no public lookup-by-input seam
exists. It is not a second canonical store or identity implementation. The table
lock and immutable row reparse authenticate complete collision identities
before a native lookup can grant signing authority. No unlocked selector hint
is accepted as authority.

## Canonical bytes, interval and pending-only retry

The owner reuses the existing evidence serializer, domain-separated reservation
ID/input payload digest/JTI, protected header/signing input/compact constructor,
strict verifier and canonical pending constructor. Legacy bytes, preimages, digest domains, fixed vectors and RS256 headers remain
unchanged. The opt-in profile adds only its explicit signed payload marker.

One trusted UTC integer-millisecond observation is sampled after all relevant
lock waits. Fractional time floors conservatively using the existing exact
integer helper. Evidence expiry is positive, exclusive and at most observation
plus the explicitly configured profile maximum, all four independent native deadlines, exact enrollment and
pre-enrollment expiry and selected signing trust's exclusive notAfter. The
binding deadline equals the signed V1 binding tuple. The four evidence deadlines
retain their independent native values. No formatting, wait, retry or clock
resample extends any original interval.

For a new reservation the signer is invoked once, then the real strict consumer
authenticates its exact bytes. `reserve_pending` receives the original signed
observation and separately refreshed current time. The returned row is read
again through the complete collision set, authenticated and reparsed; input,
evidence, canonical pending wire and identities must agree exactly. Freshness
and transaction continuity are checked after persistence/authentication. Only
that stored compact JWS is returned as `provisional_until_caller_commit`. A
late or failed provisional insert/sign produces denial, never success, and may
leave a provisional row requiring caller rollback.

Lost-response retry discovers pending history from input/selectors without
caller evidence. It locks and authenticates stored bytes FIRST at the original
signed observation, then checks the current exclusive interval and conservatively
rechecks the exact native graph, challenge, absence and independent deadlines.
Every stored payload value compares against that graph at its original
observation; a new observation is not compared or minted. New Full evidence
cannot replace the original proof. A live exact pending match returns identical
original JWS/observation/expiry with no signer invocation or rewrite, including
when today's issuance selection is a different key and original trust remains
registered. Missing/revoked/replaced original registration or native provenance,
changed bytes/operation/request/device/challenge/association/evidence, ambiguity,
expiry and every terminal state deny. Accepted recovery is deferred finalization.
Terminal uniqueness is never released or reopened.

## Dedicated trust operational POLICY

This policy is a requirement for future composition, not operational provisioning:

- Custody: a dedicated UBID evidence authority holds the private object through
  an explicit purpose-specific port. No generic OAuth/participant/device key is
  adopted. Private material must not be extracted, serialized or logged.
- New issuance: an explicit selected kid/revision/public JWK must match the
  independently pinned immutable registration and private object's public
  parameters. notBefore and exclusive notAfter apply; any non-null revocation
  denies. No alternative key rescues selection failure.
- Rotation/overlap: use a new unique kid and registration. Retain each original
  kid/revision/record pin and public verification trust unchanged for outstanding
  pending retries and historical verification. Do not re-sign stored evidence
  with the current selection or invent a grace period.
- Revocation: terminally revoke compromised registration; it denies even
  historical authentication under the existing consumer. No automatic rescue.
- Rollback: change future issuance selection only to an explicitly retained,
  unrevoked currently valid registration. Never erase revocation, rewrite an
  old registration, reuse a kid or modify stored bytes.
- Retirement: remove private signing access separately from public history.
  Public trust removal deliberately makes dependent retry/history unavailable;
  retention/retirement needs an explicit operational decision.

Canonical JWS/pending bytes contain kid but no separate trust revision/record
ID. The new owner's validated operational kid vocabulary closes same-key
revision/lifetime relabeling: replacing even both registration and independent
pin cannot change the original signed kid to fit new fields. The strict consumer
and all existing vectors retain their original general semantics. Server trust
registration and terminal revocation remain an administrative authority; this
source provides no registry provisioning, revocation undo or grace mechanism.

## Verification and native target boundary

Focused tests use a real synthetic issuance graph and guarded native reader,
real revision catalog doubles/history reader, real ephemeral RSA -> existing
strict verifier -> canonical pending constructor/store, transaction ABA and
expiry checks. SQLite/doubles are not native catalog, privilege or concurrency
proof. The separately opt-in native module is
`tests/integration/test_social_enrollment_v2_reservation_postgresql.py`. Without
its explicit disposable target selectors, the module skips; such a run provides
no native execution evidence. Bounded native execution is recorded separately
with exact source identities, test results and verified teardown.

Every fresh rehearsal requires all existing canonical prerequisites preinstalled by
the external DDL runner, including pinned Current-Full, binding, OAuth lifecycle,
mobile authority, V1 issuance, challenge/association/receipt, atomic pending,
issued revision and native V2 issuance migrations. In particular the unchanged
reservation, revision and provenance sources are the migrations named by their
linked canonical contracts. The required existing migration sources are:

- `2026-07-22_current_entitlement_evidence.sql`
- `2026-09-04_social_messaging_device_bindings_v1.sql`
- `2026-09-10_social_messaging_device_binding_authorization_v1.sql`
- `2026-09-13_oauth_session_lifecycle_v1.sql`
- `2026-09-13_social_messaging_mobile_authorization_v1.sql`
- `2026-09-13_social_session_issuance_v1.sql`
- `2026-09-21_social_device_challenge_store_v1.sql`
- `2026-09-22_social_device_ed25519_association_storage_v1.sql`
- `2026-09-23_social_device_admission_receipt_consumption_v1.sql`
- `2026-10-02_social_preaccepted_enrollment_v2_atomic_acceptance_storage_v1.sql`
- `2026-10-09_social_device_challenge_revision_v1.sql`
- `2026-10-10_social_session_issuance_v2_provenance_v1.sql`

This test applies no migration and requires all prerequisite tables empty at
target establishment. Runtime must have exactly the existing owners'
restricted-role privileges, including the canonical pending owner's sole
`pg_read_all_settings` membership with inheritance and no membership admin
option. The native V2 reader's composed profile accepts that exact membership;
its standalone no-membership profile remains supported. Extra or inherited
memberships and profile/OID changes during a reader operation deny. No role
switch or second connection joins these owners. Required grants are public USAGE,
canonical pending SELECT/INSERT/UPDATE, native immutable history SELECT (and
producer-only INSERT for synthetic offer/parent/acceptance/issuance setup),
legacy authority SELECT/required owner locks, challenge SELECT/UPDATE,
association history SELECT/required chain locks and receipt SELECT/UPDATE for
locked absence reads. The independent DDL owner seeds synthetic challenges.
No DELETE/TRUNCATE/TRIGGER/REFERENCES or guard-function EXECUTE, owner membership,
superuser, role/database creation, replication, BYPASSRLS or public CREATE may
be granted to runtime. Consult the pinned migration/reader privilege contracts
for the full inherited producer prerequisites; this summary waives none.

Exact selectors use prefix `UBID_V2_RESERVATION_REHEARSAL_`: `ACK` must equal
`DISPOSABLE-SYNTHETIC-V2-RESERVATION-PREINSTALLED`, with `NONCE`, `PORT`, `DATA`,
`DDL_DSN` and `RUNTIME_DSN`. Nonce is fresh lowercase 32-hex; database is
`ubid_v2_reservation_rehearsal_<nonce>`, data directory is the matching unique
`/tmp/ubid-v2-reservation-rehearsal-<nonce>/data`. PostgreSQL is 16, host exactly
127.0.0.1, port explicitly 49152..65535, no password/query/default/Unix socket
fallback. Roles are `ubid_v2_reservation_ddl` and `ubid_v2_reservation_runtime`.
Existing DATABASE_URL is never used. The external runner owns unique cluster
identity, provisioning, authorization and verified stop/removal teardown.

Bounded native execution covers rollback atomicity, exact committed retry
without candidate signing, competing first reservations and changed-input
collisions, observed combined lock order and physical backend continuity,
root-XID replacement, same-OID catalog-definition changes, history row filtering,
role-profile changes and extra-membership denial. Completed table waits exercise
fresh-clock success and expiry rejection. Event/backend-wait synchronization and
bounded diagnostic budgets allow catalog attestation to finish; timeout denial
does not substitute for completed-wait behavior. Collection and skips alone are
not native test success. The tested synthetic target does not establish live
catalog/role compatibility or general finalization after lock waits.

The caller alone commits or rolls back and owns all savepoints. This slice
creates no receipt, effect, association, consumption, accepted CAS, admission,
V2 challenge producer, Social statement signer, DM transport, HTTP route,
runtime/factory wiring, live migration, key provisioning or deployment.
Finalization must still satisfy every requirement of the unchanged
[atomic acceptance/CAS contract](SOCIAL_PREACCEPTED_ENROLLMENT_V2_ATOMIC_ACCEPTANCE_AND_CAS_V1.md),
[deadline evidence](SOCIAL_MESSAGING_DEVICE_VERIFICATION_DEADLINE_EVIDENCE_V1.md)
and [Social V2 statement contract](SOCIAL_PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENT_V2.md).

Native role-composition regressions exercise the original and composed profiles
through unpatched full-catalog readers, deny extra read-data/read-statistics
memberships, and reject a completed profile change in an already bound reader.
Temporary membership grants/revocations occur only on the explicitly authorized
synthetic PostgreSQL target and are restored in `finally` blocks. Collection
alone establishes no native execution evidence.
