# Native first-onboarding V2 phone-session issuance provenance V1

Status: **dormant additive source implementation**. Bounded synthetic
PostgreSQL 16 verification covers native issuance, locked reads, recovery
and the specific wait/concurrency cases described below. Live migration,
route, factory composition, service, configuration, transport and deployment
remain separately deferred.

The four implementation modules are `social_session_issuance_v2_contract.py`,
`social_session_issuance_v2_storage.py`, `social_session_issuance_v2_authority.py`
and `social_session_issuance_v2.py` under `app/services`. They preserve the exact
[V2 handoff](SOCIAL_PREACCEPTANCE_ED25519_HANDOFF_V2.md),
[canonical OAuth lifecycle](OAUTH_SESSION_LIFECYCLE_V1.md),
[V1 issuer](SOCIAL_SESSION_ISSUANCE_V1.md), and existing fixtures and migrations.
Only `register + initial` / `qr_desktop_pre_enrollment_v2` is supported.
Continuation, rotate/adopt/re-enrollment and deferred `lockedDeadlineMs` and
verifier-run retry semantics are outside this contract.

## Native producer and authority separation

`NativeV2SessionIssuer` receives the existing exact OAuth lifecycle owner,
configured client, backend and service principal. It does not discover keys,
read environment configuration, register clients or generate a browser login.
It invokes the existing canonical OAuth signer with that owner's injected
configuration. This signer signs only the basic OAuth credential. It cannot
replace the separately deferred dedicated UBID deadline-evidence signer or
Social verification-statement signer.

`create_offer(raw_authorization_wire, desktop_bearer=...)` reparses exact raw V2
bytes, authenticates the canonical desktop bearer, selects its exact stored
OAuth generation, locks its native owners and records the original offer and
parent in one owned transaction. It verifies current Full using the existing
subject-locking evidence-and-proof seam. The phone's original pairing-secret
and exchange-verifier commitments are already part of the canonical V2 wire.
The proposed subject must equal the native authenticated subject. Caller
parsed records, context flags and alleged browser generations are never inputs.
Creation returns the same bytes only after successful commit.

`issue(operation_id, approval_wire=..., secret=..., possession_proof=...,
verifier=..., delivery_key=..., approver_bearer=...)` refetches the exact offer
and original parent, verifies its original pairing HMAC and exchange verifier,
reparses the original approval through the real BIP340 verifier, and requires
the approver bearer to be the exact original desktop token. It rechecks all
current native owners and Full, then applies the approved exact initial X25519
binding through the existing `apply_authorized` mutation primitive. Its checks
include device history, historical public-key reuse and active-device capacity.
The V2 event is never passed into a V1-only signature verifier.

The immutable acceptance contains the original verified canonical event,
canonical V2 acceptance, original HMAC bytes, binding identity and the Full
provenance from that same locked evaluation. The native immutable acceptance
and actual digest-only OAuth token plus issuance persist atomically. Ed25519
phone-proof verification, Ed25519 association creation, challenge consumption,
reservation, final admission and Send permission remain separate future
Social/UBID finalization decisions. UBID claims no Ed25519 verification.

## Relations, causal creation and retained history

The additive migration source is
`migrations/2026-10-10_social_session_issuance_v2_provenance_v1.sql`.
Seven explicitly qualified `public.social_session_v2_*` relations use separate
SQLAlchemy declarative metadata; none is registered on default `app.models.Base`:

- `offers`: immutable exact raw V2 envelope, original context and native birth XID;
- `parents`: exact original token/session/browser/User and continuity commitment;
- `binding_births`: immutable automatically produced original binding INSERT link;
- `token_births`: immutable automatically produced original OAuth-token INSERT XID;
- `acceptances`: immutable original BIP340 approval, V2 acceptance and Full provenance;
- `issuances`: one immutable acceptance-bound original basic child credential decision;
- `invalidations`: permanent terminal operation tombstones.

Offer insertion claims the existing global request fence using its existing
`mobile` ownership vocabulary. V2 acceptance claims the existing binding-owner
fence. Existing V1 operation, handoff and acceptance rows are never relabeled,
adopted or backfilled, and their CHECKs and trigger sources remain unchanged.
The new parent INSERT guard requires the original offer's immutable birth XID
to equal the current native top-level XID. A deferred completeness trigger
requires every offer to have its parent before commit. Both rows are immutable.
Native binding and token INSERT triggers create birth records automatically;
updating an old row's `xmin` cannot manufacture that provenance. Acceptance
requires its exact original binding birth in the same transaction; issuance
requires a new token birth and acceptance in the same owned root transaction.
There is no late-link, repair-on-read, public acceptance-insert helper, default
revision or highest-version lookup.

Token birth records retain only identity and insertion XID. They do not adopt
old tokens and grant no authority. They deliberately do not impose a foreign
key on unrelated generic token cleanup; exact V2 children are retained by their
own native FK and immutable token guard. The supported producer owns a clean
root transaction and creates no savepoints. Reader savepoint support is separate.

## Stable identities and revision

Operation/pairing ID, canonical V2 acceptance ID, random issuance ID, original
OAuth token JTI, request ID, authorization digest, binding ID and revision are
separate identities. The original parent and approver lineage are equal in this
first-onboarding contract; later different-approver semantics are unsupported.

`socialSessionIssuanceRevision` is **lowercase HEX64**, exactly as required by
[deadline evidence](SOCIAL_MESSAGING_DEVICE_VERIFICATION_DEADLINE_EVIDENCE_V1.md).
It is not a positive integer. Challenge and reservation revisions retain their
own existing contracts. The revision is lowercase SHA-256 of ASCII
`HODLXXI_SOCIAL_SESSION_ISSUANCE_REVISION_V2`, NUL, and the exact compact sorted
ASCII JSON preimage produced by `revision_preimage`. Its closed fields bind
schema/version, operation ID, exact approval and acceptance wires, issuance ID,
token ID, exact parent and approver token/session/browser IDs, client/backend/
principal/issuer, delivery commitment, original signing key ID, `issuedAt` and
`expiresAt` whole seconds. This identity grants no authority by itself. Tests
pass this output through the actual frozen deadline-evidence payload consumer.

## Locking, transaction continuity and composition

The order is future reservation (if present) -> V2 operation advisory lock ->
immutable offer/parent/acceptance observations -> shared request advisory lock
-> Current-Full subject advisory/User -> device and global/sorted public-key
mutation locks -> OAuth client -> issuer -> original browser -> parent token
-> parent Session -> exact binding -> child token. Immutable V2 history needs
SELECT only. Current-Full evaluation reuses already-held subject/User locks.
The unchanged `binding_for_id` primitive defaults to `lock=True`: it refreshes
the exact binding with `FOR UPDATE` after parent owner locks. Its read and the
existing `apply_authorized` history/key/capacity reads, advisory locks and Core
writes use the same guarded Connection through `BoundSession`. Trusted time is
sampled again after binding and evidence lock work. Offline regressions check
this source ordering and routing. The opt-in PostgreSQL tests additionally
exercise a successful reader wait and rejection after a completed wait
crosses an original deadline. These controls cover this V2 reader boundary.
Existing binding/lifecycle writers conflict on the same mutation/owner locks;
new native invalidation guards also serialize on affected native owner rows.
Deadlock/serialization errors require rollback; they do not authorize a new
grant. A bounded native first-writer test observes two distinct backends
waiting for locks, then requires one acceptance/issuance and identical
results and recovery. Its test-only lock/statement budgets permit the
intended completed wait; application timeout policy is unchanged. General
Current-Full concurrency, reserve/finalize acceptance after waits and
runtime orchestration remain separate verification obligations.

`NativeV2AuthorityReader` requires a caller-owned PostgreSQL READ COMMITTED
transaction. It begins, commits, closes and rolls back nothing. All ORM reads
refresh identities and explicitly bind to its guarded physical Connection;
advisory lock SQL executes directly on that Connection. It pins Session and
Connection root/savepoint objects, non-autocommit DBAPI identity and native
`pg_current_xact_id()` before and after lock/read work. Restarted or swapped
connections/transactions, dirty sessions, inactive/replaced savepoints,
missing native provenance, expired or revoked owners, V1 history and forged
exported evidence deny. Failure poisons the reader and requires caller rollback.
The caller must exclusively use SQLAlchemy transaction APIs; raw driver/SQL
savepoint control and concurrent/reentrant Session use are unsupported. Native
XID is private and authenticates the root, never an individual savepoint.

The returned `LockedV2Authority` has no caller-writable fact fields. Exact
identity registration ties it to one internal immutable tuple and reader.
`validated_facts` rejects constructions, copies and lookalikes; field mutation,
including `object.__setattr__`, cannot alter the tuple. Every access checks the
original transaction and resamples trusted time against the independently retained
effective deadlines. Native values are frozen before parsing and validation, so
a later cached ORM mutation cannot rewrite validated provenance. The record contains exact child/acceptance/approval,
parent/approver lineage, binding/version/key commitment, independent effective
deadlines and Current-Full evidence ID/version/source hash/proof identity from
one locked evaluation. Its Full deadline is retained independently.

An optional raw verification input is reparsed through the real V2 parser and
must match that original stored approval/acceptance and current time bounds.
Its exact phone-proof bytes are preserved, and its digest is a canonical input
identity, not Ed25519 validity or acceptance of the future enrollment. Future
reserve/finalize owners must consume the record in this same transaction,
then lock the exact native challenge and association owners in the established
order and authenticate dedicated evidence/statement artifacts. They must
recheck after waits and before effects. Results remain explicitly
`provisional_until_caller_commit`; the old V1 authority owner is not invoked.

## Lifetime, recovery and invalidation

Trusted UTC is injected through the existing owner clock and sampled after
waits, after writes, before commit and before delivery, including the independently verified Full
deadline. Milliseconds use exact
integer arithmetic and JavaScript-safe nonnegative integers. Expiry is
exclusive, with no skew, extension or grace. The basic child's absolute OAuth
expiry floors the earliest original pairing, approved semantic/exchange,
pre-enrollment, binding and parent token/session/browser deadlines. It cannot
exceed the original 300-second pairing window. `iat` is the conservative whole
second containing issuance; fractional acceptance time remains exact history,
and no credential has usable authority before successful owner commit.

Scope is exactly `openid profile`, with no refresh, Full, operator, admission
or messaging privilege. This V2 source requires current Full for new issuance
and active delivery/reader observations; it never encodes Full into OAuth scope.
Full evidence revocation is checked independently. User deactivation/subject
change, client scope/metadata/deactivation, issuer deactivation, original
browser replacement/logout, parent token/Session revocation/shortening and any
change to the exact binding create terminal invalidation and revoke the child.
Child identity, digest, metadata and signing identity are immutable; expiry
cannot extend and revoked tokens cannot resurrect. Restoring owner activity
cannot erase terminal history or issue a replacement from the original offer.

The delivery commitment hashes ASCII `HODLXXI_SOCIAL_SESSION_DELIVERY_V2`, NUL,
and canonical JSON `[issuer,client,backend,principal,operation,verifier,deliveryKey]`.
The original exchange verifier and separate delivery key serve distinct purposes.
Neither is persisted in plaintext. First committed delivery context wins.
An exact active retry/recover reproduces original OAuth claims, JTI, key ID and
timestamps through the configured canonical signer and compares the bearer
SHA-256 to the original stored digest. It never remints, changes signing
identity or extends TTL. The original signing representation must remain
available in that injected configuration; a different active key or missing
original key fails closed. There is no key discovery/fallback or replacement
grant. `recover` never creates missing authority. Inactive history returns the
same receipt with null subject and bearer. Loss of original possession proofs
or delivery key retains history and denies recovery. Rollback and uncertain
commit release no precommit credential. No plaintext bearer, pairing secret,
verifier, delivery key or participant/device private key is stored.

## PostgreSQL and role boundary

PostgreSQL **16 only** is the reviewed source boundary and the major used
for bounded synthetic execution evidence. Other majors are unsupported.
The migration creates no role or grants to a runtime identity.
A separately trusted DDL owner owns the new relations/functions. Runtime must
be a distinct direct login with no owner memberships, superuser, CREATEROLE,
CREATEDB, replication, BYPASSRLS or public-schema CREATE authority. It receives
SELECT on new history and INSERT only on the four producer relations, plus
existing owner lock/insert privileges described in the migration. It receives
no new UPDATE/DELETE/TRUNCATE/REFERENCES/TRIGGER or column-level write bypass,
and no new trigger-function EXECUTE. Native producer/invalidation functions
are narrowly SECURITY DEFINER with qualified business relation names and no
dynamic SQL. Only `social_session_v2_invalidate` has the exact configuration
`search_path=pg_catalog, public, pg_temp`; all other new functions retain exactly
`search_path=pg_catalog`. Its actual child-token UPDATE invokes the unchanged
legacy invoker guards, whose unqualified public relations require this narrowly
trusted path. The permanent tombstone and actual child revocation stay atomic,
with all legacy guards and cascades active. Catalog attestation independently
checks public schema ownership and runtime USAGE, absence of CREATE and owner
membership, and pins the schema OID/owner on every recheck. pg_catalog FIRST and
pg_temp explicitly LAST prevent caller-path and temporary shadow substitution;
arbitrary path order or extra configuration denies. PUBLIC privileges are
revoked. Trusted DDL rewrite is outside this administrative boundary.

The reader pins new relation/row-type/TOAST, function, trigger, constraint and
supporting index identities, authenticates exact source-pinned new bodies and
legacy owner guard source hashes, checks closed trigger bindings and constraint
renderings, and rechecks effective restricted-role privileges. Unexpected
new hooks, bodies, constraint definitions, owners, shadows or identity changes
deny. Source expectations alone are not PostgreSQL catalog observations.
The bounded synthetic rehearsal supplies independent catalog attestation
and native restricted-role/immutable-trigger checks. It does not establish
compatibility with a live schema or its role/configuration state. Every
new target requires explicit native rehearsal; SQLite and doubles supply
no native catalog, privilege or concurrency proof.

The separately opt-in synthetic native test module is
`tests/integration/test_social_session_issuance_v2_postgresql.py`. It rejects
missing/wrong ACK, default/live targets, remote hosts, Unix sockets, implicit
DSNs and nonunique temporary data paths before connection. An external runner
must provision exact empty prerequisites and distinct roles, authorize applying
this source only there, and verify cluster teardown. The bounded rehearsal
executed committed issuance/read/retry, changed delivery, causal/privilege
guards, terminal parent invalidation, concurrent first writers, successful
reader waiting, expiry after a completed native wait, wrong original phone
proofs, producer root rollback and immutable-trigger cases. Counts, exact
source identities and teardown evidence belong in the external run report.
Fixture Session metadata is explicit SQL NULL, as required by the unchanged
OAuth generation guard; Python None in its JSON type is JSON null.
Local offline tests separately exercise real implementation decisions,
canonical consumers, cache refresh and transaction/time failures using
in-memory SQLite and constrained doubles only. These bounded V2 cases do
not establish general Current-Full PostgreSQL concurrency or future
reserve/finalize effects after lock waits.

Finalization, dedicated signer custody, transport, activation and deployment
remain separately deferred. **DEPLOYMENT_READY=NO**.
