# Social preaccepted-enrollment V2 atomic acceptance and CAS V1

Status: **dormant reservation/finalization byte contract and caller-transaction
PostgreSQL durability/CAS owner; no authority orchestration, route, runtime
wiring, migration application, or activation**.

The implementation is
`app/services/social_preaccepted_enrollment_v2_atomic_acceptance_contract.py`.
`RUNTIME_ENABLED` is `false`. UBID is the sole future owner of deadline
reservation, final acceptance/CAS, the association effect, immutable receipt,
challenge consumption and commit decision. Social owns only the separate
strict verification and verification-statement signing process.

The dormant durability owner is
`app/services/social_preaccepted_enrollment_v2_atomic_acceptance_storage.py`,
with the unapplied additive schema in
`migrations/2026-10-02_social_preaccepted_enrollment_v2_atomic_acceptance_storage_v1.sql`.
It owns only its reservation/decision row, exact-byte collision comparison,
database uniqueness and one-way CAS. It is not a current-authority reader and
cannot independently authorize an accepted transition. Production relation,
mapped model, trigger and trigger-function identity is pinned to the quoted
PostgreSQL `public` schema; neither migration nor runtime lookup depends on
`search_path`. Every operation attests the complete trigger catalog identity
and the complete stable relation, TOAST, trigger and trigger-function catalog
definition against the migration-synchronized expected digest, while also
rechecking cached object identities rather than trusting names or definitions
alone.

## Two caller-owned UBID transactions

Reservation and finalization are separate transactions because Social
verification occurs outside UBID database locks.

### Reservation transaction

The caller-owned PostgreSQL transaction must lock/recheck all four deadline
authorities plus the exact challenge and absent association state, construct
[`MessagingDeviceVerificationDeadlineEvidenceV1`](SOCIAL_MESSAGING_DEVICE_VERIFICATION_DEADLINE_EVIDENCE_V1.md)
only from those locked results, insert one immutable `pending` reservation,
sign/store the exact evidence as required by that future owner, and commit.
The pure pending-reservation constructor strictly verifies the exact compact
evidence against its dedicated public trust and exact V2 input; it does not
accept four raw deadline integers.

The storage adapter accepts only that canonical pending wire through the same
strict constructor. It uses database uniqueness across the reservation,
request, operation, device, acceptance, challenge, association, input and
evidence identities. Concurrent first writers converge by insert-on-conflict
followed by a locking collision-set read. A collision set that is missing,
changed or ambiguous fails closed. An exact live pending retry returns the
stored evidence bytes and never re-signs.

Every durable reparse receives the existing dedicated deadline-evidence trust
configuration and authenticates the exact stored compact JWS through the
canonical verifier. Pending and non-accepting terminal history uses the signed
reservation observation instant; accepted history uses the exact stored
decision instant after requiring it to equal the observation and receipt
decision time. Decoding a payload, parsing a snapshot or recomputing its digest
is never provenance. Historical verification grants no present authority and
requires the original trust record to remain explicitly registered and
unrevoked in the injected config.

### Finalization transaction

After Social returns the exact authenticated V2 statement, a new caller-owned
UBID transaction must lock, in the globally established order:

1. the exact reservation ID/revision;
2. the exact Current-Full, phone child/parent and approver authorities;
3. the exact current X25519 binding;
4. the exact issued challenge ID/revision; and
5. the exact subject/device association chain and the expected absent state.

It must reconstruct the closed current-authority snapshot from those locked
rows. The pure comparison model requires byte-for-byte equality of every
identity, revision, effective deadline, proof/digest and V2 binding frozen in
the evidence. It also requires the exact input, evidence and statement
digests; one matching acceptance/association/challenge/attempt graph; current
exclusive time bounds; challenge state `issued`; and the association CAS
tuple `absent/null/version 0/authority epoch 0`.

Only after all comparisons succeed may the durable owner, in that same
transaction, create association version 1/authority epoch 1, record exactly
one effect, insert the immutable receipt, consume the challenge, transition
the reservation to `accepted`, and commit. Any mismatch, ambiguity, expiry,
revocation, rotation, replacement, reuse or concurrent change denies and the
caller rolls back. The pure model does none of those operations and its output
is `provisional_until_caller_commit`.

This storage phase supplies the reservation-row lock and CAS only. Its
`finalizationObservation` argument remains caller-provided non-authoritative
evidence. A later transaction orchestrator must build it from the exact locked
Current-Full/session, binding, challenge and association owners in the same
transaction, and must coordinate the real association and challenge effects
before caller commit. Calling the storage adapter without that orchestrator is
not authorization. Every returned durable result remains
`provisional_until_caller_commit`, `current_authority=not_established_by_storage`
and `final_admission=denied`.

Accepted durable reparse also requires the explicit server-owned dedicated
Social V2 statement trust configuration. It invokes the existing canonical
statement verifier over the exact stored compact JWS, exact embedded
verification context/input, the four authenticated evidence deadlines and the
historical decision instant. Issuer, audience, client, service principal,
purpose/result, acceptance, association, challenge, attempt and input
identities are verified by that boundary; the exact input independently binds
subject, device, request, keys and every nested enrollment identity. The
verified statement digest must match the accepted reservation, finalization
request, effect and receipt chain. A decoded statement payload or a
self-consistent recomputed digest is not authentication.

## Closed state and retry semantics

The reservation states and replay/device-ID rules are fixed:

| State | Exact same-request retry | Changed reuse | Device-ID rule |
|---|---|---|---|
| `pending` | Return the already stored evidence while unexpired; never re-sign. | Deny. | Reserved by that exact pending request. |
| `accepted` | Return the immutable receipt; execute no second effect. | Deny. | Denied because the association is committed. |
| `rejected` | Deny; no reopening or re-signing. | Deny. | A new reservation is possible only after locked proof of no effect, receipt or association, with a new request, challenge, input and reservation. |
| `expired` | Deny; no reopening or re-signing. | Deny. | Same guarded new-reservation rule. |
| `cancelled` | Deny; no reopening or re-signing. | Deny. | Same guarded new-reservation rule. |

An accepted lost response is reconciled from immutable history and never
reexecuted. A pending lost response returns the exact stored JWS. Changed-byte,
changed-digest and changed-identity attempts fail closed. There is no fallback
to a different key, authority row, evidence version, statement, reservation,
challenge or association.

The migration rejects update of accepted or non-accepting terminal rows and
rejects delete or truncate. Device ID uniqueness is deliberately retained
after expiry, rejection or cancellation. This storage owner exposes no release
or replacement operation; a future separately reviewed orchestrator must first
prove the contract's locked no-effect/no-receipt/no-association conditions
before any later design can permit a new reservation. Expiry alone never does.

Retry reconciliation authenticates the exact stored compact evidence through
the existing verifier, compares its canonical header, payload, token identity
and every reservation identity/digest frozen by that payload and the exact V2
input, then reconstructs the one canonical authority snapshot from those
authenticated claims. The verification clock is the signed reservation
observation instant so later wall-clock expiry is not relabeled as current
authority. Pending evidence must still be within its exact signed interval for
the requested retry. Accepted history compares the exact canonical
observation, evidence-bound effect and every canonical receipt field,
including `decidedAt`, with the accepted reservation and derivable finalization
request. The receipt ID intentionally remains decision-time-independent, but
matching that ID alone never makes mutated receipt bytes immutable history.
The finalization observation parser receives the accepted reservation's exact
reservation/challenge identities, challenge revision and historical decision
instant. It reconstructs the authority snapshot at that expected instant,
rather than selecting the instant from observation bytes, before the effect
parser derives any identity. Thus challenge revision, observation time,
accepted-reservation decision time and receipt decision time must all agree.

## PostgreSQL definition and role boundary

The migration must be applied by a dedicated migration/DDL owner. The runtime
role must be a distinct direct login that is neither the table, function nor
schema owner, cannot act as any of those owners, is not superuser and has no
`CREATEROLE`, `CREATEDB`, replication, row-security bypass or authoritative
schema `CREATE` privilege. Its only permitted membership for this owner is the
predefined read-only `pg_read_all_settings` role used by the disposable target
identity guard.

The migration revokes public table and trigger-function privileges. A
deployment-specific provisioning step must grant the runtime role schema
`USAGE` and exactly table `SELECT`, `INSERT` and `UPDATE`; it receives no
`DELETE`, `TRUNCATE`, `REFERENCES`, `TRIGGER` or trigger-function `EXECUTE`
privilege. This source-only phase does not name or create a production role.
The disposable PostgreSQL proof applies the migration as one DDL owner and
runs the repository as a separate role with exactly those grants.

On construction and again before every operation, the repository checks the
relation, row-type, associated TOAST, function and both trigger identities;
relation, TOAST and function owners; all effective runtime-role properties and
privileges; and the complete stable definition payload described below. The
function cost and row estimate use canonical lowercase hexadecimal encoding of
the exact four bytes returned by `pg_catalog.float4send`, independent of
`extra_float_digits` or any other text-output setting. The source-pinned
expected bytes are derived from the migration's `COST 100` constant and the
non-SETOF trigger function's fixed zero row estimate, while the support
function uses its exact OID. Relation and TOAST options are sorted before
serialization, and `NULL` remains distinct from an empty option array. The
canonical catalog payload must hash to the deterministic digest synchronized
with the migration. Same-OID `CREATE OR REPLACE TRIGGER ... WHEN (...)`,
same-OID function-body replacement, exact-definition trigger drop/recreation,
owner changes and any expected-digest mismatch therefore fail closed.

### PostgreSQL 16 catalog-field classification

This inventory follows the PostgreSQL 16 [`pg_proc`](https://www.postgresql.org/docs/16/catalog-pg-proc.html),
[`pg_class`](https://www.postgresql.org/docs/16/catalog-pg-class.html) and
[`pg_trigger`](https://www.postgresql.org/docs/16/catalog-pg-trigger.html)
catalogs. “Definition” below means a stable logical property controlled by DDL
for this ordinary table, its TOAST relation, its trigger function or either
authoritative trigger. Object identity, ownership and effective authorization
are rechecked separately. Runtime and maintenance state is deliberately not
part of the source-pinned digest.

For `pg_proc`:

- Definition payload: `proname`, `prolang`, `procost`, `prorows`,
  `provariadic`, `prosupport`, `prokind`, `prosecdef`, `proleakproof`,
  `proisstrict`, `proretset`, `provolatile`, `proparallel`, `pronargs`,
  `pronargdefaults`, `prorettype`, `proargtypes`, `proallargtypes`,
  `proargmodes`, `proargnames`, `proargdefaults`, `protrftypes`, `prosrc`,
  `probin`, `prosqlbody` and `proconfig` are all in the canonical payload.
  Both `float4` fields use the same exact `float4send`-byte representation;
  neither passes through session-dependent floating-point text output.
- Identity, ownership and authorization: `oid` and `proowner` are cached at
  construction and rechecked; `pronamespace` is resolved through the exact
  schema on every check; `proacl` is enforced as the exact effective runtime
  rule that the restricted runtime has no function `EXECUTE` privilege. ACL
  bytes are not mistaken for logical function definition bytes.
- Runtime state excluded from the digest: none; `pg_proc` has no planner
  statistic or transaction-horizon column. For this non-SETOF trigger-returning
  function PostgreSQL fixes `prorows` at `0` and rejects `ALTER FUNCTION ...
  ROWS`; `prosupport` is canonically zero, while assigning a nonzero planner
  support function requires superuser authority and is still detected.

For `pg_class`, applied independently to the base relation and its associated
TOAST relation where meaningful:

- Definition payload: `relname`, `reloftype`, `relam`, `reltablespace`,
  `relhasindex`, `relisshared`, `relpersistence`, `relkind`, `relnatts`,
  `relchecks`, `relhasrules`, `relhastriggers`, `relhassubclass`,
  `relrowsecurity`, `relforcerowsecurity`, `relispopulated`, `relreplident`,
  `relispartition`, `reloptions` and `relpartbound`. The lazily maintained
  structural flags are pinned because the canonical relation permanently has
  its indexes and triggers and has no rules, subclasses or partitions; normal
  operation cannot change those expected values without definition DDL.
- Identity, ownership and authorization: `oid`, `reltype` and `reltoastrelid`
  are cached and rechecked; `relnamespace` is resolved through the exact base
  or `pg_toast` schema; `relowner` is cached and the TOAST owner must equal the
  base owner; `relacl` is enforced through the exact effective runtime table
  privileges rather than byte-pinned. The TOAST name must retain PostgreSQL's
  `pg_toast_<base-relation-oid>` identity, and both its OID and canonical
  options are rechecked on every operation.
- Runtime or physical state excluded from the digest: `relfilenode` is a
  replaceable physical storage locator; `relpages`, `reltuples` and
  `relallvisible` are planner/visibility estimates; `relrewrite` is transient
  rewrite state; and `relfrozenxid` and `relminmxid` are vacuum-maintained
  transaction horizons. Pinning any of them would make ordinary maintenance
  poison an otherwise unchanged definition.

For `pg_trigger`:

- Definition payload: `tgparentid`, `tgname`, `tgtype`, `tgenabled`,
  `tgisinternal`, `tgconstrrelid`, `tgconstrindid`, `tgconstraint`,
  `tgdeferrable`, `tginitdeferred`, `tgnargs`, `tgattr`, `tgargs`, `tgqual`,
  `tgoldtable` and `tgnewtable` are all serialized for each of the two exact
  expected triggers.
- Identity and association: each `oid` is cached separately at owner
  construction and rechecked; `tgrelid` must resolve to the cached relation and
  `tgfoid` to the cached guard function on every check. Triggers have no owner
  or ACL column independent of their relation.
- Runtime state excluded from the digest: none; `pg_trigger` contains no
  planner statistics, physical counters or transaction horizons.

## Canonical bytes and identities

Reservation, current-authority snapshot, finalization observation, effect and
receipt wires are compact lexically key-sorted printable-ASCII JSON with
closed member sets and bounded sizes. Parsers reject duplicate, missing or
unknown fields, alternate JSON, Unicode, booleans-as-integers, floats,
negative/unsafe integers and malformed identifiers/digests.

The reservation binds the evidence token and payload digests, exact input
domain digest and payload digest, request/operation IDs, acceptance,
challenge, association, subject/device, challenge revision and evidence
interval. The finalization request, authority snapshot, effect ID, effect
digest and receipt ID each use a different domain-separated SHA-256 preimage.
None is reinterpreted as a V1 effect, V1 receipt, row ID, request ID, challenge
ID, association ID or bearer credential.

All persisted timestamps are wall-clock UTC epoch milliseconds. Expiry is
exclusive with no skew. Any local processing timeout is monotonic and outside
all authority/evidence bytes.

Every failure is the same non-sensitive message:

```text
social preaccepted enrollment v2 atomic acceptance denied
```

The public failure has no chained cause or context; malformed values and
internal parser or serializer failures are not retained on the exception.

The PostgreSQL invariant independently decodes the immutable stored JWS
payload, binds every duplicated reservation identity to it, reconstructs the
exact sorted authority-snapshot and observation wires, and derives the effect
and receipt chain only from that evidence-bound snapshot. Whitespace variants,
alternate observation serialization, forged nested snapshot bytes and
snapshot-bound identity recomputation all fail closed. PostgreSQL deliberately
does not implement RSA verification; public accepted-history reparse supplies
that authentication for both signed artifacts. The runtime guard resolves the
fixed schema through PostgreSQL catalogs and rechecks the exact complete
definition and least-privilege identity on every operation; plausible
earlier-schema shadows and in-place same-OID replacements cannot redirect or
satisfy it.

## Public vector

The deterministic public fixture is
`tests/fixtures/social_preaccepted_enrollment_v2_atomic_acceptance_v1.json`:

```text
bytes  = 9638
sha256 = 6bbbf4c94f3120dbad57def6bceed7d5a9b563723402afb7cf1ca1e3121db7e8
```

It links the exact frozen deadline-evidence and Social V2 statement fixtures
and freezes one pending reservation, final locked observation, effect and
immutable receipt. These are pure values: they do not prove locks,
persistence, key custody, acceptance, an effect, challenge consumption,
receipt publication, commit, or runtime activation.

## Explicitly deferred

This phase adds the dormant model/table, unapplied migration and injected
caller-transaction durability/CAS adapter only. It adds no external authority
reader/orchestrator, association mutation, challenge consumption, route, BFF,
HTTP/socket transport, network call, background process, runtime/factory
composition, signer, key loader, provisioning/rotation command, configuration,
feature flag, service restart or deployment. The remaining prerequisites for
Phase 1 include the Social-owned
`InfrastructureMessagingDeviceVerificationSignerProcessV1` custody/lifecycle
contract and a separately authorized UBID transaction orchestrator that locks
and rechecks all current authorities and composes every acceptance effect.
