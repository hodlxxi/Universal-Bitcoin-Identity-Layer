# UBID Enrollment V2 finalization V1

Status: **dormant source only, disabled by default**. `RUNTIME_ENABLED` is false;
`final_admission` is always `denied`. The additive migrations are **unapplied to
live systems**. Isolated PostgreSQL verification covers finalization roles,
causal completeness, full commit and rollback, concurrent exact retry and
completed waits, using genuine clocks for pending acceptance. Marked-profile
acceptance requires the separate additive SQL profile below. This synthetic
verification does not establish deployed behavior, production capacity or
operational provisioning; deployment readiness and DM transport remain **NO**.

## API and immutable public trust

`V2FinalizationOwner(session, *, clock, config=FinalizationConfig())` receives an
already active caller PostgreSQL READ COMMITTED Session and a trusted server
clock returning an exact nonnegative safe integer UTC epoch millisecond. There
is no environment connection, private-key loader, detached authority port or
ambient clock. The exact keyword-only operation is:

```python
owner.finalize(
    reservation_id=reservation_id,
    reservation_revision=1,
    verification_input_wire=exact_canonical_v2_input,
    evidence_compact_jws=exact_stored_evidence,
    statement_compact_jws=exact_social_v2_statement,
    issuance_id=original_native_issuance_id,
)
```

Config owns the existing immutable `ReservationConfig`, the dedicated existing
Social V2 public trust config, and immutable `StatementTrustPin` registrations
with exact kid/SPKI fingerprint, positive revision, notBefore, exclusive notAfter
and optional terminal revocation. The identity tuples must agree with the native
backend and the exact context/audience/client/principal/purpose. Construction
reparses public material and freezes copies. No key material is operationally
provisioned. Original evidence registrations use the unchanged reservation kid
and independent revision/record-ID policy. Statement registrations are retained
in the native receipt ledger and compared exactly on recovery. Changed lifetimes,
revision, fingerprint, trust removal or revocation cannot rescue stored history.

Both compact artifacts enter their real strict RS256 consumers. The exact raw
V2 input enters the canonical parser, including genuine BIP340 approval. UBID
neither verifies Ed25519 nor produces Social's verification statement. Tests use
synthetic, freshly generated in-memory RSA objects, never serialized private
keys; shape-valid phone proof is not Social verification evidence.

The byte protocols remain canonical in the
[reservation contract](SOCIAL_ENROLLMENT_V2_RESERVATION_V1.md),
[native issuance provenance](SOCIAL_SESSION_ISSUANCE_V2_PROVENANCE_V1.md),
[issued revision contract](SOCIAL_DEVICE_CHALLENGE_REVISION_V1.md),
[Current-Full evidence](CURRENT_ENTITLEMENT_EVIDENCE_V1.md),
[V2 handoff](SOCIAL_PREACCEPTANCE_ED25519_HANDOFF_V2.md),
[deadline evidence](SOCIAL_MESSAGING_DEVICE_VERIFICATION_DEADLINE_EVIDENCE_V1.md),
[Social V2 statement](SOCIAL_PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENT_V2.md)
and [atomic model/CAS](SOCIAL_PREACCEPTED_ENROLLMENT_V2_ATOMIC_ACCEPTANCE_AND_CAS_V1.md).
Legacy wire bytes, digest domains and retry identities remain unchanged. The
separately selected signed freshness profile is defined below.

## Server-selected signed freshness profiles

The canonical policy is `social_enrollment_v2_freshness_policy.py`. Both immutable
RSA configs default to `legacy-10s`, including disabled configs and old positional
calls. Legacy evidence and statements omit `freshnessProfile`, retain their exact
closed field sets, fixed vectors and JTI preimages, and keep a maximum of 10,000 ms.
The global legacy lifetime constants remain 10,000. No runtime activation occurs.

A trusted server may separately opt in to `native-v2-60s-v1` on **both** evidence
and statement configs. Enabled finalization requires matching profiles; defensive
copies retain them. Each new payload must include exactly
`freshnessProfile: "native-v2-60s-v1"`. That field is covered by the canonical JTI
preimage and real RS256 signature. The schema, purpose, audiences, type, original
claims and bindings remain exact. Parsers, canonicalizers, signer, pending/CAS
builders and stored-history consumers receive the explicit server profile. They
never select policy from a pending browser payload, marker or duration. Legacy
readers reject marked artifacts even below ten seconds; new readers reject
unmarked legacy bytes. Unknown, bool, integer and unbounded profiles deny, even
on disabled configs. Exact field sets reject missing, mismatched and extra fields.

The opt-in maximum is 60,000 ms for each newly marked artifact. Reservation
`observedAt` is sampled after the existing locks and never refreshed after signing.
Its exclusive `expiresAt` is the minimum of observation plus the selected maximum,
phone, approver, Full, binding, pre-enrollment, enrollment and signing trust
`notAfter`. Those independent deadlines and all key pins remain authoritative.
The statement also obeys every original input/authority deadline and immutable
statement trust pin; `evidence.observedAt <= statement.issuedAt` and
`statement.expiresAt <= evidence.expiresAt` are required. Exactly 60,000 ms is
allowed only before its exclusive expiry; 60,001 ms denies. No underlying input,
key, session or enrollment lifetime changes.

Stored signed bytes already contain absolute exclusive expiry; no lifetime-data
rewrite is needed. The original CAS guard requires exactly 46 unmarked evidence
fields. The separate additive SQL profile below accepts the required signed
marker as a forty-seventh field only for the named native profile, while keeping
the legacy ten-second shape and all other guards exact. Its source remains
dormant; a disposable rehearsal does not authorize a live migration.
The profile cannot renew expired legacy or new bytes: no reissue,
renewed pending proof, backdating, skew, historical pending clock or remaining-time
recalculation extends a signed interval. Pending admission uses current authority.
Accepted retry authenticates byte-identical immutable native history at original
`decidedAt`; historical recovery creates no new effects or current admission.

This remains default off, source only, with `final_admission=denied`. Results are
provisional until the caller commits the complete transaction; publication must
follow a successful caller commit. Disposable synthetic PostgreSQL feedback is
rehearsal evidence only. The separate dormant
[caller composition](SOCIAL_ENROLLMENT_V2_RUNTIME_COMPOSITION_V1.md) and
[confidential ingress](SOCIAL_ENROLLMENT_V2_INGRESS_V1.md) can publish only after
confirmed commit. Their operational installation, live DB/HTTP access,
deployment, key provisioning and production activation remain separate obligations.

## Transaction, locks and current authority

The owner reuses `TransactionGuard` and exact `BoundSession`: one Session,
physical Connection, native root XID and original active root/nested objects.
No internal begin, commit, rollback, close or savepoint occurs. Dirty ORM state,
autoflush, routing to another bind, reconnection, replaced root/XID/savepoint or
poisoned transaction denies. SQLAlchemy transaction events additionally fence
completed savepoint ABA. Listener references are weak. As with the original
readers, callers must use SQLAlchemy transaction APIs exclusively; raw driver
savepoint management and concurrent/reentrant use of a Session are unsupported.
Native XID authenticates the root, not a raw backend savepoint.

The combined order is:

1. reservation table `SHARE ROW EXCLUSIVE` serialization, then exact collision
   rows in reservation-ID order;
2. native V2 operation and immutable offer/parent/acceptance/issuance graph;
3. native reader's request, Full subject/User, device and public-key mutation
   locks, exact client/issuer/browser/parent authorities;
4. exact X25519 binding, same transaction-bound Current-Full provenance, child
   token and exact approver authority under that reader's original order;
5. exact issued challenge, followed by its immutable native revision;
6. subject/device pair advisory lock, chain and complete immutable event history,
   then V1 receipt and V2 native history; and
7. real initial event, V2 effect/receipt, exact consumption and accepted CAS.

The native reader supplies only registered `validated_facts`; the real issued
revision reader supplies revision and exact original challenge bytes. The owner
reconstructs the frozen reservation payload from those same immutable locked
facts and compares every original identity, deadline, Full evidence ID/version/
source hash/proof and issuance revision with authenticated stored evidence.
It then invokes the existing closed snapshot constructor and finalization
observation/model. Newer or equivalent authority does not replace frozen facts.
Revoked chains and historical events do not count as absent. The native initial
INSERT also refuses an existing empty chain; there is no adoption/backfill.

Only an exact weak-registry `LockedFinalizationPlan` produced by that owner can
enter the writer. Its private record retains immutable primitive wire/time
snapshots, rather than mutable parsed dataclass facts. Construction, subclassing,
copying, detached model output, object forgery, another owner/guard and reuse
cannot register a plan. Every stage rechecks native facts, signatures, catalog
identity and root continuity. Failure poisons the owner/proof and original roots;
caller rollback is mandatory before another owner may continue.

## Distinct native V2 effects and causal completeness

The existing V1 association owner/receipt/consumption APIs retain their V1
cryptographic inputs and identities. V2 never manufactures a V1 authenticated
statement or re-roots a V2 signature/digest. It uses the existing pure lifecycle
serializer to derive the unchanged shared Enrollment V2 initial association
and event bytes, then inserts into the real shared chain/event relations.
The original V1 effect/receipt protocol remains separate.

`2026-10-12_social_enrollment_v2_finalization_v1.sql` adds immutable native
association-birth, canonical V2 effect/receipt, consumption and decision
companions. The narrow native function has exactly three stages: `association`,
`receipt`, `consumption`. Plain initial INSERTs create version 1/epoch 1 and the
existing event trigger advances the shared chain. Subsequent stages bind those
real records and the exact challenge/revision. They record server-native root
XID in the same function that performs each real mutation, never caller XID or
mutable xmin. Public/runtime INSERT/UPDATE/DELETE/TRUNCATE on companions is denied.

The additional accepted-decision trigger captures pending-to-accepted birth and
requires complete matching native evidence immediately. Deferred companion
triggers and the extended shared enrollment invariant require the exact accepted
row, original native acceptance/issuance, one real initial event, exact canonical
V2 effect/receipt and consumed challenge, with every birth on the same physical
root. Decision birth is unique per native root. Missing/partial effects, effects
without decision, accepted JSON without effects, fake V1 receipt, old-row
backfill, wrong IDs/bytes, extra matching events and split transactions deny.
The original shared V1 branch/checks remain present unchanged after the distinct
V2 branch; no old migration is edited and no original trigger is removed.

The native writer has a fixed safe composed search path with `pg_catalog`,
`public`, then `pg_temp`: this is required by the unchanged legacy shared trigger
bodies, while new SQL explicitly names `public` relations. It admits no
search-path shadow or schema-CREATE authority. The original CAS profile remains
supported; the separately activated extended profile has exactly its original
triggers plus the pinned native decision trigger. Unknown extra triggers and
profile/OID/definition changes deny. The new attestor reparses native function catalog fields, new companion
columns/constraints/indexes/FKs, combined shared trigger bindings and predicates,
role identity and visibility. It now also reads the full ordered attribute
catalogs, closed constraint catalogs and every index of the shared association
chains, association events, legacy enrollment receipts and CAS relation. The
fixed definitions are transcribed from their original migrations and models;
the installed target never supplies an expected definition. This includes the
five distinct partial unique creation indexes, their ordered keys, opclasses,
collations, direction/null rules and exact predicates, all backing indexes,
FK child/parent tuples and equality operators, actions/deferral/validation,
CHECK normal forms and constraint-trigger identities. Defaults, dropped or
inherited columns, missing/generated/identity state, compression, attribute
options/ACLs and unknown or ambiguous catalog entries deny.

Shared and native table/index relation definitions are checked in full. Where
the source creates TOAST, its relation, attributes and unique index are checked
through the same evaluator. The bounded association-chain, challenge-revision
and issuance-invalidation schemas have no TOAST table; an unexpected TOAST
binding denies. By default, direct table ACLs admit only the actual DDL owner and runtime role,
with the original supported history grants and no runtime grant options.
The optional [explicit challenge-writer profile](SOCIAL_ENROLLMENT_V2_RUNTIME_COMPOSITION_V1.md#explicit-challenge-writer-role)
admits one configured name/OID and its fixed privilege matrix only inside the
same caller root; it grants no rights and preserves the original finalizer profile.
Fresh native definitions are validated on every pass. Raw expression trees and
object identities supplement the fixed deparsed definitions as retained
fingerprints; they are never substitutes for fresh definition checks. OID JSON
strings, native vectors and ordinary numeric fields have separate narrow
handling. Physical `relfilenode`, page/tuple/visibility statistics and maintenance
`relfrozenxid`/`relminmxid` do not define a schema and are excluded after native
type validation. Index `indisclustered` records CLUSTER selection and is excluded.
The frozen original revision validator retains its existing requirement that
its primary index is not selected for CLUSTER.
Nonzero `relrewrite`, relation options, replica identity, index validity,
readiness/liveness and `indcheckxmin` remain denial conditions.

The actual writer path first checks its authority, invokes the original guarded
issued-revision reader on its bound port, invokes native issuance `attest(guard)`,
and invokes the new schema attestor on `guard.connection`, then checks authority
again. Ordinary CAS continuity checks retain the original transaction, role,
pending-relation and guard-definition checks, and freshly validate the additional
decision trigger and its exact function. They do not audit unrelated finalization
relations during reservation signing or clock reads. This local profile grants
no finalization or device authority. On the extended profile, `finalize_accepted`
requires the complete schema on the same Connection before locking, immediately
before a new accepted UPDATE, and after its result is reparsed. An exact accepted retry also requires
the complete schema again after the locked read. Local trigger identity and
complete schema identity are independently retained and compared; observed
identities never replace fresh validation. The full default `validate_cas_profile`
API and every existing `NativeV2Effects.check` checkpoint remain intact. The
original two-trigger profile retains its original CAS validation contract and
does not acquire native effects authority. Direct CAS calls use the same extended
profile checkpoints; they cannot bypass them by omitting the finalization owner.
Any failed check poisons storage and requires caller rollback, including after a
provisional accepted UPDATE. Raw history reconciliation remains non-authoritative;
native receipt recovery separately verifies the complete effects history. The
schema pass additionally invokes the original revision `_constraints` validator
on fresh original catalog rows and compares referenced PK/index identities at
the later FK boundary. Supplemental challenge/revision attribute checks do not
clone their canonical challenge or authority rules. All these paths use the
same actual guarded Connection and canonical public schema. A raw Connection
is a catalog observation port and supplies no issued facts or mutation authority.
There is no catalog/role/authority cache shared across attestations. These checks
do not claim stronger isolation than READ COMMITTED.

The COMPLETE FRESH catalog transport identifies exact SQLAlchemy `TextClause`
families from their raw text without compiling them. Other statement objects,
different SQL or parameter shapes and repeated logical reads use the original
live statement at that checkpoint. Eleven fixed row-producing catalog families
use grouped scans over the bounded relation/TOAST selectors, retaining every
original projected field and aggregate ordering. A left join supplies empty
`[]` results; scalar privilege and count queries retain their original plans,
including count zero. Distinct source SQL families retain distinct labels even
when their projections are equivalent.

The fixed ordinal envelope uses `row_to_json(ROW(...))` and `json_agg`, with
ordering inside each ordered aggregate and JSON `[]` for absent selector rows.
Every inner complete `to_jsonb(a/k/i/c/t/p)` projection remains unchanged;
the envelope avoids rebuilding those native records as JSONB. This is a catalog
transport encoding, not a public protocol or an arbitrary user-JSON conversion.
Closed ordinal fields retain full column width, SQL NULL and count-zero rows.
Decoded object key order does not carry authority; array and aggregate order do.

Each closed ordinal carrier owns one recursively immutable snapshot. Mapping
views share that snapshot; every returned row receives independently mutable
containers without another JSON encode/decode cycle. Boolean, integer, OID
string, array and SQL NULL distinctions remain intact, and the original complete
validators still consume the projected rows. Exact native scalar children bypass
recursive Python calls; scalar subclasses still become owned base scalars with
their metadata stripped. Every nested container is frozen, and scalar children
remain subject to the same exclusive depth bound. This transport is source
implemented with deterministic offline regressions. Isolated PostgreSQL
checks establish equivalent complete catalog identity before and after the
native scenarios; those bounded observations are not production performance
or capacity guarantees.

The additional definition evaluator freezes the original issuance companion
constraint contracts and validates their full native fields on this same
Connection. It closes ancillary attributes/defaults, complete constraint and FK
fields, ordered index vectors, index relation definitions, unknown standalone
indexes, relation/TOAST definitions, direct and column ACLs, complete trigger
bindings and internal RI bindings for `social_session_v2_offers`,
`social_session_v2_parents`, `social_session_v2_acceptances`,
`social_session_v2_issuances`, `social_session_v2_invalidations`,
`social_session_v2_binding_births` and `social_session_v2_token_births`.
Token births have no FK in the original migration. Required parent keys are
validated through separate canonical public relation, constraint and index
bindings. These key checks do not attest an unrelated parent's entire schema.
The original issuance validator remains invoked on the guarded Connection.

The evaluator closes the complete source profiles for `users`,
`current_entitlement_evidence`, `oauth_tokens`, `sessions`, `oauth_clients`,
`oauth_session_generations`, `oauth_browser_generations`,
`social_messaging_device_bindings`, `social_session_issuers`,
`social_messaging_mobile_operations` and
`social_messaging_device_authorization_binding_owners`. Ordered attributes,
absent server defaults, PK/UNIQUE/CHECK/FK/constraint-trigger inventories,
backing and standalone unique/nonunique/partial indexes, relation/TOAST fields,
direct and effective inherited privileges, column ACLs, user triggers and
internal RI bindings have closed source expectations. Core tables are the
original compiled models before lifecycle additions; the original migrations
supply additional constraints omitted from later Python declarations.

The sole `users.is_active` profile is nullable, with no server default, as in
the original model plus migrations. The older minimal isolated V1 fixture's
NOT NULL alternative is insufficient for this composed finalization schema.
Python defaults do not become server defaults. Expectations never come from
caller models, installed catalogs or capture files at runtime.

Required external bindings include the canonical authorization-request PK and
incoming FKs from OAuth code/session-code, binding-authorization evidence,
mobile acceptance, session pairing and original issuance tables. Only their
required attributes, FK descriptors and referenced canonical keys/indexes are
validated. This bounded graph does not recursively attest unrelated schemas.
Both RI trigger halves of every required FK are validated, including the
external endpoint. Unexpected incoming/outgoing RI bindings on the guarded
relations deny; unrelated external triggers remain outside this bounded scope.
Self-referencing FKs retain distinct child and parent trigger bindings; RESTRICT
triggers remain immediate even for a deferred FK.

The source inventory is complete. PostgreSQL source-schema rendering supports
the fixed normal forms, and offline replay exercises the captured catalog rows.
Separate isolated native execution covers current authority, acceptance,
rollback, causal completeness, concurrent retry and completed waits. Source
coverage and synthetic execution remain distinct from deployed authority.
PG16 TOAST chunk attributes are nullable, its internal unique index is primary
without a user PK constraint, and its oid btree opclass is `oid_ops`. Fabricated
alternative TOAST layouts deny. Canonical PG16 type, opclass, operator, collation
and RI function bindings are independently resolved on every schema pass.

Expected normal forms remain those of the pinned original readers and
migrations. FK and trigger function qualification have only the explicit
qualified/unqualified spellings already supported by their canonical contracts;
casts and parentheses are not stripped. Column type OIDs/typmods and storage
layouts, absent defaults, default btree opclasses/collations/options, CHECK and
predicate deparsing, and TOAST layouts are source expectations. Empty source-schema rendering of these normalizations is evidence; complete
runtime role and native effects validation remains a separate obligation.

DDL ownership and runtime login are distinct. Runtime must have only the closed
composed `pg_read_all_settings` profile, public USAGE, the original prerequisite
reader/owner grants required by their canonical contracts, companion SELECT and
EXECUTE on the narrow native staged writer. It receives no companion writes or
EXECUTE on guard/completeness functions, ownership, superuser/BYPASSRLS,
role/database creation, schema CREATE, extra inherited memberships or DDL.
The migration revokes PUBLIC table/function privileges and names no live role.
No role provisioning or automatic production upgrade occurs here.

## Clock, rollback and caller publication

Decision time is sampled after completed waits. Signature/model work and catalog
reads can be slow; the owner resamples and authenticates at fresh server time
before and after each staged native call, CAS and receipt reconciliation. All
four native deadlines, original evidence/statement intervals, input intervals
and retained trust lifetimes are independent exclusive bounds. No skew, flooring
extension, timestamp substitution, re-signing or byte rewrite extends them.
Canonical receipt `decidedAt` remains equal to its original observation.

A late mutation or SQL/validation failure can leave provisional writes. It
returns denial and requires caller rollback, including when a provisional CAS
has already succeeded. The caller alone commits and must ensure publication
occurs within the original exclusive authority/evidence interval; this owner
cannot prove a later caller commit or refresh authority after returning.
Every result is `provisional_until_caller_commit`, with `final_admission=denied`
and no bearer/reexecution permission. Uncertain commit is reconciled from
immutable historical evidence, never retried as a new effect.

The separately composed [caller transaction boundary](SOCIAL_ENROLLMENT_V2_RUNTIME_COMPOSITION_V1.md)
owns flush, the additive `check_before_commit(result)` recheck, commit and
postcommit publication fencing. The original owner API still never commits and
still returns a provisional result. The composition is dormant source with no
HTTP/factory installation or deployment authority.

The separately prepared [native challenge producer](SOCIAL_ENROLLMENT_V2_CHALLENGE_V1.md)
uses the issuance lifecycle and an independent challenge writer. It does not
change this owner's closed privileges, association-history checks or effect
protocol, and is not installed into the running application.

## Accepted historical receipt recovery

The exact row is discovered and locked before current authority. Accepted retry
authenticates BOTH original stored artifacts at the original decision instant,
compares exact input/request/evidence/statement/issuance selectors and canonical
reservation/effect/receipt bytes, then reconciles retained actual event,
consumed challenge/revision, native causal companions and immutable original
issuance/acceptance graph. It executes no native writer, new CAS or signer.

Later current session/evidence expiry or association rotation/revocation does
not renew authority and does not erase the original receipt. Original history
must remain unambiguous and complete. Altered bytes, missing/replaced/revoked
original trust, conflicting history and every nonaccepting terminal state deny.
No device-ID release, reopening, challenge reuse or historical backfill exists.
A historical receipt is not an admission credential or permission to send.
An accepted row born on the current physical root is still provisional and is
denied as historical recovery; expiry cannot be bypassed by another owner in
that same uncommitted transaction.

## Disposable native verification and remaining boundaries

The integration module is
`tests/integration/test_social_enrollment_v2_finalization_postgresql.py`.
Its individual cases collect and default-skip without the explicit ACK/target;
skips and collection are **NOT_RUN**, never native success.

External selectors use `UBID_V2_FINALIZATION_REHEARSAL_`:

- `ACK=DISPOSABLE-SYNTHETIC-V2-FINALIZATION-PREINSTALLED` and a 32-character
  lowercase hexadecimal `NONCE`;
- `PORT` in 49152..65535, loopback `127.0.0.1`, Unix sockets disabled;
- `DATA=/tmp/ubid-v2-finalization-rehearsal-<NONCE>/data`, with PG_VERSION 16;
- `DDL_DSN` and `RUNTIME_DSN`, `postgresql+psycopg2`, no password/query options,
  database `ubid_v2_finalization_rehearsal_<NONCE>`, roles
  `ubid_v2_finalization_ddl` and `ubid_v2_finalization_runtime`;
- `ORIGINAL_DDL_DSN`/`ORIGINAL_RUNTIME_DSN` for the separately preinstalled
  original profile in database `ubid_v2_finalization_original_<NONCE>`.

Both targets require the original pinned prerequisite migrations listed by the
reservation contract, the full compiled core model schema before lifecycle additions, complete
canonical migration prerequisites and distinct roles and no preexisting conflicting synthetic vector rows. Only the extended
target preinstalls the finalization and additive freshness-guard migrations.
The tests apply no migrations or persistent schema.
The DDL principal must be externally authorized for the bounded synthetic COST,
membership and shared-definition regressions; runtime grants are never inferred from it. Concurrent
workers use explicit Sessions and backend-observed waits/events; a timeout is
never acceptance evidence. External provisioning must pin all migration sources,
verify catalog/role/target identity, then capture verified stop/removal of exactly
that disposable cluster. The source job starts no cluster and performs no teardown.

A real V1 signature fixture separately exercises the unchanged V1 shared
storage primitives on original/extended profiles; it is not synthesized from a
V2 statement and does not claim a new V1 Current-Full orchestrator rehearsal.
The shared-definition native negative cases change nullability/defaults,
FK deferral, CHECK definitions, index options and a partial predicate on the
explicit disposable fixture, retaining table identity and ALTER object identity
where supported. It observes runtime mutation statements and requires denial
before a staged V2 writer call or accepted CAS. Its restoring DDL uses pinned
test constants; no system-catalog writes or disabled guards are used.
Additional individually opt-in cases replace dependency defaults, native index
options, TOAST options, compression, PUBLIC table/column grants and standalone
indexes. Each uses restoring DDL, retains table identity, and requires no runtime
mutation and no accepted CAS on denial. Authority negatives additionally replace CHECK semantics, FK deferral and
real RI bindings, core nonunique and partial index options, PUBLIC table/column
ACLs, incoming OAuth-code FKs and the external request PK index. The extended
fixture first invokes the real schema attestor on the selected runtime
Connection, so a former minimal prerequisite schema cannot count as a positive
fixture. These tests do not provision a target or fall back to a live database.

Isolated native execution covers role/ACL compatibility, causal completeness,
rollback, concurrent exact retry, a successful completed wait and expiry after
a completed wait. It also compares complete catalog fingerprints through the
original and batched transports before and after the scenarios. Offline fixed
rows and source synchronization alone cannot establish these behaviors.
A genuine-clock setup that expires while rereading authority must still deny;
synthetic positive execution supplies no production latency or capacity promise.
The original ten-second profile and fresh exclusive time checks remain unchanged.
The separately selected signed profile is defined in
[Server-selected signed freshness profiles](#server-selected-signed-freshness-profiles);
it changes only the maximum for explicitly marked new artifacts.

Social's verifier/signer process, a V2 challenge producer, operational public
trust/key lifecycle provisioning, HTTP/route/factory/runtime composition,
activation, migration application, staging/production deployment and DM
transport remain separate work. This source grants no Full and enables no Send.


### Fresh catalog transport within the evidence deadline

Each original native V2 catalog observation still performs three fresh guarded
statements and runs the same complete validators. Within each statement, a
materialized scan per fixed catalog family replaces a separate catalog scan
for each function, table, or index selector. Every selector retains its exact
projection, ordering, native JSON scalar types and cardinality. The captured
rows are private to one observation; a later observation reads PostgreSQL again.

An exact internal BoundSession chain executes an ORM statement on its checked
leaf Session, with populate_existing and an explicit pinned Connection bind.
The outer guard still validates every parent layer and native XID before and
after the data statement. Arbitrary Session wrappers retain the ordinary path.

Native effects construct their event from the private immutable plan before the
first complete schema/authority checkpoint. The existing effects loop keeps
complete fresh checks before and after all three native stages. This removes
an extra pre-loop read/audit/read, without changing any write boundary, SQL,
clock, signature, evidence lifetime, or caller-owned transaction.

These changes are transport and duplicate-work corrections. They do not grant
admission or enable runtime behavior. End-to-end acceptance remains gated on a
real PostgreSQL flow with a genuine clock and zero skipped native cases.
Separate caller/ingress rehearsals cover that native flow and a real Social
Node client through a temporary Unix listener. The trusted synthetic statement
and shape-only phone proof retain the cryptographic and deployment limits above.


## Completion transport equivalence

Named constraint, FK and index reads now have distinct, bounded fresh family
captures on the same Connection. Canonical visibility discovers the table and
TOAST selectors, including required external bindings at their later visibility
checkpoint. Complete index captures retain both the full index and index-relation
projections. Selecting one name from that owned capture reproduces the original
SQL name predicate; duplicate matching rows remain duplicates. Each compound
selector is consumed once. Its next read executes the original live SQL, so later
FK comparisons cannot reuse an earlier observation. Captures and mutable views
remain private to one attestation, with unchanged continuity checks.

The original issuance three-batch transport uses JSON ordinal carriers rather
than repeatedly normalizing them as JSONB. Every original projection, cast,
aggregate order, SQL NULL, type and cardinality is retained. Both complete
validators and every authorization, clock, expiry and mutation checkpoint remain
unchanged. This source remains provisional, default off and final admission denied.

The issuance transport retains a bounded cache of immutable SQL text and parameter
locations keyed only by source family and shape. Selector values, expected row
identities, parameter lists and catalog observations are rebuilt independently on
every attestation; no observed database state enters that cache.


## Additive SQL freshness profile

The separately selected signed `native-v2-60s-v1` profile also requires
`migrations/2026-10-14_social_enrollment_v2_freshness_profile_guard_v1.sql`, after
the original atomic-acceptance and native-finalization prerequisites. The old
migration files, legacy crypto vectors and ten-second defaults remain unchanged.
This additional migration replaces only the existing CAS guard's closed evidence
shape predicate, retaining its function identity, triggers, owner, privileges,
canonical identity chains, one-way transition and immutable history checks.

The new guard accepts exactly 46 unmarked legacy fields with a maximum 10,000-ms
interval, or those same required fields plus exactly the signed string
`freshnessProfile: native-v2-60s-v1` with a maximum 60,000-ms interval. Unknown,
NULL, boolean or numeric markers, missing required fields, extra fields and
overlong intervals deny. Field count alone never selects the new profile.
Cryptographic consumers still require the exact server-configured profile; SQL
format recognition is not authentication or current authority.

The storage reader recognizes the original definition and this one exact new
definition, with the new definition confined to the native-finalization trigger
profile. Unknown sources deny. Complete catalog identity distinguishes the two
known bodies even at the same function OID; each transaction retains and freshly
compares its observed definition. All before/after mutation checks remain.

The opt-in SQL format tests use transaction-local TEMP table copies with the
installed guard. They establish shape/identity behavior only, do not touch real
native ledgers and grant no current authorization. The complete native suite
separately checks real authority, genuine clock, mutations, rollback and recovery.
Source and disposable verification do not authorize applying this migration to
live staging/production, provisioning keys or enabling runtime/DM transport.


## Native legacy compatibility fixture

The frozen V1 admission vector establishes canonical shape and RSA verification;
its proposed association is not the identity derived for an absent-to-initial
lifecycle transition. Native compatibility tests derive the initial association
fields from the exact original challenge, preserve its phone proof and approval
event bytes, and genuinely sign and verify the corrected V1 statement with a
temporary in-memory RSA key. The frozen vector itself, legacy protocol and
ten-second interval remain unchanged. Pure regressions retain the original
vector's lifecycle denial and prove that only the corrected, authenticated
initial identity enters the unchanged V1 storage operations on both targets.
