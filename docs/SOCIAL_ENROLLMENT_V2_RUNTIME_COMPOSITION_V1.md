# Social Enrollment V2 transaction composition V1

This is dormant source preparation. It installs no Flask extension or HTTP
route, opens no connection on import or disabled construction, provisions no
key, and changes no deployed service. The separate default-off
[native challenge producer](SOCIAL_ENROLLMENT_V2_CHALLENGE_V1.md) reuses this
transaction boundary. The separate default-off
[confidential HTTP ingress](SOCIAL_ENROLLMENT_V2_INGRESS_V1.md) authenticates
service and matching phone on that same transaction boundary. Operational
installation remains separate.

## Explicit ownership

`build_social_enrollment_v2_composition()` returns `None` by default. Only
literal `enabled=True`, an explicit fresh PostgreSQL Session factory, an
already-held `DedicatedRS256EvidenceSigner`, and a fully enabled immutable
`FinalizationConfig` construct the service. Public trust is copied through the
existing canonical config constructor. There is no environment, database URL,
OAuth signing-key provider, key-file lookup, or request-selected freshness
policy. A trusted server clock defaults to genuine UTC epoch milliseconds;
an injected clock belongs to server configuration, never request fields.
One operation rejects backward clock movement instead of extending freshness.

`SocialEnrollmentV2Composition.reserve(input_wire, issuance_id=...)` and
`.finalize(...)` use the existing exact owner selectors and canonical wire
implementations. Each opens one fresh Session and owns one complete root
transaction. An existing Session/savepoint or externally active Connection
transaction is rejected. The real owners retain their PostgreSQL READ COMMITTED,
same-connection, XID, locked authority, signature and catalog checks.

The service flushes, rechecks the exact result inside the original transaction,
then commits and closes its Session before returning anything. Pending retries
use the existing discovery-before-signing owner, so they retain the original
bytes, reservation ID and exclusive deadline. They never re-sign or buy another
freshness interval. This caller boundary does not modify legacy serializers,
vectors or migration SQL. The optional explicit peer-role profile below leaves
the original single-role catalog behavior as the default.

## Finalization publication and uncertain commit

`V2FinalizationOwner.check_before_commit(result)` accepts only the exact result
produced by that still-active owner. For new effects it rechecks the retained
transaction-bound plan and original native authorities, authenticates both
original signed artifacts, and returns their earliest exclusive expiry. It
never commits or renews anything. The original public `finalize` result remains
`provisional_until_caller_commit` for existing callers.

The composition samples time immediately before commit and again after commit
and Session close. Expiry at either publication boundary denies. SQL and commit
failures roll back where possible and discard the transient result. If commit
succeeds but its acknowledgment is lost, or expiry occurs during commit, the
stored history can already exist: the service does not pretend it rolled back,
does not retry effects automatically, and publishes no current result.

An exact finalization retry authenticates the immutable accepted history through
the original owner, returning byte-identical receipt bytes without repeating
effects. Historical recovery has no new live freshness window and grants no
current device authority. A pending reservation that has expired remains
expired. Neither behavior invents a fresh deadline after lost delivery.

Only this caller service returns the distinct immutable `CommittedReservation`
or `CommittedFinalization` wrapper after confirmed commit. Their
`publication_status="committed"` describes database publication, with
`final_admission="denied"` and `bearer_authority="none"`. These wrappers are
not detached authorization capabilities and do not enable messaging.

## Remaining activation work

This source boundary needs an explicit restricted Session factory and the
existing dedicated infrastructure trust/signing objects at runtime. No database
grant or key is provisioned here. In particular, the existing finalization
principal cannot directly insert challenges. The separate
[native initial-enrollment challenge producer](SOCIAL_ENROLLMENT_V2_CHALLENGE_V1.md)
has its own source writer composition, using the existing challenge store and
same-transaction immutable revision trigger. It persists original canonical
bytes once and does not refresh their deadline on retry. Disposable PostgreSQL
verification covers separate writer/finalizer grants, native revision,
concurrent creation and completed lock waits. Operational grants and installation
must still be reviewed against the actual target before activation.

## Explicit challenge-writer role

`FinalizationConfig.challenge_writer_role` defaults to `None`. This retains the
original exact owner/current-runtime ACL and rejects every additional grantee.
A trusted server can instead supply a `ChallengeWriterCatalogPin(role_name,
role_oid)`. Names are canonical PostgreSQL role identifiers, OIDs are exact
non-system integers, and neither comes from HTTP, environment fallback or a
browser payload. Configuration is defensively copied and immutable.

The optional profile admits exactly that additional role and the code-owned
`CHALLENGE_WRITER_PRIVILEGES` matrix. The matrix selects the existing 39 tables,
permits the original native issuance writes and challenge creation, and leaves
revision evidence, pending decisions and native effects read-only to this role.
No DELETE, TRUNCATE, REFERENCES, TRIGGER, column grants, grant options or unknown
effective table/sequence privileges are admitted. The finalizer's own profile
still forbids challenge INSERT. PUBLIC, a third grantee, extra privilege or a
changed configured role identity still denies.

Each fresh complete catalog observation checks the peer's name/OID, restricted
role flags, sole `pg_read_all_settings` membership, absence of ownership/schema
CREATE and denial of native-effects function execution. It rechecks all effective
table privileges and retains an immutable identity in the original schema
fingerprint. Shared ACLs must equal owner + original finalizer profile + exact
peer profile, with no other entries. The optional setting grants no SQL rights.

The existing CAS callback receives a raw Connection below the configuration API.
The composition therefore installs the explicit setting only in a lexical
`catalog_role_scope` around its operation and precommit checks. The scope is
bound to that exact Session/root/Connection/root; active savepoints, replaced roots,
closed/invalidated connections, different connections and nested scopes deny.
It is removed on success or exception before commit and is never stored in a
pool, Engine, Session info or process-wide default. Other threads inherit no
setting. The original owner guards still enforce backend XID continuity and
savepoint ABA detection. Direct caller-owned owner APIs retain their original behavior; an
operator choosing this optional policy for such callers must explicitly use
the same root-bound scope. This does not install a runtime factory or provision
roles, keys, permissions or migrations.

[Authenticated internal HTTP ingress](SOCIAL_ENROLLMENT_V2_INGRESS_V1.md) is a
separate dormant source adapter. Social's server-selected producer profile
installation, factory composition, live migration/role preparation and staging
activation remain separate. No route may accept a parsed object, caller clock,
raw identity, arbitrary callback or `verified=True` as current authority. A
historical receipt never substitutes for the existing current-admission reader.

## Verification boundary

Small standard-library tests exercise actual commit/rollback control flow,
precommit and postcommit expiry, uncertain commit and no automatic retry.
Additional offline tests cross the existing real reservation/finalization
owners, RSA consumers and canonical receipt/history on synthetic SQLite with
the existing explicit PostgreSQL catalog/effects doubles. Those offline tests
establish source behavior only.

Separate disposable PostgreSQL verification exercises the actual restricted
roles, original challenge/revision rollback, concurrent original creation,
desktop-bearer denial, clock sampling after a completed native lock wait and
concurrent durable assertion replay. The real Flask caller completes
challenge/reservation/finalization and recovers the byte-identical committed
receipt without extra effects. A cross-repository rehearsal additionally runs
Social's default Node HTTP client through a real temporary Unix listener into
the same native owners, with genuine clocks and no PostgreSQL catalog, lock,
trigger, effect or replay doubles. Wrong issuance and damaged statements deny.

The native fixture trusts a synthetic Social RSA statement and uses a shape-only
phone proof; it is not a new execution of Social's Ed25519 verifier. The separate
producer/consumer crypto interoperability checks remain distinct evidence.
These synthetic rehearsals establish neither a deployed phone/browser flow nor
operational key/trust registration, capacity, current admission or DM readiness.

The canonical lower-level contracts remain
[reservation](SOCIAL_ENROLLMENT_V2_RESERVATION_V1.md) and
[finalization](SOCIAL_ENROLLMENT_V2_FINALIZATION_V1.md).
