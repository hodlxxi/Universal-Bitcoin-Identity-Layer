# Social messaging recipient routing V1

Status: dormant, source-only contract and PostgreSQL durability prerequisites.
The additive source includes a transaction-bound UBID repository adapter and
migration for exact routing snapshots/routes, confidential pairwise-handle
ownership and the message-ID decision ledger. A separate empty-by-default
registry and transaction-bound read-only adapter can reconcile one explicitly
ACTIVE alias namespace with the secret/version already loaded from trusted
startup configuration. A separate dormant internal adapter can compare the one
exact self-read handle from a strictly parsed device-request input with that
locked namespace, immutable handle history and the exact current device
binding established by the real transaction-bound admission-authority
producer. Its result is explicitly non-authorizing and returns no ciphertext.
An additional dormant transaction owner can provision an empty registry or
rotate it from one exact locked predecessor only after authenticating the
exact offline-signed command and configured successor secret commitment. None
of the migrations is applied. There is no HTTP route, factory wiring, key
provisioning, ciphertext persistence, self-read effect, request admission,
receipt, challenge consumption, deployment or runtime activation. Social
source and ciphertext formats are unchanged.

The dormant `social_messaging_active_alias_namespace_lifecycle.py` module now
defines the operator-approved **offline UBID deployment-key** command contract
and verifies its signature against one explicitly injected pinned Ed25519
public key and exact key ID. It does not load, create or keep the private key.
The separate transaction-bound storage owner and immutable event ledger remain
dormant: there is no CLI, trust configuration, runtime import, migration
application or authorized `ACTIVE` row.

## Privacy and authority boundary

The outward recipient package remains privacy-minimized. It contains a
viewer-pairwise recipient alias and viewer-pairwise device handles, plus the
X25519 public material needed by the browser to wrap a message key. It does not
contain the canonical recipient subject, device ID, or binding ID.

The device handle is intentionally non-reversible:

    d_ || base64url_no_padding(
      HMAC-SHA256(
        alias_secret,
        "HODLXXI_RECIPIENT_DEVICE_HANDLE_V1" || 0x00 ||
        "1" || 0x00 || alias_version || 0x00 ||
        viewer_subject || 0x00 || recipient_subject || 0x00 || binding_id
      )[0:16]
    )

It is stable only for the same secret namespace, alias version, viewer,
recipient, and exact binding ID. It separates viewers and alias versions. The
HMAC is not an encoded identifier and cannot itself recover its inputs.
Consequently, authoritative delivery requires UBID to retain the exact mapping
when the recipient package is issued. Reconstructing identity later from a
public key, binding version, array position, or snapshot time is forbidden.

The immutable confidential snapshot binds the viewer subject, recipient
subject, alias namespace version, exact outward package snapshot ID and
deadline, and the complete sorted set of handle/device/binding/version routes.
Each route also retains the stable identifier and bounded interval of its
independently verified binding-authorization evidence. Public keys are used
only transiently to compare the authoritative binding and outward package and
are discarded before the snapshot or decision is constructed. Alias, private
label, keys or seeds, credentials, plaintext, ciphertext, and message keys are
not routing metadata.

The immutable decision binds the message ID and envelope digest to the same
authenticated viewer for whom the pairwise handles were created, the exact
recipient, the exact package snapshot, its expiry, and all routes. It is an
internal UBID result. It is not an outward package or ciphertext envelope.

## Independent authorization prerequisite

OAuth or session possession authenticates a request context; it does not prove
that a participant authorized an exact X25519 binding. The existing
SocialMessagingDeviceBinding registration path is therefore insufficient on
its own. V1 requires an injected verifier to return a strict immutable result
for exact equality of:

- subject, device ID, binding ID, and binding version;
- X25519 public key;
- binding valid-from and expiry;
- a bounded evidence interval and stable proof identifier.

A boolean, mapping, OAuth bearer, session, service token, key equality, version,
ordering, or timing is never accepted as evidence. Missing, malformed,
expired, duplicate, or mismatched evidence fails closed. The dormant
identity-signature producer and verifier contract is now defined in
`SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_V1.md`; no provider,
persistence, application composition, or runtime path is implemented or wired.
That identity authorization does not itself prove browser possession of the
X25519 private key. A future runtime adapter must source the public key from an
already proven browser-device setup or add an explicit possession challenge.

Current exact bindings and current Full entitlement for both viewer and
recipient are separately injected authority ports. They are checked when a
snapshot is retained and again when a request is resolved. Snapshot expiry
must be no more than 300,000 milliseconds after issue and no later than every
binding, binding-authorization proof, and Full-entitlement proof. Rotation or
revocation makes the retained exact route set differ from current authority,
so the old snapshot fails before a decision is accepted.

Replacement devices receive only packages and wraps created for their new
binding. There is no historical-wrap delivery. Revocation prevents future
acceptance but cannot promise retroactive erasure of ciphertext already copied
or delivered.

The Current-Full result uses the canonical
`hodlxxi-full-entitlement-v1-sha256:<64 lowercase hex>` producer defined in
`CURRENT_ENTITLEMENT_EVIDENCE_V1.md`. The routing consumer accepts that exact
typed output and still independently requires an exact subject match, current
validity, and coverage of the complete package or snapshot interval. Regex
validity alone never grants authority: the digest is a content identity, not a
signature, credential, or caller-supplied proof.

## Closed request

The only accepted request is canonical ASCII JSON: duplicate-member rejecting,
compact, and sorted by key. Its maximum encoded size is 2,048 bytes.

    {
      "envelopeDigest":"hodlxxi-social-message-envelope-v1-sha256:<64 lowercase hex>",
      "messageId":"m_<43 canonical unpadded base64url characters>",
      "recipientDeviceHandles":["d_<22 canonical unpadded base64url characters>"],
      "recipientPackageSnapshotId":"sha256:<64 lowercase hex>",
      "schema":"hodlxxi.social_messaging_recipient_routing_request.v1",
      "version":1
    }

The handle array contains 1 through 16 strictly increasing unique values and
must equal the snapshot's complete handle set. Unknown members, Unicode,
noncanonical encodings, missing, extra, subset, or duplicate handles, and all
identity, key, alias, and credential fields are rejected.

Internal snapshots and decisions also use compact sorted-key ASCII
serialization for deterministic comparison, capped at 16,384 and 8,192 bytes
respectively. Subjects, device IDs, and binding IDs are canonical lowercase
64-hex strings. Binding versions are integers from 1 through 1,024. Timestamps
are nonnegative JavaScript-safe UTC epoch milliseconds; authority evidence
uses whole-second UTC datetimes at its injected boundary.

## Durable repository contract and failure behavior

`app/services/social_messaging_recipient_routing_storage.py` implements the
existing `RecipientRoutingRepository` Protocol. The additive migration is
`migrations/2026-09-24_social_messaging_recipient_routing_registry_v1.sql`.
It introduces five dormant UBID tables: immutable handle owners, snapshots,
snapshot routes, decisions and decision routes. Exact canonical snapshot and
decision strings remain authoritative bytes; indexed columns and complete
ordered route rows are reparsed and compared on every adapter read.

The handle owner records the original alias-version namespace, viewer,
recipient, device, binding and binding version for the exact `d_` value. No
public key, alias secret or reverse derivation is stored. The handle is the
global primary key, and the complete owner tuple within one alias-version
namespace is also unique. A same-tuple renewal reuses the retained owner. An
alias-version rotation may add its new handle namespace but cannot rewrite or
delete the old mapping. A same-version secret change cannot silently remap the
same tuple to a second handle.

The repository provides exact snapshot retention, unambiguous snapshot lookup,
and a global message-ID decision ledger. It enforces:

- one handle has one viewer/recipient/device/binding owner at a time;
- exact snapshot registration is idempotent, including renewal for the same
  tuple, while conflicting ownership fails;
- duplicate device IDs, binding IDs, proof IDs, or handle mappings fail;
- one message ID plus the same digest is an idempotent retry;
- one message ID plus a different digest is a conflict;
- duplicate rows or any other repository ambiguity fail rather than selecting
  a record.

Every failure exposed by this boundary is the same generic message:

    recipient messaging routing unavailable

No partial route, count, target-existence detail, or dependency error crosses
the boundary.

Database uniqueness and deferred completeness triggers require every canonical
snapshot/decision route, exact owner relationship and snapshot-to-decision
route match at commit. Updates, deletes and truncation are denied. The adapter
also rejects noncanonical, duplicate, incomplete, conflicting or otherwise
ambiguous retained history rather than choosing a row.

The adapter accepts one caller-owned, already-active PostgreSQL READ COMMITTED
SQLAlchemy transaction. It pins the Session transaction/savepoint, physical
connection and database transaction/savepoint; requires driver autocommit off
and all immutable/completeness triggers installed; and never begins, commits,
rolls back, closes or replaces anything. SQLite metadata compatibility grants
no authority. Core reads bypass ORM identity caching. Advisory-lock contenders
re-read authoritative rows after every wait.

Future request composition must first lock its exact challenge and establish
`CurrentAdmissionAuthorityV1` under the admission lock order. Only then may it
enter this registry's local sorted handle-owner, snapshot and message-ID order.
No network or Unix call belongs inside those locks. The existing pure
`SocialMessagingRecipientRoutingGateV1` remains unwired: its injected current
binding/entitlement ports do not share this caller transaction, so composing
the durable adapter into that gate would not establish atomic current
authority without changing the gate's semantics.

The immutable handle-owner rows are historical routing evidence for exact
snapshot and decision idempotence only. They remain outside current namespace
selection and cannot be queried as current-handle or self-read authority.

`app/services/social_messaging_active_alias_namespace_storage.py` adds the
narrow namespace reader. Its additive migration is
`migrations/2026-09-24_social_messaging_active_alias_namespace_v1.sql`. The
registry has no seed or backfill and stores only alias version, a
domain-separated commitment to that version and secret, and the explicit
`ACTIVE`/`RETIRED` lifecycle state. It never stores the alias secret. A partial
unique index permits at most one `ACTIVE` row; the read requires exactly one.
Rows can be inserted only as `ACTIVE`, can transition only once from `ACTIVE`
to `RETIRED` without identity changes, and cannot be deleted or truncated.
That original source exposes no writer. The separate additive lifecycle owner
described below supplies the signed transaction-bound mutation path;
activation and operational cutover remain separate prerequisites.

The exact commitment is a 112-character lowercase ASCII value:

    "hodlxxi-social-active-alias-namespace-v1-sha256:" || lowercase_hex(
      SHA256(
        ASCII("HODLXXI_SOCIAL_ACTIVE_ALIAS_NAMESPACE_SECRET_COMMITMENT_V1") ||
        0x00 || ASCII(canonical_decimal(alias_version)) || 0x00 ||
        exact_alias_secret_file_bytes
      )
    )

The configured version is an integer from 1 through 2,147,483,647. Secret
bytes are 32 through 4,096 bytes and are not decoded, trimmed or otherwise
normalized. The commitment is distinct from directory aliases, device handles,
snapshot IDs and every request/effect/receipt digest.

### Offline-signed lifecycle command prerequisite

The separate command schema is
`hodlxxi.social_active_alias_namespace_lifecycle_command.v1`, version 1,
audience `hodlxxi.ubid.alias_namespace_lifecycle.v1`, algorithm `Ed25519`.
Its strictly sorted, compact ASCII JSON binds the pinned `keyId`, action
`provision`/`rotate`, exact old version and commitment (both null only for
provision), exact next version and commitment, a canonical 32-byte nonce,
Unix-millisecond issuance/expiry and a domain-separated SHA-256 command ID.
The signature is separate canonical unpadded base64url over
`HODLXXI_SOCIAL_ACTIVE_ALIAS_LIFECYCLE_SIGNATURE_V1 || NUL || command_wire`.
The parser rejects changed bytes, duplicate fields and unknown vocabulary;
the verifier requires the exact pinned key ID and public key, issuance not in
the future and expiry not reached. Maximum command validity is 24 hours.
Provision starts at version 1; rotation increments by exactly one.

The signed payload contains the commitment, never the alias secret. The
deployed alias secret remains in its existing UBID startup file, separate from
this infrastructure signing key and from every participant/device key.
Signature validity alone cannot insert a row. The dormant
`social_messaging_active_alias_namespace_lifecycle_storage.py` owner reverifies
the raw canonical command and signature against its injected pinned public key
and key ID, and independently reduces the configured successor secret/version
to the existing domain-separated commitment. It verifies before locking,
takes one dedicated transaction-scoped advisory lock before inspecting the
`ACTIVE` set, then reverifies with the PostgreSQL database clock after the
advisory wait and again after the row-lock wait. It never accepts a caller-made
verified object and retains or stores no raw alias secret.

The owner requires one caller-owned, already-active PostgreSQL READ COMMITTED
SQLAlchemy transaction pinned to the same Session transaction/savepoint,
connection and database transaction/savepoint. Provisioning requires the
registry and event ledger both to be empty and can create only version 1.
Rotation requires exactly one locked `ACTIVE` row byte-matching the signed
expected version and commitment; the configured and signed successor must be
exactly the predecessor version plus one. In one transaction it retires that
row, inserts the `ACTIVE` successor and inserts the immutable exact command
wire/signature event, then rereads and compares the affected state. It never
begins, commits, rolls back or closes the caller transaction. A failure poisons
the one-shot owner and requires caller rollback. No external or Unix call
occurs while its locks are held.

The event guard overwrites the ledger's `xid8` transaction field on insert
with PostgreSQL's full top-level transaction ID. Retry and uncertain-commit
classification compare only that server-stamped value with the current
top-level transaction ID; caller input and a row's 32-bit `xmin` cannot declare
an event committed. This also keeps an event inserted by a savepoint
provisional until its outer transaction actually commits.

The additive empty-by-default migration is
`migrations/2026-09-25_social_messaging_active_alias_namespace_lifecycle_v1.sql`.
It refuses to adopt a pre-existing unauthenticated registry. Deferred
constraints require a contiguous version-1 provision/rotation sequence, one
event per namespace row, exact predecessor/successor commitments, exactly one
highest `ACTIVE` generation and retired history. Row-only, event-only and
partial rotations cannot commit; commands/nonces/successors cannot replay;
events and historical rows cannot be rewritten, deleted or truncated. These
SQL guards establish structural atomicity only. PostgreSQL cannot authenticate
the Ed25519 signer or grant or restrict database actor privileges; pinned
signature verification and least-privilege database role configuration remain
independent required boundaries.

An exact fresh retry returns already-committed evidence without executing a
second transition. The separate read-only uncertain-commit reconciliation
path authenticates the same exact command/signature and classifies only
durable matching evidence as committed, a truly untouched predecessor as
absent, and denies partial or conflicting evidence. It does not execute an
absent or expired command. Caller commit remains the sole publication point.
Neither Social read tokens, OAuth, a configured secret file, historical
handle owners nor an `ACTIVE` database label can replace that signature.
Operational cutover still requires a reviewed fail-closed maintenance window
or another explicit coordination protocol for already-running UBID processes.

The privacy-directory runtime loads
`PRIVACY_FULL_DIRECTORY_ALIAS_SECRET_FILE` and
`PRIVACY_FULL_DIRECTORY_ALIAS_VERSION` once at startup. The recipient runtime
reuses that exact privacy runtime and therefore the same secret object and
version; it does not load an independent namespace. The reader receives that
trusted configured pair at construction, immediately reduces the secret to
the commitment, and retains no secret. In one caller-owned, already-active
PostgreSQL READ COMMITTED transaction it executes `FOR UPDATE` over the
explicitly `ACTIVE` set, requires exactly one returned row, and compares both
the exact configured version and commitment. It pins the SQLAlchemy transaction,
savepoint, physical connection and database transaction, requires autocommit
off and the migration guards installed, and never begins, commits, rolls back,
closes or replaces anything.

This result is configuration/lifecycle reconciliation evidence valid only
while that transaction retains the row lock. The column label is not authority
by itself: a row is accepted only at the intersection of the guarded singleton
registry and the independently loaded exact configuration. Missing, ambiguous,
retired, stale-version, same-version/different-secret, malformed or replaced
state denies through the one non-sensitive failure `social messaging active
alias namespace unavailable`. Rotation waits behind an
already locked reader; a reader waiting behind rotation re-evaluates the old
row and denies rather than accepting stale configuration. No maximum version,
snapshot age, historical owner row, caller-supplied version/secret or handle
is a currentness selector.

The reader deliberately exposes no provisioning, rotation, current-handle
resolution or self-read authority; mutation remains isolated in the separate
signed owner. The dormant
`app/services/social_messaging_current_handle_candidate.py` adapter performs
only the next internal candidate comparison. It accepts the complete canonical
`VerificationInputV1` wire, requires `recipient-self-read`, and obtains the
single requested `d_` handle only by reparsing its exact `actualRequest`; it
does not accept a separately supplied handle, subject or binding and never
derives a handle with the recipient substituted as viewer.

In the same pinned caller-owned PostgreSQL READ COMMITTED transaction, the
adapter constructs and invokes the real
`SqlAlchemyTransactionBoundAdmissionAuthority` from authenticated
server-resolved issuance/client/issuer selectors. It does not accept a caller-
constructed `CurrentAdmissionAuthorityV1`. Only after that complete existing
Full/User, OAuth/session, current X25519 and Ed25519 lock order succeeds does it
lock the configured ACTIVE namespace, acquire the routing registry's one exact
historical-owner advisory/row lock, and recheck the ACTIVE namespace. It then
re-reads the exact current binding row and compares its current subject, device
ID, binding ID and binding version with the retained owner and locked alias
version. Finally it repeats the real current-admission comparison and ACTIVE
namespace read after those waits. Missing, ambiguous, inactive, expired,
revoked, rotated, remapped, stale-version or mismatched state fails through
the one message `social messaging current handle candidate unavailable`.

The historical owner is used only as the immutable mapping half of that
comparison. It never selects currentness. Highest alias version, snapshot age
or expiry, key equality, caller fields, or either provisional authority result
alone cannot produce a candidate. No network or Unix call occurs under the
locks. Success returns only the requested handle, locked alias version and
context digest plus fixed markers `authorization=not_granted`,
`recipient_self_read=not_granted` and `ciphertext=not_returned`. This record is
not accepted by any effect or admission port and remains unwired.

This registry's decision proves only exact routing resolution against retained
snapshot evidence, while the new candidate proves only that one exact request
handle matched locked namespace, history and current admission/binding state at
that provisional transaction point. Neither is ciphertext persistence,
delivery, recipient read selection, a request operation effect, a committed
receipt or final admission. Social still needs an independent transaction-
bound ciphertext/message owner, and UBID still needs a bounded self-read
selection/effect owner before request receipt storage or challenge consumption
can truthfully be added.

## Accepted mobile evidence prerequisite

The dormant [accepted mobile routing adapter](SOCIAL_MESSAGING_MOBILE_ROUTING_V1.md)
now reads the established committed mobile ownership and re-verifies LEGACY/QR
proofs for the exact binding. Its distinct mobile proof namespace is accepted
only with the routing gate's explicit `mobile_authorization_enabled=True`;
the default is false. Existing Nostr evidence and all wire/handle/package
identifiers are unchanged. The earlier identity-verifier-only description above
remains the default path. The dormant UBID routing registry does not activate
runtime package retention, sender-device admission, ciphertext transport or an
inbox. The linked document lists every remaining Phase 3 boundary.
