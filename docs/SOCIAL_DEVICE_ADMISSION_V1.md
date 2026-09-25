# Social Device Admission V1

Status: **dormant contracts, authenticated statement verifier, immutable
challenge store, Ed25519 association store, transaction-bound current
authority, pure enrollment transition-authority/effect-identity contract,
transaction-bound enrollment transition-authority adapter, immutable enrollment
receipt storage, narrow challenge-consumption primitive and enrollment-only
atomic owner, pure device-request effect/receipt identity, and a read-only
transaction-bound ACTIVE alias-namespace reconciliation prerequisite, a
dormant offline-signed transaction-bound namespace lifecycle owner, plus one
non-authorizing transaction-bound exact current-handle candidate comparison;
final admission remains denied**. The source defines canonical bytes,
ownership, state vocabulary, typed future ports and an explicitly injected,
disabled-by-default public trust registration. The challenge store adds a
model, SQL migration and transaction-bound database adapter. The Ed25519
association store adds a separate model and additive migration. Request
effect/receipt identity remains pure and has no storage or execution owner. A
separate dormant PostgreSQL recipient-routing registry now owns exact
snapshots/routes, confidential pairwise-handle mappings and the message-ID
decision ledger, but those records and the new candidate are not either
request operation's real effect. There is no route, blueprint, factory/config
import, key provisioning, socket client, service credential or runtime
activation. Migration source is not migration application.

## Architecture selection

UBID is the selected future owner of challenge creation and persistence,
atomic single-use consumption, Ed25519 association lifecycle,
rotation/revocation invalidation, exact operation effects and final device
admission. Immutable challenge persistence, provisional current-authority
evaluation and locked pre-effect enrollment transition authority are
implemented below. Durable receipt insertion and enrollment-only challenge
consumption are separate transaction-bound primitives with commit-time database
invariants. The dormant high-level owner now composes those primitives for the
exact `enrollment-activate` operation. Generic request-effect ownership,
runtime activation and final admission remain future work.

Social is the cryptographic attestor. It owns strict Ed25519
verification and Enrollment V2 Ed25519 plus Nostr approval verification. The
boundary selected between Social and UBID is a purpose-specific Unix-socket
protocol carrying a dedicated infrastructure-signed verification statement.
The socket client and route remain future work. UBID's pure RSA verifier and
immutable public trust configuration are implemented below; operational key
registration and runtime composition remain future work. The existing UBID
proof-profile results remain shape-only and cannot be promoted into
cryptographic authority.

Compromise of Social's dedicated verification signer or strict verifier is an
explicit residual trust boundary: an authorized malicious attestor could
forge a cryptographic-evidence statement. UBID must still check the exact
current viewer, sessions, Current-Full evidence, binding, association, epoch,
challenge, request and effect in its consuming transaction. This design does
not claim end-to-end immunity from a compromised Social verifier.

## Implemented pure contract

The source contract is
`app/services/social_messaging_device_admission_contract.py`. It provides:

- closed canonical constructors and parsers for verification context and
  input bytes;
- domain-separated SHA-256 context and input digests;
- canonical compact RS256 JWS shape inspection without RSA verification;
- the exact internal command/response routes and receipt shape;
- immutable enrollment, challenge, association and receipt transition
  vocabulary;
- exclusive epoch-millisecond deadline inspection with zero skew;
- typed Protocol definitions for future dependencies; and
- fixed non-claims that no constructor option can turn into success.

Every JSON wire is compact, lexically key-sorted printable ASCII. Parsing
rejects missing, unknown and duplicate members, alternate escapes and numeric
forms, non-ASCII, coercion and noncanonical serialization. Embedded documents
remain exact strings; the contract never normalizes or reserializes accepted
caller bytes. The one public failure is `social messaging device admission
unavailable`.

The inspection result is fixed as follows:

```text
canonical structure = valid
RSA signature verification = not_evaluated
cryptographic verification = not_evaluated
current authority = not_evaluated
challenge consumption = not_implemented
operation effect = not_implemented
final admission = denied
runtime enabled = false
atomic owner = ubid_selected_not_implemented
```

No API accepts a caller-provided verification boolean. There is no generic
admission method or reusable admission token. A receipt is immutable history
and has neither bearer nor re-execution authority.

This generic shape inspection remains unchanged because it covers all three
admission operations and does not execute the enrollment owner. The
enrollment-specific owner described below separately reports its dormant,
caller-commit-required status; it does not upgrade this inspection or either
device-request operation to implemented admission.

## Session binding prerequisite (pure source contract)

`app/services/social_admission_session_binding.py` freezes the previously
opaque `sessionBinding` and `approverSessionBinding` meanings. It is additive:
the existing admission context, input and fixture bytes are unchanged. The
module performs no I/O, has no clock or runtime state, loads no credential,
and does not decide whether any persisted authority is current.

`sessionBinding` identifies one exact Social device session authority
generation. Its canonical preimage is compact, lexically key-sorted printable
ASCII JSON with exactly:

```text
schema = hodlxxi.social_admission_session_binding_preimage.v1
version = 1
subject
deviceId
x25519BindingId
socialSessionIssuanceId
socialSessionTokenId
parentOAuthTokenId
parentOAuthSessionId
parentOAuthBrowserGenerationId
clientId
```

The subject, device, X25519 binding, Social issuance, parent OAuth Session and
browser identifiers are lowercase hexadecimal with their source-contract
lengths: subject/device/binding/issuance/Session/browser are 64 characters;
the two token generation identifiers are 32 characters. `clientId` is 1..255
printable ASCII characters under the closed configured-identifier grammar.
These inputs come from one locked `SocialSessionIssuance`, its exact
`parent_token_id` `OAuthSessionGeneration`, and that generation's immutable
Session/browser ownership. The Social issuance's `token_id` is distinct from
its non-bearer `issuance_id`. No access-token bytes, access-token digest,
viewer credential, pairing secret or private material is an input.

The exact derivation is:

```text
sessionBinding = lowercase_hex(
  SHA256(
    ASCII("HODLXXI_SOCIAL_ADMISSION_SESSION_BINDING_V1")
    || NUL
    || ASCII(canonicalDeviceSessionPreimage)
  )
)
```

It is therefore not a Session ID, OAuth token ID, access token, X25519 binding
ID, device ID, Ed25519 association ID or OAuth browser generation ID. Those
immutable identifiers remain separate inputs or separate authority dimensions;
none alone is the resulting commitment.

`approverSessionBinding` identifies the independently authenticated desktop
approver OAuth authority generation used by Enrollment V2. Its canonical
preimage is compact, lexically key-sorted printable ASCII JSON with exactly:

```text
schema = hodlxxi.social_admission_approver_session_binding_preimage.v1
version = 1
subject
oauthTokenId
oauthSessionId
oauthBrowserGenerationId
clientId
```

Its derivation uses the distinct role domain:

```text
approverSessionBinding = lowercase_hex(
  SHA256(
    ASCII("HODLXXI_SOCIAL_ADMISSION_APPROVER_SESSION_BINDING_V1")
    || NUL
    || ASCII(canonicalApproverSessionPreimage)
  )
)
```

The future enrollment owner must resolve that preimage from the authenticated
desktop approver, not from the new device or caller-supplied identity. The role
domains ensure that even an approver OAuth generation also present among the
device session's ancestry cannot produce the device `sessionBinding`. The new
device's binding cannot satisfy the approver comparison and cannot self-approve.
`approverFullProofId` remains a separate frozen context field and current-Full
authority check; it is not folded into either session preimage.

The future `TransactionBoundAdmissionAuthority` must keep three operations
separate in one caller-owned transaction:

1. Resolve trusted server-side presentation/session ownership, lock the current
   persisted rows, and validate current User, client, issuer, OAuth token,
   Session, browser generation, Social issuance and exact X25519 binding. For
   enrollment it must independently resolve, lock and validate the desktop
   approver OAuth generation. Context hashes are never selectors for this step.
2. Construct the exact preimage from those locked immutable columns and derive
   the expected role-specific binding. Inconsistent joins, owners, subjects,
   clients, devices or binding identities deny before comparison.
3. Compare the derived lowercase 64-hex value byte-for-byte with the parsed
   `VerificationContextV1` field. The pure helpers validate both sides and use
   constant-time comparison, but deliberately do not perform step 1.

A matching hash is not evidence that the underlying authority is active. If
an OAuth Session expires or is deactivated, an OAuth token is revoked, a
browser generation is replaced, a Social issuance token is revoked, or the
exact X25519 binding is revoked/rotated, the old rows have no current binding
to return even though their immutable historical preimage still hashes to the
same value. A replacement OAuth generation changes its token, Session and/or
browser identifiers. A replacement Social issuance changes its issuance and
token identifiers. An X25519 replacement changes `x25519BindingId`. The newly
derived current value therefore differs after replacement; after expiry or
revocation without replacement, comparison is not reached. No new mutable
session epoch is introduced.

Ed25519 `associationId`/`authorityEpoch`, current-Full proof identity,
cryptographic statement verification, challenge consumption and operation
effect remain independent required checks. Fixed public vectors, including
every substitution and device/approver role separation, are in
`tests/fixtures/social_admission_session_binding_v1.json`.

## Transaction-bound current authority

`app/services/social_current_admission_authority.py` implements the frozen
`TransactionBoundAdmissionAuthority` port. It accepts an already-active,
caller-owned PostgreSQL READ COMMITTED session and never begins, commits,
rolls back, closes or replaces its transaction. Construction receives the
exact device Social issuance selector and, only for enrollment, the exact
desktop approver OAuth Session selector previously resolved from authenticated
server-side presentation state. Neither selector is read from a context hash,
and neither is a bearer capability by itself.

The adapter first takes the Current-Full subject advisory lock, exact `User`
row and evidence rows. It then locks active OAuth/Social owners in causal
order: clients, Social issuer, exact OAuth generations, browser generations,
parent/approver OAuth tokens and Sessions, then the child Social token and
immutable issuance. Discovery reads select those exact rows but grant no
authority; every authority row is subsequently locked and re-read. The
parent-before-child token order matches durable invalidation triggers. The
already-held Full/User boundary serializes OAuth replacement and X25519
writers before the adapter locks the exact X25519 row. Ed25519 remains last in
its independent pair-advisory, chain-row and event-history order. Current-Full
invalidation shares the first advisory domain. This is the global admission
read order; code adding another owner must reconcile with it before acquiring
locks.

After all waits, the adapter revalidates every owner with the explicit integer
epoch-millisecond `observed_at`. Expiry is exclusive with zero skew. It derives
the device `sessionBinding` from the locked Social issuance and its exact
parent OAuth generation. Enrollment independently derives
`approverSessionBinding` from the locked desktop OAuth generation and repeats
the Current-Full proof comparison for that role. It then compares the exact
current X25519 identity/commitment and the complete current Ed25519 association
identity, including predecessor only where the frozen operation matrix makes
it applicable.

Success returns only `CurrentAdmissionAuthorityV1`: a context digest, current
authority epoch, earliest locked authority deadline and the compared Full
proof identities. This is provisional evidence for a future atomic consumer.
It does not inspect or mutate a challenge, create a receipt, execute an effect,
activate enrollment, persist ciphertext, route or read messages, grant final
admission, add a route or enable runtime. SQLite, missing owner guards,
replaced transactions, malformed state and every mismatch deny through the
existing non-sensitive admission failure. No migration is introduced by this
adapter.

`CurrentAdmissionAuthorityV1` continues to mean that every identity in the
context, including its Ed25519 association generation and authority epoch, is
already current. That meaning is not changed for enrollment. In particular,
it cannot prove a proposed rotation or re-enrollment successor before the
successor exists, and initial enrollment has no current Ed25519 generation to
compare. Its independently checked non-Ed25519 dimensions -- exact context,
Current-Full proofs, device and approver sessions, X25519 binding and earliest
locked deadline -- remain required enrollment preconditions, but its Ed25519
fields must not be reinterpreted as pre-effect successor evidence.
Specifically, the context digest, locked deadline and Full proof identities
retain their existing meanings after independent validation. The
`CurrentAdmissionAuthorityV1.authority_epoch` is the epoch of an
already-current context and cannot be used as proof that the proposed
successor epoch is current. The enrollment-specific authority instead records
both locked `preEffectAuthorityEpoch` and lifecycle-derived
`proposedAuthorityEpoch` without changing the existing type.

## Device-request effect and receipt identity (pure prerequisite)

`app/services/social_device_request_operation_effect.py` freezes the pure
identity contract for the two exact `device-request-v1` operations:
`ciphertext-submit` and `recipient-self-read`. It accepts only an exact parsed
`VerificationInputV1`, the concrete
`AuthenticatedSocialDeviceVerificationStatementV1` returned by the strict RSA
verifier, the existing `CurrentAdmissionAuthorityV1`, and an explicit
observation time used only for exclusive freshness checks. It reparses the
existing admission wires and does not define an alternate request parser. The
older generic `AuthenticatedVerificationStatementV1` Protocol placeholder and
shape-inspection results are not accepted as authenticated authority.

Success returns a closed, frozen
`PreparedDeviceRequestOperationEffectV1`. Its common typed fields retain the
exact challenge, operation, subject/device, X25519 binding generation, current
Ed25519 association generation, context/input digests, authority epoch, locked
deadline, current Full proof identity, null request approver proof, statement
JTI and statement attempt. Its promised effect is one of two distinct concrete
types, so submit routing facts cannot be substituted for self-read facts. A
separate helper returns the existing three-field `PreparedAdmissionEffectV1`
only as an interface projection; that generic shape does not supply or grant
the request identity semantics.

The exact one-shot operation identity preimage is compact sorted-key printable
ASCII JSON with schema
`hodlxxi.social_device_request_effect_id_preimage.v1`, version 1, and exactly:

```text
approverFullProofId = null
authorityEpoch
challengeId, challengeKind = device-request-v1
contextDigest, deviceId, fullProofId, inputDigest, lockedDeadlineMs
operation = ciphertext-submit | recipient-self-read
statementAttemptId, statementTokenId, subject
schema, version
```

The JTI is the authenticated statement identity, while the independently
bound statement attempt, context and input prevent cross-attempt,
cross-context and cross-input substitution. The context digest binds the exact
current association and all other frozen context identities. The input digest
binds the exact proof, actual request and operation-specific routing
nullability. The identifier is lowercase hexadecimal:

```text
effect_id = SHA256(
  ASCII("HODLXXI_SOCIAL_DEVICE_REQUEST_EFFECT_ID_V1")
  || NUL
  || ASCII(effectIdPreimage)
)
```

The operation-effect digest is independently domain-separated and commits to
the exact effect facts already available before execution. Both operation
preimages contain the exact `actualRequestWire`, body digest, challenge,
subject/device, X25519 binding generation, current Ed25519 association
generation, context digest, authority epoch, locked deadline and current Full
proof identity. They do not contain an observation or completion time.

For `ciphertext-submit`, the preimage schema is
`hodlxxi.social_device_request_ciphertext_submit_effect.v1`. It additionally
contains the exact `routingRequestWire`, message ID, envelope digest, recipient
package snapshot ID and complete sorted unique recipient-device-handle array.
The actual request has a null recipient handle. These are request-time promises
only: there is no routing decision, resolved destination, work ID, ciphertext
storage or delivery claim.

For `recipient-self-read`, the preimage schema is
`hodlxxi.social_device_request_recipient_self_read_effect.v1`. It additionally
contains the exact recipient handle from the actual request, and has no routing
request fields. The handle remains related to the exact current request
authority through the common subject/device, binding, association, context and
epoch fields. It is not resolved here. No inbox item, cursor, page, message
list, ownership inference or storage result is selected or invented.

For either operation:

```text
effect_digest = SHA256(
  ASCII("HODLXXI_SOCIAL_DEVICE_REQUEST_EFFECT_DIGEST_V1")
  || NUL
  || ASCII(operationSpecificEffectPreimage)
)
```

Future durable routing or self-read owners must refine these promises with the
real authoritative decision/effect evidence that is unavailable today. They
must not reinterpret the prepared digest as proof that routing, resolution,
storage, selection or delivery occurred.

The future immutable request receipt identity has its own compact sorted-key
ASCII preimage with schema
`hodlxxi.social_device_request_receipt_id_preimage.v1`, version 1, and exactly:

```text
approverFullProofId = null
authorityEpoch
challengeId, challengeKind, contextDigest, deviceId
effectDigest, effectId
fullProofId, inputDigest, lockedDeadlineMs, operation
statementAttemptId, statementTokenId, subject
schema, version
```

Its lowercase hexadecimal identity is:

```text
receipt_id = SHA256(
  ASCII("HODLXXI_SOCIAL_DEVICE_REQUEST_RECEIPT_ID_V1")
  || NUL
  || ASCII(receiptIdPreimage)
)
```

`decidedAt` is deliberately absent, as are randomness, sequence numbers and
mutable post-effect state. This helper does not construct the existing
`AdmissionReceiptV1`, whose `status=committed` and `decidedAt` belong only to a
future durable decision after the real effect and request atomicity invariants
exist.

All three request domains are distinct from one another and from the enrollment
domains. An input digest, body digest, envelope digest, routing snapshot ID,
challenge ID, statement JTI, effect ID, effect digest and receipt ID retain
separate meanings and cannot be relabeled as one another. The canonical
non-authoritative prepared projection uses schema
`hodlxxi.social_device_request_prepared_effect.v1` and embeds the exact
operation-specific promised-effect object.

This module performs no I/O and has no database, Redis, network, socket,
environment, credential, clock, route, factory, challenge creation/consumption,
recipient resolution, routing execution, receipt insertion or final-admission
capability. `CurrentAdmissionAuthorityV1` remains the pre-effect request
authority; no request transition authority, epoch advancement or successor is
introduced. Existing enrollment domains, bytes, fixtures and behavior are
unchanged.

The dormant
`app/services/social_messaging_recipient_routing_storage.py` adapter now
implements exact routing snapshot/route retention, permanent confidential
handle ownership and one-message-ID decision idempotence in a caller-owned
PostgreSQL transaction. That decision remains only routing resolution. It does
not persist ciphertext, select a self-read page, refine either prepared request
effect with real effect evidence, issue a request receipt or consume a request
challenge. Its immutable handle owners retain historical snapshot/decision
evidence only; they do not identify the active alias namespace or a current
handle.

The separate dormant
`app/services/social_messaging_active_alias_namespace_storage.py` adapter and
empty-by-default additive migration narrow that blocker without reinterpreting
history. In a caller-owned PostgreSQL READ COMMITTED transaction the reader
locks the explicitly `ACTIVE` namespace row, requires exactly one, and matches
both its version and domain-separated secret commitment to the alias
secret/version already loaded from trusted startup configuration. The
recipient runtime reuses the privacy-directory runtime's exact configured
secret and version; there is no second configuration source. The registry
persists no secret, has no seed/backfill, and exposes no writer. A row is not
authoritative merely because its state column says `ACTIVE`: only the guarded
singleton row plus the independent exact configured pair can produce locked
reconciliation evidence, valid while the transaction remains held. Missing,
ambiguous, retired, stale-version, commitment-mismatched and post-rotation
state deny. Highest version, row age, snapshot expiry, historical owner rows
and caller input are never selectors.

The dormant alias-lifecycle command module verifies exact offline-signed UBID
deployment commands with an explicitly pinned Ed25519 public key and key ID.
It creates no signing key. A separate dormant transaction owner now reverifies
the raw command, freshness, key pin and configured successor commitment before
and after lock waits; serializes writers with a dedicated transaction advisory
lock; and atomically stages empty version-1 provisioning or an exact locked
one-step rotation with its immutable signed event. It owns no commit and
retains no raw secret. Deferred migration guards reject row-only, event-only,
partial, nonsequential, replayed or rewritten history at commit. Those guards
are structural: they neither authenticate the Ed25519 signer nor establish
database actor privileges. Runtime trust configuration, key provisioning,
migration application and operational cutover remain absent. The
dormant `social_messaging_current_handle_candidate.py` adapter now narrows the
next boundary without granting it: it strictly parses the complete existing
self-read verification input, establishes the real current admission authority
from server-resolved selectors, locks and rechecks the configured ACTIVE
namespace, locks one exact immutable historical owner, and compares that owner
with the re-read exact current binding subject/device/ID/version in the same
caller transaction. It repeats current admission and namespace checks after
waits. It accepts no detached authority dataclass or separately supplied
identity and performs no handle derivation, network or Unix call.

The returned candidate fixes authorization and recipient self-read to
`not_granted` and ciphertext to `not_returned`. It is not an effect port,
receipt, challenge consumer or final-admission result. The pure routing gate
also remains unwired because its authority ports are not the same locked
transaction. A future request owner still must supply bounded self-read
selection/effect ownership and atomic request durability without reinterpreting
this candidate as authority.

Fixed valid, mutation, rejection, domain-separation and exact projection
vectors are in
`tests/fixtures/social_device_request_operation_effect_v1.json`. Durable
request execution remains blocked. The next durable prerequisite requires a
new additive migration for request effects, immutable request receipts,
request-specific challenge consumption and deferred atomic completeness. The
merged enrollment migration remains unchanged and no migration is added here.

## Enrollment transition authority and effect identity (pure prerequisite)

`app/services/social_enrollment_transition_authority.py` freezes the separate
`EnrollmentTransitionAuthorityV1` contract for one exact authenticated
`enrollment-v2` / `enrollment-activate` attempt. It describes authorization
against locked pre-effect state; it does not mean admitted, effect executed,
challenge consumed, receipt issued or committed. The module is pure and
dormant. It performs no I/O, reads no environment or clock, and provides no
storage adapter, transaction owner, route or runtime wiring.

The PostgreSQL adapter described below constructs this authority only after
following the established global admission lock order and, after every wait,
validating the exact issued challenge, authenticated Social verification
statement, Current-Full proofs, device and approver sessions, X25519 authority
and locked Ed25519 history. The adapter supplies explicit integer
epoch-millisecond observation/deadline values. The pure helper accepts the
frozen lifecycle as candidate locked evidence and applies the existing
lifecycle functions; by itself it does not establish that a database lock
exists.

The closed authority wire is compact, sorted-key printable ASCII JSON with
schema `hodlxxi.social_enrollment_transition_authority.v1`, version 1, and
exactly:

```text
schema, version
operation = enrollment-activate
challengeKind = enrollment-v2
challengeId, subject, deviceId
contextDigest, inputDigest, enrollmentDigest, statementTokenId
observedAt, lockedDeadlineMs
fullProofId, approverFullProofId
transitionKind = initial | rotate | reenroll
preEffectAssociationState
preEffectAssociationId, preEffectAssociationVersion, preEffectAuthorityEpoch
proposedEd25519PublicKey
proposedAssociationId, proposedAssociationVersion
proposedPredecessorAssociationId, proposedAuthorityEpoch
```

The transition matrix is exact:

- `initial` requires an absent pre-effect association, null pre-effect ID and
  version, epoch 0, null predecessor, and proposed version/epoch 1/1.
- `rotate` requires the exact current active predecessor. The proposed
  predecessor equals that locked association ID, and proposed version and
  authority epoch are each the predecessor snapshot value plus one.
- `reenroll` requires no current association and the exact last generation to
  be revoked. The proposed predecessor equals that revoked association ID,
  and proposed version and authority epoch are each the locked snapshot value
  plus one.

No fourth transition exists. In every case the existing lifecycle computes
the candidate generation and compares every proposed Ed25519 field with the
context. The proposed successor is never called or treated as current before
mutation. Stale/forked predecessors, wrong versions or epochs, replaced
subjects/devices, reused keys/challenges and every lifecycle state outside the
matrix fail through the one non-sensitive contract error. The typed authority's
public constructor and subclassing are disabled; wire validation alone does
not grant typed authority. As with the authenticated statement boundary,
arbitrary Python reflection or mutation of trusted process code is not treated
as a process trust boundary.

The exact operation-instance identity preimage is compact, sorted-key ASCII
JSON with schema `hodlxxi.social_enrollment_effect_id_preimage.v1`, version 1,
and exactly `challengeId`, `challengeKind`, `contextDigest`, `deviceId`,
`inputDigest`, `operation`, `statementTokenId`, `subject`, `schema`, `version`.
The real authenticated statement exposes its canonical token ID, rather than a
digest of the compact signed statement, as statement identity; that token ID
is therefore the bound statement identity. Signing key ID/fingerprint remain
authenticated trust metadata and are not substituted for the statement's
operation-instance identity.
The identifier is lowercase hexadecimal:

```text
effect_id = SHA256(
  ASCII("HODLXXI_SOCIAL_ENROLLMENT_EFFECT_ID_V1")
  || NUL
  || ASCII(effectIdPreimage)
)
```

The promised-transition preimage is compact, sorted-key ASCII JSON with
schema `hodlxxi.social_enrollment_effect_transition.v1`, version 1, and
exactly:

```text
challengeId, challengeKind, operation, subject, deviceId, enrollmentDigest
transitionKind
preEffectAssociationState, preEffectAssociationId
preEffectAssociationVersion, preEffectAuthorityEpoch
proposedState = active
proposedEd25519PublicKey, proposedAssociationId
proposedAssociationVersion, proposedPredecessorAssociationId
proposedAuthorityEpoch
schema, version
```

Non-applicable initial predecessor fields are explicit JSON nulls rather than
omitted. The digest is lowercase hexadecimal:

```text
effect_digest = SHA256(
  ASCII("HODLXXI_SOCIAL_ENROLLMENT_EFFECT_DIGEST_V1")
  || NUL
  || ASCII(effectTransitionPreimage)
)
```

The domains and preimages keep operation-instance identity distinct from the
state transition promised. Neither derivation uses randomness, time, bearer
material or mutable post-effect database state. `PreparedAdmissionEffectV1`
will contain operation `enrollment-activate` and these two values. Here,
prepared means only that this exact effect is deterministically described and
authorized against locked pre-effect state; it does not claim execution or
commit. The enrollment atomic owner below composes operation mutation,
immutable receipt and issued-to-consumed challenge transition in one
caller-owned transaction. Fixed authority, ID, digest, mutation and rejection
vectors are in
`tests/fixtures/social_enrollment_transition_authority_effect_identity_v1.json`.

## Transaction-bound enrollment transition authority

`app/services/social_enrollment_transition_authority_storage.py` is the
dormant PostgreSQL adapter that establishes the locked pre-effect evidence for
the pure contract. It accepts only an already-active caller-owned READ
COMMITTED SQLAlchemy transaction and the exact server-resolved device Social
issuance and desktop approver OAuth Session selectors. It has no session
factory, connection URL or clock and never begins, commits, rolls back, closes
or replaces a transaction.

The deterministic lock order is the exact challenge row first; the existing
Current-Full/User, OAuth/browser/Session/Social issuance and X25519 order from
the current-authority adapter next; and the Ed25519 pair advisory, chain and
complete event-history order last. This permits the enrollment consuming
owner to retain the same first lock without reversing any existing
authority-owner edge. Every locked owner is re-read and validated with the
caller's explicit integer epoch-millisecond `observed_at`. PostgreSQL READ
COMMITTED, physical
transaction, connection and savepoint identity checks remain in force.

The challenge must still be `issued`, byte-identical to the verification
context and Enrollment V2 challenge, and current under exclusive zero-skew
deadline semantics. The adapter accepts only the real authenticated Social
statement type and binds it again to the exact challenge, attempt,
context/input digests, enrollment result/purpose and observation time. It
reuses the current-authority adapter's non-Ed25519 owner logic without calling
the proposed successor current, then loads complete locked Ed25519 event
evidence and invokes the pure transition matrix. `lockedDeadlineMs` is the
earliest locked Full/session/X25519 or challenge deadline.

Success returns only `EnrollmentTransitionAuthorityV1`. An optional caller may
derive the pure `PreparedAdmissionEffectV1` description from it, but this
adapter inserts no association event, changes no challenge state, creates no
receipt and executes no effect. It rejects SQLite and other non-PostgreSQL
backends. It adds no schema or migration, route, factory composition, socket
surface or runtime activation. Final admission remains denied.

## Enrollment receipt identity, storage and challenge consumption prerequisite

`app/services/social_enrollment_receipt_storage.py` freezes the deterministic
identity of a durable `enrollment-activate` receipt. Its compact sorted-key
ASCII preimage has schema
`hodlxxi.social_enrollment_receipt_id_preimage.v1`, version 1, and exactly
`challengeId`, `effectDigest`, `effectId`, `operation`, `schema`, `version`.
The lowercase hexadecimal identity is:

```text
receipt_id = SHA256(
  ASCII("HODLXXI_SOCIAL_ENROLLMENT_RECEIPT_ID_V1")
  || NUL
  || ASCII(receiptIdPreimage)
)
```

`decidedAt` is deliberately excluded. Recovery after an uncertain commit
therefore derives the same identity from the authenticated operation instance
and exact promised transition. There is no randomness, sequence, secret or
mutable post-effect state. This enrollment-specific derivation does not change
the existing generic `AdmissionReceiptV1` wire or its fixed public vectors.
Independent receipt-identity vectors are in
`tests/fixtures/social_enrollment_receipt_identity_v1.json`.

The additive migration
`migrations/2026-09-23_social_device_admission_receipt_consumption_v1.sql`
creates one immutable receipt row per challenge, makes `effectId` single-use,
and stores the exact canonical authority and receipt wires with indexed
receipt, challenge, effect and proposed-association identities. Database
guards recompute the frozen effect ID, effect digest, receipt ID and receipt
wire. Update, deletion and truncation are denied. Reads return history with no
bearer or re-execution authority.

The same migration narrowly extends the existing challenge guard to permit
only an enrollment `issued` to `consumed` transition without changing any
challenge evidence. `record_enrollment_consumed()` re-locks the authoritative
row, requires the exact typed transition authority and already-inserted
matching receipt, resamples explicit exclusive zero-skew time, and compares
the exact context, operation, challenge, proposed association and frozen
digests. Other terminal semantics and all resurrection denials remain intact.

Deferred constraint triggers on each newly inserted Ed25519 creation event,
each receipt and each consumed challenge require the final transaction state
to contain all three matching records. They compare the challenge/context,
association generation, subject/device chain, predecessor, pre-effect epoch,
effect identities and exact authority evidence. Thus the enrollment owner uses
the established lock order and one caller-owned transaction in the logical
order effect, receipt, consume, commit; an effect-only, receipt-only,
consume-only or other incomplete subset cannot commit. Existing association
history predating this additive migration is retained without backfill.

Both adapters require an already-active caller-owned PostgreSQL READ COMMITTED
transaction. They have no session factory, URL or ambient clock and never
begin, commit, roll back, close or replace the transaction. SQLite remains
metadata compatibility only and grants no durable authority. These primitives
remain independently dormant and do not themselves compose the three
mutations. The enrollment-only owner below performs that composition without
adding a route, wiring runtime or granting final admission.

## Enrollment activation atomic owner

`app/services/social_enrollment_atomic_owner.py` implements the single dormant
PostgreSQL owner for the exact `enrollment-activate` operation. It accepts one
already-active caller-owned READ COMMITTED SQLAlchemy transaction and the same
server-resolved device issuance and desktop approver selectors required by the
transition-authority adapter. Construction fails closed for SQLite, every
other non-PostgreSQL path, a missing transaction, missing database guards or a
replaced physical transaction, connection or savepoint.

`execute_enrollment_activate()` is one-shot. It accepts the exact parsed
verification input, authenticated Social statement, explicit authority
observation time and a later explicit decision time. The decision time must be
at least the authority observation and earlier than the locked authority
deadline. The association adapter rechecks enrollment and statement deadlines
at that later decision time; challenge consumption then resamples the same
explicit decision time under its exclusive zero-skew rule.

The owner preserves the established lock and mutation order:

1. lock the exact issued challenge, then all non-Ed25519 and Ed25519 pre-effect
   authority through
   `SqlAlchemyTransactionBoundEnrollmentTransitionAuthority`;
2. derive the existing deterministic `PreparedAdmissionEffectV1`;
3. execute exactly one lifecycle method selected by the locked transition:
   `establish_initial`, `rotate` with the exact predecessor and pre-effect
   epoch, or `reenroll` with the exact revoked predecessor and epoch;
4. compare the returned association's subject, device, key, ID, version,
   predecessor, epoch and active state with every proposed authority field;
5. insert the existing deterministic immutable enrollment receipt and compare
   its effect and association evidence;
6. transition that same challenge from `issued` to `consumed` through
   `record_enrollment_consumed()`.

There is no fourth transition and no duplicated receipt, effect, association
or challenge identity implementation. Re-locking the already-held Ed25519 pair
and challenge uses the same order and transaction; it introduces no reverse
lock edge. The deferred migration constraints remain the final database check
that effect, receipt and consumption are all present and byte-matched at the
caller's commit.

Success returns only frozen `ProvisionalEnrollmentActivationV1`, containing
the exact typed authority, prepared effect, active association, stored receipt
and consumed challenge. Its publication status is
`provisional_until_caller_commit`; neither the receipt's historical
`status=committed` wire nor the returned Python value claims that the caller
has committed. Only caller commit makes the three mutations durable. Caller
rollback removes all three, and commit-time invariant failure rejects the
transaction.

The owner never begins, commits, rolls back, closes or replaces a transaction.
It has no session factory, connection URL, environment lookup or clock. Any
authority, storage, returned-evidence, deadline, replay, uniqueness, deadlock
or lock-timeout failure is mapped to one non-sensitive owner failure and
poisons that one-shot instance. The caller must propagate the failure and roll
back the entire transaction. Recovery reads remain non-bearer history and
cannot authorize replay or re-execution.

This source is enrollment-specific and dormant. It does not implement either
device-request effect, generic device admission, final admission, an HTTP or
Unix-socket route, Social verifier transport, factory composition, feature
flags, migration application or deployment. The existing 2026-09-23 migration
is sufficient; this owner adds no schema.

## Verification context

The context is at most 4,096 ASCII bytes and contains exactly:

```text
schema = hodlxxi.social_device_verification_context.v1
version = 1
challengeKind = enrollment-v2 | device-request-v1
challengeId, attemptId, audience, subject, deviceId,
bindingId, bindingVersion, x25519PublicKeyCommitment,
profile, ed25519PublicKey,
associationId, associationVersion, predecessorAssociationId, authorityEpoch,
sessionBinding, approverSessionBinding,
fullProofId, approverFullProofId
```

Hex identities are exactly 64 lowercase hexadecimal characters.
`bindingVersion`, `associationVersion` and `authorityEpoch` are positive safe
integers; binding versions remain at most 1,024. The profile is exactly
`hodlxxi.social_messaging_device_proof.ed25519_webcrypto.v1`. Current-Full
proof identities retain their existing prefixed form and remain content
identities rather than credentials.

For a request, predecessor and both approver fields are null. For enrollment,
the approver session and Full proof are present. A first enrollment has
association version 1 and null predecessor; a successor has a non-null exact
predecessor and a version greater than 1. The context audience uses the frozen
canonical HTTPS-origin grammar shared with the existing proof profile.

The digest is:

```text
hodlxxi-social-device-verification-context-v1-sha256:
SHA256(
  ASCII("HODLXXI_SOCIAL_DEVICE_VERIFICATION_CONTEXT_V1")
  || NUL
  || ASCII(contextWire)
)
```

## Ed25519 association lifecycle (pure source contract)

`app/services/social_messaging_device_ed25519_association_lifecycle.py`
defines a dormant, immutable event sequence for one exact `(subject, deviceId)`
association chain. Events are candidate evidence: the enrollment atomic owner
must authenticate enrollment and load the complete locked history before
replay or current-authority comparison. This source does not consume a
challenge, store an association, admit a device or invalidate an outstanding
challenge.

`associationId` identifies one concrete Ed25519 association generation. It is
the lowercase hexadecimal SHA-256 of ASCII
`HODLXXI_SOCIAL_MESSAGING_DEVICE_ED25519_ASSOCIATION_ID_V1`, one NUL byte and
the compact, sorted-key ASCII JSON creation preimage. That preimage has exactly
`associationVersion`, `deviceId`, `ed25519PublicKey`, `enrollmentDigest`,
`predecessorAssociationId`, `schema`, `subject`, `version`. The schema is
`hodlxxi.social_messaging_device_ed25519_association_creation.v1`; version is
1. `enrollmentDigest` is the existing domain-separated digest of the exact
canonical Enrollment V2 wire. Neither `associationId`, `authorityEpoch` nor a
storage identifier is an input to its own derivation. It is distinct from the
device ID, Ed25519 key and X25519 binding ID.

`associationVersion` counts generations in this exact chain: initial is 1,
and each successful rotation or re-enrollment is its predecessor's version
plus 1. `predecessorAssociationId` is null only for initial creation and is
the exact prior generation ID for a successor. `authorityEpoch` counts
committed authority-invalidating transitions: initial is 1, and rotation,
explicit invalidation, revocation and re-enrollment each advance it exactly
once. Invalidation preserves the current association and version while
invalidating earlier authority observations. Thus version 2 and epoch 4 are
valid together; they are never inferred from one another.

Rotation requires an active predecessor; a future committed rotation must
make it `rotated` as the new generation becomes active in one transaction.
Revocation requires an active generation,
leaves its version unchanged, advances the epoch and leaves no current
association. Re-enrollment after revocation requires the exact revoked
predecessor, increments version and epoch, and creates a fresh association;
it cannot reopen the revoked generation or reuse a prior Ed25519 key or
enrollment challenge ID in the chain. Initial creation cannot be replayed
after any history exists. Replay rejects skipped or repeated epochs, wrong
versions, cross-subject/device successors, stale predecessors, forks,
rollback and resurrection. The durable owner below enforces one current
association per exact device and serializes competing transitions at commit;
independent in-memory candidate histories cannot establish that fact.

`current_association_matches_v1` compares the fully parsed frozen
`VerificationContextV1` with the active generation's exact subject, device,
Ed25519 key, association ID, version and current epoch. For an enrollment
context it also compares the exact predecessor. The frozen
`device-request-v1` context requires a null predecessor because that field is
not applicable to a request; the comparison therefore uses the current
association ID, version and epoch without treating null as a new initial
generation. Binding, entitlement, challenge, cryptographic statement and
operation checks remain independent future admission checks. Fixed lifecycle
vectors are in
`tests/fixtures/social_messaging_device_ed25519_association_lifecycle_v1.json`.

## Durable Ed25519 association authority

`app/services/social_device_ed25519_association_storage.py` is a dormant
PostgreSQL adapter for the pure lifecycle above. Its additive migration creates
one exact `(subject, deviceId)` chain row and immutable event history, without
backfill. The row records the current generation and epoch; every read locks
the pair, reparses all canonical event wires, replays the frozen lifecycle and
checks the row against the resulting snapshot. The read returns only current
Ed25519 association facts, or no current association after revocation. A
separate locked history read retains rotated and revoked evidence.

Initial association, rotation and re-enrollment require an exact canonical
Enrollment V2 verification input and the typed result of the authenticated
Social statement verifier. The adapter binds the statement digests to the
input and its context, compares the context with the new lifecycle generation,
and checks explicit epoch-millisecond `now` against enrollment and statement
intervals. The caller must acquire the statement through the configured
verifier and independently own the challenge, current session, Current-Full,
X25519 binding and operation transaction checks. Revocation and explicit
invalidation require exact current ID and epoch. Invalidation advances the
epoch without changing the current generation.

Every method uses a caller-owned active read-committed PostgreSQL transaction;
it never commits, rolls back, closes or creates a session. Lock order is pair
advisory lock, chain row, then immutable events in epoch order. The advisory
lock protects the absent-row case; a hash collision only adds contention.
PostgreSQL triggers serialize event insertion with the chain row, advance the
materialized current state, reject direct rewrites/deletes/truncation, and
prevent an empty chain from committing. Unique indexes prevent generation ID,
version, predecessor, key and enrollment challenge reuse. The adapter rejects
SQLite as an authority even though its shared model metadata remains safe for
SQLite create/drop tests.

This storage does not consume an enrollment challenge, invalidate outstanding
challenges, prove a current session, Current-Full or X25519 binding, or admit a
device. Migration source is not migration application; no runtime factory,
route or Social transport is activated.

## Verification input

The input is at most 24,576 ASCII bytes and contains exactly:

```text
schema = hodlxxi.social_device_verification_input.v1
version = 1
context = exact contextWire STRING
challenge = exact stored challenge STRING
proof = exact proof wire STRING
approvalEvent = exact canonical full Nostr event STRING | null
actualRequest = exact actual request candidate STRING | null
routingRequest = exact six-field Phase 3 routing request STRING | null
```

Inner caps are challenge 4,096, proof 1,024, approval event 8,192, actual
request 2,048 and routing request 2,048 bytes. The outer cap applies as well.

Enrollment requires the exact Enrollment V2 challenge, phone proof and one
seven-field Nostr event; actual request and routing request are null. The pure
contract checks canonical event bytes, the event ID preimage, ordered tags and
all cross-document identities. It does not verify the BIP340 or Ed25519
signatures.

A device request requires the exact stored request challenge and actual
request, and approval event is null. `ciphertext-submit` requires its exact
six-field routing request. `recipient-self-read` requires routing request null.
The only admitted-operation tuples frozen for future use are:

```text
POST /messaging/v1/ciphertext-submit
POST /messaging/v1/recipient-self-read
```

The input digest is:

```text
hodlxxi-social-device-verification-input-v1-sha256:
SHA256(
  ASCII("HODLXXI_SOCIAL_DEVICE_VERIFICATION_INPUT_V1")
  || NUL
  || ASCII(inputWire)
)
```

## Verification statement shape

The compact JWS is at most 4,096 ASCII bytes. All three segments use canonical
unpadded base64url. The protected header is exactly:

```json
{"alg":"RS256","kid":"<configured identifier>","typ":"hodlxxi-social-device-verification+jws"}
```

The payload contains exactly:

```text
schema = hodlxxi.social_device_verification_statement.v1
version = 1
iss, aud, clientId, servicePrincipal
purpose = social_device_cryptographic_verification_v1
result = strict-ed25519-valid |
         enrollment-v2-ed25519-and-nostr-valid
challengeKind, challengeId, attemptId, contextDigest, inputDigest,
issuedAt, expiresAt, jti
```

`aud` is the configured canonical UBID HTTPS origin followed by
`/internal/v1/social/device-admission/consume`. Times are safe integer epoch
milliseconds. Shape inspection requires `issuedAt <= now < expiresAt`, a
positive lifetime of at most 10,000 ms, zero skew, and expiry no later than the
challenge and relevant phone/approver sessions. The result must match the
challenge kind. Context, input, challenge and attempt bindings must match the
exact supplied wires. Both `iss` and the verification context's `audience`
must equal the same exact configured Social issuer; a coherently rebuilt
alternate context and input cannot be attested by that configured issuer.

The parser rejects `none`, other algorithms, wrong type, unknown or missing
members, embedded JWK, `jku`, `x5u`, duplicate/noncanonical JSON and
noncanonical base64url. It intentionally accepts any canonical nonempty
signature bytes as shape. The separate authenticated verifier below adds RSA
verification without changing the shape inspector or its non-claims.

## Authenticated statement verifier

`app/services/social_device_verification_statement.py` provides
`SocialDeviceVerificationStatementConfig` and
`verify_social_device_verification_statement_v1`. The empty configuration is
disabled. Explicit configuration binds the exact Social issuer, UBID consume
audience, client ID, service principal, fixed statement purpose, and one or
more public RSA JWKs. This is a dedicated trust domain; it neither imports nor
calls the generic confidential service-token decoder.

Registration is immutable and validates all keys eagerly, including when
disabled. JWKs contain exactly `kty`, `use`, `alg`, `kid`, `n`, and `e`, with
`RSA`, `sig`, and `RS256` fixed. Identifiers use the existing contract grammar.
Modulus and exponent use minimal, unpadded canonical Base64urlUInt; keys are
2,048..8,192 bits with odd modulus and a valid odd public exponent. Encoded
modulus and exponent are bounded to 1,366 and 16 characters respectively.
Unknown members, every RSA private parameter (`d`, `p`, `q`, `dp`, `dq`, `qi`,
`oth`), symmetric material, private key objects, remote key locators, malformed
keys and duplicate identifiers are rejected. Only copies of validated public
material are retained. Key selection requires exactly one registered key with
the exact protected-header `kid`; there is no fallback to another key.

The verifier invokes the existing canonical statement/context/input inspector
with exact configured expectations and caller-supplied epoch-millisecond time
and deadlines. The enrollment owner's authenticated caller must supply the
expected wires and deadlines from authoritative state. Enrollment requires an
approver-session deadline; device requests require none. All deadlines remain exclusive with
zero skew. The statement must also fit inside the exact embedded challenge's
issued-at/expiry interval, even if an injected challenge deadline is later.

Registration uses PyJWT's established public-JWK loader. Only after all shape
and binding checks does the verifier use `cryptography`'s
**RSASSA-PKCS1-v1_5 with SHA-256** verification over
the inspector's original `signing_input` and decoded signature. It never
reserializes header or payload for signature verification. PSS, alternate
hashes, algorithm/type substitutions and noncanonical representations cannot
authenticate. All configuration and verification failures expose only
`social device verification statement denied`, without internal exception
chains or logging inputs, signatures or key material.

Success returns a frozen `AuthenticatedSocialDeviceVerificationStatementV1`
containing only issuer, audience, client ID, service principal, purpose,
result, challenge kind/ID, attempt ID, context/input digests, issued-at,
expires-at, token ID, key ID and SHA-256 DER-SPKI fingerprint. Its public
constructor and subclassing are disabled; neither a shape-inspection record
nor caller booleans can construct it. There is no conversion from the earlier
future-port placeholder. This API boundary does not claim isolation against
arbitrary Python reflection or mutation of trusted process code.

The record authenticates Social's statement, not current Full/session/binding
authority, challenge consumption, an operation effect or an admission receipt.
It is not a bearer credential and has no execution capability. Reverification
is stateless; replay prevention, trust invalidation after waits and the atomic
consumer remain future work. There is no ambient clock, environment access,
key loading/provisioning, storage, I/O or factory import. Final admission
remains denied, challenge consumption remains unimplemented, and current
authority remains unevaluated.

## Internal route vocabulary

The dormant literal prefix is `/internal/v1/social/device-admission`. These
tuples are data constants and parsers only; no HTTP route exists.

| Path | Exact command | Exact response kind |
|---|---|---|
| `/session-bind` | `session-bind` | `session-binding` |
| `/enrollment-prepare` | `enrollment-prepare` | `enrollment-prepared` |
| `/enrollment-challenge` | `enrollment-challenge` | `challenge` |
| `/enrollment-read` | `enrollment-read` | `enrollment-state` |
| `/enrollment-phone-proof` | `enrollment-phone-proof` | `enrollment-state` |
| `/enrollment-approval` | `enrollment-approval` | `enrollment-state` |
| `/enrollment-cancel` | `enrollment-cancel` | `enrollment-terminal` |
| `/challenge` | `challenge` | `challenge` |
| `/challenge-read` | `challenge-read` | `challenge` |
| `/consume` | `consume` | `receipt` |
| `/recover` | `recover` | `receipt-history` |

Commands use schema `hodlxxi.social_device_admission_command.v1`; responses
use `hodlxxi.social_device_admission_response.v1`. Both use version 1. The
route parser requires the literal command/kind assigned to that route and the
closed fields specified by the source contract. The exact `/challenge`
command also requires its selector `deviceId` to equal the `deviceId` in the
canonical `actualRequestWire`; the selector does not establish subject,
session or authority.

Every challenge response fully cross-binds its `challengeWire` and
`contextWire`. Enrollment V2 pairs require equal challenge ID, audience,
subject, device ID, X25519 binding ID and version, X25519 public-key commitment
and Ed25519 public key. Device-request V1 pairs require equal challenge ID,
audience, subject, device ID, X25519 binding ID and version, and session
binding. Enrollment-state responses use the same Enrollment V2 pair check.

The receipt is exactly:

```text
schema = hodlxxi.social_device_admission_receipt.v1
version = 1
receiptId, challengeId
operation = enrollment-activate | ciphertext-submit | recipient-self-read
decidedAt
status = committed
```

## State and future ports

Enrollment states are `prepared`, `challenged`, `consumed`, `cancelled`,
`expired`, `invalidated`. Challenge states are `issued`, `consumed`, `expired`,
`invalidated`, `cancelled`. Association states are `active`, `rotated`,
`revoked`, `expired`. A receipt has only `committed`. Consumed/cancelled/
expired/invalidated enrollment and challenge states, rotated/revoked/expired
associations, and committed receipts are terminal. The transition validator
cannot reopen them.

Enrollment-state response evidence is frozen as follows:

- `prepared` has null challenge, context, phone proof, approval event and
  receipt.
- `challenged` requires an exactly cross-bound challenge/context pair. Phone
  proof and approval event are independently optional and strictly validated
  when present. Receipt is null.
- `consumed` requires the cross-bound pair, a phone proof bound to the exact
  enrollment challenge, enrollment digest, context challenge ID and context
  Ed25519 key, an approval event bound to the exact enrollment, context subject
  and event-ID preimage, and a committed `enrollment-activate` receipt bound to
  the context challenge ID.
- `cancelled`, `expired` and `invalidated` always have a null receipt. A state
  reached before challenge assignment has all four challenge/context/proof/
  approval fields null. Otherwise challenge and context are both present and
  exactly cross-bound, while proof and approval are independently optional and
  strictly validated. A lone challenge or context is forbidden.

The typed future ports are:

- challenge storage owner;
- authenticated Social verification-statement verifier;
- transaction-bound canonical viewer, Current-Full and binding authority;
- exact atomic operation-effect port; and
- receipt/history projection.

These are structural Protocols and perform no I/O. They accept and return
typed records rather than booleans. They do not implement storage,
authentication, signature verification or a transaction. The challenge owner
has separate terminal methods: consumed transition recording requires an
`AdmissionReceiptV1`, while cancelled/expired/invalidated terminal recording
has no receipt parameter and cannot accept one.

The enrollment owner denies on deadlock or lock timeout, and the caller must
roll back the whole transaction. A known rollback commits no effect, receipt
or challenge consumption. Caller commit is the durable publication point. An
uncertain commit must be reconciled from immutable history and must never be treated as
a known rollback or re-executed. Deadline checks are exclusive and must be
sampled again after waits.

## Immutable challenge storage

`app/services/social_device_challenge_store.py` supplies the dormant
`SocialDeviceAdmissionChallengeRow`, frozen `DeviceAdmissionChallengeV1`, pure
`parse_stored_device_challenge_v1` decoder and `SqlAlchemyDeviceChallengeStore`.
The additive migration is
`migrations/2026-09-21_social_device_challenge_store_v1.sql`. This repository
uses ordered, dated SQL migrations rather than an Alembic revision graph. The
file follows the session issuance migration and must be applied atomically by
an explicitly authorized migration owner. `metadata.create_all` does not
install the required guards and is insufficient.

The model uses a local SQLAlchemy dialect compiler for PostgreSQL-only wire
and JSON checks. PostgreSQL compilation preserves the migration expressions
exactly. For SQLite shared `Base.metadata.create_all`/`drop_all` compatibility,
those checks compile to a constant true expression; portable state and identity
checks remain. This is metadata compatibility only: SQLite neither enforces
the PostgreSQL evidence/trigger contract nor implements the challenge store.
The adapter continues to reject every non-PostgreSQL transaction.

The `social_device_admission_challenges` table contains only:

| Column | Persistence contract |
|---|---|
| `challenge_id` | Immutable primary key and sole indexed duplicate; exact equality with the context and challenge IDs is required for unique creation and row locking. |
| `context_wire` | Immutable, exact canonical printable ASCII `TEXT`, at most 4,096 bytes. |
| `challenge_wire` | Immutable, exact canonical printable ASCII `TEXT`, at most 4,096 bytes. |
| `routing_request_wire` | Immutable, exact canonical printable ASCII `TEXT`, at most 2,048 bytes; present only for ciphertext submit. |
| `state` | Separate lifecycle state using the frozen challenge vocabulary. |

Every context identity, including challenge kind, attempt ID, subject, device,
session binding, binding ID/version, X25519 commitment, Ed25519 key,
association/predecessor/version, authority epoch and phone/approver Full proof
and session identities, is derived from the exact context. Operation and exact
integer epoch-millisecond `issuedAt`/`expiresAt` are derived from the challenge.
For device requests, the actual request is already an exact canonical string
inside the challenge and is not stored twice. Creation requires the supplied
actual request to match that embedded string byte-for-byte. Enrollment has
null actual/routing requests; recipient self-read has null routing. These
nullability and cross-document checks reuse the existing admission parsers.
The store does not create a new preimage, digest, proof ID or serializer.

The original attempt ID and issued-at time are the creation metadata. No
additional creation clock, ordering sequence or invented idempotency identity
is needed: the primary key arbitrates competing creates. `create_issued`
performs a plain insert; an existing ID always fails, including exact retries
and terminal history. A contender waits for an uncommitted conflicting insert:
after commit it is denied; after rollback it can create. A returned create
record is provisional until the caller commits. Reconciliation after uncertain
commit uses a read of retained evidence, never an overwrite or assumed retry.

All reads reparse the original strings through the shared canonical contract
and compare the indexed key. They neither normalize JSON nor load mutable ORM
evidence objects. Only the original strings persist; derived record fields
are not additional authority columns. Invalid, ambiguous, noncanonical or
mismatched stored evidence fails closed. SQL bounds and key checks supplement
the complete Python parser. SQL JSON casts in constraints inspect the key;
they do not rewrite `TEXT` into JSON/JSONB storage. Direct database writers
remain trusted infrastructure; arbitrary database-owner changes are not a
cryptographic integrity boundary.

Database triggers reject evidence replacement, deletion and truncation. Inserts
must be `issued`. The original migration permits only `issued` to `expired`,
`invalidated` or `cancelled`, without any evidence change, and forbids terminal
reopening. Its bytes remain unchanged. The additive receipt/consumption
migration replaces only the guard function semantics to add the narrow
enrollment `issued` to `consumed` transition under the deferred receipt/effect
invariant described above. No arbitrary state mutation is exposed.
An expired challenge remains stored evidence; deadline inspection takes an
explicit `now`, uses `issuedAt <= now < expiresAt` with zero skew and never
changes timestamps or state. Creation/storage does not assert current validity.

The adapter requires a clean, active PostgreSQL READ COMMITTED SQLAlchemy
`Session` transaction and the installed immutable guards. It captures that
transaction and any current savepoint; every operation checks the same active
identity and refuses transaction or savepoint replacement. The caller must
flush pending ORM work explicitly. All SQL uses the caller's same pinned
connection and physical transaction; closed, invalidated or replaced
connections and driver autocommit are rejected. A logical SQLAlchemy
transaction alone is insufficient to establish a durable row lock. The adapter
never begins, commits, rolls
back, closes or replaces a transaction, and has no ambient session factory,
environment connection string or clock. All failures expose only `social
device challenge storage unavailable`, without exception chains, and poison
that adapter instance. The caller must propagate failures and roll back its
whole unit of work; the adapter cannot prevent arbitrary caller code from
catching a failure and attempting unrelated work.

`read_for_update(challenge_id)` selects the authoritative row with PostgreSQL
`FOR UPDATE` in the injected transaction, retaining the lock until the caller
completes it. It reads current database columns even if an ORM object or an
earlier read is cached. It returns any stored state, never skips locked rows,
and is not a successful consumption capability. The enrollment owner requires
`issued`, resamples exclusive deadlines after waits, authenticates the exact
Social statement and rechecks current authority. The enrollment-only method
then records consumption after the caller has provisionally executed the exact
association effect and inserted its receipt in this same transaction. No
second independent transaction is hidden behind either operation. The generic
`ChallengeStorageOwner` protocol remains unimplemented because the adapter does
not broaden consumption to other operations or add non-consumed terminal
recording. No network or Unix-socket attestation call occurs while holding a
lock.

The guarded integration test accepts only an explicitly identified disposable
PostgreSQL 16 target under a unique temporary directory, on a non-live loopback
TCP port, with Unix sockets disabled and synthetic data. It never falls back to
`DATABASE_URL` or default PostgreSQL settings. Live migration application,
service access and runtime activation remain separately authorized operations.

## Fixed public vectors

`tests/fixtures/social_device_admission_v1.json` contains independent fixed
vectors for Enrollment V2, ciphertext submit and recipient self-read. Each has
exact context/input bytes and digests, canonical protected header/payload,
compact synthetic RS256 JWS, commands, responses and receipt shapes. It also
contains negative canonical/boundary cases.

`tests/fixtures/social_device_request_operation_effect_v1.json` separately
freezes the pure request effect-ID, operation-effect-digest and future receipt-ID
preimages and identities for both request operations. It also freezes exact
prepared projections and adversarial field mutation/rejection cases while
pinning the unchanged admission and Phase 3 routing fixture hashes.

The synthetic 2,048-bit RSA key was generated offline in memory only to sign
the fixed test bytes. No private key was serialized or retained. The fixture
contains only its public JWK and SPKI PEM. The public SPKI fingerprint is:

```text
sha256:569df6a856bb51a38cabd7fca78160ad847ac3ba433af226a1810f1f351a9cce
```

The request proof signatures are explicit shape-only synthetic bytes. The
Enrollment V2 public evidence is copied byte-for-byte from the independently
signed shared proof-profile fixture. Tests independently validate the fixed RSA
signatures from public material through the authenticated verifier, while the
separate shape parser continues to report RSA verification as `not_evaluated`.
Social's producer uses the same closed header/payload vocabulary, digest
domains and exact ASCII compact-JWS signing input. Its deterministic `jti`
derivation supplies a token identifier; UBID authenticates that signed hex64
claim without turning it into a replay record or admission authority. The
fixed synthetic vectors remain unchanged and tests require no Social checkout.

## Activation blockers and non-claims

Future work must separately provide and test active trust provisioning and
invalidation, lifecycle signing-key/configuration provisioning and coordinated
alias-namespace operational cutover,
authorizing current-handle/self-read effect ownership, transaction-bound
ciphertext persistence, bounded self-read selection/effect ownership, durable
request-effect refinement, request receipt storage and atomic challenge
consumption under a new additive migration, internal routes, purpose-bound
Unix-socket client, quotas, credentials and explicit factory composition.
Migration application, credential provisioning, socket exposure, runtime
activation and deployment require separate authorization.

There is no participant or device private-key custody in UBID or Social server
storage. A future dedicated Social infrastructure statement-signing key is a
separate provisioned service credential. OAuth possession alone never enrolls
or admits a device. X25519 remains encryption-only. The phone does not require
NIP-07; Enrollment V2 approval is performed by the authenticated Full desktop
under the existing exact contract. Existing Phase 2 bindings and proof-profile
results do not become admitted associations. Every final admission decision
remains denied.
