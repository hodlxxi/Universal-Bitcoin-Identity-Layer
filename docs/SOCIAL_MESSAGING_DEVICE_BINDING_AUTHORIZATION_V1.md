# Social messaging device binding authorization V1

Status: dormant, source-only security and PostgreSQL storage contract. This
phase adds ORM storage models, one additive migration, and a transaction-bound
adapter. It adds no HTTP route, configuration, factory wiring, background task,
applied migration, deployment change, or runtime activation.

## Identity-signature convention

The signing identity is UBID's canonical lowercase 32-byte x-only secp256k1
participant public key. It must equal the independently authenticated
participant. OAuth or session possession supplies that authenticated context;
it is not binding authorization.

V1 reuses UBID's established identity signature convention without adding a
cryptographic dependency: `bip340_schnorr_sha256`. The participant signs the
32-byte SHA-256 digest of compact, key-sorted ASCII JSON:

```text
{"authorization":<claim>,"domain":"HODLXXI_SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_V1"}
```

The closed claim contains exactly:

- `schema`: `hodlxxi.social_messaging_device_binding_authorization.v1`;
- integer `version`: `1`;
- `bindingRecordSchema`:
  `hodlxxi.social_messaging_device_binding_record.v1`;
- integer `bindingRecordVersion`: `1`;
- `operation`: `register`, `rotate`, or `revoke`;
- canonical `subject`, `deviceId`, `algorithm`, and X25519 `publicKey`;
- integer `bindingVersion`;
- whole-second UTC `bindingValidFrom` and `bindingExpiresAt`;
- canonical `priorBindingId`, or null only for register;
- canonical globally replay-protected `requestId`;
- whole-second UTC request `issuedAt` and `expiresAt`.

The signed object adds its lowercase SHA-256 `digest`, exact
`signatureFormat`, and lowercase 64-byte Schnorr `signature`. This
authorization digest is signature and evidence identity only. It is never a
binding ID, predecessor ID, expected binding ID, device-handle input, package
identity, routing identity, or replacement for any of those values.

The sole authoritative `bindingId` is SHA-256 of the existing canonical
binding-record bytes. Those bytes are compact, key-sorted ASCII JSON with
schema `hodlxxi.social_messaging_device_binding_record.v1`, integer version
`1`, and exactly `subject`, `deviceId`, `algorithm`, `publicKey`,
`bindingVersion`, `validFrom`, `expiresAt`, `operation`, `priorBindingId`, and
`requestId`. The shared pure canonicalizer preserves the legacy storage
timestamp normalization and preimage byte for byte. Register, rotate, and
revoke authorization results compute only this identity. A client cannot
select or substitute it.

The corrected fixed register binding vector is
`6d64122a05d41e5823f2e9ff95bbc220035cfae53f0364410851f86d2b62a56d`.
The corrected authorization fixture was deliberately aligned with that frozen
storage vector by using its matching canonical subject and exact
storage-derived interval. Those fixture corrections, together with the
explicit binding-record schema/version commitments and separation of binding
and authorization digests, determine the new signed bytes; adding only the
schema/version fields did not cause every changed byte. The authorization
digest is now
`70aa19a24077c3365a836f0476660f0132ab7959615d2c8c67ba75afd9071d9c`.
Its deterministic offline Schnorr signature vector is now
`afedbfdd98495e098195a1716c3241fe490fad95f127cbda9a292cccabb644dae5b91c3fe13c3e11df70445071afb92b53b486a984b74f6c7f8c3893f3e12bf7`.
The authorization contract remains dormant. No external authorization payload
or deployed persisted authorization evidence exists. The additive storage
migration does not change the external payload. Binding storage, handle,
package, routing, and resolver vectors are unchanged.

Input is canonical JSON text, not a decoded mapping. Duplicate names, unknown
or missing members, whitespace variants, non-ASCII text, alternate key or
identifier encodings, fractional timestamps, booleans used as integers, and
noncanonical serialization fail before authorization. X25519 validation uses
UBID's centralized validator, including low-order, high-bit-alias, and field
range rejection. Neither an identity private key nor an X25519 private key is
an input or output.

The request authorization window is at most 300 seconds and must contain the
trusted whole-second server time. The separately signed binding interval must
also contain server time. Every lifecycle claim requires exact whole-second
`bindingValidFrom` equal to `issuedAt`. Register and rotate sign their exact
new interval. Revoke signs the predecessor's exact key and expiry while using
the new revoke record's exact whole-second `validFrom`, matching the storage
record rather than copying the predecessor's creation time. The request
deadline limits lifecycle-command use; it does not erase accepted signature
evidence. Routing evidence starts at the signed `issuedAt` and may remain
useful after the short command window, but its expiry is bounded by the signed
binding expiry.

## Lifecycle state

The coordinator consumes immutable, injected, complete current-state views.
Exact device, public-key, and binding-ID views are requested with a `maximum`
of two so the provider can expose ambiguity rather than truncate. The complete
subject-wide active-binding view is requested with `MAX_ACTIVE_DEVICES + 1`
(17), so overflow is exposed rather than silently truncated. Every view must
have the exact schema, version, lookup identity, immutable tuple type,
`complete=True`, and `truncated=False`. Every returned active record must be
an exact identity-signed current lifecycle or adopted result. Mappings, lists,
untyped OAuth records, expired or inactive records, malformed records, and
provider-selected partial output fail. Subject-wide device IDs, binding IDs,
and public keys must each be unique; ordering conveys no authority. The
device, subject, and public-key current-state views accept evidence only while
its normalized interval contains trusted server time:
`evidenceValidFrom <= now < evidenceExpiresAt`. The binding-ID view is a
historical uniqueness lookup and deliberately does not apply this current
evidence-window restriction.

- Register requires version 1, no predecessor, subject capacity below the
  authoritative 16-active-device cap, no current active subject/device, and no
  active owner of the exact proposed public key.
- Rotate requires exactly one current identity-signed active device record,
  that exact predecessor exactly once in the complete subject set, and that
  same sole record in the predecessor public-key index. It names the exact
  predecessor binding ID, uses its exact next version, supplies a different
  X25519 key with no active owner, cannot backdate validity, and cannot extend
  expiry beyond its predecessor.
- Revoke requires the same exact device, subject-set, and predecessor-key
  agreement, names the exact predecessor binding ID and next version, repeats
  its exact key and expiry with the new record timestamp as audit evidence,
  and produces an inactive result. Missing, incomplete, truncated, overflowed,
  inactive, expired, different, superseded, duplicate, or ambiguous state
  fails closed.

The returned value is immutable and contains the exact signed authorization,
the exact `MessagingDeviceBinding` lifecycle result, and the strict
`VerifiedBindingAuthorization` required by the already-merged recipient
routing gate. Revoke results are inactive and cannot pass that routing gate.

## Legacy binding adoption

Adoption is a separate, source-only identity-signed authorization action. It
is not a fourth persisted binding operation and cannot insert, update, retire,
replace, rotate, reuse, or revoke a key or binding row. The dormant PostgreSQL
adapter inserts only authorization evidence and replay retention for adoption;
there is no runtime composition in this phase.

The closed adoption claim uses schema
`hodlxxi.social_messaging_device_binding_adoption.v1`, integer version `1`,
action `adopt`, a canonical lowercase 64-hex adoption `requestId`, the exact
existing `bindingId`, the complete canonical binding record as
`bindingRecord`, and whole-second `issuedAt` and `expiresAt`. The adoption
request ID is a new authorization-action identity. It must differ from the
embedded binding record's historical OAuth-only register/rotate `requestId`
and cannot reuse that value. Its separate signature domain is
`HODLXXI_SOCIAL_MESSAGING_DEVICE_BINDING_ADOPTION_V1`. The binding record is
re-canonicalized and its SHA-256 must equal the claimed and stored binding ID.
The authenticated canonical subject and BIP340 signer must both equal the
record subject. The X25519 encryption public key must differ from that
secp256k1 identity subject, matching lifecycle authorization and recipient
routing.

The independent frozen adoption fixture embeds the corrected register binding
vector above, uses the participant x-only public key derived from BIP340 test
secret scalar `3`, and uses 32 zero auxiliary bytes for deterministic signing.
Its expected canonical signed bytes are hard-coded independently of the
production serializer in the unit test. The canonical byte length is `958`,
the SHA-256 adoption digest is
`c96902ddb67f6d63c1579e81100f267be27f5f0cd12727b521c76c66d8f25c36`,
and the deterministic BIP340 signature is
`06b5a3e0ae6fb0b14047b3a0ec34640e4993730660540deedbaae73b6c9fba65fbf7ddbba40e555c2148654a18a841faf403f4285acb00e0abfb3cb8fa313421`.
The test hashes those independent bytes, checks the production serializer and
digest against them, reproduces the zero-aux signature, and verifies it with
the corresponding x-only public key.

The adoption coordinator consumes only injected immutable ports. A strict
transaction-bound current-Full prerequisite must expose
`verify_in_transaction(subject, now=...)` and return the canonical typed
producer result. A detached prerequisite exposing only `verify(...)` is rejected
at construction and cannot satisfy the future atomic storage path. A complete,
untruncated exact-binding lookup with a maximum of two must contain exactly
one structurally valid, active, unexpired matching record. A separate
complete evidence lookup must contain no existing authorization. Missing,
inactive, expired, revoked, ambiguous, malformed, already-attested,
subject-mismatched, key-mismatched, or binding-ID-mismatched state fails
closed. OAuth possession without the identity signature cannot create
evidence.

Successful adoption returns authorization evidence for the unchanged binding.
Evidence validity starts at the signed attestation `issuedAt`, never at the
older binding `validFrom`, and ends at the binding expiry. The verifier rejects
use before attestation, and the routing contract also requires evidence
validity to cover the package or snapshot issue time. Consequently packages
and snapshots predating adoption remain unroutable.

## Replay and atomicity port

Lifecycle authorization and adoption consume one injected, logically global
request-ID namespace. The ledger may return either exact frozen replay-record
type: a lifecycle record contains its request ID, authorization digest, and
exact `AuthorizedDeviceBinding`; an adoption record contains its distinct
adoption request ID, adoption digest, and exact
`AdoptedDeviceBindingAuthorization`. Each coordinator rejects the other
record type, so reuse between lifecycle and adoption fails closed.

The ledger is consulted only after canonical parsing, identity-signature
verification, and request-window validation. An exact request ID, digest, and
immutable result retry returns the same result without reinterpreting
already-changed state. Reuse with changed signed content, a changed result,
the wrong record type, duplicate or ambiguous lookup results, provider
exceptions, or any malformed response fails closed. For a new adoption,
retention occurs only after current Full, the exact current legacy binding,
and absence of existing authorization evidence have all been established.

The authorization-storage unit of work constructs the Current-Full verifier,
replay ledger, legacy-binding reader, authorization-evidence reader, and
mutation writer over the same caller-owned active PostgreSQL session and
transaction. It requires PostgreSQL `READ COMMITTED` and refuses other
dialects, inactive transactions, or other isolation levels. None of its
adapters begins, commits, rolls back, closes, or replaces the session. The
caller completes the transaction with one commit or one complete rollback.

Before any replay or state snapshot, the unit of work takes the following
operation locks in global order. Each advisory lock is transaction-level:

1. global authorization/adoption request ID;
2. canonical subject in the exact Current-Full subject-lock domain;
3. exact canonical subject `User` row with `FOR UPDATE`;
4. subject-qualified device ID;
5. the global public-key namespace guard;
6. all public keys named by the signed request, sorted canonically.

Only canonical parsing and identity-signature verification needed to obtain
those trusted lock identifiers occurs before this sequence. The exact `User`
row lock reuses the device-storage primitive in the same caller-owned session
and transaction. The trusted clock is sampled exactly once, only after every
lock in this operation-lock sequence has returned. That single whole-second
UTC value is used for replay validation, Current-Full verification,
coordinator validation, binding mutation, evidence creation, and replay
persistence. Request, binding, adoption, and Current-Full expiry are therefore
re-evaluated after waits at this operation-lock boundary; PostgreSQL
transaction time is not used because it may precede those waits.

The public-key namespace guard covers rotate's predecessor key before that key
can be learned from durable state. The earlier exact `User` row lock conflicts
with a legacy binding writer even though that writer does not participate in
the Current-Full subject advisory-lock domain. The existing transaction-bound
Current-Full verifier then re-enters the same subject and `User` locks before
locking its evidence rows. Binding/evidence reads and lifecycle mutation
follow. Database primary, unique, foreign-key, historical-key, and
partial-active indexes remain the final collision authority.

The additive migration creates one immutable evidence row per binding and one
immutable globally unique replay row per request ID. A deferred composite
foreign key binds replay type, action, digest, request, and result identity to
the authoritative evidence row; another deferred composite foreign key binds
the evidence's complete binding identity to the binding row. Lifecycle and
adoption reconstruct and revalidate the exact signed payload on every read.
An exact retry returns only the same typed digest, binding/result identity, and
public result. A conflicting type, content, digest, result, malformed row, or
constraint failure fails closed. Evidence, replay, and binding mutation are
flushed in the caller transaction and therefore commit or roll back together.

The Current-Full proof ID remains the canonical content identity defined in
`CURRENT_ENTITLEMENT_EVIDENCE_V1.md`, not a caller assertion or independently
authoritative credential. Separate non-atomic runtime adapters are not safe.

## Recipient-handle and routing boundary

The existing recipient device handle remains byte-for-byte unchanged. It is a
viewer-pairwise HMAC over the exact binding ID, viewer, recipient, alias
version, and server alias secret, as specified by
`SOCIAL_MESSAGING_RECIPIENT_ROUTING_V1.md`. It cannot be supplied or computed
authoritatively by a participant because the viewer context and server secret
are intentionally absent at binding authorization time. Since the binding ID
is the canonical binding-record digest and commits the canonical X25519 key,
key substitution changes both the binding ID and every later derived handle.
Authorization or adoption proof identity remains separate. The routing gate
recomputes the handle from the binding ID and requires exact package
agreement.

The provided `IdentitySignedBindingAuthorizationVerifier` implements the
routing gate's existing verifier port. It obtains one complete evidence record
by exact binding ID, re-verifies its identity signature, reconstructs either
lifecycle or adoption evidence, and requires exact equality with the current
active binding. It does not alter the routing gate's separate, repeated
current-Full checks for viewer and recipient. Routing accepts the real canonical
producer output byte-for-byte while retaining its independent subject and
validity bounds.

Raw X25519 public keys exist only in the signed authorization, lifecycle
binding, strict verification comparison, and already-defined outward
recipient package. They are not added to routing snapshots or decisions.
Identity authorization proves that the participant approved the named public
key; it does not prove that the browser controls the corresponding X25519
private key. A future runtime adapter must obtain that key from an already
proven browser-device setup or add an explicit possession challenge.

All public failures from this contract use only:

```text
social messaging device binding authorization unavailable
```

No signature, raw key, dependency detail, exception detail, or secret is
logged or reflected.
