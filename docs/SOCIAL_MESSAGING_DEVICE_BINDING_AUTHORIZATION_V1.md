# Social messaging device binding authorization V1

Status: disabled-by-default runtime/factory/internal-HTTP wiring in source,
together with the security and PostgreSQL storage contracts. The application
factory composes the runtime and registers the internal Social routes only
behind a dedicated default-off flag. Source presence, runtime activation,
migration application, and deployment are separate phases. This change does
not itself activate the flag or perform a deployment, and this document does
not infer environment migration, restart, or deployment history from source.

## Deterministic Nostr signature carrier

The signing identity is UBID's canonical lowercase 32-byte x-only secp256k1
participant public key. It must equal the independently authenticated
participant. OAuth or session possession supplies that authenticated context;
it is not binding authorization.

V1 uses signature format `nostr_event_id_bip340_v1`. The existing semantic
claim, canonical semantic bytes, and SHA-256 semantic digest below remain
authoritative and byte-for-byte unchanged:

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

The participant does not sign that semantic digest directly. UBID reconstructs
a purpose-specific NIP-01 event with `kind` 27236, the authenticated canonical
subject as `pubkey`, the exact Unix second of `issuedAt` as `created_at`, the
semantic bytes decoded as ASCII as `content`, and exactly these ordered tags:

```json
[
  ["purpose", "hodlxxi-social-messaging-device-binding-authorization-v1"],
  ["semantic-digest", "<semantic digest>"],
  ["request-id", "<requestId>"],
  ["action", "<register|rotate|revoke|adopt>"]
]
```

The exact event serialization is compact UTF-8 JSON for
`[0,pubkey,created_at,27236,tags,content]`. Its lowercase SHA-256 is the event
ID, and the 64-byte BIP340 signature is over that raw 32-byte ID. UBID trusts
no caller-supplied event field or ID. It reconstructs every component, requires
the semantic-digest tag/final digest/SHA-256 of content to agree, and rejects
direct semantic-digest signatures and every altered kind, time, tag, content,
subject, ID, or signature.

Kind 27236 is a repository-local application assignment in Nostr's ephemeral
range. It is not an official NIP allocation. This private carrier is never
published to a relay, and relay publication is neither evidence nor required.

The submitted signed object keeps its existing closed flattened shape. Only
`signatureFormat` changes to `nostr_event_id_bip340_v1`, and `signature` is the
returned lowercase 64-byte event-ID signature. The unchanged semantic digest
continues to identify evidence. It is never a binding ID, predecessor ID,
expected binding ID, device-handle input, package identity, routing identity,
or replacement for any of those values.

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
Its carrier event ID is
`4fb89f90de1379e47893ad335c4839805be4265767d1972b7281aea2ef2e0ad0`,
and its zero-auxiliary-randomness Schnorr signature vector is
`6fb5dcbb6791eaf44bb2fa9282a1db21c702e88db58ab388d974baae4b082ff69cfbfe4eb62fe36a8040fb9de010a1e6a9a2b6232332fac21d2d7a2a7e689570`.
The authorization contract remains behind the default-off runtime flag. The
additive storage migration does not change the external payload. Binding
storage, handle, package, routing, and resolver vectors are unchanged.

Input is canonical JSON text, not a decoded mapping. Duplicate names, unknown
or missing members, whitespace variants, non-ASCII text, alternate key or
identifier encodings, fractional timestamps, booleans used as integers, and
noncanonical serialization fail before authorization. X25519 validation uses
UBID's centralized validator, including low-order, high-bit-alias, and field
range rejection. Neither an identity private key nor an X25519 private key is
an input or output.

The semantic request authorization window is at most 300 seconds and must contain the
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

## Trusted authorization intent

The browser cannot author the semantic claim. It submits one compact,
canonical, closed proposal. Lifecycle proposals contain exactly `operation`,
`deviceId`, `publicKey`, `requestId`, and `expectedBindingId`; revoke requires a
null public key, register requires a null expected binding, and rotate/revoke
use the expected binding only as a checked concurrency hint. Adoption proposals
contain exactly `operation=adopt`, `requestId`, and the selected `bindingId` for
authoritative lookup. A caller-supplied subject, clock, interval, version,
predecessor, derived binding ID, state snapshot, or Current-Full proof is an
unknown field and fails.

UBID derives subject from the viewer bearer and derives or validates operation
eligibility, binding version, predecessor, revoke key, binding interval,
adoption record, binding ID, whole-second timestamps, semantic bytes/digest,
the unsigned carrier, complete binding state, and Current-Full from trusted
transaction-bound inputs. Intent creation performs no write, reserves no
request ID, persists no token, and rolls its read transaction back. It returns
one closed canonical object with schema
`hodlxxi.social_messaging_device_binding_authorization_intent.v1`, version 1,
`claimType`, the exact `claim`, `digest`, `signatureFormat`, `expectedPubkey`,
an `unsignedEvent` without `pubkey`, `id`, or `sig`, and `intentToken`.

The intent token uses the already-loaded runtime signing key only in this
strictly separate RS256 domain:

```text
typ=hodlxxi-device-binding-intent+jwt
tokenUse=device_binding_authorization_intent
purpose=social_messaging_device_binding_authorization_intent_v1
aud=urn:hodlxxi:ubid:social-messaging-device-binding-authorization-submit:v1
```

Its closed claims bind exact issuer, subject, `iat`, `exp`, `jti=requestId`,
claim type, action, semantic digest, reconstructed event ID, and signature
format. The intent-token deadline equals the exact semantic claim deadline,
which is at most 300 seconds after `issuedAt`; an earlier binding or claim
expiry remains the deadline and the token never extends it. Verification
selects the exact configured RSA key ID, permits
only RS256 and the protected intent type, validates the closed claim set, and
does not reuse the access-token parser. The token contains no secret, is never
logged, is not participant authorization or Current-Full proof, and is not
persisted as authorization evidence.

Final submission transports the token separately in the bounded
`X-HODLXXI-Device-Binding-Intent` header. The request body remains only the
existing canonical flattened participant payload, so storage persists no
transport wrapper or intent token. UBID authenticates the confidential Social
service, authenticates the viewer, validates exact seal/payload/carrier
correspondence before opening storage, and validates the seal again against the
post-lock trusted clock inside the caller-owned write transaction. Replay,
complete authoritative state, Current-Full, timestamps, lifecycle rules,
binding/evidence mutation, and replay retention remain in that same atomic
transaction. Every failure rolls back. An earlier intent never outranks the
final transactional state; stale or expired intents fail generically.

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

Adoption is a separate identity-signed authorization action. It is not a
fourth persisted binding operation and cannot insert, update, retire, replace,
rotate, reuse, or revoke a key or binding row. The PostgreSQL adapter inserts
only authorization evidence and replay retention for adoption; when the
default-off runtime is activated, adoption uses the same transaction-bound
internal composition as lifecycle authorization.

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
Its expected canonical semantic bytes are hard-coded independently of the
production serializer in the unit test. The canonical byte length is `958`,
the unchanged SHA-256 adoption digest is
`c96902ddb67f6d63c1579e81100f267be27f5f0cd12727b521c76c66d8f25c36`,
its carrier event ID is
`68bb9d6a6dc3a13630a47e27350be22859be407a0c2ff903a6820ab214d50955`.
The zero-auxiliary-randomness carrier signature is
`70e3bc1a5609d946e607c8a63506ac3770889ae01b0c60721e88fa1228ba047f1911f4a3a64aac0d60687df2a183cff1e33e7e64a6233a6708df4e16f9a6022f`.
The test hashes the independent semantic bytes, checks the production
serializer and digest, reconstructs the carrier bytes and event ID, reproduces
the zero-aux signature, and verifies it with the corresponding x-only key.

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
private key. Any activating browser-device flow must obtain that key from an
already proven setup or add an explicit possession challenge.

All public failures from this contract use only:

```text
social messaging device binding authorization unavailable
```

No signature, raw key, dependency detail, exception detail, or secret is
logged or reflected.

## Disabled internal runtime composition

The disabled-by-default runtime/factory/internal-HTTP boundary is registered
only when
`SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_INTERNAL_ENABLED` is exactly
enabled. It does not inherit or reuse the legacy
`SOCIAL_MESSAGING_DEVICE_INTERNAL_ENABLED` gate. When disabled, neither the
runtime extension nor any dedicated route exists. Explicit enablement requires the
complete dedicated confidential-client, issuer, token/resource audience,
viewer OAuth client, client JWKS directory, signing JWKS directory, and clock
skew configuration. Register intent uses the existing bounded device-binding
lifetime setting when present and the source contract's 30-day default otherwise.
Missing, malformed, symlinked, overlapping, or incomplete
trust material fails application construction. The builder reads existing key
material only; it creates no key, row, transaction, background task, or
migration.

The private routes are:

- `POST /internal/v1/social/messaging/device-binding-authorization-service-token`
  for the existing strict `private_key_jwt` client-credentials exchange and
  durable assertion replay consumption;
- `POST /internal/v1/social/messaging/device-binding-authorization-intents` for
  authoritative read-only claim derivation and the short-lived sealed intent;
- `POST /internal/v1/social/messaging/device-binding-authorizations` for one
  exact register, rotate, revoke, or adoption authorization, with the intent
  token supplied separately in `X-HODLXXI-Device-Binding-Intent`.

The service-token route rejects query parameters and requires a declared,
positive `Content-Length` no greater than 24 KiB before form parsing. That
finite envelope accommodates the credential layer's unchanged 16-KiB maximum
client assertion plus the four other URL-encoded fields. The parsed form must
then contain exactly one value for each of the five named fields; missing,
unknown, or duplicate fields fail with the same non-sensitive request error.

The resource token has the dedicated scope
`social:messaging-device-binding-authorization:manage` and purpose
`social_messaging_device_binding_authorization_manage`; a token from the
legacy messaging-device or recipient domains cannot cross this boundary. The
operation route also validates the established
`X-HODLXXI-Viewer-Authorization` canonical OAuth bearer and derives the
participant subject from that exact typed result. The viewer bearer supplies
only independently authenticated subject context. It is never accepted as
binding authorization or as Current-Full evidence.

When this successor runtime is enabled, the legacy OAuth-only mutating
`POST /internal/v1/social/messaging/device-bindings` fails closed before
credential or payload processing. The legacy read-only binding snapshot route
remains available. With the successor runtime disabled, legacy behavior is
unchanged.

The route accepts only a bounded printable-ASCII canonical JSON body. It
passes that exact text to the existing signed lifecycle or adoption parser;
decoded mappings, duplicate fields, alternate serialization, and caller Full
proofs are not accepted. After service and viewer authentication, the runtime
creates one session, begins one transaction, and supplies that same active
session to
`SqlAlchemySocialMessagingDeviceBindingAuthorizationStorage`. The storage unit
of work constructs `SqlAlchemyTransactionBoundCurrentFullVerifier` from that
same session. The runtime caller alone commits, rolls back, and closes. It
constructs and validates the response bytes before commit, so replay reads,
locked Current-Full verification, binding/adoption and evidence mutation,
replay retention, and the returned result are one coherent transaction.

Success uses canonical compact sorted-key ASCII JSON with schema
`hodlxxi.social_messaging_device_binding_authorization_result.v1` and version
`1`. It returns only the action, authorization request ID, canonical binding
ID, device ID, binding operation/version and active state, binding interval,
and authorization proof/interval. It does not return the participant subject,
raw X25519 key, identity signature, signed request, Current-Full proof, or
storage detail. Exact retries reconstruct the same verified typed result and
therefore the same response bytes. Every signed-authorization, replay,
Current-Full, state, storage, transaction, or serialization failure maps to
the single non-sensitive internal API error
`device_binding_authorization_unavailable`.
