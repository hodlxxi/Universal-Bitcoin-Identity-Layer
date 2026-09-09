# Social messaging device binding authorization V1

Status: dormant, source-only security contract. This phase adds no HTTP route,
model, migration, database adapter, configuration, factory wiring, background
task, deployment change, or runtime activation.

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
- `operation`: `register`, `rotate`, or `revoke`;
- canonical `subject`, `deviceId`, `algorithm`, and X25519 `publicKey`;
- integer `bindingVersion`;
- whole-second UTC `bindingValidFrom` and `bindingExpiresAt`;
- canonical `priorBindingId`, or null only for register;
- canonical globally replay-protected `requestId`;
- whole-second UTC request `issuedAt` and `expiresAt`.

The signed object adds its lowercase SHA-256 `digest`, exact
`signatureFormat`, and lowercase 64-byte Schnorr `signature`. The digest is
also the server-derived binding identifier for the exact lifecycle edge. It
therefore commits the identity, logical device, canonical encryption key,
operation, lifecycle version, predecessor, request identifier, binding
interval, and request interval. A client cannot select or substitute the
binding identifier.

Input is canonical JSON text, not a decoded mapping. Duplicate names, unknown
or missing members, whitespace variants, non-ASCII text, alternate key or
identifier encodings, fractional timestamps, booleans used as integers, and
noncanonical serialization fail before authorization. X25519 validation uses
UBID's centralized validator, including low-order, high-bit-alias, and field
range rejection. Neither an identity private key nor an X25519 private key is
an input or output.

The request authorization window is at most 300 seconds and must contain the
trusted whole-second server time. The separately signed binding interval must
also contain server time. Active register and rotate claims require
`bindingValidFrom` to equal `issuedAt`, so neither a binding nor its routing
evidence can appear valid before the identity signature existed. Revoke is an
inactive audit edge and instead repeats the predecessor's exact key and
binding interval. The request deadline limits lifecycle-command use; it does
not erase accepted signature evidence. Routing evidence starts at the signed
`issuedAt` and may remain useful after the short command window, but its expiry
is bounded by the signed binding expiry.

## Lifecycle state

The coordinator consumes immutable, injected, complete current-state views.
Exact device, public-key, and binding-ID views are requested with a `maximum`
of two so the provider can expose ambiguity rather than truncate. The complete
subject-wide active-binding view is requested with `MAX_ACTIVE_DEVICES + 1`
(17), so overflow is exposed rather than silently truncated. Every view must
have the exact schema, version, lookup identity, immutable tuple type,
`complete=True`, and `truncated=False`. Every returned active record must be
an exact identity-signed current register or rotate result. Mappings, lists,
untyped OAuth records, expired or inactive records, malformed records, and
provider-selected partial output fail. Subject-wide device IDs, binding IDs,
and public keys must each be unique; ordering conveys no authority.

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
  its exact key and original binding interval as audit evidence, and produces
  an inactive result. Missing, incomplete, truncated, overflowed, inactive,
  expired, different, superseded, duplicate, or ambiguous state fails closed.

The returned value is immutable and contains the exact signed authorization,
the exact `MessagingDeviceBinding` lifecycle result, and the strict
`VerifiedBindingAuthorization` required by the already-merged recipient
routing gate. Revoke results are inactive and cannot pass that routing gate.

## Replay and atomicity port

An injected request-ID ledger is consulted after signature and time
validation. An exact request ID, digest, and immutable result retry returns the
same result without reinterpreting already-changed lifecycle state. Reuse of a
request ID with any changed signed content fails. The future ledger's
`record` operation must atomically insert-or-compare and must reject duplicate
rows or a conflicting digest/result. This module does not implement that
persistence.

Actual application of a lifecycle result and durable replay retention will
require one future atomic repository transaction. This source-only verifier
does not claim that separate non-atomic adapters are safe for runtime use.

## Recipient-handle and routing boundary

The existing recipient device handle remains byte-for-byte unchanged. It is a
viewer-pairwise HMAC over the exact binding ID, viewer, recipient, alias
version, and server alias secret, as specified by
`SOCIAL_MESSAGING_RECIPIENT_ROUTING_V1.md`. It cannot be supplied or computed
authoritatively by a participant because the viewer context and server secret
are intentionally absent at binding authorization time. Since the binding ID
is the signed-claim digest and commits the canonical X25519 key, key
substitution changes both the binding ID and every later derived handle. The
routing gate recomputes the handle and requires exact package agreement.

The provided `IdentitySignedBindingAuthorizationVerifier` implements the
routing gate's existing verifier port. It obtains one complete evidence record
by exact binding ID, re-verifies its identity signature, reconstructs the
binding and routing proof, and requires exact equality with the current active
binding. It does not alter the routing gate's separate, repeated current-Full
checks for viewer and recipient.

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
