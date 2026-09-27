# Social preacceptance Ed25519 handoff V2

Status: **dormant deterministic pure contract; no runtime activation**. The
implementation is
`app/services/social_messaging_mobile_pre_enrollment_v2.py`. It adds no model,
migration, route, factory import, feature flag, repository adapter, service
transport, session issuer, or deployment behavior.

This contract freezes only the first-onboarding boundary from one exact
desktop-approved phone proposal through deterministic candidate association-link
bytes. It reuses the existing V1 X25519 authorization semantics and the existing
Enrollment V2 and Ed25519 association bytes without changing them.

The later device-session continuation boundary is **DEFERRED** in its entirety.
Verifier-run identifiers do not yet define a stable retry identity, and
`lockedDeadlineMs` semantics remain unresolved. No continuation challenge,
phone proof, stable identity, issuer evidence, lifetime, or lost-response
behavior is canonicalized here.

## Authority separation

The phone creates two distinct keys before proposal construction:

- X25519 is the existing encryption-only device-binding key.
- Ed25519 is the dedicated Enrollment V2 proof-of-possession key.

Neither state machine implies the other. The desktop participant signs one
private, never-published kind-27236 event containing both the exact unchanged
V1 X25519 authorization string and the exact V2 pre-enrollment string. The
event establishes participant approval of that tuple. The later unchanged
Enrollment V2 phone proof establishes possession of the approved Ed25519 key.

UBID verifies the existing BIP340 participant event. UBID does not perform or
claim Ed25519 cryptographic verification. The exact Ed25519 proof bytes are
preserved for Social's existing strict verifier, and an eventual transaction
owner must separately authenticate Social's purpose-bound result and recheck
all current authorities.

## Canonical encoding

Every new wire is compact, lexically key-sorted printable-ASCII JSON with no
trailing newline. Parsing requires byte-for-byte canonical round trip and a
closed member set. It rejects duplicate, missing, or unknown members;
whitespace variants; alternate escapes or numeric forms; non-ASCII text;
booleans used as integers; integers outside JavaScript's safe nonnegative
range; and malformed, uppercase, or noncanonical hexadecimal values.

New epoch-millisecond values are nonnegative safe integers. Embedded V1
timestamps remain their exact whole-second UTC-Z strings. Embedded V1 content,
the approval event, the existing verification context, Enrollment V2, and the
Enrollment V2 phone proof remain exact canonical JSON strings; the V2 contract
does not normalize or replace their bytes.

All SHA-256 and HMAC inputs below are ASCII unless a raw key is explicitly
named. `NUL` is one byte `0x00`; hexadecimal output is lowercase.

## Pre-enrollment and authorization envelope

The pre-enrollment object contains exactly:

```text
bindingAuthorizationDigest, deviceId, domain, ed25519PublicKey,
expiresAt, issuedAt, pairingId,
preEffectAssociationId, preEffectAssociationState,
preEffectAssociationVersion, preEffectAuthorityEpoch,
profile, proposedAssociationVersion, proposedAuthorityEpoch,
proposedPredecessorAssociationId, requestId, schema, subject,
transitionKind, version, x25519BindingId, x25519BindingVersion,
x25519PublicKeyCommitment
```

Its fixed vocabulary is:

```text
domain  = HODLXXI_SOCIAL_MESSAGING_DEVICE_PRE_ENROLLMENT_V2
schema  = hodlxxi.social_messaging_device_pre_enrollment.v2
version = 2
profile = hodlxxi.social_messaging_device_proof.ed25519_webcrypto.v1
```

Only the reviewed first-onboarding transition is accepted:

```text
X25519 operation                  = register
transitionKind                   = initial
preEffectAssociationState        = absent
preEffectAssociationId           = null
preEffectAssociationVersion      = null
preEffectAuthorityEpoch          = 0
proposedAssociationVersion       = 1
proposedAuthorityEpoch           = 1
proposedPredecessorAssociationId = null
```

Rotate, adopt, revoke, Ed25519 rotate, and Ed25519 re-enrollment combinations
are deferred for later review. `register + initial` is frozen for these exact
bytes. A future transition requires an explicitly reviewed additive method,
schema, and version and MUST NOT reinterpret these bytes.

The pre-enrollment digest is:

```text
"hodlxxi-social-messaging-device-pre-enrollment-v2-sha256:" +
hex(SHA256(
  ASCII("HODLXXI_SOCIAL_MESSAGING_DEVICE_PRE_ENROLLMENT_DIGEST_V2") ||
  NUL || ASCII(preEnrollmentWire)
))
```

The outer envelope contains exactly `content`, `context`, `domain`, `method`,
`preEnrollment`, `schema`, and `version`:

```text
domain  = HODLXXI_SOCIAL_MESSAGING_DEVICE_AUTHORIZATION_METHOD_V2
method  = qr_desktop_pre_enrollment_v2
schema  = hodlxxi.social_messaging_device_authorization_method.v2
version = 2
content = exact unchanged V1 semantic authorization JSON string
preEnrollment = exact V2 pre-enrollment JSON string
authorizationDigest = hex(SHA256(ASCII(outerEnvelopeWire)))
```

The context is the closed object containing exactly `createdAt`,
`desktopContext`, `exchangeCommitment`, `expiresAt`, `pairingId`, and
`secretCommitment`. Its whole-second interval is positive and at most 300
seconds. The V2 commitments are:

```text
secretCommitment = hex(SHA256(
  ASCII("HODLXXI_SOCIAL_PAIRING_SECRET_V2") || NUL || ASCII(secretHex)
))

exchangeCommitment = hex(SHA256(
  ASCII("HODLXXI_SOCIAL_PHONE_EXCHANGE_V2") || NUL || ASCII(verifierHex)
))
```

The pairing-possession proof is:

```text
HMAC-SHA256(
  rawPairingSecret,
  ASCII("HODLXXI_SOCIAL_PAIRING_POSSESSION_V2") || NUL ||
  ASCII(authorizationDigest)
)
```

## Cross-object invariants

The outer parser reuses the existing V1 canonical semantic and binding-record
helpers. It derives, rather than accepts, every cross-object identity:

- pre-enrollment `subject`, `deviceId`, and `requestId` equal the exact
  embedded V1 semantic values;
- `bindingAuthorizationDigest` is SHA-256 of the exact embedded V1 string;
- X25519 binding ID, version, and public-key commitment equal values derived
  from the exact V1 canonical binding record;
- the Ed25519 public key is distinct from both the participant subject and the
  exact X25519 public key;
- pre-enrollment and pairing-context pairing IDs are equal;
- pre-enrollment `issuedAt` is exactly 1,000 times the embedded V1 whole-second
  `issuedAt`;
- the only accepted X25519/Ed25519 action pair is `register + initial`.

Let `T` be the embedded V1 semantic `issuedAt` Unix second. Then
pre-enrollment `issuedAt` is exactly `1000*T`, while NIP-01 `created_at` is
exactly `T`. The pairing offer may precede the phone proposal. The required
nested half-open order is:

```text
context.createdAt <= V1.issuedAt < V1.expiresAt <= context.expiresAt
```

No grace is applied and the exact original bytes remain unchanged.

Pre-enrollment expiry is separate from the shorter pairing/V1 command window:

```text
preEnrollment.issuedAt < preEnrollment.expiresAt
preEnrollment.expiresAt <= preEnrollment.issuedAt + 600000
preEnrollment.expiresAt <= resulting X25519 binding expiry
```

It may outlive the pairing/V1 command window. This pure time helper only checks
the signed intervals supplied in the wire; it does not establish that their
offers, sessions, entitlements, or bindings are live. It requires
`now < preEnrollment.expiresAt` and grants no permission to create a challenge,
activate an enrollment, or persist an association.

## Approval event

The approval event has kind `27236`, `pubkey=subject`,
`created_at=V1.issuedAt`, `content=exact outerEnvelopeWire`, and exactly these
ordered tags:

```text
[purpose, hodlxxi-social-messaging-device-qr-pre-enrollment-approval-v2]
[authorization-digest, authorizationDigest]
[pre-enrollment-digest, preEnrollmentDigest]
[request-id, requestId]
[action, register]
[pairing-id, pairingId]
```

The NIP-01 event-ID input is compact JSON
`[0,pubkey,created_at,27236,tags,content]`. The event ID is SHA-256 of those
exact bytes, and `sig` is the existing 64-byte lowercase BIP340 event-ID
signature. The strict event parser reconstructs every field, checks tag order,
recomputes the ID, and uses the repository's existing public BIP340 verifier.
The private approval event **MUST NOT** be published.

## Acceptance identity and closed wire

The acceptance-ID preimage contains exactly `approvalEventId`,
`authorizationDigest`, `bindingId`, `pairingId`, `preEnrollmentDigest`,
`requestId`, `schema`, `subject`, and `version`:

```text
schema  = hodlxxi.social_mobile_pre_enrollment_acceptance_id_preimage.v2
version = 2

acceptanceId = hex(SHA256(
  ASCII("HODLXXI_SOCIAL_MOBILE_PRE_ENROLLMENT_ACCEPTANCE_ID_V2") || NUL ||
  ASCII(acceptanceIdPreimage)
))
```

The closed acceptance wire contains exactly `acceptanceId`, `approvalEventId`,
`authorizationDigest`, `bindingId`, `deviceId`, `ed25519PublicKey`, `pairingId`,
`preEnrollmentDigest`, `profile`, `requestId`, `schema`, `subject`, `version`,
`x25519BindingVersion`, and `x25519PublicKeyCommitment`:

```text
schema  = hodlxxi.social_mobile_authorization_acceptance.v2
version = 2
```

Every field is derived from the verified event, exact envelope, exact embedded
V1 semantic contract, and exact pre-enrollment tuple. The constructor exposes
no caller-supplied acceptance field. This wire is confidential non-bearer
metadata; persistence and retry ownership are later phases. The serializer is
not acceptance authority.

A future transaction owner MUST lock and revalidate the exact stored live offer
and desktop generation, verify the pairing-secret commitment and possession
HMAC, open the stored original exchange verifier and compare it with
`exchangeCommitment`, and verify the authoritative subject, Current-Full, and
X25519-binding owners. It MUST repeat every relevant check after any wait and
before persistence. Recomputed acceptance bytes alone satisfy none of those
requirements.

## Preaccepted Enrollment V2 verification input

Enrollment V2, its digest, phone-proof signing preimage, phone-proof wire, and
association-creation preimage remain the existing exact contracts. The new
outer verification-input wire contains exactly:

```text
acceptanceId, approvalEvent, context, enrollment, phoneProof, schema, version

schema  = hodlxxi.social_preaccepted_enrollment_verification_input.v2
version = 2
```

The four nested documents are their exact canonical JSON strings. The input
digest is:

```text
"hodlxxi-social-preaccepted-enrollment-verification-input-v2-sha256:" +
hex(SHA256(
  ASCII("HODLXXI_SOCIAL_PREACCEPTED_ENROLLMENT_VERIFICATION_INPUT_V2") ||
  NUL || ASCII(inputWire)
))
```

The parser recomputes the acceptance ID from the approval event, validates the
existing Enrollment V2/context/proof shapes, derives the existing association
ID, and requires exact equality for subject, device, Ed25519 key, profile,
X25519 binding ID/version/commitment, enrollment challenge, association
ID/version, authority epoch, and null predecessor. Public time validation and
candidate-link construction accept only the exact canonical verification-input
wire; exported parsed records and their cached nested values are never trusted.

Enrollment timestamps are newly issued and are not copied from `T`. Their
frozen relationship is:

```text
preEnrollment.issuedAt <= enrollment.issuedAt < enrollment.expiresAt
enrollment.expiresAt - enrollment.issuedAt <= 60000
```

Enrollment expiry is capped mechanically by pre-enrollment and by caller-
supplied phone-session, approver-session, Full, and X25519-binding deadline
integers. Validation uses exclusive deadlines and zero grace. The supplied
X25519 deadline must equal the deadline derived from the signed V1 binding
tuple. These comparisons do not establish that any session, Full entitlement,
subject, or binding is live.

Changing canonical phone-signature bytes changes the verification-input
digest, but UBID does not interpret that fact as Ed25519 validity. Social must
strictly verify the exact phone proof before any later UBID transaction can
consume an authenticated verification result.

## Association creation identity and candidate link

The association ID remains the existing V1 association identity over the exact
unchanged Enrollment V2 wire, association version `1`, and null predecessor.
The new candidate link bytes contain exactly:

```text
acceptanceId, associationId, associationVersion, authorityEpoch,
enrollmentChallengeId, enrollmentDigest, preEnrollmentDigest, schema, version

schema             = hodlxxi.social_pre_enrollment_association_link.v2
version            = 2
associationVersion = 1
authorityEpoch     = 1
```

The link constructor derives every field from the strictly reparsed canonical
verification-input wire and checks only the supplied deadline integers. It
produces candidate bytes; it does not perform or authorize an association
commit. Shape-valid phone-proof bytes, caller-supplied expiry integers, a
recomputed `acceptanceId`, and the candidate link bytes do not prove Ed25519
validity, a committed acceptance root, live sessions, Current-Full, current
binding or association state, or permission to activate or persist an
association.

A future owner MUST authenticate the purpose-bound Social V2 verification
statement and lock/recheck the stored acceptance, enrollment challenge, and
authoritative session, Full, subject, binding, and association owners in the
transaction. This phase adds no caller boolean and invents no substitute
"verified" authority. A future persistence owner must also enforce immutable
unique and foreign-key relationships; this pure module creates no row or
transaction.

## Reviewed public vector

The public fixture is
`tests/fixtures/social_preacceptance_ed25519_handoff_v2.json`:

```text
bytes  = 32998
sha256 = 4f79dd0f24fd8ded4c2e4e3e644811dd42ca620d8c0e09aea177237dd5d199dc
```

It includes the reviewed exact pre-enrollment, outer authorization, NIP-01 ID
input, completed public approval event/signature, pairing-possession proof,
acceptance identity/wire, verification context, complete preaccepted
verification input and digest, unchanged Enrollment V2 proof material,
existing association-creation preimage, and candidate association link. It
contains no private signing material and no values from the deferred later
boundary.

Selected cross-object identities are:

```text
preEnrollmentDigest = hodlxxi-social-messaging-device-pre-enrollment-v2-sha256:56756600d06b1d97b2bbd3e664c62960d6654bafb9bebc2760a255116f954f72
authorizationDigest = c57f9ff5983a6478e53551e9581060f2789212bc2cf6093cce7e418379c08f25
approvalEventId      = 3e43cecf3c2d30d280f7b10a0a2d41d7bd44bc818d8a9d0a4f2513416ddca42c
acceptanceId         = 79527b0846c15188288f97281b9e92e0c783100512d0ea01f1400dfb24a1f16c
enrollmentDigest     = hodlxxi-social-messaging-device-enrollment-v2-sha256:10779b5d1aaef3641655f1c74e621de94355f4c1540d34d7f03a235628a5faa1
associationId        = 9a75b0fbb4ceaa87209355ac50922af779609854b62ae9d59f388b9bfe9c64e6
verificationInputDigest = hodlxxi-social-preaccepted-enrollment-verification-input-v2-sha256:3cbd20bc4061fc8fd074c76bbd70239a102519ac5196417d0c2c20b8a6a02939
```

The fixture and tests also pin the existing V1 mobile authorization, proof
profile, and device-admission fixture hashes. No existing fixture is modified.

## Explicit non-changes

- No model, migration, repository, durable adapter, route, factory, runtime
  entrypoint, configuration, flag, dependency, or deployment is changed.
- No database, Redis, HTTP service, Unix socket, signer provider, or network
  application is contacted by this contract.
- No Enrollment V2, phone-proof, association-creation, or V1 authorization
  bytes are redefined.
- No Ed25519 verifier is added to UBID runtime authority.
- No runtime acceptance, challenge creation, association mutation, session
  issuance, or final admission is implemented.
