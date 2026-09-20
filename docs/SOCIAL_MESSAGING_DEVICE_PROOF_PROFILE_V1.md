# Social Exact Messaging Device Proof Profile V1 and Enrollment V2

Status: **implemented as dormant pure canonical contracts; no runtime
activation**. This source adds no route, factory import, configuration gate,
challenge store, association store, migration, Redis/PostgreSQL adapter or
final admission. Existing Phase 2 and Phase 3 bytes are unchanged.

## Authority and key roles

The frozen profile identifier is exactly:

```text
hodlxxi.social_messaging_device_proof.ed25519_webcrypto.v1
```

The dedicated Ed25519 key is proof-of-possession/authentication only. X25519
remains encryption-only. Neither is derived from, aliased to or substituted for
the other. Ed25519 is not participant/Nostr identity, a Bitcoin/wallet/funds or
covenant key, or a general-purpose signing key. The phone does not require
NIP-07. Existing devices must explicitly re-enroll or re-pair through Enrollment
V2; OAuth, QR possession and historical Phase 2 acceptance cannot attach a key.

The current strict Ed25519 primitive implementation is in Social. It uses
pinned `@noble/ed25519` 2.3.0 with ZIP-215 disabled, strict canonical point
decoding/re-encoding for public A and signature R, identity/small-order/torsion
rejection, `isTorsionFree`, canonical S bounds and an independent adversarial
corpus. Native WebCrypto/OpenSSL Ed25519 verification is not that primitive.

UBID's `app/services/social_messaging_device_proof_profile.py` only validates
and reconstructs the shared canonical shape. Its result is explicitly
`not_evaluated_by_ubid` for Ed25519 and always `denied` for final admission.
This avoids duplicated cryptographic authority.

It does not establish final authority. The architecture audit result is:

```text
FINAL_AUTHORITY_MODEL=ATOMIC_OWNER_PENDING
ATOMIC_CHALLENGE_OWNER=PENDING
FINAL_ADMISSION_OWNER=PENDING
```

UBID already owns or specifies accepted X25519 binding evidence, mobile
authorization and replay state, canonical session state and transaction-bound
Current-Full evidence. The reviewed documents do not yet assign one component
to combine those state owners with this exact Ed25519 proof, immutable challenge
storage and atomic consumption. The future Ed25519 key-association,
rotation/revocation and challenge owners are also pending; existing UBID state
does not silently select them.

Runtime activation is explicitly blocked until one atomic authority either:

1. verifies the exact proof and consumes the exact immutable challenge in the
   same authoritative transaction as every current session, Current-Full,
   accepted-binding, Ed25519 association, expiry, rotation/revocation and
   operation recheck; or
2. consumes a separately reviewed, cryptographically authenticated Social
   attestation with frozen exact bytes, audience, expiry, replay binding,
   transaction binding and failure semantics.

This correction does not design or implement option 2. A boolean, string,
historical result or ordinary service assertion such as `valid=true` is never
cryptographic proof or final-admission authority.

## Encoding and closed parsing

All wires below are compact lexically key-sorted printable-ASCII JSON with no
trailing newline. Parsers reject missing, unknown or duplicate members,
alternate escapes or numeric forms, coercion and noncanonical serialization.
The Ed25519 public key is exactly 32 raw bytes represented by exactly 64
lowercase hexadecimal ASCII characters. The signature is exactly 64 raw bytes
represented by exactly 128 lowercase hexadecimal ASCII characters. There is no
`0x` prefix, uppercase, base64, padding or whitespace form.

The proof wire contains exactly:

```text
algorithm = Ed25519
challengeId = lowercase hex64
profile = hodlxxi.social_messaging_device_proof.ed25519_webcrypto.v1
publicKey = lowercase hex64
schema = hodlxxi.social_messaging_device_proof.v1
signature = lowercase hex128
version = integer 1
```

The signing preimage is the ASCII encoding of compact sorted JSON containing
exactly:

```text
challenge = exact immutable server-stored challenge STRING
domain = HODLXXI_SOCIAL_MESSAGING_DEVICE_PROOF_ED25519_WEBCRYPTO_V1
profile = hodlxxi.social_messaging_device_proof.ed25519_webcrypto.v1
publicKey = exact approved Ed25519 public key
schema = hodlxxi.social_messaging_device_proof_preimage.v1
version = integer 1
```

The stored challenge is the existing frozen Social V1 challenge wire. Its exact
embedded request binds schema/version, operation, subject, authenticated
session generation, accepted mobile/X25519 binding ID and version, exact device
ID, method, path, canonical request-body digest, recipient handle where
applicable, challenge ID, issued-at, expires-at and exact audience. The lifetime
is at most 60,000 ms, with `issuedAt <= now < expiresAt` and no grace. Proof JSON
cannot replace the stored challenge bytes.

Successful Social pure verification reports these independent states:

```text
canonical structure = valid
strict Ed25519 cryptography = valid
current device/key association = not_evaluated
atomic challenge consumption = not_implemented
final admission = denied
```

UBID can establish only canonical structure. A boolean signature result, a
matching public key, an OAuth session or historical authorization is never final
admission.

## Frozen canonical audience grammar

Request/challenge and Enrollment V2 audiences use the same grammar, identified
by `hodlxxi.canonical_https_origin.ascii_ldh_no_idn.v1` in the byte-identical
shared proof fixture's `audienceCorpus`. An audience is 1..255 ASCII bytes,
exactly `https://HOST` or `https://HOST:PORT`. Validation never normalizes input.

- DNS hosts are dot-separated labels of 1..63 lowercase ASCII letters, digits
  or hyphens; each label starts and ends with a letter or digit. Empty labels,
  trailing dots and underscores are forbidden. A final label consisting only
  of digits, or matching `0x[0-9a-f]*`, is forbidden unless the whole host is a
  canonical IPv4 address. This excludes alternative numeric URL-host forms.
  This narrow V1 grammar excludes IDNs, including every `xn--` label; it does
  not perform IDNA or punycode conversion.
- IPv4 is exactly four decimal octets in 0..255, with no leading zeros except
  the octet `0`. Abbreviated, integer, hexadecimal and octal forms are forbidden.
- IPv6 is bracketed, lowercase hexadecimal: no leading group zeros, and the
  longest run of at least two zero groups is compressed with `::`, choosing
  the first run on ties. A single zero group is never compressed. Zone IDs
  and dotted IPv4 tails are forbidden; mapped addresses use canonical hex.
- An optional port is decimal 1..65535, without leading zeros; explicit `443`
  is forbidden. No credentials, path, query, fragment, trailing slash,
  whitespace, percent encoding or Unicode is accepted. JSON-escaped Unicode
  is rejected after decoding as well as in constructors; canonical wire rules
  also reject alternate JSON escapes.

Social shares one audience validator between admission candidates and
Enrollment V2. UBID validates the host grammar explicitly, compares IPv4
against standard-library `ipaddress` canonical spelling, and compares IPv6
against an explicit pure-hex RFC 5952 serializer of its eight 16-bit groups. Every shared
corpus member is exercised through enrollment constructors/parsers and the
real request/challenge proof paths in both repositories. The fixture SHA-256
assertions pin the corpus alongside the unchanged signed vectors. These shape
checks do not authenticate an origin or grant final admission.

## Enrollment V2

Enrollment V2 contains exactly:

```text
audience, deviceId, domain, ed25519PublicKey, enrollmentChallengeId,
expiresAt, issuedAt, profile, schema, subject, version, x25519BindingId,
x25519BindingVersion, x25519PublicKeyCommitment

domain = HODLXXI_SOCIAL_MESSAGING_DEVICE_ENROLLMENT_V2
schema = hodlxxi.social_messaging_device_enrollment.v2
version = integer 2
profile = hodlxxi.social_messaging_device_proof.ed25519_webcrypto.v1
```

The challenge is fresh server-originated lowercase hex64. The interval uses
nonnegative safe-integer epoch milliseconds and is exclusive at expiry with a
maximum 60,000-ms lifetime. The X25519 commitment is:

```text
"hodlxxi-social-messaging-x25519-public-key-v1-sha256:" +
hex(SHA256(ASCII("HODLXXI_SOCIAL_MESSAGING_X25519_PUBLIC_KEY_COMMITMENT_V1")
|| NUL || lowercase-hex64-X25519-public-key))
```

The enrollment digest prefixes the SHA-256 result with
`hodlxxi-social-messaging-device-enrollment-v2-sha256:` and hashes domain
`HODLXXI_SOCIAL_MESSAGING_DEVICE_ENROLLMENT_DIGEST_V2`, NUL, then the exact
enrollment wire.

Exactly one external-signer approval event is required. Its participant public
key must equal both the authenticated Social session subject and Enrollment V2
subject. The never-published kind-27236 event has the exact enrollment wire as
content, `created_at=floor(issuedAt/1000)`, and ordered purpose, enrollment
digest, challenge ID and device ID tags. Social locally verifies the event ID,
BIP340 signature and subject equality, then releases the one-shot signer/provider.
No different Full participant, sponsor, recipient, operator, administrator or
OAuth session may approve it. Full is necessary but insufficient.

The phone proof wire contains exactly `algorithm`, `enrollmentChallengeId`,
`enrollmentDigest`, `profile`, `publicKey`, `schema`, `signature`, `version`,
using schema `hodlxxi.social_messaging_device_enrollment_proof.v2` and version
2. Its exact sorted signing preimage contains the exact enrollment string, key
and profile under domain
`HODLXXI_SOCIAL_MESSAGING_DEVICE_ENROLLMENT_PROOF_V2` and schema
`hodlxxi.social_messaging_device_enrollment_proof_preimage.v2`. Social applies
the same strict Ed25519 boundary. Public-key, profile, subject, session, device,
binding, X25519 commitment and challenge substitution therefore fail.

One current active association is permitted per exact device. Rotation and
revocation must atomically invalidate the predecessor association and every
outstanding challenge. No lifecycle storage is implemented in this increment.

## Fixed vectors and runtime boundary

Both repositories contain identical
`tests/fixtures/social_messaging_device_proof_profile_v1.json`. It includes an
independently signed proof vector, independently signed Enrollment V2 phone
proof, a completed independently generated and valid kind-27236 Nostr approval
event containing no participant private key, RFC 8032 vector 1, the pinned C2SP
complete low-order/noncanonical point set and mixed-order A/R sets. Tests cover
invalid S, identity degeneracy, wrong keys, mutation and every contract
substitution. The existing Phase 2 and Phase 3 routing fixture hashes remain
unchanged.

`DEVICE_PROOF_RUNTIME_ENABLED` and `ENROLLMENT_V2_RUNTIME_ENABLED` are false.
There is no atomic single-use challenge owner, current association verifier or
final admission path. A cryptographically valid proof remains a narrow dormant
result and cannot authorize routing, storage, delivery, inbox access or any
other operation.
