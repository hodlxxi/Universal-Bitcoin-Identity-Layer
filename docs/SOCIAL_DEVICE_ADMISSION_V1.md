# Social Device Admission V1

Status: **dormant pure contracts and authenticated statement verifier;
final admission remains denied**. The source defines canonical bytes,
ownership, state vocabulary, typed future ports and an explicitly injected,
disabled-by-default public trust registration. It adds no migration, model,
database adapter, route, blueprint, factory/config import, key provisioning,
socket client, service credential or runtime activation.

## Architecture selection

UBID is the selected future owner of challenge creation and persistence,
atomic single-use consumption, Ed25519 association lifecycle,
rotation/revocation invalidation, exact operation effects and final device
admission. Those durable capabilities are selected but are not implemented by
this increment.

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
and deadlines. The future atomic owner must supply the expected wires and
deadlines from authoritative state. Enrollment requires an approver-session
deadline; device requests require none. All deadlines remain exclusive with
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

The future owner must deny and roll back the whole transaction on deadlock or
lock timeout. A known rollback commits no effect, receipt or challenge
consumption. Commit is the future durable publication point. An uncertain
commit must be reconciled from immutable history and must never be treated as
a known rollback or re-executed. Deadline checks are exclusive and must be
sampled again after waits.

## Fixed public vectors

`tests/fixtures/social_device_admission_v1.json` contains independent fixed
vectors for Enrollment V2, ciphertext submit and recipient self-read. Each has
exact context/input bytes and digests, canonical protected header/payload,
compact synthetic RS256 JWS, commands, responses and receipt shapes. It also
contains negative canonical/boundary cases.

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
invalidation, PostgreSQL challenge/association/receipt schema, immutable
challenge repository, transaction-bound viewer/session/Current-Full/binding
authority, atomic enrollment owner, routing/effect owner, internal routes,
purpose-bound Unix-socket client, quotas, credentials and explicit factory
composition. Migration application, credential provisioning, socket exposure,
runtime activation and deployment require separate authorization.

There is no participant or device private-key custody in UBID or Social server
storage. A future dedicated Social infrastructure statement-signing key is a
separate provisioned service credential. OAuth possession alone never enrolls
or admits a device. X25519 remains encryption-only. The phone does not require
NIP-07; Enrollment V2 approval is performed by the authenticated Full desktop
under the existing exact contract. Existing Phase 2 bindings and proof-profile
results do not become admitted associations. Every final admission decision
remains denied.
