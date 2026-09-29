# Social preaccepted-enrollment verification statement V2

Status: **dormant canonical byte contract and pure authenticated consumer; no
producer, route, runtime wiring or authority activation**.

The implementation is
`app/services/social_preaccepted_enrollment_verification_statement_v2.py`.
UBID owns and freezes these bytes. Social production and signing are a later
separate change. `RUNTIME_ENABLED` is `false`.

## Architecture boundary

The exact dedicated audience suffix is:

```text
/internal/v2/social/device-admission/consume
```

This is a statement-audience literal only. No HTTP, socket or internal route
is added. It does not reuse or fall back to the V1 consume audience. V1 and V2
trust registration, schemas, protected types, purposes, results and JTI
domains are separate closed protocols; neither consumer relabels, autodetects
or adapts the other.

This slice authenticates a Social claim that strict cryptographic verification
succeeded for one exact [`Preaccepted Enrollment V2 verification
input`](SOCIAL_PREACCEPTANCE_ED25519_HANDOFF_V2.md#preaccepted-enrollment-v2-verification-input).
It does not perform Ed25519 verification in UBID. The existing UBID V2 input
parser still validates its frozen canonical graph and existing BIP340 approval
event; Social remains responsible for strict Ed25519 verification before a
future producer may issue this statement.

## Frozen statement vocabulary

The V2-only constants are:

```text
schema  = hodlxxi.social_preaccepted_enrollment_verification_statement.v2
version = 2
alg     = RS256
typ     = hodlxxi-social-preaccepted-enrollment-verification-v2+jws
purpose = social_preaccepted_enrollment_cryptographic_verification_v2
result  = preaccepted-enrollment-v2-bip340-and-ed25519-valid
JTI domain = HODLXXI_SOCIAL_PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENT_JTI_V2
audience suffix = /internal/v2/social/device-admission/consume
```

The compact JWS is printable ASCII and at most 4,096 bytes. It has exactly
three nonempty canonical unpadded base64url segments. The protected header is
compact sorted-key ASCII JSON containing exactly:

```json
{"alg":"RS256","kid":"<configured V2 identifier>","typ":"hodlxxi-social-preaccepted-enrollment-verification-v2+jws"}
```

The payload without `jti` is compact sorted-key ASCII JSON containing exactly:

```text
acceptanceId, associationId, attemptId, aud, clientId,
enrollmentChallengeId, expiresAt, inputDigest, iss, issuedAt,
purpose, result, schema, servicePrincipal, version
```

The complete payload adds exactly `jti`. Missing, unknown or duplicate
members; whitespace, alternate escapes or numeric forms; non-ASCII;
booleans-as-integers; negative or unsafe integers; padding; empty or extra
segments; and alternate algorithms or extensions all fail closed.

The deterministic token identifier is lowercase hexadecimal:

```text
jti = hex(SHA256(
  ASCII("HODLXXI_SOCIAL_PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENT_JTI_V2")
  || NUL
  || ASCII(canonicalPayloadWithoutJti)
))
```

It is a signed statement identity only. It is not a replay record, receipt,
acceptance ID, association ID, challenge ID or bearer credential.

## Exact derived bindings

The serializer and consumer require both the exact canonical expected V2 input
wire and its exact embedded V1 verification-context wire. They reparse the
complete input and require byte-for-byte context equality. Equivalent decoded
JSON is insufficient.

The payload accepts no independent caller assertion for its equality-critical
identities. It freshly derives:

- `inputDigest` from the exact V2 input wire under the existing V2 input digest
  domain;
- `acceptanceId` from the exact nested approval event and authorization;
- `associationId` from the exact Enrollment V2 wire and existing association
  identity contract;
- `enrollmentChallengeId` from the exact Enrollment V2 wire; and
- `attemptId` from the exact embedded verification-context wire.

The configured issuer must equal the exact context audience. The protected
V2 `kid`, configured issuer, exact V2 consume audience, client ID, service
principal and fixed purpose are all checked independently.

Consequently, changing any nested subject, device, request, desktop-context
revision, Ed25519 key, X25519 binding/version/commitment, authorization,
approval event, Enrollment V2 field or phone-proof field changes or invalidates
the exact input and cannot authenticate under the fixed statement. Canonical
phone-signature bytes remain part of the input digest; UBID does not infer
Ed25519 validity merely from their shape or digest.

## Time and freshness

All clocks and deadlines are explicitly injected nonnegative safe-integer
epoch milliseconds. There is no ambient clock and no skew. The statement
requires:

```text
enrollment.issuedAt <= statement.issuedAt <= now < statement.expiresAt
0 < statement.expiresAt - statement.issuedAt <= 10000
```

The consumer strictly reparses the V2 input and invokes its existing V2 time
contract. Statement expiry cannot exceed the reparsed Enrollment V2 expiry,
pre-enrollment expiry or signed X25519 binding expiry, nor any of the explicit
phone-session, approver-session, Full or X25519-binding deadlines. The supplied
X25519 deadline must exactly equal the deadline reparsed from the signed
binding authorization.

These comparisons validate cryptographic-evidence freshness only. Caller
deadlines and signed historical intervals do not establish live sessions,
Current-Full entitlement, current X25519 authority, a durable acceptance root,
an issued or unconsumed challenge, or current association state.

## Dedicated V2 RSA trust

`SocialPreacceptedEnrollmentVerificationStatementV2Config` is empty and
disabled by default. It is a dedicated V2 registration, not a generic JWT or
service-token key selector and not inherited from V1.

Each registered public JWK contains exactly `kty`, `use`, `alg`, `kid`, `n`
and `e`, with `RSA`, `sig` and `RS256` fixed. Modulus and exponent are minimal
canonical unpadded Base64urlUInt values. RSA moduli are 2,048..8,192 bits and
odd; the public exponent is odd, at least 65,537 and smaller than the modulus.
All keys are validated eagerly, copied and frozen. Duplicate `kid` values,
weak or malformed integers, private parameters, symmetric material, embedded
keys, remote key URLs, certificates and unknown fields are rejected. Exact
`kid` selection must find one key; another key cannot rescue an unknown or
wrong selected key.

After every shape, binding and freshness check, the consumer verifies
RSASSA-PKCS1-v1_5 with SHA-256 over the original ASCII protected and payload
segments joined by one dot. It never decodes and reserializes before signature
verification. Signature length must exactly match the selected RSA modulus.
There is no filesystem, environment, network, key URL, certificate, database
or ambient key discovery.

Every failure is the single bounded message:

```text
social preaccepted enrollment verification statement denied
```

Internal exception chaining and sensitive logging are suppressed.

## Authenticated result and non-authority

Success returns only a frozen, slot-only, repr-hidden
`AuthenticatedSocialPreacceptedEnrollmentVerificationStatementV2`. The public
object has no per-fact instance slots or dictionary. Its read-only properties
expose the configured identities, fixed purpose/result, derived acceptance,
association, challenge, attempt and input identities, statement interval/JTI,
and selected key ID/SPKI fingerprint from one private immutable authenticated
snapshot created only after successful signature verification.

The result and complete immutable snapshot are registered together by exact
object identity in a private weak registry. Direct property access resolves
only that registered snapshot. The public authentic-evidence projection first
resolves that snapshot once and then projects only from that one immutable
value; it never checks or rereads attacker-modifiable instance facts. Attempts
to use `object.__setattr__` on any public fact cannot change either direct
access or projection. Weak-reference cleanup removes the snapshot with the
exact result object. Public construction, subclasses, `object.__new__`
forgeries, copied or deep-copied objects, dataclass/dict/prototype lookalikes
and pickle-style substitution do not pass the projection.

The projection fixes the remaining boundaries as:

```text
authority = not-granted
durable acceptance = not_established
current authority = not_evaluated
challenge consumption = not_implemented
association commitment = not_implemented
receipt = not_issued
final admission = denied
runtime enabled = false
```

Those eight projection values are fixed literals at the authenticated handoff;
rebinding exported boundary constants, or adding an `AUTHORITY` module name,
cannot change them.

Verification is stateless. Repeating it may return the same authenticated
facts, but consumes nothing, persists nothing and grants no capability. The
result is not a bearer token and cannot represent durable acceptance, current
Full/session/binding authority, challenge consumption, association creation,
admission or a receipt. A future atomic owner must independently lock and
recheck every applicable authority and lifecycle owner after waits and before
any mutation.

## Public vector and preservation gate

The fixed public vector is
`tests/fixtures/social_preaccepted_enrollment_verification_statement_v2.json`:

```text
bytes  = 12018
sha256 = fdbbed748f28d1ef850ef3d82b1680e7dca12b0f7a2d863acf14dc7b75770f39
```

It freezes the canonical protected header, payload without JTI, deterministic
JTI, complete payload, original signing input, synthetic RS256 signature,
compact JWS, public RSA JWK/SPKI fingerprint, explicit test deadlines and
expected authenticated projection. The synthetic private key was generated
only in memory and was not serialized or retained.

The vector links to the existing shared V2 preacceptance fixture by exact path,
byte count, SHA-256, verification-input SHA-256 and domain-separated input
digest. Both UBID and Social contain that identical source fixture:

```text
bytes  = 32998
sha256 = 4f79dd0f24fd8ded4c2e4e3e644811dd42ca620d8c0e09aea177237dd5d199dc
input digest = hodlxxi-social-preaccepted-enrollment-verification-input-v2-sha256:3cbd20bc4061fc8fd074c76bbd70239a102519ac5196417d0c2c20b8a6a02939
```

Existing V1 source, fixtures, schemas, identifiers, statement bytes and
behavior remain unchanged.

## Explicitly deferred

This slice adds no Social producer or signer, Ed25519 verifier in UBID, caller
`verified`/`accepted`/`current` boolean, durable acceptance or rejection,
challenge issuance or consumption, association mutation, current session or
Full authority, model, repository, migration, replay table, route, socket,
HTTP/BFF/browser surface, factory/configuration/feature-flag wiring, service
restart or deployment.
