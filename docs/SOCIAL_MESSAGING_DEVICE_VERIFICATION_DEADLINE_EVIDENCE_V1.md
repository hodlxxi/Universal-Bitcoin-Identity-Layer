# Social messaging-device verification deadline evidence V1

Status: **dormant pure byte and public-trust contract; no signer, reservation
adapter, route, runtime wiring, or authority activation**.

The implementation is
`app/services/social_messaging_device_verification_deadline_evidence_v1.py`.
`RUNTIME_ENABLED` is `false`. UBID is the sole future producer and trust owner
for this evidence. Social remains the owner of the separate verification and
verification-statement signing process described by
[`SOCIAL_PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENT_V2.md`](SOCIAL_PREACCEPTED_ENROLLMENT_VERIFICATION_STATEMENT_V2.md).

## Authority boundary

This evidence exists so that neither Social nor the existing V2 consumer can
treat four caller-supplied integers as current authority. A future UBID
reservation owner must run in one caller-owned PostgreSQL transaction and:

1. lock and recheck the exact child phone issuance and its exact parent OAuth
   token, durable session, and browser generation;
2. lock and recheck the exact approver OAuth token, durable session, and
   browser generation;
3. obtain Current-Full only from the existing subject-locking current evidence
   verifier, including its exact evidence ID, version, source hash and proof
   identity;
4. lock the exact X25519 binding ID and require its exact version, active
   state, public-key commitment and effective deadline;
5. lock and recheck the exact challenge and association pre-effect state;
6. create one immutable pending reservation bound to the exact V2 input and
   evidence bytes; and
7. invoke the separately provisioned dedicated evidence signer, store the
   exact compact JWS, and return that same stored value.

The transaction owner, not a pure helper, supplies lock, persistence, and
commit authority. This phase deliberately exposes no raw-field payload
constructor and no caller `current`, `verified`, `reserved` or `accepted`
marker. Parsing a payload does not authenticate it. The registry-backed result
exists only after strict JWS verification and still proves no currentness at
final acceptance.

No historical row, highest-version lookup, snapshot-age policy,
configuration value, caller deadline, OAuth assertion, session token, service
response, service-client assertion, participant key, Nostr key, Bitcoin key,
X25519 key, Ed25519 device key, or existing generic runtime signing key can
substitute for those locked readers or for this dedicated evidence key.

## Canonical payload

The payload is compact lexically key-sorted printable-ASCII JSON with no
trailing newline and the fixed values:

```text
schema  = hodlxxi.social_messaging_device_verification_deadline_evidence.v1
version = 1
purpose = social_messaging_device_verification_deadline_evidence_v1
```

Its closed fields bind:

- `subject`, `deviceId`, `requestId`, `operation=register`, and the exact
  UBID issuance `operationId`;
- the V2 `acceptanceId`, approval-event ID, authorization digest, enrollment
  challenge ID, attempt ID, association ID and association version;
- the child Social issuance ID/revision/token ID plus its exact parent OAuth
  token, session and browser-generation IDs;
- the approver OAuth token, session and browser-generation IDs;
- the Current-Full evidence ID/version/source SHA-256 and the canonical Full
  proof ID;
- the exact X25519 binding ID/version/public-key commitment;
- the four independent effective deadlines;
- one `observedAt`, one `expiresAt`, one reservation ID/revision, the existing
  V2 `inputDigest`, and a domain-separated digest of the exact V2 input payload;
  and
- fixed issuer, audience, client ID, service principal, purpose and JWS token
  identity.

Every epoch-millisecond value is a nonnegative JavaScript-safe integer and
represents wall-clock UTC. Booleans and floats are not integers. The interval
is exclusive at expiry, positive, no longer than 10,000 ms, and bounded by the
minimum of all four effective deadlines, Enrollment V2 expiry and
pre-enrollment expiry. The X25519 deadline must also equal the deadline in the
exact signed V1 binding tuple. Processing timeouts, if a later adapter needs
them, use a monotonic clock and are never placed in evidence.

The pending-reservation constructor requires its caller-owned transaction
observation to equal signed `observedAt` exactly. An earlier or later value is
not an alternate observation of the same evidence.

The reservation ID is SHA-256 over a closed canonical V2-specific identity
preimage under
`HODLXXI_SOCIAL_MESSAGING_DEVICE_VERIFICATION_DEADLINE_RESERVATION_ID_V1`.
The input payload digest and JTI use their own domains. They are not row IDs,
receipts, challenge IDs, association IDs, bearer capabilities, or substitutes
for each other.

## Dedicated compact JWS and trust lifecycle

The compact JWS is canonical unpadded Base64url and at most 16,384 bytes. Its
protected header contains exactly:

```json
{"alg":"RS256","kid":"<dedicated UBID evidence key ID>","typ":"hodlxxi-social-messaging-device-verification-deadline-evidence-v1+jws"}
```

The algorithm is fixed to RS256. Verification uses the original ASCII header
and payload segments. The module can construct that deterministic signing
input, but it has no signing operation, private-key loader, filesystem or
provider discovery, provisioning command, rotation command, runtime factory,
or private key.

Each trust record contains exactly one public JWK plus a positive trust
revision, `notBefore`, `notAfter`, and optional terminal `revokedAt`. The JWK
contains exactly `kty,use,alg,kid,n,e`; all private RSA members, unknown
members, certificates and remote key URLs are rejected. RSA modulus and
exponent checks match the repository's strict V2 public trust posture. Key IDs
are unique, exact selection is mandatory, and another key cannot rescue a
missing, replaced, rotated, revoked or mismatched selected key. A non-null
revocation disables that record. The empty configuration is disabled.

The key is a new purpose-specific asymmetric UBID authority. A later
operational contract must provision custody and freeze issuance, overlap,
rotation, revocation, rollback and retirement. This source provisions none of
those things.

Every failure is the same non-sensitive message:

```text
social messaging device verification deadline evidence denied
```

The public failure has no chained cause or context; malformed values and
internal parser or serializer failures are not retained on the exception.

## Public vector

The synthetic public fixture is
`tests/fixtures/social_messaging_device_verification_deadline_evidence_v1.json`:

```text
bytes  = 6846
sha256 = 5c2d9fa2c73b295ff6e4d3477c591273ec06251c65551b646468b62a35343dbb
```

It links the unchanged 32,998-byte V2 input fixture, freezes the protected
header, payload, signature, public JWK and trust lifecycle, and contains no
private material. The synthetic private key was created in memory only and
was not serialized or retained.

## Explicit non-authority and non-changes

Authenticated evidence proves only that the configured dedicated UBID public
key authenticated those exact bounded bytes. It does not prove database
locks, reservation persistence, signing-key custody, Social verification,
challenge currentness or consumption, association state or mutation, an
acceptance effect, receipt publication, commit, final admission, or runtime
activation.

No model, table, migration, repository adapter, route, BFF, HTTP or socket
transport, network call, background process, service configuration, feature
flag, runtime/factory composition, private key, deployment, or existing V1/V2
fixture/protocol byte is changed.
