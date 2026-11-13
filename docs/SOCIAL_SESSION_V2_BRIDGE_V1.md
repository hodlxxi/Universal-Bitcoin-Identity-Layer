# Native V2 phone-session bridge V1

This additive source bridge is default off. The default application factory
does not import or install it. It does not change the V1 QR/mobile session
contract, register a client, load keys, provision roles or apply migrations.

## Separate service-authenticated transport

`NativeV2SessionIngress` accepts only the exact `NativeV2SessionIssuer`, its
exact OAuth lifecycle and a PostgreSQL assertion-replay store sharing that
lifecycle's Session factory. Five closed service configurations bind the
same issuer, backend and principal, separate resource audiences, separate
purposes and zero clock skew. Replacing the owner/factory identity denies.
The installer requires literal explicit enablement and an already-held
infrastructure signing key. Nothing is installed through environment fallback.

The prefix is `/internal/v2/social/session-issuance` with `/service-token`.
Each command requires its own `social:session-issuance-v2:<command>` token.
Service credentials are authenticated before participant database work and
again before delivery. Client assertions use the existing durable replay
consumer. A service credential is never a participant credential.

| Command | Closed JSON fields | Original participant credential |
| --- | --- | --- |
| offer | authorizationWire | original desktop bearer |
| issue | operationId, approvalWire, secret, possessionProof, verifier, deliveryKey | original desktop bearer |
| recover | operationId, approvalWire, secret, possessionProof, verifier, deliveryKey | none; extra viewer header denies |
| resolve | issuanceId | exact native child bearer |
| revoke | issuanceId | exact native child bearer, cancellation only |

Participant credentials use only `X-HODLXXI-Viewer-Authorization`. Signed
protocol objects remain original printable-ASCII strings. Bodies reject extra,
duplicate, malformed or oversized fields. Transport rejects query parameters,
unexpected encoding, non-POST methods and redirects. All responses are no-store.
Public denial contains no credential, native catalog detail or participant data.

## Original issuance and cancellation

Offer creation takes the existing native operation advisory lock before
creation. An exact retry authenticates the same original desktop lineage,
refetches the immutable offer/parent and rechecks current owners and original
exclusive deadlines. It returns the original bytes without inserting another
offer or parent. A changed wire or parent denies. Concurrency never changes
the original interval. Acceptance and issue/recover continue through the
[native V2 provenance owner](SOCIAL_SESSION_ISSUANCE_V2_PROVENANCE_V1.md).

Self-revocation authenticates possession against the stored original child's
SHA-256 digest, not unverified JWT claims or an issuance selector alone. It
checks immutable acceptance, native token birth, original revision and owner
identity, then revokes only that token through the guarded connection and
existing mutation triggers. It commits before acknowledging. Repeated exact
cancellation is idempotent. Expired or already-revoked original credentials
can cancel themselves without a signer or active-parent grant; this negative
operation cannot issue, resolve or deliver current authority. A wrong bearer
or the desktop credential cannot cancel another child.

Active issue/recover returns only the existing basic `openid profile` child.
Inactive history returns the original receipt with null bearer and subject.
The HEX64 issuance revision is distinct from numeric challenge/reservation
revisions. No session in this contract grants Full, device admission or Send.

## Verification and activation boundary

The paired Social bridge has a separate strict Unix client and explicit V2
session store/manager. Existing V1 sessions are not relabeled. Unit checks
separate real service RSA and owner decisions from explicit SQLite catalog,
trigger and replay doubles. A disposable PG16 runner must independently
exercise first HTTP offer/issue, original recovery, same-bearer cancellation,
genuine expiry, concurrent original offer creation and a real Node Unix client.
Collection or offline tests alone establish none of those native properties.

Operational factories, live roles/trust/keys and Unix routing remain separate.
The active Social browser/BFF is still V1. Its native V2 cross-device proposal,
desktop approval, device-local IndexedDB upgrade/cleanup, real Social
BIP340/Ed25519 statement orchestration and current-admission checks must be
completed and reviewed before activation. This source bridge does not install
those routes or imply deployment readiness. DMs remain disabled.
