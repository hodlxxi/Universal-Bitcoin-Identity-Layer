# Confidential Social mobile authorization ingress V1

This is dormant source. Only an explicit call to
`install_mobile_ingress(app, runtime, enabled=True)` registers these routes.
The default factory has no import, configuration fallback or registration for
this ingress. No Social session/cookie, deployment or activation is implemented.

The canonical bases are [mobile protocol](SOCIAL_MOBILE_DEVICE_AUTHORIZATION_V1.md),
[durable mobile ownership](SOCIAL_MOBILE_DEVICE_AUTHORIZATION_PERSISTENCE_V1.md)
and [OAuth lifecycle](OAUTH_SESSION_LIFECYCLE_V1.md). Their canonical signatures,
identifiers and exclusive deadlines remain authoritative. Consumer examples are
in `tests/fixtures/social_mobile_authorization_ingress_v1.json`; the original
Phase-1 fixture remains unchanged.

## Explicit trust configuration

Construction requires four `ConfidentialServiceConfig` objects, infrastructure
signing key and key ID, exact viewer OAuth client ID, and the real lifecycle,
mobile service and PostgreSQL assertion replay store. All state owners must
share the same explicitly injected SQLAlchemy session-factory object. The
lifecycle client ID must equal the configured viewer client. Backend client ID,
service principal and issuer must agree across the four capabilities. Missing
composition, credentials or committed migration guards fail closed. There is
no default database, environment credential, cached principal or process-local
replay fallback. No new migration is needed.

Let `I` be the configured lowercase HTTPS issuer origin, with no path, trailing
slash, credentials, query or fragment. Let `P` be
`/internal/v1/social/mobile-authorization`. The exact assertion audience is
`I + P + /service-token`. Resource audiences are distinct from that audience:

| Group | Exact scope | Exact purpose | Resource audience |
| --- | --- | --- | --- |
| desktop | `social:mobile-authorization:desktop` | `social_mobile_authorization_desktop_v1` | `I + P + /desktop` |
| phone | `social:mobile-authorization:phone` | `social_mobile_authorization_phone_v1` | `I + P + /phone` |
| exchange | `social:mobile-authorization:exchange` | `social_mobile_authorization_exchange_v1` | `I + P + /exchange` |
| invalidate | `social:mobile-authorization:invalidate` | `social_mobile_authorization_invalidate_v1` | `I + P + /invalidate` |

The existing confidential signing/verification and maximum 60-second token
lifetime are reused, including the configured bounded skew (examples use zero).
Each operation requires its exact group. Full Directory scope, purpose,
audience, defaults and existing endpoint remain unchanged; cross-service and
cross-group substitutions fail. Socket reachability, loopback, Host and
forwarded headers confer no authority. Backend identity is not human identity,
Current-Full evidence or device authorization.

`POST P/service-token` requires exact `application/x-www-form-urlencoded`, with
one each of `grant_type=client_credentials`, configured `client_id`,
`client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`,
`client_assertion` and one exact `scope` above. No extra or duplicate fields or
query string is allowed. Assertion verification precedes durable shared JTI
consumption. Success is exactly `{access_token,token_type:"Bearer",expires_in:60,
scope}`. A consumed assertion cannot be retried through a different group or
recreated runtime. After a lost token response use a fresh assertion.

## Closed HTTP operation matrix

All suffixes below are literal paths under `P` and accept **POST only**. There
is no request-selected Python method or generic action endpoint. Every request
requires `Authorization: Bearer <group-specific service token>`. Desktop and
invalidation additionally require `X-HODLXXI-Viewer-Authorization: Bearer <OAuth
credential>`. Phone/exchange requests reject an added viewer header; the phone
does not need a login it has not yet obtained. Service credentials stay in the
Social backend and must never reach browsers.

Use exact `Content-Type: application/json`, no query, Content-Encoding or
Transfer-Encoding, and a positive Content-Length no greater than 65,536 bytes.
Bodies are flat strict UTF-8 JSON objects; all declared fields are required,
all values are strings, and empty commands use `{}`. Unknown/duplicate members,
nested objects/arrays, invalid Unicode, non-finite numbers, booleans and other
type substitutions fail. `content`, `source` and `proof` carry exact canonical
ASCII JSON strings, each at most 16,384 characters, without reserialization.

| Suffix | Group | Exact request members | Closed response |
| --- | --- | --- | --- |
| `/legacy/reserve` | desktop | `content` | legacy reservation |
| `/legacy/accept` | desktop | `operationId,authorizationDigest,proof` | acceptance |
| `/legacy/status` | desktop | `operationId` | `{authorizationDigest,status}` |
| `/legacy/close` | desktop | `operationId,status` | `{status}` |
| `/qr/create` | desktop | none | pairing creation |
| `/qr/offer` | phone | `qr` | pairing offer |
| `/qr/scan` | phone | `source,qr,possessionProof` | pairing snapshot |
| `/qr/snapshot` | desktop | `pairingId,revision` | pairing offer or snapshot |
| `/qr/claim` | desktop | `pairingId,revision,authorizationDigest,humanCode` | `{status:"approval-claimed"}` |
| `/qr/accept` | desktop | `pairingId,revision,authorizationDigest,proof` | acceptance |
| `/qr/status` | desktop | `pairingId` | `{authorizationDigest,status}` |
| `/qr/close` | desktop | `pairingId,status` | `{status}` |
| `/phone/status` | phone | `pairingId,revision,authorizationDigest,verifier` | `{authorizationDigest,status}` |
| `/phone/recover` | phone | `source,qr,possessionProof,verifier,revision` | `{authorizationDigest,status}` |
| `/phone/exchange` | exchange | `pairingId,revision,authorizationDigest,verifier` | handoff delivery |
| `/oauth/invalidate` | invalidate | none | invalidation receipt |

`operationId` is the canonical lowercase UUID-v4 LEGACY challenge. Pairing ID,
revision, digest, verifier and possession proof are lowercase hex64. The QR
locator has the unchanged `hodlxxi-social-pair:v1:<hex64>:<hex64>` grammar.
`humanCode` is exactly `ABCD-EF01-2345`. Explicit close states are `cancelled`,
`abandoned` or `rejected`; expiry can take precedence. Locators/verifiers belong
only in confidential POST bodies, never URLs, logs, analytics or durable retry
material. Requests have no unsigned subject/user/Session/browser-generation/JTI,
context override or imported handoff fields. Required public identity fields
inside frozen signed content remain intact and are compared to the real owner.

## Identity, context and transaction boundaries

Backend verification precedes authority-dependent database operations. Desktop
and LEGACY call exactly `lifecycle.resolve(viewer_bearer)` for the internal
Session ID and canonical subject. Unmapped, expired, revoked or wrong-client
credentials cannot resolve. Session ID, token JTI and browser generation never
appear in mobile responses or become operation contexts.

Reservation creates a fresh server CSPRNG 32-byte loginContext. Offer creation
creates independent server CSPRNG desktopContext and revision values, with a
300-second offer TTL. The existing operation transaction durably binds context
to the resolved Session/subject continuity commitment before returning. Initial
context/revision cannot be chosen by a browser. Lost creation responses can
leave committed reservations/offers; a retry must not infer rollback.

Later commands call `original_context` under operation locking and `_owned/_auth`
to recover the original context. It grants no future authority. The real mobile
command repeats its unchanged Session/User, ownership, expiry and continuity
checks in its own transaction. Logout or replacement after resolver return or
context recovery therefore denies acceptance. HTTP handlers contain no SQL.
Signature, Current-Full, replay ownership, binding eligibility and mutation
remain in the existing atomic mobile acceptance transaction. No response is
released before its durable transaction commits.

Phone lookup requires a live offer's exact QR secret commitment. Scan and
recovery check original transcript possession; phone status/exchange require
the separate verifier. Subject comes from persisted pairing state inside the
proof-checked service. QR possession and approval claim cannot authorize login
or device binding. LEGACY retains its original bound proof and has no QR phone
handoff or second signature; future Social OAuth continuation is separate work.

## Exact success schemas

Responses use key-sorted compact ASCII JSON without a trailing newline. Every
version below is integer `1`. No additional fields are permitted.

- Legacy reservation: `schema="hodlxxi.social_mobile_legacy_reservation.v1"`,
  `version,challenge,loginContext,authorizationDigest,expiresAt`. Reconstruct the
  frozen envelope using original exact content and returned challenge/context.
- Pairing offer: `schema="hodlxxi.social_mobile_pairing_offer.v1"`,
  `version,pairingId,secretCommitment,desktopContext,subject,createdAt,expiresAt,
  revision,status`. Public subject/context are protocol inputs for the exact
  signed transcript; neither authenticates a caller.
- Pairing creation: `schema="hodlxxi.social_mobile_pairing_creation.v1"`,
  `version,offer,qr`; offer is the closed object above.
- Pairing snapshot: `schema="hodlxxi.social_mobile_pairing_snapshot.v1"`,
  `version,source,revision,status,acceptance`. Acceptance is null until accepted,
  otherwise the closed acceptance below. An unscanned snapshot is an offer.
- Acceptance: unchanged `schema="hodlxxi.social_mobile_authorization_acceptance.v1"`,
  `version,authorizationDigest,bindingId,subject,requestId`. Exact authenticated
  historical retries recover the same bytes, including after authorization
  expiry; they do not resign, extend expiry or assert current readiness.
- Invalidation: `schema="hodlxxi.social_mobile_generation_invalidation.v1"`,
  `version,status="invalidated"`; no original or replacement identity is returned.

Status values are those of the existing state machine. authorizationDigest is
null before a proposal exists. `never-accepted` is a linearizable observation,
not terminal cancellation; it cannot justify destroying pending device keys
while an acceptance may still commit.

## Durable handoff history and Social obligations

Delivery is exactly `schema="hodlxxi.social_mobile_handoff_delivery.v1"`,
`version,identity,operation,revision,consumedAt,delivery,freshIssuanceAuthorized`.
`delivery` distinguishes `created` from `recovered` work items.
`freshIssuanceAuthorized` is always **false**. First consumption retains all
reviewed checks: accepted non-revoke authorization, active unchanged binding,
correct separate verifier/revision/digest and exclusive deadline. Historical
retry can recover after expiry or later binding revocation, but cannot restore
access or refresh any deadline. Operation/revision come from original signed
state; consumedAt is the immutable original consumption time.

The nested frozen identity has exactly `schema,version,pairingId,
authorizationDigest,bindingId,deviceId,subject,requestId,exchangeCommitment,
expiresAt`, with `schema="hodlxxi.social_phone_session_exchange_identity.v1"`.
Method/operation/revision/issuance time are not inserted into it. Browser JSON
cannot assert that an exchange was consumed: the service retrieves the durable
work item after verifier and original-identity checks in its transaction.

The future Social issuer must authenticate UBID as its source, validate the
closed envelope and original operation, bind its durable one-handoff/one-issuance
owner to the exact pairing/digest/revision/subject/device/binding/request, enforce
original deadlines and current eligibility, and atomically persist its one
issued-session result. Lost responses recover that exact result. Historical
delivery can locate an existing issuance record; it cannot create or reactivate
one. Current-eligibility revalidation at actual Social issuance remains separate
issuer work; this endpoint issues no eligibility bearer or reusable grant.
No distributed acknowledgement or end-to-end Social issuance/recovery is claimed.

Verifier loss fails closed. QR secret, backend token, subject and device ID
cannot substitute. The non-extractable messaging CryptoKey stays device-local;
it must never be exported for recovery. Full/operator/sponsor/CRT/covenant and
friendship authority are not granted. Mobile proof is not relabeled as existing
Nostr routing evidence.

## Revocation-only retries, failures and activation gates

`invalidate_original` verifies the exact stored token digest, RS256 signature,
trusted signing key, issuer/client, canonical token contract/scopes/dates and
immutable generation owner/subject. Only expiry/revocation and current User
activity/subject are irrelevant to this revocation-only command. It returns no
principal. Unknown or retired signing keys fail closed. Repeated calls revoke
only that original token/Session, never a replacement, another User/client or
all generations for a subject. Storage failure produces no false receipt.

Social must separately implement logout CSRF, retention of its original OAuth
credential, delivery/acknowledgement, local cleanup and replacement policy.
Adding this UBID primitive does not wire Social logout. Lifecycle-enabled GET
logout with a missing/expired/revoked browser generation can still return 503;
a safe local-cleanup path remains required before activation.

All confidential success/error responses require `Cache-Control: no-store` and
`Pragma: no-cache`. Malformed input uses `400 invalid_request`; malformed/invalid
backend credentials use `401 invalid_credential`. Viewer/proof/ownership/state
and storage failures share `503 mobile_authorization_unavailable`. Missing or
disabled composition provides no capability. Registered-but-unconfigured routes
return 404. Wrong methods, unknown paths and excessive bodies are generic and
contain no redirects or internal details. Public discovery is unchanged.
Production private-path controls, credentials, migration application, factory
composition and activation each remain separately authorized work.

Prior adjacent/full test interpreters needed controlled termination after pytest
returned; existing CI uses `os._exit(rc)`. Assertions and actual process shutdown
must be reported separately. This ingress does not repair that global issue.
