# Confidential Social Enrollment V2 HTTP ingress V1

This is source-only, default-off HTTP composition. The default app factory
does not import or install it. No deployed route, database role, migration,
key, environment configuration or service changes are included. It enables
neither current device admission nor messaging.

## Explicit construction

`EnrollmentV2Ingress` requires the exact enabled challenge composition, an
`AuthenticatedEnrollmentV2Composition`, three explicit immutable confidential
service configurations, the existing infrastructure RS256 service signer and
the existing durable assertion replay store. No path or environment lookup
provides a missing key, Session factory, token, identity or enable flag.

The authenticated composition receives the exact existing
`SocialEnrollmentV2Composition` and `SqlAlchemyOAuthSessionLifecycle` sharing
the identical explicit Session factory. Client and issuer must match the
existing evidence configuration. The challenge composition uses its separate
native issuance writer factory: the finalization role's closed profile still
forbids challenge INSERT. The replay store shares that explicit challenge
factory. Challenge and reservation/finalization client, backend, principal,
issuer and Social audience must agree. No permissions are broadened here.

`install_enrollment_v2_ingress(app, runtime)` returns `False` by default without
registering a blueprint or extension. Installation requires literal
`enabled=True`, the exact configured runtime type and an unused extension.
It is not invoked by the default app factory. Runtime activation is a separate
operator-reviewed operation after native database verification.

## Closed HTTP contract

All paths below are literal POST-only paths. GET, HEAD, OPTIONS and unknown
commands do not execute operations. Automatic redirects do not execute them.
Responses, including failures, use `Cache-Control: no-store` and
`Pragma: no-cache`.

| Path | Exact body fields |
| --- | --- |
| `/internal/v2/social/enrollment/service-token` | Form: `grant_type`, `client_id`, `client_assertion_type`, `client_assertion`, `scope` |
| `/internal/v2/social/enrollment/challenge` | JSON: `issuanceId` |
| `/internal/v2/social/enrollment/reserve` | JSON: `issuanceId`, `verificationInputWire` |
| `/internal/v2/social/enrollment/finalize` | JSON: `issuanceId`, `reservationId`, `reservationRevision`, `verificationInputWire`, `evidenceCompactJws`, `statementCompactJws` |

The token endpoint requires exact `application/x-www-form-urlencoded`, the
existing `client_credentials` grant and private-key JWT assertion type. It
accepts no Authorization or viewer header. It reuses the real confidential
assertion verifier, domain-separated service token issuer and durable consume
once replay store. An assertion cannot be replayed to issue another token.

Each command requires `Authorization: Bearer <service-token>` and
`X-HODLXXI-Viewer-Authorization: Bearer <phone-access-token>`. Service tokens
are independently scoped to `social:enrollment-v2:challenge`, `:reserve` or
`:finalize`; resource audiences are the exact issuer plus the command path.
Purposes are respectively `social_enrollment_v2_challenge_v1`,
`social_enrollment_v2_reserve_v1` and `social_enrollment_v2_finalize_v1`.
No other service audience/scope/purpose, including legacy issuance, crosses
this boundary. Service signatures and identity are checked before participant
storage and again before publication. Exclusive service expiry is checked with
zero configured skew. Client assertions retain the existing credential contract.

Command content type is exactly `application/json`. The outer object is flat
and all values are strings; the only accepted transport revision is `"1"`,
converted to the native integer 1 after strict parsing. Canonical nested
objects remain their exact ASCII wire strings; no reserialization changes
their signatures. JSON duplicate/escaped-duplicate properties, nested objects,
numbers, booleans, nonfinite values, extra/missing fields and invalid UTF-8 deny.
IDs are lowercase 64-character hex. Individual wire bounds equal their existing
canonical consumers. Total body size is at most 65,536 bytes. Query parameters,
content/transfer encoding, missing/inconsistent lengths and wrong media types
deny. Duplicate form fields and malformed percent escapes deny.

Request fields cannot select a clock, freshness profile, user, device, trusted
key, config, callback, SQL operation or authority flag. Malformed transport
returns a generic 400; invalid service/header credentials return a generic
401. Phone, ownership, proof and storage denials return the same non-sensitive
503 without revealing whether a participant, issuance or receipt exists.

## Same-transaction phone authentication

The original [challenge producer](SOCIAL_ENROLLMENT_V2_CHALLENGE_V1.md) already
validates the exact phone bearer against the locked native child and its parent
graph. The HTTP adapter calls that real composition without a replacement
lookup or caller-provided authority.

For reservation/finalization, the authenticated adapter uses the existing
`_run_owned` transaction kernel and actual lower-level owners. Canonical bearer
signature, digest, revocation, client and subject are checked through that
owner's same bound Session/Connection. Its exact JTI, subject and client must
match the authenticated RSA evidence's original native phone issuance facts.
A desktop token, unrelated valid phone, raw issuance ID or copied parsed
projection cannot select someone else's operation.

Reservation validates the bearer before work and matches the exact native
phone identity against the real returned evidence before commit; mismatch
rolls back any provisional pending row and releases no signature/result.
The unchanged owner retains native locks and current authority checks.
Its precommit retry still returns original bytes/deadline without re-signing.

Finalization authenticates original evidence and matches its phone before
native effects. The original observation time is parsed only to authenticate
that original signed identity; it supplies no current validity. The unchanged
owner independently applies all current native checks and expiry for new work,
or authenticates byte-identical accepted history at the original decision time.
It remains solely responsible for the atomic effects and exact receipt.

Immediately before commit the adapter rechecks the phone against the same
original evidence, then intersects the publication interval with the original
phone expiry. Canonical bearer leeway never extends that exclusive interval.
All current lower-level lock, signature, binding, Current-Full and expiry checks
remain intact. Historical recovery requires an authenticated, currently valid
matching phone at this ingress, but creates no new receipt freshness, native
current-authority read, association or effects.

## Publication and verification limits

Only exact committed result types are projected. They expose the original
canonical wire strings and existing selectors/times, never a bearer token.
Every response retains `publicationStatus="committed"`,
`finalAdmission="denied"` and `bearerAuthority="none"`. A committed receipt
is not a current device admission capability.

The transaction kernel commits and closes before publication and retains its
real precommit/postcommit expiry fences. Lost commit acknowledgment or late
expiry publishes no result and does not automatically retry. A service token
can expire after a successful commit: its delivery is denied, while durable
history may exist. Exact retries use the original lower-level history rules
and cannot buy a renewed challenge, reservation or receipt interval.

Dependency-free tests cover closed parsing. Additional offline tests use real
service RSA signatures and Flask in-process dispatch, plus real canonical phone
verification and reservation/finalization owners with explicit SQLite/native
catalog/effects doubles. The replay HTTP fixture doubles only storage, retaining
the actual assertion and service-token crypto. Those offline checks do not
establish native PostgreSQL behavior or a deployed flow.

Separate disposable PostgreSQL rehearsals exercise the real restricted roles,
challenge revision trigger, replay concurrency and complete committed
challenge/reservation/finalization/history flow with genuine clocks. The real
Social Node client also crosses a temporary Unix HTTP listener into this Flask
ingress and the actual native owners, without injected transport or clocks and
without PostgreSQL doubles. Desktop viewers, wrong issuance selectors and
damaged statement signatures deny; exact retry preserves receipt bytes and
effect counts. Expected ownership/proof denials retain the generic 503.

The native fixture uses a trusted synthetic Social RSA issuer and shape-only
phone proof. It does not replace the separate Social BIP340/Ed25519 verifier or
prove an installed browser/session bridge. Server-selected producer profile
installation, explicit operational factory/key/trust/role composition, browser
lifecycle preparation and staging activation remain separate work. None is
implicitly authorized by installing or merging this source.
