# Durable OAuth Session lifecycle V1

This is a dormant authentication-continuity prerequisite for the
[mobile persistence contract](SOCIAL_MOBILE_DEVICE_AUTHORIZATION_PERSISTENCE_V1.md).
It adds no mobile ingress, Social session issuer, new route path, factory
composition, environment activation, deployment or live migration. The existing
logout path gains an explicit protected POST when this lifecycle is configured.

## Existing lifecycle and opt-in boundary

The factory's Legacy and Nostr verification paths persist an active canonical
User before setting Flask login fields. The OAuth authorization endpoint admits
those authenticated browser fields, persists a ten-minute PKCE code, and the
token endpoint authenticates the OAuth client and exchanges the code for the
existing canonical RS256 access token. Introspection and confidential
[Full-directory viewer authentication](PRIVACY_FULL_DIRECTORY_INTERNAL_DELIVERY_V1.md)
use the existing signature-and-persisted-record bearer validator.

The factory OAuth token endpoint supports only authorization_code. The separate
legacy monolith and the factory's basic-login compatibility branch have other
access/refresh-token code; those credentials do not participate in this
lifecycle and cannot be imported into it.

Only an explicitly constructed SqlAlchemyOAuthSessionLifecycle installed as
the application extension oauth_session_lifecycle_v1 opts one exact persisted
OAuth client into these source hooks. Nothing installs this extension by
default. Invalid composition fails closed. Unconfigured clients retain their
existing code/token behavior. Dynamic client registration cannot enable the
extension or select a durable Session.

The session factory, client ID, existing JWT issuer/key configuration and clock
are trusted construction inputs. The service uses PostgreSQL READ COMMITTED,
requires the migration's enabled guards, never loads environment/database
defaults, and never calls Redis. It reuses the existing signer and canonical
bearer validator. No participant signing key enters this contract.

## Browser login, code admission and token generation

These are three separate identities. A successful signature verification creates
a fresh server-generated oauth_browser_generations reference, stored only in
the authenticated Flask session. It binds the exact User, original canonical
x-only subject, configured client, creation time, exclusive expiry and active
state. Its default lifetime is one hour; trusted construction may choose
1–86400 seconds. Existing cookies without this reference require fresh verified
login for the selected OAuth client. No subject-only adoption is available.

The verified-login hook consumes the actual server-issued challenge by storing
a unique SHA-256 commitment to the UTF-8 preimage
HODLXXI_BROWSER_LOGIN_PROOF_V1 followed by a NUL and the exact challenge.
The immutable browser row retains that commitment after expiry, logout and
replacement. This prevents a consumed proof from creating another generation,
even in a recreated service or another worker retaining the old challenge.
The hook checks the server challenge's original creation and exclusive expiry
under its transaction locks, and again after writes. Only actual successful
Legacy/Nostr verification branches invoke it. The generic membership helper
requires completion of that verified branch in the current request; knowing a
public key cannot establish authority.

Every code binding references the exact browser generation that admitted it.
Reservation and exchange both lock/reread that reference and its active owner
and client. The code expiry is capped by browser expiry. Code reservation
rechecks browser validity after writes, so cached admission cannot extend it.

A token/Session generation is one successful canonical authorization-code exchange for the
selected client. It creates one fresh server-generated Session ID and one
canonical OAuth token JTI. These are distinct identifiers. The mapping binds
the exact token, client, User and original canonical x-only subject.

There is at most one current generation per User/client through this service.
A successful subsequent exchange replaces all preceding mapped generations
for that pair, including generations used by other browsers. It also consumes
all outstanding bound codes for that pair. This intentionally conservative
replacement policy prevents old pending codes from restoring prior continuity.
Token replacement preserves its browser generation; it does not renew that
browser generation's expiry or consume a new login proof. A fresh verified
browser login rotates the browser generation and closes preceding browser and
token generations for that User/client, including other browsers. When the
verified login changes subject, it also closes the exact previous cookie
generation; an old cookie never supplies authority to close a replacement.
The browser generation itself is not a UBID durable Session ID.

The Session has session_type=web, exact UTC creation time (including fractional
seconds), is_active=true, and expiry equal to the signed access token's exp, capped by browser expiry.
Creation is never rounded earlier; expiry is never rounded later. The opted-in
token TTL must be positive and at most 24 hours. Token and Session extension,
generation reassignment and reactivation are prohibited. Session expiry may
only shorten. A token expiry reduction invalidates its Session and caps that
Session's stored expiry to the new bound.

The mobile service's existing whole-second clock may admit a newly created
fractional-second Session only at the next whole second. Its original _auth
checks and continuity preimage are unchanged. Replacing a generation changes
Session identity and cannot complete the prior generation's mobile operation.

## Relational representation

The source migration migrations/2026-09-13_oauth_session_lifecycle_v1.sql adds:

* oauth_browser_generations: immutable generation/owner/subject/proof identity,
  bounded validity and monotonic invalidation. The proof commitment is globally
  unique; a partial unique index permits one active browser generation per
  User/client. Rows cannot be deleted or reactivated.
* oauth_session_code_bindings: an immutable browser-generation reference and the existing
  OAuthCode primary key and a canonical subject snapshot captured during
  admitted authorization. Parent-code deletion cascades ephemeral binding
  cleanup; the binding cannot be independently deleted or rebound.
* oauth_session_generations: immutable token_id, unique session_id, user_id,
  client_id, original subject and browser-generation reference. Composite foreign keys ensure that the token
  and Session share the exact User, and that the token and browser generation
  have the exact client and original subject.
* Composite unique keys on existing oauth_tokens(id,user_id,client_id) and
  sessions(session_id,user_id), needed by those foreign keys.
* Guards preventing reassignment, resurrection and lifetime extension, and
  transaction-bound token/User/client invalidation of mapped Sessions.

No existing row is backfilled with inferred authority. No access or refresh
bearer value is copied. The code-binding foreign key references the existing
short-lived OAuth code; it is confidential and must never be logged. The
Session metadata remains SQL NULL. The relation contains no entitlement,
private key, mobile proof, device binding or Social session.
Mapped generation history is retained: referenced tokens and Sessions cannot
be deleted. Invalidate them instead. Expired OAuth codes can still be deleted
with their ephemeral subject bindings.

Separate relational linkage is necessary because OAuthCode and OAuthToken
previously referred only to User, while Session had no OAuth-generation owner.
A User join alone cannot distinguish successive logins, and arbitrary JSON
metadata cannot enforce these ownership constraints.

## Serialization and atomic issuance

All service admission/issuance/logout commands lock User, then the selected
client, then browser generation, code/token and Session as applicable. A
cross-subject verified replacement locks all affected Users in sorted ID order
before the client. Browser invalidation consumes its bound codes and revokes
its mapped tokens/Sessions transactionally through database guards.

If logout commits first, a previously admitted request cannot reserve a new
code or exchange an existing one under that generation. If issuance commits
first, subsequent logout revokes the issued token and its exact Session; a
delayed token response contains no usable authority after that revocation.
Subject equality does not satisfy this fence. Database owner/subject/client
changes also invalidate browser generations and their linked authority.

For the selected client the existing token route delegates after its existing
OAuth client authentication. The service locks and rereads the User, client and
code and bound browser generation, checks active owners, the original subject snapshot, exact redirect,
canonical allowed scopes, PKCE S256, unused code and exclusive expiry.

One outer database transaction then:

1. Prepares the existing signed access and ID-token response in memory.
2. Revokes previous mapped tokens for this User/client and consumes all its
   bound codes, including the submitted one.
3. Persists the canonical access-token digest record and the fresh Session.
4. Inserts the immutable relational mapping.
5. Revalidates the signed output, browser fence and exclusive expiry after writes.
6. Commits before returning any token.

Failures roll back code consumption, old-generation invalidation, token,
Session and mapping together. Concurrent exchanges of one code have one
winner. A response lost after commit leaves one issued generation; retrying
that code fails as already consumed and cannot create another Session. This
preserves existing OAuth one-shot semantics, without a bearer-recovery store.

## Resolver and invalidation interfaces

resolve(viewer_bearer) returns an immutable internal OAuthSessionAuthority
containing session_id and subject. These fields are never added to OAuth
responses or accepted as browser inputs. There is no resolve-by-Session-ID
interface.

The resolver verifies the canonical token's signature, issuer, client audience,
purpose, digest, scopes, timestamps, revocation and exact User binding. Its
transaction-bound record loader uses the same database as generation storage.
It locks/rereads active User/client and the exact mapped Session, then
revalidates the token after the locks. It requires a matching original subject,
User, client, creation time, active web Session and exclusive bounded expiry.
There is no clock leeway, cached-principal fallback or adoption of unmapped
credentials. An expired/revoked token cannot resolve authority.

invalidate(viewer_bearer) validates a current canonical viewer credential and
revokes that exact mapped token/Session.

invalidate_generation(token_id=..., user_id=...) is the server-only idempotent
primitive for a trusted issuer's recorded OAuth identity, including retries
after revocation or expiry. It additionally checks the configured client and
immutable owner relation. These arguments must never be sourced from browser
JSON. Retrying invalidation of an old generation cannot invalidate its
replacement or another User/client. This primitive cannot create authority.

invalidate_subject(subject) is the server-only UBID browser-lifecycle primitive:
it locks that canonical User and revokes the selected client's mapped
generations and outstanding bound codes. It accepts only identity derived from
UBID's authenticated browser state or newly verified signature, never a
submitted unsigned subject.

## Lifecycle events and remaining logout boundary

Database updates revoking a mapped OAuth token invalidate its Session in that
same transaction, including updates through the existing storage revocation
owner. Canonical tokens are stored by digest; the existing
revoke_oauth_token storage function takes that stored digest for these tokens.
The new bearer invalidation interface performs the lookup itself.

User deactivation or subject change revokes mapped tokens, invalidates their
Sessions and consumes bound codes. Client deactivation does the same for that
client. Later reactivation or restoration of the original subject does not
resurrect old generations. Explicit durable Session invalidation immediately
denies resolution and mobile _auth; it does not confer any new token authority.

When the extension is present, successful factory Legacy/Nostr verification
completes the browser generation transaction before publishing its reference
in Flask session state. The monolith's overlapping verification routes delegate
to those same verified branches when configured; its special-login verifier
uses the same completion hook after successful verification. Failed writes or
commit return no browser reference and roll back predecessor invalidation.
A failed, rolled-back proof consumption is not a committed authentication and
may be retried while its original challenge remains valid; committed proof
consumption can never be replayed.

Enabled-lifecycle GET and HEAD /logout return a non-mutating confirmation
form with a usable explicit POST action. OPTIONS performs no durable mutation.
The shared helper, blueprint and compatibility registrations apply the same
policy. Existing logout links continue to open the confirmation. No Session,
browser generation or OAuth code is invalidated by a safe method.

The POST requires one bounded form field, csrf_token, and no query string.
The proof is HMAC-SHA256 under the trusted Flask secret over
HODLXXI_BROWSER_LOGOUT_CSRF_V1, a NUL and the authenticated browser-generation
reference; comparison is constant-time. It is delivered only in the no-store
confirmation body, never a URL or log. JSON, extra/duplicate fields, malformed
proofs and proofs from another generation are rejected without mutation.
An exact Origin matching the HTTPS origin of the trusted configured JWT issuer
is also required. Missing Origin and literal null are rejected; Host,
forwarded headers, Referer and SameSite cannot bypass this check.

A valid POST invalidates only the authenticated cookie's exact generation and
its linked pending/issued authority, then clears local state after commit.
An equal retry with the old authenticated cookie and its matching proof is
idempotent and cannot revoke a newer generation. Missing or invalid durable
mapping fails closed, and storage failure does not report logout success.
The all-browser User/client policy applies to fresh verified login replacement
and the trusted administrative invalidate_subject primitive, not to an old
browser logout retry. Extension-disabled logout keeps its existing behavior.

Social local logout currently supplies no authoritative UBID notification in
this repository. Social logout/replacement must later invoke authenticated
ingress backed by the invalidation primitive, using its trusted recorded OAuth
identity and recovering the same invalidation outcome. The dormant
[mobile ingress](SOCIAL_MOBILE_AUTHORIZATION_INGRESS_V1.md) supplies the
revocation-only `invalidate_original` command and transport; Social delivery,
acknowledgement and local cleanup remain unimplemented. Its exact original
signed credential can retry only its own invalidation after expiry/revocation
and yields no authentication or replacement-generation authority.
The server-only primitive is not itself an HTTP authentication boundary.

Lifecycle-enabled GET logout with a missing/expired/revoked browser generation
still needs a safe local-cleanup path before activation. Prior adjacent/full
interpreter shutdown was not normal; CI's `os._exit(rc)` does not establish
normal shutdown. Neither caveat is fixed by mobile ingress.

The factory issues no refresh tokens and rejects refresh_token grants.
Therefore there is no refresh-based Session extension: another code exchange
creates a fresh generation and invalidates its predecessor. Legacy refresh
tokens cannot resolve or extend this lifecycle.

Existing mobile historical acceptance and exchange recovery remain governed
by their unchanged contracts. Authentication continuity grants no Full,
operator, sponsor, CRT, covenant, friendship or device-binding authority.

## Verification and activation

Tests use the existing identity-checked disposable PostgreSQL harness and
synthetic clients/users. They exercise transactional migration rollback,
constraints, issuance rollback, concurrent exchange, deterministic event-based
admission/logout and exchange/logout ordering, real signed Nostr login and
consumed-proof replay, CSRF and safe-method dispatch through logout aliases,
replacement, revocation,
subject changes, expiry, generic failures, and the actual unchanged mobile
service as the next consumer. Existing mobile fixed vectors remain unchanged.

Before any separate activation, review/apply the migration in its explicitly
authorized environment, compose the selected client/service, provide the
authenticated mobile/logout ingress and trusted original desktop/login context,
and complete Social's own session-issuer integration. Source hooks and a passing
disposable rehearsal establish none of those runtime operations.
