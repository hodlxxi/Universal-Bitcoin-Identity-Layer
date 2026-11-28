# Registered-device messaging sessions V1

Status: opt-in source in UBID #597 and Social #73. Production and VPS migrations
have not been changed. This is not the live acceptance gate for issue #588.

## Implemented contract

Native Enrollment V2 remains immutable provenance. Its original approval,
challenge, OAuth lineage and short-lived issuance are never extended or revived.
A registered device instead proves possession of its retained non-extractable
Ed25519 key over a fresh, single-use, purpose-separated challenge. UBID rechecks
original committed native history, active user/client/issuer, exact active
X25519 binding, epoch-1 Ed25519 association and canonical Current Full.

The transaction owner stores only the credential digest. Issuance, current read,
message authorization and revocation run on the native finalizer's directly
connected SQL role. Results leave the private boundary after commit and a final
deadline check. Protected operations recheck current authority; expiry, revocation,
Full loss, retired binding, rotation and mismatched browser context deny access.
Revocation is idempotent and can still terminate the exact credential after Full
loss or expiry. A revoked session is never treated as a valid login.

Message proofs use `HODLXXI_REGISTERED_DEVICE_MESSAGE_SESSION_BINDING_V1`, bound
to the new session generation and context, independent of enrollment's OAuth
binding. Directory, recipient packages, exact request proof, ciphertext mailbox
and inbox share the registered authority path. No registered credential is
accepted as a general-purpose OAuth token.

Social keeps the scoped credential server-side behind an opaque HttpOnly cookie.
The browser sends only public selectors and exact proof bytes. Existing device
keys remain in their approved stores. Reload reads a live session before trying
another challenge; use renews the short session before expiry. Explicit logout
revokes the scoped credential, preserves the existing mobile CSRF/logout contract,
and sets a separate HttpOnly denial preference. An explicit sign-in clears that
preference only after a successful possession proof. Concurrent proof completion
after logout cannot install a cookie. No Nostr provider is needed for this path.

## Opt-in deployment prerequisites

1. Existing native Enrollment V2 and message-delivery migrations/configuration.
2. Apply, using the existing migration owner, in this order:
   - `2026-11-24_social_registered_device_sessions_v1.sql`
   - `2026-11-24_social_registered_device_message_challenges_v1.sql`
3. The native finalizer requires SELECT and INSERT on the three new registered
   history tables, the existing message-delivery routing-table profile, and
   EXECUTE on `create_registered_device_message_challenge_v1(text,text,text,text,text)`.
   It must **not** gain INSERT on `social_device_admission_challenges`.
   The narrow definer function only stores message requests for an existing scoped
   session; it cannot create enrollment challenges. Public execution is revoked.
4. Both message-delivery manifests must explicitly set `registeredDeviceSessions`
   to boolean `true`. Omission keeps the path disabled. No manifest reader applies
   migrations or grants. The ordinary app/server defaults remain unchanged.
5. Registered login statements use the explicitly configured native Enrollment
   V2 statement key/trust set with a new signature domain. Message verification
   statements continue to use the separately configured message statement trust.
6. Catalog attestation closes the three new tables' columns, constraints, guards,
   runtime privileges and exact source of the definer writer. A missing guard,
   broader privilege, owner membership or substituted function denies access.

The history has a global hard budget of 131,072 challenges and one issue per device
per 60 seconds. Exhaustion denies issuance. A separately reviewed archive/retention
policy is still required before long-term production operation; no native history
is pruned by this feature. Initial epoch-1 associations only; later rotation must
use a separately verified lifecycle contract and is currently denied.

## Validation and remaining acceptance

The disposable PG16 paired test uses genuine signatures, immutable native
finalization, original-issuance expiry, new session issuance, digest-only storage,
replay/context/expiry denial, the new message binding, strict Social Ed25519
message verification, native inbox authorization, exact lost-response retry,
idempotent logout and catalog tamper denial. Its participants and retained route
are synthetic test fixtures, not evidence of real Alice/Bob browser acceptance.

Social tests cover retained-key resume, reload, renewal, identity mismatch, current
Full loss, wrong origin/context, replay, logout races, capability generations,
existing entry-action compatibility and normal HTTP framing.

Still required: hosted checks on both exact heads, coordinated isolated preview
activation, real automatically admitted Bob and Bob-to-Charlie, browser-local
Alice/Bob encryption -> durable ciphertext -> receiving-browser decryption, reload,
wrong/Limited denial, and trusted HTTPS phone smoke. Keep both PRs draft and #588
open until that complete vertical acceptance succeeds. Production promotion still
requires the founder's separate approval after staging acceptance.
