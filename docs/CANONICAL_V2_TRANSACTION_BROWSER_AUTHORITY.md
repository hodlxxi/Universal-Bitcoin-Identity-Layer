# Issue #588 — transaction-bound browser identity for proposed admission

**Stage:** source-only, OFF; this is not a Full grant or a production change.

Before this change, the Canon V2 browser ingress used
`lifecycle.browser_subject(...)`, which reads the OAuth browser generation
in a **separate** PostgreSQL transaction. A logout, replacement login, or
user/client deactivation could commit after that reader returned and
before the proposed admission's own nonce or UTXO transaction committed.

This change replaces that split read with
`locked_browser_subject_in_transaction(db, ...)`, using the **same physical
SQLAlchemy PostgreSQL Session** as the existing sponsor challenge issue
and child candidate registration.

## Exact lock and validation boundary

- Require caller-owned active PostgreSQL READ COMMITTED transaction.
- Obtain browser generation ID only from authenticated Flask session
  reference (`browser_reference()`), not from browser JSON or URL.
- Resolve configured client ID only from the server's OAuth lifecycle
  configuration. The request's Origin must equal the server's configured
  HTTPS issuer origin; require JSON POST, existing Legacy/Nostr login
  method and a canonical cookie subject matching the signed proposal.
- Under one transaction and deterministic User → OAuthClient →
  OAuthBrowserGeneration `FOR UPDATE` locks, re-read active subject,
  active client, exact non-revoked generation and UTC validity interval.
  Match generation's user/client/subject to the locked rows.
- Only after that locked check issue one-use sponsor challenge or consume
  two BTC signatures with server-owned Core and persist PROPOSED N+M
  collateral. A concurrent logout or generation replacement, which also
  locks the User and generation, cannot commit midway.
- A revoked/expired generation, inactive user/client, wrong subject,
  forged cookie, wrong Origin or missing PostgreSQL transaction fails
  closed. The PostgreSQL test additionally checks lock contention.

The stored lock-bearing identity returned here is *not a bearer token*,
not a reusable entitlement, and is valid only within the ongoing
transaction. A PR solely checking a generated SHA is not a substitute.

## Not yet EFFECTIVE or Full

This module and the ingress remain `RUNTIME_ENABLED=False`. The two
flows are independent browser requests, but the challenge still records
the sponsor compressed public key, not the sponsor's exact OAuth
generation. For future EFFECTIVE authority, the signed proposal and
challenge must carry server-authenticated issuance provenance, and the
sponsor's generation must be checked again or its legitimate revocation
semantics defined. Parent sponsorship still requires an EFFECTIVE edge,
but active parent collateral and Current Full need fresh validation.

No HTTP route is created. No effective edge or Current Full evidence is
written; there is no Social status/messaging change. No live database
migration or staging/production service restart is authorized.

The next admission coordinator must preserve one trust chain:
verified locked sponsor/child login → role-specific signed proposal →
one-use nonce → server-owned confirmed UTXOs → effective parent and
current sponsor Full → **atomic** EFFECTIVE edge plus Current Full
evidence. Verify stale/revoked collateral fail-closed, cross-version
duplicate identities and SQL role privileges in disposable PostgreSQL
and staging before any production rollout.

## CI

Disposable PostgreSQL 16 tests install minimal OAuth User/client/browser
tables and exercise two different browser generations, no consent from
inactive/revoked principals, no sponsorship from only PROPOSED parent,
and a concurrent revoke attempt blocked until the caller transaction
releases its exact generation row. Test OAuth and Bitcoin RPC fixtures
are synthetic and do not establish real-chain authority.
