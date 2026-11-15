# Issue #588 — Sponsor browser generation provenance for signed consent

**Status: proposed-only integration, disabled; not an EFFECTIVE/Current Full grant.**

PR #593 locked the exact sponsor/child OAuth browser generation in each
registration transaction. One gap remained **between** Alice's nonce issuance
and Bob's later consumption: a nonce persisted only the sponsor compressed
pubkey, not which verified server-side browser generation issued it. Alice
could log out or have her generation replaced and the old, still-unexpired
nonce could be consumed by Bob.

## Immutable consent → generation binding

Additive migration `2026-11-15_canonical_multileg_issuer_generation_binding_v2.sql`
creates a **sidecar**, rather than changing historical nonce format or its
role-separated Bitcoin message. It preserves, for each unique challenge:
its issuer's exact 64-hex OAuthBrowserGeneration ID, canonical sponsor
subject, configured OAuthClient ID, User ID, and issuance timestamp.

On sponsor issuance, after verifying the live, signed-in sponsor browser,
locked Current Full, and effective parent if applicable, the **same PostgreSQL
transaction** inserts both the one-use consent challenge and the sidecar.
SQL requires the sidecar's issuer to match nonce sponsor key, subject,
active OAuth generation, actual User/client and issued timestamp, and
forbids mutating/deleting provenance history.

On child finalization, while Bob's own verified generation remains locked,
the server looks up the exact nonce and provenance and **locks Alice's
original User, OAuthClient and OAuthBrowserGeneration in the same
transaction**. The generation must still be active and unexpired, with
matching subject, client, user and challenge hash. If Alice logged out,
switched generation, lost user/client eligibility, or the nonce lacks
provenance, finalization fails closed without consuming nonce or claiming
UTXOs. A concurrent logout cannot commit between this check and the
candidate commit.

The original domain-separated, role-specific Bitcoin signatures,
immutable proposal SHA and five-output UTXO preflight are unchanged.

## Security / rollout limits

- This new binding is enforced through the **verified browser ingress**,
  not the legacy low-level, caller-provided nonce API. Existing source-only
  old tests remain supported but unbound challenges **cannot** pass the new
  browser ingress.
- SQL checks are useful, but a PostgreSQL table owner/superuser can bypass
  triggers. Production needs a non-owner writer role and reviewed DB ACLs.
- No committed EFFECTIVE edge, no authoritative Current Full update, no
  Social entitlement, no session/deployment/route changes, and no real
  Bitcoin on-chain test is performed by this PR. `RUNTIME_ENABLED=False`.
- No live migration authorized. The sidecar is exercised only in
  disposable PostgreSQL 16 CI with synthetic users and Bitcoin RPC.
- This deliberately **invalidates old outstanding consent** after logout
  or replacement, even if Bitcoin signatures are still cryptographically
  valid. Resuming requires a **new signed one-use challenge**, not
  reactivation of an old nonce.
- A later EFFECTIVE coordinator must still lock live current Full sponsor,
  enforce global/ancestor uniqueness and active confirmed collateral,
  re-check the chain against reorgs/spends, and atomically persist
  EFFECTIVE + authoritative Current Full evidence in one transaction
  whose DB role cannot synthesize privileged evidence.

## Acceptance tests

Disposable PG16 covers challenge→exact issuer generation, immutability,
expiry/revocation, wrong-client/subject, unbound nonce denial, rollback
without consumption or reservations, and the two independent browser
generation flow. `main`, staging and production Runtime remain dormant.
