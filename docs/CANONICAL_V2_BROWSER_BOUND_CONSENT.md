# Issue #588: browser-bound sponsored admission, *PROPOSED only*

This is the first application-facing identity-binding composition following PRs
#589–#591. It uses the **existing OAuth browser generation owner**, not a
request body `pubkey`, a cached `access_level`, a generic Flask signed
cookie, a caller-chosen Bitcoin Core, or a fabricated Current Full claim.

## Two independent verified-browser operations

1. Alice logs in through the existing signature-verified legacy/Nostr
   browser flow, with an active server-side `OAuthBrowserGeneration` and
   a same-origin POST. The sponsor method resolves the exact generation
   via `configured_lifecycle(...).browser_subject(browser_reference())`,
   checks that both the canonical login subject and signed proposal sponsor
   agree, verifies locked Current Full through PostgreSQL, ensures any
   non-root parent is **EFFECTIVE**, and issues a one-use role-separated
   consent challenge through the existing durable PostgreSQL ledger.
2. Bob, on his own separately verified browser generation, submits the
   exact immutable proposal plus both BTC signatures and the issued
   challenge digest. The child method resolves the canonical subject from
   his **own** active generation, checks the effective sponsor parent, and
   invokes the server-owned Core/mempool revalidation, Current Full sponsor
   lock, nonce consumption and atomic multi-UTXO PROPOSED registration.
   All writes use the same caller-owned transaction; errors require rollback.

Distinct subject keys and signed role-specific messages mean Bob cannot
complete enrollment by presenting Alice's browser cookie. A guessed or
revoked generation, guest login, missing origin, request-supplied identity
or disabled OAuth lifecycle fail closed. No new HTTP routes are registered.

## Important limitations and deployment blockers

**NO Full or EFFECTIVE admission is granted here.** This source-only module
has `RUNTIME_ENABLED=False`. Its PostgreSQL output remains
`candidate_only_no_full`; it never inserts into the EFFECTIVE table,
creates Current Full rows, promotes Social users, or changes messaging.

- `browser_subject` currently validates the browser generation in its
  **own** lifecycle transaction. Before EFFECTIVE promotion, re-check and
  lock both browser generations and User rows in the **same physical
  PostgreSQL transaction** as the admission edge. This eliminates the
  logout/revocation race between session validation and durable commit.
- Generation provenance for the sponsor at challenge issuance is not yet
  preserved in the challenge table: cancellation/logouts must be bound to
  issuance before EFFECTIVE is possible.
- The proposal object is not constructed by a reviewed request parser or
  backed by a persisted signed-proposal document yet. No ingestion
  endpoint exists. The caller must NOT deserialize arbitrary application
  objects into trusted classes without a strict parser and size bounds.
- Exact source and CURRENT evidence of E923 genesis must be verified, not
  accepted as caller-provided `sponsor_basis`.
- DB role ownership, cross-version child identity uniqueness, atomic
  EFFECTIVE edge + Current Full writing, mempool drift/reorg and
  revocation/refresh fail-closed semantics all remain mandatory.
- Do not set a feature flag, migrate a live database, restart services,
  assume staging is isolated, or treat CI as proof of real Bitcoin funds.

## CI

Dedicated disposable PostgreSQL 16 integration tests exercise sponsor and
child in *separate Flask request contexts*, positive five-outpoint
reservation, wrong child, missing sponsor session, and a merely PROPOSED
parent rejected as a sponsor. Unit tests cover cookie claim spoofing,
wrong origin, guest, missing or revoked generations. The test lifecycle
and Bitcoin RPC are deliberately synthetic; these tests establish code
composition, **not** live Full or cryptographic provenance.

**Next milestone:** a transaction-bound active-generation proof and
trusted EFFECTIVE/Current Full coordinator, then read-only staging audit,
isolation rehearsal and controlled Alice → Bob → Charlie admission test.
