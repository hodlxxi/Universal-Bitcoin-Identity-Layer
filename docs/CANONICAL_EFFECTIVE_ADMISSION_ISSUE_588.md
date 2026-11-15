# Issue #588 — Canon V2 EFFECTIVE admission and Current Full binding

**Slice 1: durable EFFECTIVE-edge/evidence transaction constraints. Draft only.**

This is the first implementation slice after the merged preflight stack (#578–#587).
It adds an immutable PostgreSQL table that binds one multileg candidate,
one child x-only identity, its exact sponsor/parent, a bounded current Full
evidence record, and a current Bitcoin tip/mempool receipt **inside one
database transaction**. PostgreSQL rejects an incomplete proposed candidate,
a missing signature consumption, an expired reservation, mismatched child
identity, stale confirmation receipt, a missing effective parent, or missing
global collateral claims.

When an effective edge exists, database triggers prevent release of its live
outpoint and child reservations. Historic candidate and consent evidence remain
immutable. In a future independently trusted admission transaction, this
implements the permanent-collateral portion of the irreversible transition.

## What this does NOT yet prove or permit

The migration and tests do **not** create a trusted authority or a public
endpoint. SQL can check that the supplied evidence fields match; it cannot
cryptographically prove the **source** of a purported Bitcoin Core RPC
observation or the user's authenticated browser/device session.

In particular, the test suite deliberately creates **synthetic** Full evidence
and chain receipts to verify transactional constraints. Their acceptance in
disposable PostgreSQL is **not** a live Full membership result. Do not expose
the table, treat a row as Current Full independently of the existing
authoritative entitlement verifier, or use these tests as proof that Bob is Full.

The following remain mandatory *before runtime activation*:

1. A server-owned, authenticated Bitcoin Core client and a fresh,
   mempool-inclusive observation of every N+M P2WSH output, bound to this
   exact proposal, tip and mempool sequence. A fake/injected RPC is not
   acceptable for production authority.
2. Server-authenticated sponsor and child sessions bound to the same exact
   compressed/x-only keys as the scripts and the nonce. Independent current
   sponsor Full and effective ancestor provenance; a proposed parent can
   never sponsor. Explicit cross-version global child-identity uniqueness.
3. One server-only transactional coordinator that verifies the above,
   rechecks Current Full at the locking boundary, then atomically writes
   current entitlement evidence and the effective edge. A partial commit,
   expired sponsor, stale receipt, reorg or spent UTXO must fail closed.
4. Current Full refresh/revocation on chain spend or reorg and matching
   UBID/Social subject mapping. Verify Bob→Charlie and two-user encrypted
   messages end-to-end in staging before a production rollout.
5. Dedicated non-owner PostgreSQL roles and explicit ownership/permissions
   audit. Existing migration-owner/superuser and TRUNCATE bypass issues must
   be resolved separately; this schema does not close those holes.

## Local verification boundary

The CI workflow uses a disposable PostgreSQL 16 instance with an explicitly
acknowledged loopback-only test URL. It composes the existing strict-two,
multileg, expiry and global UTXO-claim migrations, then the new schema.
No staging or live database is migrated. No production Runtime flag is set,
no evidence is issued for a real Bitcoin subject, and no Social status changes.

**DO NOT DEPLOY, APPLY TO LIVE DATABASES, OR MERGE AS AN END-TO-END FEATURE.**
Review this PR as the first durable SQL contract in Issue #588, not as the
authorization/composition deliverable. The next PR must add that independently
trusted transaction coordinator and tests; mere caller-provided hashes must
never be sufficient for granting Full.
