# Canon V2 multileg consent — durable nonce stage

**Stacked on PR #582. Dormant and proposed-only. No production migration.**

The historical V2 challenge ledger accepts only the exactly-two-output
CanonicalAdmissionProposalV2. Real mirrored funding may have several UTXOs
per side. The new multileg proposal from #582 commits all outpoints and
the aggregate trust ceiling; signatures must bind that exact canonical SHA.

## Implementation

- New independent PostgreSQL table canonical_multileg_consent_challenges_v2,
  NOT an alteration or reinterpretation of the historical two-output
  table, with a constant proposal_schema constraint and unique nonce.
- A caller starts an explicit PostgreSQL transaction, then issues a
  challenge after *external* authentication of the sponsor pubkey.
  Issuance persists the full-proposal SHA, both participant pubkeys,
  the challenge digest, nonce and 300-second expiration.
- Consumption locks that database row FOR UPDATE, reconstructs the exact
  issued challenge, validates its SHA and complete multi-outpoint proposal
  binding, requires the authenticated child's key and performs both
  role-separated Bitcoin Signed Message verifymessage checks.
  A conditional UPDATE sets consumed_at and verification_sha256 once.
  PostgreSQL triggers forbid modifying challenge details, re-consuming
  a receipt or deleting evidence.
- The caller must commit or roll back the entire transaction. A method
  return does not establish durable permission. Every returned result
  explicitly says grants_full=False and is_effective=False.
- Disposable PostgreSQL 16 tests cover 3+2 signature binding, one-time
  nonce, rollback, wrong subject, one-output tampering, expiry, bad RPC,
  duplicate nonce and immutable receipts. Signature test doubles are
  not real cryptographic proof.

## Still mandatory before effective V2 admission or deployment

1. The new ledger has no authenticated route: the key arguments are only
   equality checks against keys supplied by the caller. Trust must come
   from an independently authenticated session bound to these keys.
2. The #580 candidate registry and SQL primary key (edge_id, leg_order)
   still handle **exactly two** UTXOs and use the *historical* two-output
   nonce table. Neither is connected to this new multileg nonce ledger.
   A new versioned multioutpoint candidate registry and atomic transaction
   must bind the entire funding set and this consumed receipt.
3. An authoritative source for each effective ancestor, current Bitcoin
   UTXO and mempool/reorg state, current sponsor Full, uniqueness and
   cancellation/re-enrollment lifecycle is not yet integrated.
4. Issued or consumed consent is NOT Full; there is no entitlement
   materialization, cross-application Social Full status, encrypted
   messaging enablement, staging validation or production deployment.

**DO NOT run migrations on the live HODLXXI database or merge this
proposed-only feature as if end-to-end admission were complete.**
