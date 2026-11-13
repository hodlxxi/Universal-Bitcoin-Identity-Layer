# Canon V2 multileg signed proposal — proposed-only bridge

**Stacked Draft, depends on PRs #578 → #581. No runtime changes.**

## Why

The legacy Canon V2 admission intent binds exactly two same-value UTXOs.
In the actual multi-output covenant model the two P2WSH scripts may each
hold several UTXOs. The *entire* enumerated output set and collateral ceiling
must be committed to by both people before a server may claim consent.

## Implemented

A new immutable, versioned Canon V2 multi-output proposed admission:
`CanonicalMultiOutpointAdmissionProposalV2` includes:

- The exact V2 sponsor/child keys, sponsor depth and 777-block script pair.
- The full 3+2 (or 1+n) registered source-bound P2WSH outpoint list,
  each exact txid:vout, value, direction and P2WSH script hash.
- The observation digest, snapshot block height, earlier-side total,
  later-side total and **trust ceiling = min(side sums)**.
- Genesis or a structurally exact parent V2 proposal (including an existing
  strict two-output proposal as a read-only ancestor reference), matched by
  child/sponsor key, depth, ID and canonical hash.
- Three distinct historical evidence reference hashes, currently **only
  unverified references**.

The payload is deterministic canonical JSON with SHA-256. Two separate
Bitcoin Signed Messages commit to the SAME complete proposal digest,
nonce, expiry, role and each counterparty's compressed public key.
Bitcoin Core verifymessage is required to validate signatures. Tests
use a synthetic stub, **not real Bitcoin signatures**.

## Important non-claims / blockers

1. In-memory nonce generation is NOT trusted server issuance. The existing
   durable PostgreSQL issued-challenge ledger accepts the older strict
   two-output Canon V2 proposal only. A new versioned ledger binding and
   atomic consume for the multi-output proposal is required before any
   admission. Neither signature proof nor nonce here grants Full.
2. The multi-output bundle and Bitcoin observations are inputs. Current
   trusted funding registration still expects exactly one UTXO per side;
   authoritative durable multi-output registration is a separate step.
3. All ancestors are *proposals* and are not necessarily EFFECTIVE.
   The current Full verifier and complete effective-ancestor lifecycle
   must be enforced in the future transaction-bound registrar.
4. The existing proposed-only candidate table still has a UNIQUE
   (edge_id, leg_order) restriction, preventing 3+2 output storage.
   Reconcile unique UTXO claims across old and new candidate records,
   with lifecycle cancellation/expiry before deployment.
5. There is no authenticated session route, server-owned Bitcoin Core
   source, mempool/reorg safety, entitlement publication, Social bridge,
   message delivery or rollout procedure in this PR.

No merges, production migrations, service restarts or Full changes.
