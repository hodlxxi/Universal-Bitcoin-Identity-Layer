# Canon V2 multiple-output mirrored funding — compatibility preflight

**Scope:** new proposed-only V2 source-bound bundle, stacked after Draft PR #580.
**No production/Runtime changes; no database migration, Full grants or session route.**

## Blocker addressed

The current `TrustedCovenantRegistration` and V2 admission proposal
are limited to **exactly two** outpoints, one per direction, and the
admission proposal requires **equal individual satoshi amounts**.
That is not representative of all financed HODLXXI mirrored contracts.
The V2 bundle introduces a *separate* representation allowing
multiple distinct registered P2WSH UTXOs per side and unequal
aggregate balances; V1 and the earlier V2 candidate contract remain
unchanged.

An example with 3 earlier-leg outputs × 100,000 sats and 2 later-leg
outputs × 150,000 sats has a trust ceiling of 300,000 sats.
If earlier is 150,000 sats and later is 100,000 sats, the ceiling is
100,000 sats. This is the **smaller aggregate**, not the larger
balance, one arbitrarily selected output or an invented 1:1
requirement.

## Validation

`CanonicalMultiOutpointMirrorV2` binds exact:
- Canon V2 sponsor-early, child-middle, sponsor-late script policy and
  full schedule for the child depth;
- compressed sponsor and child keys via canonical x-only subject and
  counterparty identities on every output;
- one or more P2WSH outpoints *per leg*, each distinguished by
  (txid,vout), expected scriptPubKey SHA-256 and amount;
- a fresh, complete, confirmed and unspent observation (max 120s).
  Any missing, spent, unconfirmed or mismatched output fails closed.

`observe_canonical_multi_outpoint_mirror_v2` can use the existing
Bitcoin Core-style trusted observation adapter and will check the
network snapshot height/hash consistency and individual outputs.
It is still an *injected* RPC. The existing adapter calls
`gettxout(..., False)`, which does not prove that a transaction
spending an output is absent from mempool. A future authority must
add mempool-aware policy and obtain a verified trusted RPC dependency.

All outputs carry **grants_full=False**, **is_effective=False** and
**source_is_authoritative=False**.

## Remaining before merging as a functional end-to-end feature

1. Replace the strict two-outpoint V2 proposal and candidate ledger
   bindings with a versioned multileg/aggregate registration, without
   rewriting existing V1 immutable evidence. Ensure migration and
   lifecycle support parent/child relationship transitions.
2. Add independent server-side registration provenance, effective
   ancestor checks, authentic signed sessions, mempool/reorg-safe
   Bitcoin observations and transactional Full materialization.
3. Test funded Alice/Bob pairs and Bob/Charlie in staging, confirm
   UBID and Social agree on current Full, and execute encrypted
   Alice↔Bob messages before production rollout.

**This PR is a source-compatibility prerequisite, not automatic
admission.** Prior Draft PRs #578–#580 may pass their CI while still
being incompatible with a funded 3+2 UTXO mirror. Do not merge or
deploy any component on the assumption that this is already wired.
