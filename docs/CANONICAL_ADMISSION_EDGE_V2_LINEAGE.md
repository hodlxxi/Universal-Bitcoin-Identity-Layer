# Canonical Admission Edge V2 — proposed-only finite lineage preflight

**Stage:** Draft, stacked on PR #578. Dormant domain code. No database migration, route, Full grant or deployment.

## Why a separate V2 edge

The historical `CanonicalAdmissionEdgeV1` records are immutable. Their
script-role orientation differs from the already-funded Alice/Bob mirror,
where Alice has unilateral early and late branches while Bob has both
middle-height branches. Canon V2 validates this demonstrator orientation
without rewriting V1 or reclassifying legacy records.

`CanonicalAdmissionEdgeV2` is a distinct, canonicalized proposal-bound
object. Its fixed authorization boundary is
`proposed_only_no_admission_no_current_full`. Both `is_effective`
and `grants_full` are **always False**.

## Complete ancestor path and current UTXO snapshots

`evaluate_canonical_sponsor_lineage_v2` accepts one exact finite
path from the genesis anchor to a requested proposed edge, with both
its original registration/funding sources and independent *supplied*
current observations for each link:

- Depth 1: E923/Alice sponsors Bob, early/middle/late =
  1,777,000 / 1,777,777 / 1,778,554.
- Depth 2: Bob sponsors Charlie, early/middle/late =
  1,776,223 / 1,777,000 / 1,777,777.
- Child depth `d`: `middle=1,777,777-777*(d-1)`, with
  `early=middle-777` and `late=middle+777`.
  This fixed schedule has finite maximum depth 2,288.

Each link must contain the exact V2 proposal, its stored original
observation, ACTIVE trusted registration, EFFECTIVE funding set and
current two-output observation of the same keys, scripts, amounts
and outpoints. The current observation must be no more than 120 seconds
old, must show both outputs unspent with confirmations, and cannot be
reused as another ancestor's collateral. Every parent digest, parent
identity, depth, child key and edge ID must connect precisely. Missing,
extraneous, duplicated, cyclic or inconsistent evidence fails closed.

**A successful result proves structural consistency of supplied data,
not independent observation of the Bitcoin network.** Observations can
be caller-provided; this pure preflight does not contact Bitcoin Core.
It also does not prove committed admission, active child acceptance,
an authenticated sponsor, current Full or that a current root evaluation
was fetched from an authoritative repository. A genesis evaluation
whose `state` is active is an input, not independently established
current authority. An old parent proposal is not a Full credential.

Both `sponsor_authorized` and `grants_full` are unconditionally False.
Do not use a returned digest, read-only result or `edge` instance as a
Full/authorization token, persist it as an EFFECTIVE V2 edge, or publish
it to Social.

## Required next authority boundary

A future controlled transaction must hold the authoritative Postgres
admission and current-entitlement state locks, source authenticated
sponsor/child identities, validate issued-and-consumed signatures from
PR #578, independently refresh Bitcoin UTXO and mempool/reorg state,
validate the *currently effective* root and every V2 ancestor record,
ensure unique child/parent/outpoint ownership, and append or transition
a new durable V2 effective admission without races. Current-Full for
Bob must then be generated from this authoritative V2 source and
verified by the existing transaction-bound entitlement verifier.
Only then may Bob act as Charlie's sponsor on equal terms with Alice.

A read-only chain preflight is deliberately **not** that transaction.
PR #578 must be landed or this stacked PR must be rebased onto its
approved successor before either can be considered for deployment.
