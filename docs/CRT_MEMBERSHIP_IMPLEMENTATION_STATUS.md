# CRT Membership Implementation Status

> **Status: CURRENT IMPLEMENTATION INVENTORY — documentation only.**

Canon basis: `hodlxxi/hodlxxi-cryptographic-reciprocity` commit `152c87522a7d89cd5c0e7014d7915a19bf074e1a`. Runtime inventory basis: commit `7df976c59742aa84fd79cfd41f12a34a33915259`.

The only status terms used here are `IMPLEMENTED_DORMANT`, `ACTIVE_LEGACY_NON_CANONICAL`, `MISSING`, `DECLARED_UNFUNDED`, and `DOCUMENTED`.

## Inventory matrix

| Requirement | Canon rule | Runtime component/evidence | Status | Gap/next boundary |
| --- | --- | --- | --- | --- |
| Canon bridge docs | Canon is normative; runtime records implementation truth. | This document, [bridge](CRT_RUNTIME_BRIDGE.md), and [profile](CRT_COVENANT_PROFILE_V1.md). | DOCUMENTED | Documentation is not code or enforcement. |
| Canonical genesis record | E923 is depth 0 only through an effective record for the named V1 graph, with no sponsor or invented edge. | No evaluator is wired. | MISSING | Define, publish, and evaluate an effective canonical genesis record. |
| Exact mirrored raw-script validator | Admission requires two strict `legacy_777` CLTV-only mirrored legs. | PR6.7 canonical mirrored covenant pair validator. | IMPLEMENTED_DORMANT | Connect only through trusted registration and observation; validation alone is not admission. |
| Exact pair relation evaluator | Evaluate one exact subject/counterparty pair without wallet-wide aggregation; Canon admission separately requires equal positive leg amounts. | PR6.5 pure canonical covenant relation evaluator. | IMPLEMENTED_DORMANT | Its positive policy is `outgoing_sats >= incoming_sats`, so it is broader than Canon equality and is not admission, membership, or equality proof. |
| Trusted exact-outpoint observation | Exact outpoints must be confirmed, unspent, amount-bound, and script-bound. | PR6.6 trusted observation adapter. | IMPLEMENTED_DORMANT | No trusted definitions are registered or production-composed; observation does not repair PR6.5 amount semantics. |
| Entitlement materializer | Materialize relation decisions as runtime authorization evidence. | PR6.6 evidence materializer. | IMPLEMENTED_DORMANT | FULL/LIMITED are authorization evidence outcomes, not membership states; materialization does not turn the PR6.5 boolean into Canon admission. |
| Persisted current entitlement evidence | Preserve bounded current authorization evidence with fail-closed latest-state resolution. | Current entitlement evidence store/resolver. | IMPLEMENTED_DORMANT | No production membership evaluation or policy mapping is wired. |
| Trusted registration/outpoint binding | Bind declarations to exact trusted `txid:vout`, roles, amounts, and scripts. | Future PR6.8. | MISSING | PR6.8 is this boundary only; it does not complete membership. |
| Unique sponsor/admission registry | Each non-genesis child has at most one active sponsor and one exact active admission edge. | No registry is wired. | MISSING | Add authoritative uniqueness and lifecycle semantics after exact binding. |
| Cascade depth and acyclic lineage validation | `child_depth = sponsor_depth + 1`; no self-sponsorship, cycles, repeated identifiers, or repeated role-bound keys; all active paths terminate at E923. | No graph evaluator is wired. | MISSING | Build fail-closed lineage traversal against effective genesis and registered edges. |
| Ancestor inactivity propagation | Inactive edges produce `edge_inactive` and dependent `lineage_inactive` states while preserving history. | No cascade propagation component is wired. | MISSING | Add observation-context evaluation and descendant propagation. |
| CRT membership-state evaluator | Emit only `genesis_active`, `active`, `provisional`, `edge_inactive`, `lineage_inactive`, `disputed`, or `unknown`. | No evaluator is wired. | MISSING | Compose genesis, admission, current UTXO evidence, and complete ancestry. |
| FULL/LIMITED authorization policy mapping | Authorization must be separately governed from membership. FULL and LIMITED are not CRT membership states. | No Canon-conformant participant-facing mapping is wired. | MISSING | Define and review policy only after membership-state evaluation. |
| Public why-FULL proof | Explain current authorization from bounded evidence and policy. | No public proof surface is wired. | MISSING | Expose only after evaluation and mapping are defined. |
| Active wallet-wide ratio path | Wallet-wide aggregation and ratio substitution fail Canon admission. | Active legacy session FULL/LIMITED paths use incoming/outgoing balance ratios in some flows. | ACTIVE_LEGACY_NON_CANONICAL | Keep truthfully labeled until separately replaced; it is not CRT proof. |
| SPECIAL_USERS/admin paths | Administration is distinct from membership. | Active allowlist/administrator authorization paths. | ACTIVE_LEGACY_NON_CANONICAL | Do not infer membership, sponsor status, or lineage from administrator access. |
| Operator-agent `current_144` declaration | Delegation/continuity is separate from human `legacy_777` membership. | Public one-leg operator-agent declaration. | DECLARED_UNFUNDED | A single unfunded leg is not a pair, funding, admission, membership, sponsor power, or entitlement. |

## PR6.8 acceptance boundary

PR6.8 should establish a trusted registration source that binds an exact declaration to exact `txid:vout`, subject and counterparty identities, sender -> receiver direction, roles, expected integer satoshi amount, exact script digest, profile/family, and lifecycle controls needed by the observation adapter. It should fail closed for duplicates, ambiguity, mixed counterparties, mixed profiles, or missing bindings.

Acceptance of PR6.8 does not establish an effective genesis record, sponsor uniqueness, a complete admission edge, cascade ancestry, inactivity propagation, CRT membership state, a FULL/LIMITED policy mapping, or a public “why FULL” proof. Those remain separate boundaries.
Exact registration and outpoint binding also do not fix PR6.5's broader
`outgoing_sats >= incoming_sats` policy. A future admission layer must enforce
exact equality independently, or the relation policy must be separately revised
and reviewed.

## Future sequence

A. Documentation synchronization.
B. PR6.8 trusted registration/exact outpoint binding.
C. Canonical E923 genesis-record publication, lifecycle, and fail-closed evaluation.
D. Authoritative sponsor/admission registry plus cascade lineage validation and inactivity propagation.
E. CRT membership-state evaluator.
F. Separately governed FULL/LIMITED authorization mapping.
G. Public “why FULL” proof.

PR6.8 does not establish genesis, a complete admission edge, lineage, membership,
or authorization.

These documents are not code. They do not change the status, wiring, deployment state, or runtime behavior of any component. No current production enforcement is claimed.
