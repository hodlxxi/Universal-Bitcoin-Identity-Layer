# CRT Canon and Runtime Bridge

> **Status: CURRENT DOCUMENTATION BRIDGE — documentation only; no runtime behavior change.**

## Synchronization basis and authority

This bridge synchronizes the normative CRT Canon in `hodlxxi/hodlxxi-cryptographic-reciprocity` at commit `152c87522a7d89cd5c0e7014d7915a19bf074e1a` (merged PR #42) with PR6.8 implemented from branch base `fe333cdb5068a73b4dc57b875e1b0223b01855f7`. The older commit `7df976c59742aa84fd79cfd41f12a34a33915259` is the active-runtime audit basis, not the PR6.8 source basis.

The authority order is:

1. The CRT Canon repository is the normative theory and protocol source.
2. This runtime repository records implementation components and operational truth.
3. `hodlxxi.com` is observable deployed runtime evidence, not the normative protocol source.

## Canon claims and runtime status

| Canon claim | Normative subject | Runtime evidence or component | Current implementation status |
| --- | --- | --- | --- |
| `CRT-MEMBERSHIP-001` | Current human membership is an active, uniquely rooted evidence state. | Dormant pair relation, observation/materialization, and current-entitlement evidence components. | No CRT membership-state evaluator, lineage evaluator, or authorization mapping is wired. |
| `CRT-ADMISSION-001` | One human admission edge is an exact funded `legacy_777` mirrored pair. | Dormant strict raw-script pair validator, PR6.8 exact registration, pure exact-pair relation evaluator, and trusted observation adapter. | Exact binding is implemented dormant, but no admission registry, equality decision, or production wiring exists. |
| `CRT-CASCADE-001` | Active ancestry is unique, acyclic, rooted at E923, and propagates inactivity. | No runtime cascade component. | Cascade depth, ancestry validation, and descendant propagation are missing. |
| `CRT-GENESIS-001` | E923 is depth 0 only through an effective canonical genesis record for the named V1 graph. | Public operator continuity declaration is operational evidence only. | No canonical genesis record evaluator is wired; no sponsor or admission edge may be invented for genesis. |

## Distinct domains

| Domain | Meaning | Must not be substituted with |
| --- | --- | --- |
| CRT membership state | `genesis_active`, `active`, `provisional`, `edge_inactive`, `lineage_inactive`, `disputed`, or `unknown` under the Canon protocol. | FULL/LIMITED, wallet balance, session state, administrator status, or account plan. |
| Runtime FULL/LIMITED authorization | Outcomes of a separate runtime authorization policy. | CRT membership states or CRT membership proof. |
| Commercial/account membership plan | Billing or account-plan behavior, including `app/ubid_membership.py`. | CRT human membership. |
| Runtime administration | Operational privileges, including `SPECIAL_USERS` paths. | CRT membership, sponsor power, or lineage evidence. |
| Agent delegation | Bounded operator-agent continuity under `current_144`. | Human admission, human membership, or sponsor power. |

FULL and LIMITED are explicitly not CRT membership states.

## Concise normative protocol summary

E923 is the exceptional depth-0 genesis participant of the named V1 graph only through an effective canonical genesis record. Genesis has no sponsor and no invented admission edge. Every non-genesis human needs exactly one active sponsor edge and one unique active ancestry path terminating at effective E923. A sponsor may have multiple children, but a child has at most one active sponsor. `child_depth = sponsor_depth + 1`; active ancestry is acyclic; self-sponsorship is prohibited; and participant identifiers and role-bound participant keys cannot repeat in one active path. All active humans have equal membership status regardless of depth.

Human Membership V1 exclusively uses the strictly CLTV-only `legacy_777` profile. An admission edge is exactly two mirrored, equal-funded legs for the same sponsor and child, bound to two distinct exact `txid:vout` outpoints that are currently unspent and have at least one confirmation. Direction is sender -> receiver: the receiver has the earlier unilateral CLTV branch and the sender has the later fallback branch. At child depth `d >= 1`:

```text
middle(d) = 1777777 - 777 * (d - 1)
early(d)  = middle(d) - 777
late(d)   = middle(d) + 777
```

If a required edge becomes inactive, its participant becomes `edge_inactive` and dependent descendants become `lineage_inactive` as applicable; historical evidence remains preserved.

The `current_144` profile is separate operator-agent delegation/continuity evidence. It cannot create human membership or sponsor power and must never be mixed into a `legacy_777` human lineage.

## Current runtime mismatch

At active-runtime audit basis `7df976c59742aa84fd79cfd41f12a34a33915259`, active legacy paths still derive session FULL/LIMITED in some flows from wallet-wide incoming/outgoing balance ratio, and `SPECIAL_USERS` paths also exist. These are active legacy non-Canon authorization behaviors. Wallet-wide aggregation, balance ratios, session state, and administrator allowlists are not Canon-conformant CRT admission, lineage, or membership proof, and this documentation does not silently relabel them.

## Dormant strict layers

- PR6.5 provides a dormant pure exact-counterparty relation evaluator. Its current
  boolean policy requires positive totals and
  `outgoing_sats >= incoming_sats`; that is broader than Canon V1 admission,
  which requires exactly equal positive integer-satoshi amounts. A positive
  PR6.5 decision is therefore not admission, membership, or a Canon-conformant
  equality proof.
- PR6.6 provides a dormant trusted covenant observation adapter and entitlement
  materializer. Observation and materialization preserve the PR6.5 decision;
  they do not independently repair its amount-policy mismatch.
- Persisted current entitlement evidence provides a dormant resolver/evidence layer.
- PR6.7 provides a dormant strict canonical mirrored covenant raw-script validator.
- PR6.8 provides dormant exact registration and normalized append-only storage.
  Only active registrations materialize trusted observation definitions.
  Unequal positive amounts are preserved, so registration is not admission or
  Canon equality proof. Lifecycle transition orchestration is not implemented.

The registration layer is independently constructible but is not composed into
the adapter or any production path. These strict layers are not production
enforcement. PR6.8 exact registration and outpoint binding does not fix the PR6.5
amount-policy mismatch. A future admission layer must independently enforce exact
amount equality, or the relation policy must be separately revised and reviewed.

## Implementation sequence

A. This documentation synchronization.
B. PR6.8 trusted registration and exact outpoint binding. (IMPLEMENTED_DORMANT)
C. Canonical E923 genesis-record publication, lifecycle, and fail-closed evaluation.
D. Authoritative sponsor/admission registry plus cascade lineage validation and inactivity propagation.
E. CRT membership-state evaluator.
F. Separately governed mapping from CRT membership state to participant-facing FULL/LIMITED authorization.
G. Public “why FULL” proof surface.

PR6.8 does not establish genesis, a complete admission edge, lineage, membership,
or authorization.

## Explicit non-claims

This bridge does not assert that Canon membership is implemented, enforced, deployed, funded, or active. It does not assert a canonical genesis record, trusted admission registry, lineage graph, membership evaluator, participant-facing mapping, or public proof surface exists. It changes no runtime behavior and makes no deployment claim.

## Related runtime documents

- [CRT Membership Implementation Status](CRT_MEMBERSHIP_IMPLEMENTATION_STATUS.md)
- [CRT Covenant Profile V1](CRT_COVENANT_PROFILE_V1.md)
- [Canonical Covenant Relation V1](CANONICAL_COVENANT_RELATION_V1.md)
- [Trusted Covenant Observation V1](TRUSTED_COVENANT_OBSERVATION_V1.md)
- [Current Entitlement Evidence V1](CURRENT_ENTITLEMENT_EVIDENCE_V1.md)
- [Mirrored Covenant Pair V1](MIRRORED_COVENANT_PAIR_V1.md)
- [Trusted Covenant Registration V1](TRUSTED_COVENANT_REGISTRATION_V1.md)
- [Operator Continuity E923](OPERATOR_CONTINUITY_E923.md)
