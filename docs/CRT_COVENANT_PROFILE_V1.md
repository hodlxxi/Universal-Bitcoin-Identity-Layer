# CRT Covenant Profile V1

> **Status: CURRENT CANON-TO-RUNTIME PROFILE MAPPING — documentation only.**

Canon basis: CRT Canon commit `152c87522a7d89cd5c0e7014d7915a19bf074e1a`; PR6.8 implementation branch base: `fe333cdb5068a73b4dc57b875e1b0223b01855f7`.

## Profile comparison

| Property | `legacy_777` | `current_144` |
| --- | --- | --- |
| Exact family | Strict `cltv_only` | `cooperative_2_of_2_cltv` with CLTV fallbacks |
| Use | Human Membership V1 admission | Operator-agent delegation/continuity |
| Participants | Exactly one human sponsor and one human child | Operator and delegated agent |
| Delta | Exactly 777 blocks | Exactly 144 blocks |
| Pair requirement | Exactly two mirrored legs for the same sponsor and child | Human admission pair rules do not apply; the public declaration is one leg |
| Funding/UTXO requirement | Two distinct exact `txid:vout` outpoints, equal positive integer satoshi amounts, both currently unspent and at least one confirmation | Public declaration is unfunded and not on-chain verified |
| Membership effect | May support an admission edge only when all genesis, registry, observation, ancestry, and state rules also pass | None |
| Sponsorship effect | An active human member may sponsor multiple children; a child may have at most one active sponsor | None; an agent cannot sponsor a human |
| Current runtime status | Strict validation/observation/relation components are dormant; no admission or membership evaluator is wired | `DECLARED_UNFUNDED` single public operator-agent leg |

`legacy_777` and `current_144` must never be mixed in one human lineage.

## Direction and branch semantics

Direction is always sender -> receiver. In each directed leg, the receiver has the earlier unilateral CLTV branch and the sender has the later fallback branch.

For a sponsor and child:

- Sponsor -> child: sponsor is sender; child is receiver; child/receiver is earlier; sponsor/sender is later.
- Child -> sponsor: child is sender; sponsor is receiver; sponsor/receiver is earlier; child/sender is later.

The two legs must use equal funded amounts and bind two distinct exact outpoints.

## `legacy_777` depth schedule

For child depth `d >= 1`:

```text
middle(d) = 1777777 - 777 * (d - 1)
early(d)  = middle(d) - 777
late(d)   = middle(d) + 777
```

| Child depth | early -> middle -> late |
| --- | --- |
| 1 | `1777000 -> 1777777 -> 1778554` |
| 2 | `1776223 -> 1777000 -> 1777777` |
| 3 | `1775446 -> 1776223 -> 1777000` |

The depth-1 pair is the first admission edge from E923 to a child, not a genesis self-covenant. Every deeper admission shifts the complete three-height schedule 777 blocks earlier.

## Strict rejection rules

Evaluation fails closed for duplicate legs; a single leg; mixed counterparties; wallet-wide aggregation; balance-ratio substitution; unfunded declarations; arbitrary deltas; mixed script families; profile mixing; unequal or non-positive amounts; the same outpoint twice; spent outpoints; unconfirmed outpoints; self-sponsorship; ambiguous sponsor edges; cycles; repeated participant identifiers or role-bound participant keys in one active path; or an active non-genesis path that does not terminate exactly at effective E923.

## Separate evaluation layers

1. **Pair validation:** parse and validate the two exact mirrored raw scripts and their roles/profile.
2. **Registration:** bind one validated pair to two distinct exact outpoints; only active registrations materialize observation definitions.
3. **Observation:** verify registered exact outpoints, amount, script, confirmations, and current unspent state.
4. **Relation decision:** evaluate the exact subject/counterparty evidence without wallet-wide aggregation.
5. **Membership:** evaluate effective genesis, unique admission, complete ancestry, cascade activity, and one of the Canon membership states.
6. **Authorization:** under a separately governed policy, map evaluated state to participant-facing runtime access.

FULL and LIMITED are authorization outcomes, not CRT membership states. Success at an earlier layer does not imply success at a later layer.
In particular, dormant PR6.5 currently returns a positive relation decision when
both totals are positive and `outgoing_sats >= incoming_sats`. That policy is
broader than Canon V1 admission's exact equal-positive-amount requirement. A
positive PR6.5 decision is not admission, membership, or a Canon-conformant
equality proof, and PR6.6 observation/materialization does not repair the
mismatch. PR6.8 exact registration/outpoint binding is IMPLEMENTED_DORMANT and
does not repair it
either. A future admission layer must enforce exact equality independently, or
the relation policy must be separately revised and reviewed.

## Implementation sequence

A. Documentation synchronization.
B. PR6.8 trusted registration and exact outpoint binding. (IMPLEMENTED_DORMANT)
C. Canonical E923 genesis-record publication, lifecycle, and fail-closed evaluation.
D. Authoritative sponsor/admission registry plus cascade lineage validation and inactivity propagation.
E. CRT membership-state evaluator.
F. Separately governed FULL/LIMITED authorization mapping.
G. Public “why FULL” proof.

PR6.8 does not establish genesis, a complete admission edge, lineage, membership,
or authorization.

## `current_144` public declaration boundary

The public operator-agent covenant is a declared, unfunded single leg. It is not a mirrored pair, funding, membership, sponsor power, or entitlement. Delegation does not make the agent a V1 human member and does not authorize the agent to sponsor a human independently.

## Explicit non-claims

This mapping does not claim that either profile is funded, that the public declaration is observed on-chain, or that Canon-conformant admission, genesis, lineage, membership, authorization, or production enforcement is wired. It changes no runtime behavior.

## Related documents

- [Mirrored Covenant Pair V1](MIRRORED_COVENANT_PAIR_V1.md)
- [Trusted Covenant Observation V1](TRUSTED_COVENANT_OBSERVATION_V1.md)
- [Trusted Covenant Registration V1](TRUSTED_COVENANT_REGISTRATION_V1.md)
- [Canonical Covenant Relation V1](CANONICAL_COVENANT_RELATION_V1.md)
- [CRT Runtime Bridge](CRT_RUNTIME_BRIDGE.md)
- [CRT Membership Implementation Status](CRT_MEMBERSHIP_IMPLEMENTATION_STATUS.md)
