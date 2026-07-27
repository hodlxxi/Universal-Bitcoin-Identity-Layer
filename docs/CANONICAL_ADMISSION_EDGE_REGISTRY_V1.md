# Canonical Admission Edge Registry V1

Status: **IMPLEMENTED_DORMANT**

PR6.10 implements a dormant authoritative canonical human admission-edge registry and
pure depth-1 current-edge evaluation. It adds no route, API, command, runtime
composition, entitlement write, Bitcoin RPC, seed, or deployed behavior. Its additive
migration is intentionally unapplied.

The source is HODLXXI Canon commit
`152c87522a7d89cd5c0e7014d7915a19bf074e1a`. The schema is
`hodlxxi.canonical_admission_edge.v1`; service, verification, and evaluator versions
are `hodlxxi.canonical_admission_edge_service.v1`,
`hodlxxi.canonical_admission_edge_verification.v1`, and
`hodlxxi.canonical_admission_edge_evaluator.v1`.

One edge binds exactly one PR6.8 registration containing two legs. Direction is
child-subject-relative: incoming is sponsor-to-child and outgoing is child-to-sponsor.
In sponsor-to-child the child/receiver has the early branch and sponsor/sender the
middle fallback. In child-to-sponsor the sponsor/receiver has the middle branch and
child/sender the late fallback.

Human V1 accepts only `cltv_only`, `legacy_777`, and delta 777. Both distinct exact
outpoints have equal positive integer amounts. This is stricter than PR6.5's separate
`outgoing_sats >= incoming_sats` relation policy.

For child depth `d >= 1`, `middle = 1777777 - 777 * (d - 1)`, `early = middle -
777`, `late = middle + 777`, and `child_depth = sponsor_depth + 1`. Depth 1 is exactly
`1777000 / 1777777 / 1778554`.

E923 is the exceptional depth-0 identifier. No stronger ordinary human identifier
convention exists in the runtime, so ordinary identifiers are exact lowercase 64-hex
role-bound x-only keys; IDs and both key encodings remain separate immutable fields.

A depth-1 edge binds the exact selected active canonical genesis record. A deeper edge
binds an exact effective immediate parent whose child is the new sponsor at the stated
depth. This proves only that static immediate-parent reference. At most one effective
edge exists per child identifier and x-only key in one graph; one sponsor may have
multiple children.

Persisted lifecycle is `proposed`, `effective`, `disputed`, `superseded`, or `revoked`.
History is append-preserved, with no update or delete methods. Evaluation returns
`active`, `provisional`, `edge_inactive`, `lineage_inactive`, `disputed`, or `unknown`.
Depth 1 is active only with an effective record, active exact registration,
`genesis_active`, and two exact unspent observations with at least one confirmation.
Missing, spent, or zero-confirmation own outputs are inactive; malformed or mismatched
evidence is unknown.

Depth greater than one never returns active in PR6.10. It returns `unknown` with
`sponsor_lineage_evaluator_unavailable`.

Every record and evaluation states that it provides no FULL/LIMITED authorization,
administration, legal identity/KYC/personhood, current key-possession, custody,
guardianship, sponsor control, fairness, consent, sincerity, loyalty, trustworthiness,
future cooperation, decentralization, universal legitimacy, reputation, rank, complete
deeper ancestry, lineage bypass, production enforcement, deployment, or operator-agent
`current_144` admission. Human interpretation is always required.

Future work is complete lineage traversal and ancestor inactivity propagation; CRT
membership-state composition; FULL/LIMITED policy mapping; and public why-FULL proof.
