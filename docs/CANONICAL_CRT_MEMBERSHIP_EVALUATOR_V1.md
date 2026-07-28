# Canonical CRT Membership Evaluator V1

**Status: PR6.12 `IMPLEMENTED_DORMANT`.**

This pure domain service answers one question under one exact canonical source
evaluation and the identical whole-second UTC `evaluated_at`: what is the
participant's current CRT Membership V1 state?

E923 is the exceptional `genesis` subject. Its exact depth-0 identity consumes
one `CanonicalGenesisEvaluation`. Every `ordinary` subject has depth at least
one, is identified by its x-only key, names its target edge, and consumes one
`CanonicalSponsorLineageEvaluation`. The evaluator never accepts raw edges,
registrations, observations, or a graph to traverse.

The fixed identifiers are:

- schema `hodlxxi.canonical_crt_membership_evaluation.v1`
- evaluator `hodlxxi.canonical_crt_membership_evaluator.v1`
- verification rule `hodlxxi.canonical_crt_membership_verification.v1`
- graph `hodlxxi.crt_membership_graph.v1`
- network `bitcoin`
- human profile `legacy_777`

The seven states are `genesis_active`, `active`, `provisional`,
`edge_inactive`, `lineage_inactive`, `disputed`, and `unknown`. An inactive
participant target edge maps only to `edge_inactive`; an inactive ancestor or genesis maps only to `lineage_inactive`. PR6.11's reason and controlling fields,
not membership depth inference, determine that distinction.

Canonical source binding requires the exact graph and timestamp. Ordinary
sources also require the exact network, profile, target edge, and, when PR6.11
provides it, target participant identity and depth. Binding mismatches fail
closed to `unknown`; malformed public requests raise only
`InvalidCanonicalCrtMembership`. Structural PR6.11 unknown results retain
absent target metadata without fabricating an edge digest or identity proof.
The source state/reason matrix is validated unconditionally, including for
binding failures. Supplying the opposite valid canonical source kind returns
`unknown/source_kind_mismatch` while preserving that actual source's digest,
state, reason, and relevant-record tuple.

Active ordinary membership requires both the selected genesis record pair and
the target admission-edge pair in the exact source relevant-record tuple, in
addition to the depth-derived record count. A correct count alone is never
sufficient. Every non-null target or selected-genesis reference must be backed
by its exact relevant-record pair.

Genesis-evaluation and membership-evaluation identities use sorted-key,
compact, ASCII canonical JSON, strict whole-second UTC `Z`, canonical lowercase
UUIDs and SHA-256 values, duplicate-key and float rejection, exact field sets,
and byte-for-byte canonical parsing.

This service performs no storage lookup, database access, Bitcoin RPC, LND,
HTTP, subprocess, route, API, MCP, CLI, scheduler, cache, model, migration, or
runtime composition. It grants no FULL/LIMITED role, entitlement, invite or
sponsor permission, administration privilege, or authorization write.
PR6.13 remains responsible for the separate membership-to-FULL/LIMITED policy
mapping.
