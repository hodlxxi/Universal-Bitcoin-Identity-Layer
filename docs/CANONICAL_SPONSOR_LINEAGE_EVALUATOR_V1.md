# Canonical Sponsor Lineage Evaluator V1

> **Status: PR6.11 IMPLEMENTED_DORMANT — pure domain evaluation only.**

PR6.11 evaluates one explicit, finite evidence snapshot and proves only whether
the selected target's exact sponsor path is continuously current through
canonical PR6.10 admission edges to the selected canonical PR6.9 E923 genesis
record. It performs no automatic storage lookup.

The service supports depths 1 through 2288, the final depth whose fixed
`legacy_777` early height is positive. Input tuple order is irrelevant; output
nodes are canonical depth order. Duplicate, ambiguous, cyclic, missing,
extraneous, malformed, noncanonical, or over-depth evidence fails closed.

Every edge is evaluated locally against its exact trusted registration,
immediate sponsor basis, and exactly two current mirrored observations.
Immediate-parent identity validation does not require the historical parent
record to remain effective; this lets a revoked or disputed ancestor control
the lineage result accurately. Active requires the selected genesis and every
current ancestor and target edge to be active. After complete structural
validation, the earliest non-active source in root-to-target order controls.

The canonical result contracts are:

- local-current evaluator: `hodlxxi.canonical_admission_edge_current_evaluator.v1`
- schema: `hodlxxi.canonical_sponsor_lineage_evaluation.v1`
- evaluator: `hodlxxi.canonical_sponsor_lineage_evaluator.v1`
- verification rule: `hodlxxi.canonical_sponsor_lineage_verification.v1`
- states: `active`, `provisional`, `disputed`, `lineage_inactive`, `unknown`

The local-current result is an immutable contract separate from the PR6.10
public edge-evaluation result. Its active reason is
`exact_current_edge_active` at every valid depth and means only that exact edge
is current. It never claims that ancestry is valid. A structurally resolved
lineage always selects its exact controlling genesis reference and includes
exactly that genesis record plus one admission edge and one trusted
registration per depth, whether the resulting lineage is active or controlled
by an earlier non-active source. Structural failures select no references and
include no relevant records.

This component has no Flask route, public API, MCP tool, CLI, scheduler,
automatic Bitcoin RPC observation, persistence model, table, migration, cache,
runtime composition, production wiring, or deployment. It makes no
FULL/LIMITED decision and grants no membership, authorization, administration,
or server privilege. PR6.12 remains responsible for a generic participant CRT
membership verdict.

Its explicit non-claims are embedded in every result. In particular, a result
does not prove private-key possession, legal identity, personhood, ownership,
custody, guardianship, sponsor control, reputation, rank, decentralization,
universal legitimacy, fairness, informed consent, sincerity, loyalty,
affection, trustworthiness, or future cooperation. It is valid only for the
exact supplied evidence and `evaluated_at`, and never for `current_144` or
cooperative templates.
