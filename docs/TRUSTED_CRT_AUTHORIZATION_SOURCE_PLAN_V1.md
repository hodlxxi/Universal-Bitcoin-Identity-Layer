# Trusted CRT Authorization Source Plan V1

> Status: `IMPLEMENTED_DORMANT`; `READ_ONLY_INJECTED_SOURCE_LOOKUP`;
> `SOURCE_PLAN_ONLY`; `NOT_BITCOIN_OBSERVED`; `NOT_PROOF_GENERATION`;
> `NOT_PRODUCTION_DB_WIRING`; `NOT_RUNTIME_AUTHORIZATION`; `NOT_DEPLOYED`.

PR6.17 loads trusted PR6.8, PR6.9, and PR6.10 stored domain records into
one deterministic immutable source plan. Repositories are caller-injected and
only their read methods are used. The module has no storage implementation,
SQLAlchemy, Flask, observer, RPC, PR6.16, entitlement, or authorization import.

## Public API and repository contract

`TrustedCrtAuthorizationSourcePlanAdapter(genesis_repository=...,
admission_edge_repository=..., trusted_registration_repository=...)` exposes
`resolve(participant_id=..., target_edge_id=None)`. The injected methods are
exactly:

```text
genesis_repository.list_for_graph(graph_or_protocol_id) -> tuple[CanonicalGenesisRecord, ...]
admission_edge_repository.get(edge_id) -> CanonicalAdmissionEdge | None
trusted_registration_repository.get(registration_id) -> TrustedCovenantRegistration | None
```

The result state is `READY` or `NOT_FOUND`. `NOT_FOUND` is reserved for an
exact ordinary target consistently absent on two reads and carries no plan.
Malformed requests raise `InvalidTrustedCrtAuthorizationSourceRequest`.
Unavailable, malformed, mutating, incomplete, or contradictory trusted sources
raise the sanitized `TrustedCrtAuthorizationSourceUnavailable`.

A genesis request is exactly E923 with no target. It returns depth zero, the
canonical E923 keys, all graph genesis records (including an empty tuple), and
no target or lineage. An ordinary request is an exact lowercase x-only key and
exact lowercase UUID. Its identity, keys, and depth come only from the exact
target edge; no target discovery is performed.

## Plan and traversal

`TrustedCrtAuthorizationSourcePlan` contains `schema`, `adapter_version`,
`graph_or_protocol_id`, `subject_kind`, `participant_id`,
`compressed_public_key`, `x_only_public_key`, `depth`, `target_edge_id`,
`target_edge_sha256`, `genesis_records`, `lineage_sources`, `relevant_records`,
`manifest_sha256`, `explicit_non_claims`, and
`human_interpretation_required`. Each `TrustedCrtLineageSource` contains depth,
edge ID/digest, registration ID/digest, `observation_required`, and the exact
canonical edge and registration.

The public immutable contracts independently revalidate their complete nested
state. A READY resolution must exactly match its plan identity and target; a
NOT_FOUND resolution permits only an ordinary canonical x-only participant,
one canonical target UUID, and `plan=None`. Plans enforce canonical compressed
and x-only keys, terminal-subject and target binding, contiguous root-to-target
depths, adjacent sponsor/child continuity, exact genesis-root binding, unique
source identities and digests, and the exact sorted union of relevant records.
Exact-type subclasses and cross-record identifier collisions fail closed.

Traversal starts at the exact target and follows `sponsor_basis_record_id`
until depth one, then reverses the result to root-to-target order. Every edge is
exact-type revalidated. The adapter checks ID and digest binding, depth
arithmetic, sponsor/child participant and compressed/x-only key continuity,
graph and human-profile continuity, the depth-one genesis basis, maximum depth,
and duplicate edge IDs, edge digests, and child identities. Each edge's exact
registration is retained regardless of lifecycle and checked against both
registration ID and digest bindings.

`observation_required` is true only for an EFFECTIVE edge with an ACTIVE
registration. In that case the PR6.8 materializer must produce exactly two
trusted outpoint definitions. This is only an orchestration hint; no observer
or RPC is called and no response is retained.

## Consistency and manifest

The complete genesis tuple is read twice, every selected edge and registration
is read twice, and canonical bytes—not object equality—must match. After
assembly, the target, complete genesis tuple, and every selected registration
are reread and compared again by canonical bytes. Appearance, disappearance,
mutation, malformed state, or a broken reconstructed chain fails closed. No
global transaction is assumed.

Genesis records are sorted by canonical record ID and digest. The manifest is
ASCII-safe canonical JSON with sorted keys, compact separators, no floats or
non-finite values. It binds schema/version, graph, subject and identities,
depth, target ID/digest, ordered genesis IDs/digests, ordered lineage edge and
registration IDs/digests, observation flags, sorted relevant record pairs, and
the exact non-claims. The SHA-256 is over those canonical bytes; nested source
objects are bound by their authoritative digests rather than fully embedded.
The adapter computes this digest from validated raw components before creating
the final plan. The public constructor recomputes it and rejects arbitrary,
stale, placeholder, or subsequently mutated manifest digests.

## Boundary from PR6.16 and PR6.18

PR6.16 is pure proof composition from one already supplied exact evidence
snapshot at one `evaluated_at`. PR6.17 only loads and consistency-checks trusted
stored sources into a source plan and does not invoke PR6.16.

The existing observer checks height and best-block-hash stability only inside
one observation call, while `CovenantRelationEvaluation` retains height but not
best-block hash. Calling it independently for multiple edges cannot establish
one coherent Bitcoin snapshot. PR6.18 must define a globally anchored
multi-edge observation contract binding every edge to one block height,
best-block hash, and observation window. Conversion into PR6.11 evidence,
PR6.16 invocation, participant-facing discovery, current-proof HTTP/MCP
surfaces, attestation and human verification, shadow comparison, entitlement
materialization, runtime enforcement, and deployment also remain missing.

## Explicit non-claims

The plan makes these 31 exact non-claims:

1. no Bitcoin RPC observation
2. no claim of one global Bitcoin block snapshot
3. no best-block-hash binding
4. no current UTXO claim
5. no proof generation
6. no PR6.16 invocation
7. no membership evaluation
8. no FULL/LIMITED authorization decision
9. no entitlement evidence write
10. no current-entitlement integration
11. no action-authorization integration
12. no session mutation
13. no role mutation
14. no scope grant
15. no administrator or operator grant
16. no invite or sponsor permission
17. no target-edge inference
18. no participant-facing lookup
19. no production database singleton
20. no database write
21. no migration application
22. no HTTP route
23. no MCP tool
24. no paid job
25. no CLI
26. no scheduler
27. no signing or issuer attestation
28. no proof of private-key possession
29. no authenticity claim from SHA-256 alone
30. no replacement of legacy wallet-ratio authorization
31. no deployment or production-enforcement claim
