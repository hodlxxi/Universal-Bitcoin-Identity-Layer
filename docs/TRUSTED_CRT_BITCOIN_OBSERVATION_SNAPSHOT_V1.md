# Trusted CRT Bitcoin Observation Snapshot V1

PR6.19 may consume this exact resolution through the dormant fixed HODLXXI V1
local composer. PR6.18 itself remains observation-only and does not generate a
proof or authorize runtime behavior.

> Status: `IMPLEMENTED_DORMANT`; `READ_ONLY_INJECTED_BITCOIN_OBSERVATION`;
> `GLOBALLY_ANCHORED_MULTI_EDGE_SNAPSHOT`; `BEST_BLOCK_HASH_BOUND`;
> `SOURCE_PLAN_CONSUMER_ONLY`; `NOT_LINEAGE_EVIDENCE_CONVERSION`;
> `NOT_PROOF_GENERATION`; `NOT_PRODUCTION_RPC_WIRING`;
> `NOT_RUNTIME_AUTHORIZATION`; `NOT_DEPLOYED`.

PR6.18 consumes one exact PR6.17 `TrustedCrtAuthorizationSourcePlan`. PR6.17
constructs a deterministic plan from injected trusted canonical storage;
PR6.18 performs no repository lookup. It observes only plan sources whose
`observation_required` flag is true and binds them to one globally stable
Bitcoin height, best-block hash, and observation window. It neither converts
results to PR6.11 evidence nor invokes PR6.16.

## Public API

`TrustedCrtBitcoinObservationSnapshotAdapter(rpc=..., clock=None)` exposes
`observe(source_plan=...) -> TrustedCrtBitcoinObservationResolution`. The
injected RPC must expose exactly the required reads `getblockcount()`,
`getbestblockhash()`, `getblockhash(height)`, and
`gettxout(txid, vout, include_mempool)`. Every outpoint call passes
`include_mempool=False`. The adapter has no production RPC singleton or
configuration.

Resolution states are `OBSERVED` and `NOT_REQUIRED`. `NOT_REQUIRED` means the
validated plan has no required source; it retains the exact plan-manifest
SHA-256, has `snapshot=None`, and calls neither RPC nor clock. `OBSERVED`
requires an exact snapshot. Failures become the sanitized
`TrustedCrtBitcoinObservationUnavailable`; `KeyboardInterrupt` and
`SystemExit` propagate.

## Global anchor and call order

Before clock or RPC, the adapter completely revalidates and deep-detaches the
plan, captures its canonical manifest bytes and SHA-256, materializes exactly
two authoritative PR6.8 outpoints per required source, revalidates them, sorts
each pair by `(txid, vout, direction)`, and rejects duplicate global
`(txid, vout)` identities.

For an observed plan the live call order is:

1. clock for normalized UTC `observation_started_at`;
2. `getblockcount`, `getbestblockhash`, `getblockhash(start_height)`;
3. two `gettxout(..., False)` calls per required relation, in root-to-target
   relation order and canonical outpoint order;
4. `getblockcount`, `getbestblockhash`, `getblockhash(end_height)`;
5. clock for normalized UTC `observation_completed_at`.

Both height/hash pairs must match, each height lookup must equal its reported
best hash, and completion cannot precede start. A pinned façade supplies the
captured height and hash to the existing public trusted observer, which retains
the authoritative amount, script, descriptor, confirmations, null-response,
and non-null `bestblock` validation. Thus nested evaluations share the exact
start timestamp and height while the outer snapshot retains the best hash.

## Immutable contracts and canonicalization

`TrustedCrtObservedLineageRelation` contains `depth`, `edge_id`, `edge_sha256`,
`registration_id`, `registration_sha256`, `trusted_outpoints`,
`trusted_outpoints_sha256`, `relation_evaluation`, and
`relation_evaluation_sha256`.

`TrustedCrtBitcoinObservationSnapshot` contains `schema`, `adapter_version`,
`source_plan_manifest_sha256`, the fully detached and revalidated exact
`source_plan`, `graph_or_protocol_id`, `participant_id`,
`target_edge_id`, `source_plan_depth`, `observed_block_height`,
`observed_best_block_hash`, `observation_started_at`,
`observation_completed_at`, ordered `observed_relations`, `snapshot_sha256`,
`explicit_non_claims`, and `human_interpretation_required`.

The public snapshot constructor deep-detaches and completely revalidates its
exact PR6.17 source plan, recomputes its canonical manifest bytes and digest,
and derives the exact root-to-target subset whose `observation_required` flag
is true. Every relation must match the corresponding source depth, edge and
registration identity/digest, authoritative rematerialized outpoints, subject,
counterparty, height, timestamp, observations, and evaluation digest. Missing,
extra, duplicated, reordered, non-required, or foreign relations fail closed.

The outpoint manifest is canonical ASCII JSON using built-in primitives,
sorted keys, compact separators, and no floats or non-finite values. It binds
schema and each exact subject, counterparty, direction, txid, vout, amount,
script digest, and descriptor digest in `(txid, vout, direction)` order.

`trusted_crt_bitcoin_observation_snapshot_bytes` emits canonical ASCII JSON
with sorted keys and compact separators. It binds schema/version, plan digest,
graph, participant, target, plan depth, global height/hash, both timestamps,
ordered relation identities and source digests, outpoint-manifest digests,
relation-evaluation digests, and exact non-claims. `snapshot_sha256` is excluded
from its own payload. The complete source plan is intentionally omitted from
canonical snapshot JSON because that payload already binds its authoritative
manifest digest; it remains present in the immutable in-memory contract so
constructors and serializers can prove semantic consistency. Public
constructors and serializers revalidate nested objects and the exact digest.
Deep plan detachment, reconstruction of every
definition/evaluation, and immediate scalar/canonical capture prevent caller
plan, outpoint, or mutable RPC dictionary aliases from affecting results.

An `OBSERVED` resolution independently reconstructs its snapshot and requires
its digest to equal both the snapshot digest field and the validated embedded
plan manifest. A standalone `NOT_REQUIRED` resolution is only a digest-bearing
result: the adapter obtains that digest from a fully validated plan, but its
public constructor does not independently claim plan authenticity because it
contains no snapshot or source plan.

## Explicit non-claims

The snapshot makes these 36 exact non-claims:

1. no transaction broadcast
2. no signing
3. no wallet import
4. no custody
5. no LND call
6. no production RPC singleton
7. no production RPC configuration
8. no database read
9. no database write
10. no repository lookup
11. no target-edge discovery
12. no participant discovery
13. no lineage-evidence conversion
14. no PR6.16 invocation
15. no membership evaluation
16. no FULL/LIMITED decision
17. no authorization proof generation
18. no entitlement evidence write
19. no current-entitlement integration
20. no action-authorization integration
21. no session mutation
22. no role mutation
23. no scope grant
24. no administrator/operator grant
25. no invite/sponsor permission
26. no proof of private-key possession
27. no signature or issuer attestation
28. no finality guarantee beyond reported confirmations
29. no claim after observation_completed_at
30. no mempool-inclusive observation
31. no HTTP route
32. no MCP tool
33. no paid job
34. no CLI
35. no scheduler
36. no deployment or production-enforcement claim

## Deferred PR6.19 boundary

Still missing are conversion of observed relations into exact PR6.11 edge
evidence; composition with inactive/disputed non-observed sources; PR6.16
invocation; current-proof lookup; HTTP/MCP surfaces; attestation; entitlement
materialization; shadow authorization; enforcement; and deployment.
