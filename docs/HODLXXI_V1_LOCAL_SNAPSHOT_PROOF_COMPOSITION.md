# HODLXXI V1 Local Snapshot Proof Composition

Status: `IMPLEMENTED_DORMANT`, `HODLXXI_V1_PROFILE_SPECIFIC`,
`LOCAL_UNSIGNED_SNAPSHOT_COMPOSITION`, `SOURCE_PLAN_BOUND`,
`BITCOIN_SNAPSHOT_BOUND`, `PR6_11_EVIDENCE_COMPOSITION`,
`PR6_16_PROOF_RESOLUTION`, `NOT_PORTABLE_AUTHORITY`, `NOT_SIGNED`,
`NOT_ATTESTED`, `NOT_REPLICA_PROTOCOL`, `NOT_FORK_DETECTION`,
`NOT_LIVE_SOURCE_LOOKUP`, `NOT_RUNTIME_ENTITLEMENT`,
`NOT_RUNTIME_AUTHORIZATION`, `NOT_DEPLOYED`.

This dormant pure service composes one exact PR6.17 source plan and its exact
PR6.18 pinned Bitcoin observation resolution into PR6.11 edge evidence, then
calls the public PR6.16 explicit-snapshot resolver. The output is an unsigned
local evaluation. It does not change production authorization behavior.

## Fixed profile boundary

This is exactly the named HODLXXI Network Profile V1:
`hodlxxi.crt_membership_graph.v1`, fixed genesis participant E923 and its
existing keys, Bitcoin, human profile `legacy_777`, anchor middle height
1777777, and delta 777. It is not a generic multi-genesis protocol and does not
support `vasya.crt.graph.v1` or arbitrary profiles.

## Public contract

`HodlxxiV1SnapshotProofCompositionRequest` contains only `source_plan`,
`bitcoin_observation_resolution`, `evaluated_at`, and `freshness_deadline`.
Exact built-in/domain types are required; subclasses are rejected. Nested
caller-owned values are detached and revalidated.

`compose_hodlxxi_v1_snapshot_authorization_proof(request)` returns an immutable
`HodlxxiV1SnapshotProofCompositionResult`. Canonical result and evidence bytes
and SHA-256 helpers bind the source-plan manifest, pinned snapshot, ordered edge
and registration digests, observation digests, PR6.14 proof digest, timestamps,
profile, and all local metadata.

The result retains fully detached exact copies of both the PR6.17 source plan
and PR6.18 observation resolution (including its snapshot), as well as the
exact PR6.11 evidence and PR6.14 proof. These nested objects are validation
bindings; the public canonical JSON commits to them through their authoritative
digests rather than embedding their complete JSON.

Every result construction and every public serialization revalidates the
detached plan and resolution, recomputes the plan manifest and snapshot digest,
reconstructs the ordered PR6.11 evidence from the plan's authoritative
`source.observation_required` flags and exact observed relations, and invokes
the public PR6.16 resolver again. The supplied PR6.14 proof must have byte-exact
canonical equality with that expected proof. All derived identity, depth,
Bitcoin basis, observation-window, evidence-manifest, proof-digest, time, and
result-digest fields must then agree. Replacing a scalar or any valid nested
object and recomputing only the outer result SHA-256 therefore fails closed.

Both timestamps must be exact timezone-aware UTC datetimes at whole-second
precision. No clock is read and no rounding or normalization occurs. The local
freshness deadline must not precede evaluation or observation completion. It is
not a Bitcoin consensus fact, issuer signature, universal validity period, or
evidence that lifecycle state did not later change.

Lifecycle-controlled proposed, disputed, revoked, or superseded sources use
`None` observation evidence. No fake empty, spent, or zero-balance evaluation is
created. Effective edges with active registrations still require an exact
PR6.18 relation, and cannot produce ACTIVE/FULL without every required relation.

## Non-claims

The canonical result states 32 explicit non-claims: no repository lookup; no
database read or write; no Bitcoin RPC call; no LND call; no network request;
no participant or target discovery; no fabricated Bitcoin observation; no
descriptor import or custody proof; no transaction broadcast; no signing; no
issuer attestation; no authority-legitimacy proof; no proof of private-key
possession; no portable trust bundle; no replica synchronization; no graph
checkpoint; no cross-node fork detection; no universal freshness claim; no
claim after `freshness_deadline`; no JWT or session issuance; no FULL/LIMITED
session mutation; no entitlement evidence write; no action authorization; no
administrator or sponsor permission grant; no HTTP route; no MCP tool; no paid
job; no CLI; no scheduler; no migration; no deployment; and no replacement of
the active legacy runtime path.

Signed portable envelopes, authority rules, replication, fork handling, and
production/schema release compatibility tooling remain deferred.
