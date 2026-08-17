# HODLXXI Project Compass V1

Status: **CANONICAL PROJECT DIRECTION**

This is the canonical project-direction and architectural-boundary document for
HODLXXI V1. It is normative for future design and PR scope. It is not itself a
protocol proof. It is not a legal contract and not a deployment claim. When it describes
present technical behavior, it is subordinate to executable Bitcoin consensus
and exact implemented contracts.

Future PRs touching identity, membership, descriptors, sponsorship,
authorization, JWT, deployment, replication, or federation must be evaluated
against this Compass.

## Mission

HODLXXI exists to make long-lived Bitcoin covenant relationships observable,
non-custodial, locally verifiable, and socially accountable without turning one
website, database, administrator, or session issuer into the trust itself.

## Original trust model

If Alice trusts Bob, Alice stores and observes Bob's watch-only descriptor. Bob
reciprocally stores and observes Alice's descriptor. This is reciprocal
descriptor custody: both direct counterparties independently preserve enough
information to observe their shared covenant relationship.

Each sponsor stores and observes the covenant relationships of its direct
children. A sponsor is responsible for participant selection, monitoring,
containment, revocation, and remediation of its direct branch.

A downstream participant's violation does not automatically condemn the
sponsor when the sponsor responds correctly and promptly. A sponsor who
ignores, conceals, or continues authorizing a known harmful downstream
relationship may lose the trust of its own sponsor.

## Normative invariants

### HC-01 — Reciprocal Descriptor Custody

Mutual trust is represented by reciprocal watch-only observation. For an
active direct trust relationship, each direct counterparty must independently
retain enough descriptor/script information to observe the shared covenant
relationship. Descriptor custody alone does not
prove independent human ownership.

### HC-02 — Non-Custodial Key Boundary

A watch-only descriptor does not transfer private keys or spending authority.
Custody and spending rights remain governed by keys and Bitcoin scripts.

### HC-03 — Bitcoin Objective Layer

Bitcoin establishes objective facts such as exact outpoint existence, amount,
script, confirmation context, and spent or unspent state. Bitcoin does not
determine social trust, sponsor legitimacy, dispute outcome, or revocation
authority.

### HC-04 — Direct Sponsor Responsibility

Each sponsor is directly responsible for the children it admits and for
responding to problems in that branch. Responsibility means selection,
monitoring, containment, revocation, and remediation—not an assertion that
downstream participants can never misbehave.

### HC-05 — Recursive Lineage

A participant's active membership depends on a valid root-to-target sponsor
lineage. A broken controlling edge can make descendants lineage-inactive
according to the canonical evaluator. Exact descendant migration and
re-sponsorship rules remain an explicit future protocol decision.

### HC-06 — Revocation Preserves Evidence

Revocation removes active trust and runtime rights. It must not silently erase
historical observation or prior records. A revoked descriptor may remain
archived, quarantined, or watch-only for historical evidence, investigation,
continued observation, and recovery or re-sponsorship analysis. "Delete from
trust" and "destroy observation history" are different actions.

### HC-07 — Exact Relationship, Not Wallet-Wide Aggregation

Canonical CRT membership must be based on exact participant-bound descriptors
or descriptor commitments, scripts, registrations, `txid:vout` outpoints,
admission edges, sponsor lineage, and Bitcoin observations. Unrelated wallet
balances, change outputs, or another participant's funds must not make a
participant FULL.

### HC-08 — Membership and Authorization Separation

Authentication, CRT membership state, local FULL/LIMITED authorization,
runtime entitlement, administrator/operator access, agent delegation, and
JWT/session state are distinct. CRT FULL never automatically means server
administrator or root access.

### HC-09 — Fail-Closed Authorization

Unknown, stale, contradictory, incomplete, or unverifiable canonical state
must not fall back to an automatic FULL result. Canonical failure must not be
bypassed through a legacy balance-to-FULL shortcut after enforcement cutover.

### HC-10 — Node Sovereignty

The intended architecture permits a participant to run its own open-source
runtime, Bitcoin node, database, domain, and JWT signing keys. A participant
should not permanently depend on hodlxxi.com being online merely to observe an
already established Bitcoin covenant. This is a target architecture, not the
currently implemented replica capability.

### HC-11 — Local JWT Boundary

JWTs are local to the issuing runtime. One node's JWT must not automatically
authorize another node. Portable CRT records and proofs may be verified before
a receiving runtime applies its own policy and issues its own local JWT.

### HC-12 — HODLXXI V1 Profile Boundary

E923 is the fixed genesis participant of HODLXXI V1. E923 is not an
always-online central server for every Bitcoin observation. The current
implementation is profile-specific and does not implement an arbitrary
multi-genesis generic protocol. A future Vasya sovereign graph must have a
distinct graph identity and explicit profile/version rules.

### HC-13 — Portable Proofs Before Federation Claims

Portable signed trust bundles are not yet implemented. Signed lifecycle
authority, replica synchronization, checkpointing, and fork detection are also
not yet implemented. Unsigned local evaluation must never be described as
universally authoritative across independent nodes.

### HC-14 — Preserve Useful Legacy Infrastructure

Retain useful legacy components where appropriate: watch-only descriptors,
Bitcoin Core observation, participant labels and mappings, historical balances,
monitoring, diagnostics, local authentication, and JWT/session infrastructure.
The eventual removal target is the legacy balance-to-FULL shortcut and unsafe
fallback—not descriptor observation itself.

### HC-15 — Shadow Before Cutover

Before canonical enforcement replaces legacy authorization: compute legacy and
canonical outcomes in parallel; record and explain every shadow comparison
mismatch; prove freshness and rollback behavior; introduce bounded canonical
entitlement; enable enforcement gradually; and remove fail-open legacy fallback
only after validation.

### HC-16 — Release-Train Discipline

Do not deploy a large staging divergence as one unreviewed release. Separate
security/auth foundation, schema and migrations, dormant CRT domain, read-only
proof surfaces, live source lookup, shadow entitlement, enforcement, and
federation/replication. Each release train requires entry gates, validation,
rollback, and exit gates.

## Objective Bitcoin facts versus social/protocol assertions

Bitcoin can establish exact transaction and outpoint existence in an accepted
chain view, amount, script commitment, confirmation context, and spent/unspent
state. It cannot establish a human name, participant-key binding, reciprocal
descriptor possession, sponsor consent or legitimacy, graph selection,
lifecycle authority, dispute resolution, revocation authority, or local
authorization. Those are social or protocol assertions and require explicit
records, authority rules, and—where portability is claimed—signatures.

## Sponsor responsibility and downstream failure

Responsibility attaches directly to the sponsor's admission and response. A
child's misconduct is not automatic proof of sponsor misconduct. The sponsor
must monitor its direct branch, contain known harm, revoke or quarantine active
trust where justified, preserve evidence, and remediate promptly. Ignoring,
concealing, or continuing to authorize known harm can break the sponsor's own
upstream trust.

## Revocation, quarantine and historical preservation

Revocation changes current trust and rights; quarantine contains uncertainty or
risk. Neither authorizes destruction of history. Append-preserved lifecycle
records, descriptor commitments, observations, disputes, and prior proofs must
remain available according to retention and privacy policy. Exact quarantine,
remediation, and re-sponsorship authority remains unresolved.

## Self-hosting and node sovereignty

A sovereign participant should be able to operate the open-source runtime with
its own Bitcoin node, database, domain, and signing keys and independently
observe established covenants. Current pure evaluators can operate locally when
given exact records and Bitcoin evidence, but there is no complete portable
dataset, signed event protocol, or replica synchronization capability. Node
sovereignty is therefore the architectural target, not a completed claim.

## E923 as HODLXXI V1 genesis versus E923 as a live central server

E923 is the fixed genesis of the named HODLXXI Network Profile V1 and the
exceptional depth-zero participant. That profile fact does not require E923 or
hodlxxi.com to remain online for every node's Bitcoin observation. The current
code and schemas are intentionally HODLXXI V1 profile-specific; they are not a
generic profile configuration layer.

## Portable CRT proof versus local JWT

A portable CRT proof is graph-specific evidence a receiving node may verify.
A JWT or session is a short-lived, audience-bound local credential governed by
the issuing runtime's keys, revocation state, and policy. Foreign proof
verification may inform local entitlement, but the receiving node must make its
own decision and issue its own credential. No current unsigned proof is
portable authority, and one runtime's JWT is not global identity or global
authorization.

## Legacy infrastructure that remains useful

Watch-only descriptor handling, Bitcoin Core observation, participant labels
and mappings, historical balance data, monitoring and diagnostics, local
authentication, and JWT/session machinery remain useful building blocks. They
must be scoped, hardened, and bound to exact relationships where canonical
claims depend on them.

## Legacy behavior that must eventually be retired

The active wallet-wide, participant-key-filtered balance-ratio path is not
canonical membership proof. The legacy balance-to-FULL shortcut and any unsafe
fail-open fallback must be retired after measured shadow operation and a safe
cutover. Descriptor observation, historical records, and local authentication
are not retirement targets.

## Current implementation boundary

Implemented in staging are canonical HODLXXI V1 genesis, admission edges,
trusted covenant registration, sponsor lineage, membership evaluation,
FULL/LIMITED policy, authorization proof, trusted source planning, a globally
anchored Bitcoin snapshot, and local unsigned snapshot-to-proof composition.

Still deferred are production source lookup; production Bitcoin-RPC
orchestration for this path; current-proof storage; shadow comparison;
canonical runtime entitlement; action enforcement; signed portable bundles;
signed lifecycle authority; replica synchronization; checkpointing; fork
detection; independent-node conformance; and generic multi-genesis graph
profiles.

These components being implemented in staging does not mean they are deployed:
production deployment is not claimed.

## Production migration and release trains

Release security/auth foundations separately from additive schema and
migrations. Rehearse schema/model compatibility and preserve written history on
rollback. Then release dormant domain components, read-only proof surfaces,
live source lookup, shadow entitlement, bounded enforcement, and finally
federation/replication as distinct trains. Each train must define entry gates,
validation and telemetry, a reversible runtime rollback, preservation of audit
history, and measurable exit gates.

## Future signed trust-bundle and replica layer

The target layer uses versioned graph profiles, signed node/key history,
bilaterally acknowledged admission and descriptor-custody records, signed
lifecycle events, causal sequence and previous-event links, checkpoints,
explicit fork evidence, and privacy-aware export/import manifests. Local
databases should be materialized views, not globally authoritative rows.
Federated transport follows—not precedes—the signed bundle, verification,
freshness, conflict, and conformance contracts.

## Explicit non-goals

These contracts alone do not make HODLXXI:

- KYC or legal identity;
- proof of independent human key ownership;
- custody;
- a token sale, investment promise, or profit promise;
- a universal reputation score;
- automatic administrator access;
- a global JWT issuer;
- completed federation;
- proof that no fork or conflicting lifecycle history exists; or
- proof of reciprocal descriptor possession unless separately acknowledged and signed.

## Open operator decisions

The following are unresolved decisions, not current implementation:

- exact revocation authority;
- bilateral acknowledgement format;
- sponsor response/remediation deadline;
- descendant behavior after sponsor revocation;
- re-sponsorship rules;
- lifecycle event signing;
- event sequence and previous-event chaining;
- graph checkpoints;
- conflict and fork resolution;
- descriptor privacy versus portability;
- proof freshness policy;
- trust-bundle export/import format;
- independent-node conformance requirements; and
- whether and how future non-E923 graph profiles are supported.

## Mandatory future-PR alignment checklist

Every future architectural PR must answer:

1. Which Compass invariants does it touch?
2. Does it change HODLXXI V1 or define a new version/profile?
3. Does it change production behavior?
4. Does it change membership, authorization, admin or JWT boundaries?
5. Does it introduce central live-server dependency?
6. Does it preserve reciprocal descriptor observation?
7. Does it preserve historical evidence during revocation?
8. Is the result local, portable, signed or universally authoritative?
9. What fails closed?
10. What is the rollback?
11. What is explicitly deferred?
12. What user-visible outcome changes?

## Compass versioning and change control

This document is V1. Changes require an architectural PR that identifies every
affected invariant, answers the mandatory checklist, distinguishes clarification
from a semantic protocol/profile change, and updates documentation contract
tests. A change to HODLXXI V1 semantics requires explicit version/profile and
migration compatibility review; it must not silently rewrite existing canonical
digests or claims. A new sovereign graph requires its own identity, genesis,
profile, authority rules, and versioned contracts.
