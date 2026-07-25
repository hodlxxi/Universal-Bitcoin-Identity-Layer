# Trusted Covenant Registration V1

> **Status: IMPLEMENTED_DORMANT.** This is an independently constructible
> domain and persistence boundary. It is not production wiring.
> Canon basis: `152c87522a7d89cd5c0e7014d7915a19bf074e1a`; PR6.8
> implementation branch base:
> `fe333cdb5068a73b4dc57b875e1b0223b01855f7`.

## Exact contract

Schema `hodlxxi.trusted_covenant_registration.v1` binds one already validated
PR6.7 mirrored pair to exactly one incoming and one outgoing Bitcoin
`txid:vout`. The two outpoints are distinct and each binds an exact positive
integer-satoshi amount, the subject-relative raw-script SHA-256, and an optional
descriptor SHA-256. Compressed pair identities remain authoritative; the
materialized PR6.6 definitions use the pair's corresponding x-only identities.
The explicit binding field `witness_script_sha256` is
`SHA256(raw witness Script bytes)` and exactly matches the subject-relative
PR6.7 leg digest. The legacy PR6.6
`TrustedCovenantOutpoint.script_sha256` field is instead
`SHA256(serialized scriptPubKey bytes)`. PR6.8 currently materializes only the
native P2WSH wrapper `0020<witness_script_sha256>` and does not infer arbitrary
output wrappers.

Canonical registration JSON is ASCII-safe, sorted-key, compact JSON. It includes
the exact registration metadata and direction-ordered bindings and is hashed
with SHA-256. Input binding order has no effect. Canonicalization and
materialization reconstruct all frozen objects and revalidate the authoritative
PR6.7 pair, so post-construction mutation fails closed.

The normalized dormant persistence layer stores registration metadata and its
canonical digest separately from two outpoint rows. It also stores both exact
raw scripts. Every read re-runs the PR6.7 validator with the stored subject and
single explicit delta profile; hashes or duplicated semantic columns cannot
substitute for the scripts. Registration IDs, registration digests, direction
ownership, and global `txid:vout` identities are unique. Pair digests are
required but deliberately not unique: the same validated script pair may be
funded again at new exact outpoints. Active-edge ambiguity, sponsor uniqueness,
and admission uniqueness belong to later separately reviewed layers. There is
deliberately no sponsor, child, active-pair, membership, or admission-edge
uniqueness rule at registration.

## Lifecycle

The exact lifecycle values are `active`, `revoked`, `superseded`, and
`disputed`. Only `active` can materialize the immutable pair of PR6.6
`TrustedCovenantOutpoint` definitions. Every other state fails closed.
`superseded_by_registration_id` is required only for `superseded`. Lifecycle transition
orchestration, including update, revoke, and supersede operations,
is not implemented.

## Admission and amount boundary

Exact registration is not Canon admission. Unequal positive incoming and outgoing amounts may be
registered and are preserved exactly. They are not
Canon equal-leg funding proof. A later admission layer must independently
require exact equality, or PR6.5 must be separately revised and reviewed.
Registration does not repair or alter PR6.5's
`outgoing_sats >= incoming_sats` policy.

The Human Membership V1 `legacy_777` profile and operator-agent continuity
`current_144` profile remain separate. Registering a validated `current_144`
pair would not make it human membership. The public `current_144`
operator-agent declaration remains one unfunded leg, is not silently
registered, and grants nothing. It remains separate from `legacy_777` human
membership.

## Explicit non-claims

This layer does not decide admission; create a genesis record; enforce sponsor
or admission-edge uniqueness; evaluate depth, ancestry, cycles, lineage,
inactivity, or CRT membership states; map membership to FULL/LIMITED; write
current-entitlement evidence; or grant access. FULL and LIMITED remain runtime
authorization outcomes, not CRT membership states.

It does not inspect Bitcoin Core, wallets, descriptors, balances, or chain
state; create, sign, fund, or broadcast transactions; expose a route, CLI, MCP
tool, scheduler, application dependency, or configuration flag; alter legacy
wallet-ratio or `SPECIAL_USERS` behavior; apply a migration; deploy; restart
services; or provide any production composition.

See [Mirrored Covenant Pair V1](MIRRORED_COVENANT_PAIR_V1.md),
[Trusted Covenant Observation V1](TRUSTED_COVENANT_OBSERVATION_V1.md), and
[CRT Runtime Bridge](CRT_RUNTIME_BRIDGE.md).
