# Trusted Bitcoin Covenant Observation Adapter V1

## Status and boundary

> **Status: IMPLEMENTED_DORMANT.** Synchronization basis: Canon commit `152c87522a7d89cd5c0e7014d7915a19bf074e1a`; runtime base `7df976c59742aa84fd79cfd41f12a34a33915259`.

This is a dormant adapter and evidence materializer. Nothing registers trusted
outpoints, invokes the adapter automatically, or composes it into production.
Future trusted-outpoint registration and production dependency composition
remain outside this PR and must be explicit, separately reviewed work. Future
production entitlement-resolver wiring also remains outside this PR. In
particular, the public operator-agent covenant in the `unfunded_declared` state
is not registered and cannot grant FULL.

Exact UTXO observation is necessary evidence but is not admission, membership,
lineage, or authorization by itself. Materialized FULL/LIMITED are runtime
authorization evidence outcomes, not CRT membership states. The `legacy_777`
human profile and `current_144` operator-agent profile must remain separate.
The upstream PR6.5 relation boolean uses positive totals plus
`outgoing_sats >= incoming_sats`, which is broader than Canon V1 admission's
exact equal-positive-amount rule. A positive decision is not admission,
membership, or a Canon-conformant equality proof. This adapter and the PR6.6
materializer preserve that decision; they do not independently repair the
amount-policy mismatch.

## exact-outpoint trust model

The adapter accepts an immutable, non-empty tuple of pre-registered definitions.
Each trusted definition uses schema
`hodlxxi.trusted_covenant_outpoint.v1`. The adapter version is
`hodlxxi.trusted_covenant_observation_adapter.v1`, and the materializer version
is `hodlxxi.covenant_entitlement_materializer.v1`.
Every definition binds one exact `txid:vout`, direction, canonical subject,
canonical counterparty, expected integer-satoshi amount, and SHA-256 digest of
the exact decoded script bytes. A definition may additionally bind the SHA-256
digest of an exact descriptor string. The adapter does not normalize, rewrite,
parse, or infer descriptor semantics.

All definitions in one observation bind the same exact subject/counterparty
pair. Cross-counterparty aggregation is rejected:

`Alice incoming + Bob outgoing != FULL`

The rule “wallet-wide scanning is forbidden” exists because wallet contents and labels are not a
trusted relationship registry. The legacy wallet balance aggregation is not
authorization evidence: heuristic descriptor/script parsing and aggregation can
mix unrelated outputs, roles, or counterparties.

## Stable Bitcoin Core snapshot

Through an injected RPC dependency, the adapter calls:

1. `getblockcount()`
2. `getbestblockhash()`
3. `gettxout(txid, vout, include_mempool=False)` once for each deterministically
   sorted trusted outpoint; the implementation passes positional `False`
4. `getblockcount()`
5. `getbestblockhash()`

Both height and best-block hash must remain identical. Comparing both protects
against a same-height reorganization that a height-only check would miss.
Every non-null response must report that same best-block hash.

The RPC amount must convert exactly from decimal BTC to an integral number of
satoshis without float input, rounding, fractional satoshis, or range errors.
It must equal the trusted expected amount. The canonical lowercase, non-empty,
even-length script hex is decoded, hashed, and compared to the trusted script
digest. If a descriptor digest was registered, the SHA-256 of the exact UTF-8
descriptor bytes must match. An amount, script, descriptor, or response-shape
mismatch makes observation unavailable and produces no evidence.

A null `gettxout` response means only `not currently present in the queried UTXO set`. It makes no claim about whether, how, or when an output was spent. The
negative observation retains the trusted expected amount and digests, with
`unspent=False` and zero confirmations.

## Evidence materialization

The pure exact-pair evaluator determines whether the validated observation
satisfies the current reciprocal relation. A positive decision is materialized
as FULL evidence; a negative decision is materialized as LIMITED evidence. Both
are appended. Persisting fresh negative evidence is intentional: it can
supersede older positive evidence without the materializer reading older state.

Evidence is valid for exactly 300 seconds (5 minutes) from its observation time.
At materialization, the maximum observation age is 60 seconds and the permitted
future clock skew is 5 seconds; either limit is inclusive. After those checks, the causal timestamp rule is exactly
`created_at = max(materializer clock, observed_at)`. This causal rule prevents materialization from preceding its
source observation without changing that observation. Future observations do
not grant FULL before `observed_at`, because the evidence remains not yet active
until the current time reaches the preserved observation time. The source
evidence hash is copied unchanged from the pure evaluator's canonical decision.

PR6.8 trusted registration and exact outpoint binding is the next boundary. It
does not complete genesis, admission, lineage, membership-state evaluation, or
authorization enforcement. Exact registration/outpoint binding alone also does
not fix PR6.5's amount-policy mismatch. A future admission layer must enforce
exact equality independently, or the relation policy must be separately revised
and reviewed. See [CRT Runtime Bridge](CRT_RUNTIME_BRIDGE.md),
[CRT Membership Implementation Status](CRT_MEMBERSHIP_IMPLEMENTATION_STATUS.md),
and [CRT Covenant Profile V1](CRT_COVENANT_PROFILE_V1.md).

## Non-claims

This PR does not:

- discover covenant relationships;
- prove legal or KYC identity;
- prove private-key ownership;
- prove key possession;
- parse Bitcoin Script;
- infer roles from OP_IF/OP_ELSE;
- scan a wallet;
- list wallet descriptors;
- aggregate wallet balances;
- query an explorer;
- create a route or MCP tool;
- automatically run a materializer;
- wire the evidence resolver into production;
- create, sign, fund, or broadcast transactions;
- modify Bitcoin Core or its wallet;
- apply a migration; or
- deploy or restart anything.
