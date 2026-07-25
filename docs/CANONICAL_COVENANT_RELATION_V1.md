# Canonical Covenant Relation V1

## Status and purpose

> **Status: IMPLEMENTED_DORMANT.** Synchronization basis: Canon commit `152c87522a7d89cd5c0e7014d7915a19bf074e1a`; runtime base `7df976c59742aa84fd79cfd41f12a34a33915259`.

PR6.5 defines a dormant, pure-domain evaluation contract. It does not gather observations or authorize a caller. The evaluator is deterministic over trusted normalized observations. The future adapter is responsible for making those observations authoritative. This relation evaluator is one component, not CRT membership. It has no canonical genesis record evaluation, sponsor registry, lineage traversal, cascade propagation, CRT membership-state evaluation, or participant-facing authorization wiring. FULL/LIMITED are not CRT membership states.

Legacy browser-oriented wallet code aggregates incoming and outgoing balances after reading descriptors, deriving addresses, and reading UTXOs. That presentation-oriented aggregate is not authorization evidence: it does not prove that capital in both directions belongs to the same reciprocal relationship or that participant roles and policy intent were established.

Evaluation is isolated to one exact pair: one canonical x-only `subject_pubkey` and one canonical x-only `counterparty_pubkey`. Every observation must bind to both exact identities or validation fails. In particular:

`Alice incoming + Bob outgoing != FULL`

The current public operator-agent covenant is `unfunded_declared`; that declaration does not produce a positive relation decision.

## Contracts

The immutable observation schema is `hodlxxi.covenant_relation_observation.v1`. It contains `schema`, `subject_pubkey`, `counterparty_pubkey`, `direction`, `txid`, `vout`, `amount_sats`, `script_sha256`, optional `descriptor_sha256`, `confirmations`, and `unspent`. It stores script and descriptor digests only. A compressed script pubkey is not the entitlement identity; mapping to canonical x-only identities belongs to the adapter.

The immutable evaluation schema is `hodlxxi.covenant_relation_evaluation.v1`. It binds the `bitcoin` network, exact subject/counterparty pair, UTC observation time, observed block height, and an immutable observation tuple. Duplicate outpoints and mixed identities fail validation. The total supplied amount is capped at 2,100,000,000,000,000 satoshi.

The immutable decision schema is `hodlxxi.covenant_relation_decision.v1`. It records the pair, boolean result, stable reason, integer incoming and outgoing totals, qualifying and ignored counts, observation time and height, and source-evidence SHA-256.

Direction is always from the subject's perspective:

- `incoming`: capital committed by the exact counterparty in favor of the subject under a recognized HODLXXI reciprocal-relation policy.
- `outgoing`: capital committed by the subject in favor of the exact counterparty under the same recognized relation policy family.

These meanings cannot be inferred merely because a key occurs in `OP_IF` or `OP_ELSE`.

## Fixed evaluation policy

V1 has a fixed one-confirmation policy: an observation qualifies only when it is unspent and has at least one confirmation. Callers cannot lower the threshold. Spent and unconfirmed observations contribute zero satoshi, but remain in canonical source evidence and its digest.

The economic rule is an integer satoshi comparison; it never divides or uses ratios. Both positive directions must exist and `outgoing_sats >= incoming_sats`. The ordered decision reasons are:

- `no_qualifying_observations`: both totals are zero.
- `missing_incoming`: only outgoing is positive.
- `missing_outgoing`: only incoming is positive.
- `outgoing_below_incoming`: both are positive but outgoing is smaller.
- `full_relation_satisfied`: both are positive and outgoing is at least incoming.

Only `full_relation_satisfied` sets the decision boolean true.

This PR6.5 policy is broader than Canon V1 human admission. Canon requires the
two funded `legacy_777` legs to carry exactly equal positive integer-satoshi
amounts, while PR6.5 can return true when outgoing is greater than incoming. A
positive PR6.5 decision must never be described as admission, membership, or a
Canon-conformant equality proof. Trusted observation and PR6.6 materialization
do not add an independent equality decision and therefore do not repair this
semantic mismatch.

## Canonical source evidence

Canonical serialization is an exact ASCII-safe UTF-8 JSON object, with sorted object keys, compact separators, no floats, lowercase enum values, and UTC RFC3339 timestamps with a `Z` suffix and fixed microsecond precision. Optional absent descriptor digests serialize as JSON `null`. Observations are sorted by `txid` ascending, `vout` ascending, then `direction` ascending, independently of caller order.

The source-evidence digest is lowercase hexadecimal SHA-256 over those exact canonical evaluation bytes. It includes every supplied observation, including spent and zero-confirmation observations, and excludes the decision. Thus equivalent input ordering has identical bytes, totals, decision, and digest.

## Trust boundaries

The future trusted observation adapter is responsible for script validation, descriptor validation, participant-role mapping, direction assignment, unspent verification, confirmation count, amount, chain height, and observation time. It must recognize the reciprocal-relation policy rather than infer roles from branches. This PR does not parse scripts or gather any of that evidence.

The future entitlement materializer may map a positive boolean to FULL evidence and a negative boolean to LIMITED evidence. This PR neither writes evidence nor performs that mapping. Until trusted adaptation and materialization are separately implemented, this contract remains dormant.

Future PR6.8 trusted registration and exact outpoint binding is the next boundary. PR6.8 does not by itself complete admission, genesis, lineage, cascade propagation, membership evaluation, or authorization. Exact registration/outpoint binding alone also does not fix the amount-policy mismatch: a future admission layer must enforce exact equality independently, or the relation policy must be separately revised and reviewed.

See [CRT Runtime Bridge](CRT_RUNTIME_BRIDGE.md), [CRT Membership Implementation Status](CRT_MEMBERSHIP_IMPLEMENTATION_STATUS.md), and [CRT Covenant Profile V1](CRT_COVENANT_PROFILE_V1.md) for the `legacy_777` human-admission and `current_144` operator-agent separation.

## Non-claims

This PR does not:

- establish KYC or legal identity;
- establish key possession;
- establish private-key ownership;
- prove descriptor ownership;
- prove a raw descriptor is valid;
- parse Bitcoin Script;
- infer participant roles from OP_IF/OP_ELSE;
- query Bitcoin Core;
- query an explorer;
- inspect a wallet;
- verify a UTXO;
- verify funding;
- verify confirmations;
- write entitlement evidence;
- grant FULL access;
- expose a public route or MCP tool;
- create, sign, fund, or broadcast a transaction;
- apply a migration; or
- deploy or restart anything.
