# Canonical Root Entitlement Policy V1

`hodlxxi.canonical_root_entitlement_policy.v1` is a pure, read-only mapping of a successfully observed edge-local covenant relation. It accepts only `CANONICAL_ROOT_REGISTRATION_BINDING`; an admission edge, identity mismatch, malformed provenance, or contradictory summary is unavailable through one sanitized error.

A valid relation maps the root to ordinary participant Full exactly when `incoming_sats > 0`, `outgoing_sats >= incoming_sats`, the canonical reason is `full_relation_satisfied`, and the relation boolean is true. A valid unsatisfied relation maps to Limited. This grants no Operator, administrator, moderator, ownership, custody, release, permanent Social, E923, wallet, browser, OAuth, MCP, payment, or environment-derived authority.

The policy reproduces the canonical reason rule from incoming and outgoing totals and requires exact agreement with the reason and boolean. It also requires at least two recognized observations, qualifying count no greater than recognized count, zero qualifying count exactly for zero totals, and at least two qualifying observations when both directions are positive.

Every observation has a positive amount, so with `qualifying_total = incoming_sats + outgoing_sats`:

```
qualifying_total >= qualifying_count
```

Every recognized outpoint becomes one observation, and the existing evaluation limits their total money to `MAX_BITCOIN_SATS`. Therefore R3 additionally requires:

```
qualifying_total
+ (recognized_count - qualifying_count)
    <= MAX_BITCOIN_SATS
```

The exact boundary is valid. These are fail-closed consistency checks on an existing summary, not new covenant economics.

`observed_at` is copied only from the validated canonical relation decision and preserves its exact UTC microseconds. `canonical_root_bound_covenant_relation` provenance is a lowercase SHA-256 of compact, sorted-key, ASCII-safe JSON committing to the policy version, graph, pair, root selector source/ID/digest, trusted registration ID/digest, funding set ID/digest, counts, exact observation time and height, totals, relation boolean/reason, and upstream evidence digest. Serialization occurs only after complete validation and is private.

The policy performs no repository, database, RPC, LND, observation, wallet, browser, environment, persistence, or filesystem operation. It creates no evidence record, scheduler, TTL, materialization, runtime entitlement activation, public GET coupling, or Social activation.
