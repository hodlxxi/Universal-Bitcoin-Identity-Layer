# Canonical CRT Authorization Policy V1

**Status: PR6.13 `IMPLEMENTED_DORMANT`.**

This pure domain policy answers only: under Canonical CRT Authorization Policy
V1, what Canon authorization class follows from one exact canonical PR6.12
membership evaluation?

| Membership state | Canon class | Policy reason |
| --- | --- | --- |
| `genesis_active` | `full` | `exact_genesis_membership_full` |
| `active` | `full` | `exact_participant_membership_full` |
| `provisional` | `limited` | `provisional_membership_limited` |
| `edge_inactive` | `limited` | `edge_inactive_membership_limited` |
| `lineage_inactive` | `limited` | `lineage_inactive_membership_limited` |
| `disputed` | `limited` | `disputed_membership_limited` |
| `unknown` | `limited` | `unknown_membership_limited` |

`FULL` derives only from `genesis_active` or `active`. `LIMITED` is the
fail-closed classification for every other valid membership state; it is a
classification, not automatic action permission.

The identifiers are:

- schema `hodlxxi.canonical_crt_authorization_evaluation.v1`
- policy `hodlxxi.canonical_crt_authorization_policy.v1`
- verification rule `hodlxxi.canonical_crt_authorization_verification.v1`

Membership and authorization are separate domains. The two-value
`CanonicalCrtAuthorizationClass` is not runtime `IdentityClass`, and
`current_full_membership_satisfied` is not the older covenant-relation field
`current_full_relation_satisfied`. The result embeds the complete canonical
membership evaluation and binds its exact digest, identity, target edge, state,
reason, and evaluated timestamp. Both layers use strict sorted compact ASCII
JSON, exact field sets, duplicate-key and float rejection, whole-second UTC
`Z`, lowercase UUIDs and digests, and byte-for-byte canonical round trips.
Top-level authorization fields are exact-type bound to that nested membership:
in particular, only the built-in integer type is accepted for `depth`, so
booleans and floats never substitute for integers even when Python would compare
their values as equal. Every accepted authorization value serializes to bytes
that round-trip through the strict authoritative parser to the identical value
and identical canonical bytes.

This classification writes no entitlement, role, session, or scope and makes
no action decision. It grants no invite or sponsor permission and no
administrator or operator status. It performs no storage lookup, database
access, Bitcoin RPC, LND, HTTP, subprocess, route, API, MCP, CLI, scheduler,
cache, model, or migration work. No runtime wiring exists.

Active wallet-wide ratio paths remain `ACTIVE_LEGACY_NON_CANONICAL` and
unchanged. `SPECIAL_USERS`, admin allowlists, operator status, existing action
authorization, current entitlement storage, the covenant entitlement
materializer, and runtime resolvers remain separate and unchanged. No runtime
resolver consumes PR6.13.

PR6.14 remains responsible for a reviewed public “why FULL” proof. PR6.13
provides no public proof surface and does not replace legacy authorization.
