# Public Current Entitlement Assertion V1

`GET /agent/authority/current/<subject>.json` publishes the HODLXXI runtime's current participant-entitlement decision under schema `hodlxxi.current_entitlement_assertion.v1`. It is a public, JSON-only, read-only endpoint. There are no POST, PUT, PATCH, or DELETE companions.

## Subject and response

`subject` must already be a canonical lowercase 64-character hexadecimal x-only public key. Uppercase hex, compressed `02`/`03` keys, npub/nsec encodings, malformed or wrong-length values, usernames, emails, and labels are rejected rather than normalized.

A successful response exposes only `schema`, `subject`, `valid`, `identity_class`, `current_full_relation_satisfied`, `evidence_source`, and `observed_at`. It excludes balances, xpubs, descriptors, account or OAuth records, email, session data, raw evidence, source hashes, internal database identifiers, and exception details.

`limited` with `current_full_relation_satisfied=false` is a valid current assertion. `full` is valid only when the canonical runtime resolver returns `full` with `current_full_relation_satisfied=true`; the publication layer never calculates or upgrades entitlement. A denied subject receives a stable 4xx response. Unavailable storage or resolution receives a fail-closed 503 response. Neither failure fabricates Limited or Full, and underlying exception text is not public.

## Authority boundary

The source-of-truth chain is:

canonical persisted participant / active-user prerequisite → Limited baseline → current entitlement evidence lookup → evidence-backed runtime current entitlement resolver → Limited or Full `EntitlementDecision` → public current-entitlement assertion

An active canonical persisted user may therefore receive a successful Limited assertion when no current entitlement evidence row exists; successful Limited does not imply that a stored Limited evidence row exists. Full still requires valid current Full evidence.

The endpoint calls `resolve_runtime_current_entitlement(subject)` as a standalone read. It does not open an ambient caller-owned transaction, query evidence directly, materialize or refresh evidence, grant or revoke entitlement, use legacy balances, or call Bitcoin Core or LND. It does not evaluate Bitcoin, CRT membership or authorization, sponsor lineage, admission edges, genesis, or covenant state.

This contract publishes participant entitlement only: `limited` or `full`. Operator continuity is separate. It does not publish operator, admin, genesis, special, or guest status, and E923 is not automatically classified as Operator through this assertion.

## Non-claims

The assertion reports only HODLXXI runtime current participant entitlement. It does not prove legal identity, KYC, personhood, current private-key possession, Nostr identity ownership, trustworthiness, reputation, profitability, investment status, or custody.
