# Edge-Local Recognized Funding Observation V1

This internal read-only operation resolves one canonical relationship and reports its current Bitcoin relation. It does not grant runtime entitlement.

The authority chain is explicit graph and canonical x-only subject, `resolve_controlling_registration()`, its exact ACTIVE registration, and the unique EFFECTIVE canonical recognized funding set for that registration. Registration anchor outpoints remain provenance; they are not the current funding balance.

Every recognized outpoint is converted one-for-one to the existing trusted observation input. Native P2WSH scriptPubKey identity is derived with the existing canonical helper. The complete tuple is passed to `TrustedBitcoinCovenantObservationAdapter.observe()` and then to `evaluate_covenant_relation()`. Unequal INCOMING and OUTGOING counts and non-paired amounts are valid. Qualifying totals use all confirmed, unspent recognized observations and require positive incoming funding with outgoing funding greater than or equal to incoming funding.

The recognized set is the complete allowlist. The operation performs no wallet, descriptor, script, amount, `listunspent`, or `scantxoutset` discovery. Dust and capital from another registration, mirrored pair, sponsor, counterparty, or descendant edge cannot enter the evaluation. A spent recognized output remains non-qualifying evidence and is never replaced.

Repository reads retain their own session boundaries and complete before Bitcoin RPC observation. The operation has no persistence API and does not write registrations, funding sets, admission/root selectors, or CurrentEntitlementEvidence.

Successful observation with insufficient qualifying funding returns an auditable non-Full relation. Storage, configuration, RPC, snapshot, amount, script, or malformed dependency failures return only the sanitized edge-local observation unavailable error. `KeyboardInterrupt` and `SystemExit` remain visible.

The immutable result records selector, registration, funding-set, observation-count, snapshot-height, relation-total, reason, and digest provenance. The existing evaluation contract has no block-hash field, so this version does not invent one.

No public GET route, browser state, OAuth, MCP, Social, entitlement materializer, or runtime authorization is connected. A root registration can be observed as data, but the result does not decide Genesis, operator, E923, Full, or Limited entitlement.
