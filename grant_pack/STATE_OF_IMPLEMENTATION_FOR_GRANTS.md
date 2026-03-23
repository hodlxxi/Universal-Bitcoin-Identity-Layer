# State of Implementation for Grant Review

This document is intentionally conservative. Repository code and tests were treated as primary evidence. `REDTEAM_INPUT_AUDIT.md`, which the request referenced as a required input, was not present in this checkout, so no claims in this file rely on that missing document.

## Works end-to-end today
- OAuth2/OIDC core: client registration, authorization code flow, token issuance, token introspection, OpenID discovery, and JWKS publication.
- Agent discovery and paid-job loop: capabilities, well-known identity, skills listing, marketplace listing, job request, Lightning invoice creation, payment check on job fetch, signed receipt creation, attestation history, receipt verification, reputation, and chain-health reporting.
- Lightning PAYG for some protected surfaces, including agent billing endpoints and Bitcoin RPC access gating.
- Proof-of-funds challenge creation and PSBT verification APIs.
- Public PoF-facing pages and routes: landing page, leaderboard, certificate page, verify page, and `/api/pof/stats`.
- Bitcoin read-only RPC access and descriptor listing behind OAuth plus payment controls.

## Partial
- LNURL-auth exists, but the callback route explicitly notes that proper secp256k1 signature verification is still not implemented there today.
- Covenant-related runtime support exists mainly as descriptor import/export/listing, script decoding, and participant matching; this is useful inspection tooling, but it is not the same as a fully enforced covenant-backed trust system in the application layer.
- The repository still contains both a large legacy monolith (`app/app.py`) and newer blueprints/factory paths, which means route behavior and documentation can drift.
- The agent trust model exposes signed receipts and continuity data, but it does not expose verified on-chain proof or verified time-locked capital backing.

## Docs-only or aspirational
- Stronger claims about long-horizon covenant enforcement, capital-backed survivability, or consensus-enforced trust guarantees at the service level are aspirational unless backed by explicit runtime proof surfaces.
- Broad marketplace, reputation, and social/agent ecosystem narratives extend beyond the currently narrow paid-job registry in code.
- Some public prose describes the system in more mature terms than the implementation currently supports.

## Not yet implemented, or not verifiably implemented in this checkout
- A verifiable runtime proof surface showing time-locked capital or covenant-backed reserves for the public agent surface.
- Full cryptographic LNURL-auth signature verification in the callback flow.
- Evidence in this checkout of a completed third-party security audit.
- Any basis for claiming the system is decentralized, censorship-resistant in a strong sense, or survivable independent of its current hosted operator.

## Key contradictions and drift to acknowledge
- Some covenant documentation describes the system as a core production-ready covenant platform, while the agent trust model and runtime code are much more conservative.
- Public documentation sometimes implies stronger trust or enforcement than the current verifiable runtime provides.
- The codebase is real and working, but not yet in a state where every major narrative claim should be treated as runtime fact.
