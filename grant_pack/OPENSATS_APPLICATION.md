# OpenSats Grant Application Draft

## Project title
HODLXXI / Universal Bitcoin Identity Layer

## Short summary
HODLXXI is an open-source Bitcoin identity and service-verification stack built in Flask with Postgres, Redis, Bitcoin Core integration, and Lightning billing. Today the repository already exposes a working OAuth2/OIDC provider, LNURL-auth flows, proof-of-funds verification routes, Bitcoin descriptor and script inspection endpoints, and a public agent surface for paid jobs with signed receipts and attestation history. The immediate grant case is not to fund a concept, but to stabilize and modularize an implemented stack so it becomes dependable public Bitcoin infrastructure.

## Problem
Bitcoin-native applications still lack a broadly reusable identity layer that is both developer-friendly and rooted in Bitcoin keys, Lightning payments, and verifiable service behavior. Existing web identity stacks usually do not speak Bitcoin well, and many Bitcoin-native identity ideas remain mostly theoretical. HODLXXI is trying to close that gap by exposing practical runtime surfaces developers can use now: login, OAuth/OIDC, LNURL-auth, proof-of-funds APIs, descriptor inspection, and machine-readable agent discovery with payment and receipt verification.

## Why the Bitcoin and open-source ecosystem benefits
This work is useful as public infrastructure because it is not limited to a single consumer app. The repository already includes:
- Bitcoin-key-based user and session models.
- Standards-facing OAuth2/OIDC endpoints and JWKS publication.
- LNURL-auth challenge and callback routes.
- Paid API access patterns for Bitcoin RPC and agent jobs over Lightning.
- Public discovery documents for agent capabilities, skills, reputation, attestations, and chain health.
- Self-hostable deployment and test material.

That combination can serve as reusable plumbing for other Bitcoin applications that need identity, payments-gated APIs, or machine-verifiable service metadata.

## What already works today
Verified from repository code and tests, the current implementation includes:
- OAuth2/OIDC client registration, authorization code flow, token issuance, introspection, and JWKS-backed signing.
- LNURL-auth challenge creation and session-check flows.
- Proof-of-funds challenge and PSBT-verification routes, plus PoF landing, leaderboard, certificate, verify, and stats pages/routes.
- Bitcoin Core read-only RPC and descriptor access behind OAuth plus Lightning PAYG gating.
- A public agent runtime with `/agent/capabilities`, `/.well-known/agent.json`, `/agent/request`, `/agent/jobs/<job_id>`, `/agent/attestations`, `/agent/reputation`, `/agent/chain/health`, `/agent/marketplace/listing`, and `/agent/skills`.
- Signed agent receipts linked by previous-event hashes into an auditable continuity chain.

## What the grant would fund next
OpenSats support would fund the next practical stage:
1. Stabilize and document the runtime surfaces that already exist.
2. Reduce drift between monolithic legacy routes, blueprint routes, and documentation.
3. Harden proof-of-funds and OAuth/OIDC behavior for outside integrators.
4. Clarify covenant-related claims so public docs match actual runtime behavior.
5. Improve packaging for contributors: local dev setup, example configuration, sample clients, and maintainable module boundaries.
6. Expand tests around payment, attestation, PoF, and identity edge cases.

## Why now
The repository is already beyond the idea stage: there is code, data models, runtime-facing endpoints, deployment guidance, and integration tests. But there is also visible drift between ambitious documentation and what is verifiably enforced today, especially around covenants and some broader trust claims. Funding now is useful because it can turn a working but uneven prototype into dependable public infrastructure before more integrators build on inconsistent assumptions.

## Why this is fundable now
This is fundable now because there is already enough implementation to justify maintenance capital, but still enough unfinished hardening work that a targeted grant materially changes the outcome. Waiting another year would mostly delay the work needed to make current surfaces safer to rely on, easier to run locally, and more honest in how they present trust, survivability, and covenant enforcement.

## What success looks like in 6-12 months
A successful grant period would produce:
- A cleaner, better-tested open-source identity stack centered on Bitcoin keys and Lightning-paid access.
- Stable OAuth/OIDC, LNURL-auth, PoF, and agent surfaces with clearer compatibility guarantees.
- Honest covenant documentation that distinguishes descriptor inspection and script analysis from runtime-enforced covenant proofs.
- A substantially better local developer and contributor experience.
- A more credible public-good base layer other Bitcoin projects can self-host, audit, and extend.
