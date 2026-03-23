# HRF Bitcoin Development Fund Application Draft

## Project title
HODLXXI / Universal Bitcoin Identity Layer

## Problem
Bitcoin applications increasingly need identity, authorization, and service verification layers that do not depend entirely on conventional web account systems. At the same time, many claims about Bitcoin-native identity are still speculative. HODLXXI's value is that it already implements concrete runtime surfaces: Bitcoin-key-oriented identity records, OAuth2/OIDC, LNURL-auth, proof-of-funds routes, Lightning-gated APIs, and signed receipts for paid agent jobs.

## Why this matters for financial freedom and verifiable open systems
Bitcoin is strongest when users and services can verify more and trust marketing less. HODLXXI contributes to that direction by exposing public-key identity, machine-readable discovery, Lightning-paid access, and signed job receipts with observable history. That does not make the system fully decentralized or censorship-proof today, but it does move service trust toward cryptographic identity and inspectable operational evidence.

For freedom technology, the near-term relevance is practical:
- self-hostable identity and authorization infrastructure,
- reduced dependence on closed identity vendors,
- verifiable service outputs instead of opaque API claims,
- Bitcoin and Lightning as native rails for access control and payment.

## Current implementation
The repository currently contains:
- OAuth2/OIDC registration, authorization, token, introspection, discovery, and JWKS endpoints.
- LNURL-auth challenge creation, callback, and verification-check routes.
- Proof-of-funds pages and APIs, including challenge creation, PSBT verification, stats, leaderboard, and shareable certificates.
- Bitcoin descriptor and script inspection tooling connected to Bitcoin Core RPC.
- A paid agent interface with public capabilities, skills discovery, marketplace listing, job submission, signed receipts, attestations, reputation, and chain-health endpoints.
- Test coverage for OAuth, JWKS rotation, PoF verification, billing/PAYG flows, and agent receipts.

## Concrete next milestones
The next work should focus on infrastructure quality rather than new narrative claims:
1. Harden existing identity and payment flows so outside developers can rely on them.
2. Reconcile documentation with runtime reality, especially for covenant-related claims.
3. Improve modularity and local reproducibility so the stack is easier to audit and self-host.
4. Extend tests around adversarial and failure conditions.
5. Package clean developer examples for OIDC clients, LNURL-auth usage, PoF calls, and paid agent jobs.

## Realistic impact
A realistic grant outcome is not mass adoption by itself. The realistic impact is a more credible open-source Bitcoin infrastructure component that other developers can inspect, run, and adapt. If successful, HODLXXI would offer a reusable baseline for Bitcoin-native identity, paid service interfaces, and cryptographically accountable application behavior.

## Why this is fundable now
This is fundable now because the code already exposes usable Bitcoin-facing and Lightning-facing surfaces, but the project is still at the stage where focused support can significantly improve reliability, documentation honesty, and self-hostability. A year from now the same work will still be necessary; funding now increases the chance that the current implementation becomes dependable infrastructure rather than remaining an interesting but uneven prototype.
