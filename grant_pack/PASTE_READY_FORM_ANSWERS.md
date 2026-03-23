# Paste-Ready Form Answers

## Project name
HODLXXI / Universal Bitcoin Identity Layer

## Elevator pitch
An open-source Bitcoin identity and service-verification stack that combines OAuth2/OIDC, LNURL-auth, proof-of-funds routes, Lightning-paid APIs, and signed public receipts for agent-style services.

## Project description
HODLXXI is a self-hostable open-source project for Bitcoin-native identity and verifiable service interfaces. The repository already includes OAuth2/OIDC endpoints, LNURL-auth flows, proof-of-funds APIs and pages, Bitcoin descriptor/script inspection routes, and a public agent surface with Lightning-paid jobs, signed receipts, attestation history, and reputation/chain-health endpoints.

## Current status
Working implementation with tests and deployment material. The project is beyond the concept stage, but still needs hardening, codebase cleanup, documentation alignment, and better packaging for outside integrators and contributors.

## Open source links
- Main repository: https://github.com/hodlxxi/Universal-Bitcoin-Identity-Layer
- License: MIT

## Milestones
Near-term milestones are to harden the existing OAuth/OIDC, PoF, Lightning billing, and public agent surfaces; reduce documentation drift; improve local self-hosting and contributor onboarding; and expand tests around payment, receipts, and identity edge cases.

## Why funding is needed
Funding is needed to turn a real but uneven implementation into dependable public infrastructure: cleaner modules, stronger tests, clearer docs, better examples, and more reliable integration behavior.

## Why this matters to Bitcoin
Bitcoin applications need reusable identity and service-verification components that are aligned with Bitcoin keys and Lightning payments rather than generic web identity alone. HODLXXI contributes practical open-source building blocks in that direction.

## What makes this differentiated
The project combines several surfaces that are usually separate: Bitcoin-key identity, OAuth/OIDC, LNURL-auth, proof-of-funds verification, Lightning-gated APIs, and signed receipts with public attestation history. It is differentiated by trying to make service trust more inspectable, while still being honest about current limits.

## Risks / limitations
The project is not fully decentralized, does not yet expose runtime proof of covenant-backed reserves or time-locked capital, contains documentation drift in some areas, and still needs hardening before it should be treated as mature infrastructure.
