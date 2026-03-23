# One-Page Project Summary

## What it is
HODLXXI is an open-source Bitcoin identity and service-verification stack. It combines Bitcoin-key-based identity, OAuth2/OIDC, LNURL-auth, proof-of-funds verification routes, Bitcoin descriptor/script inspection, and a Lightning-paid agent interface with signed receipts.

## What already works
Repository code and tests show that the project already has:
- OAuth2/OIDC client registration, authorization code flow, token issuance, introspection, discovery, and JWKS support.
- LNURL-auth challenge creation and session verification routes.
- Proof-of-funds APIs and pages, including stats, leaderboard, certificate, challenge, and PSBT verification flows.
- Paid access patterns for some Bitcoin RPC and agent operations using Lightning invoices.
- Public machine-readable agent endpoints for capabilities, skills, marketplace listing, job submission, receipt verification, attestations, reputation, and chain health.
- Signed receipts linked into an append-only-style history model.

## What is still missing
Important gaps remain:
- Documentation and implementation drift, especially around covenant claims.
- Incomplete or uneven hardening across some routes and legacy code paths.
- A cleaner local development and contributor setup.
- More rigorous packaging for third-party integrators.
- Stronger clarity around what is verified today versus what remains a design goal.

## Why funding helps
Funding would let the project focus on stabilization rather than speculation:
- harden the existing runtime surfaces,
- improve tests and failure handling,
- simplify the codebase,
- make the system easier to self-host and audit,
- produce better examples and documentation for reuse.

## Why this is public infrastructure rather than a private product
The repository is MIT-licensed, self-hostable, and centered on reusable protocols and interfaces rather than a single closed application. Its value is in the open components it exposes to other builders: Bitcoin-key identity, OAuth/OIDC, LNURL-auth, Lightning-gated service access, public discovery documents, and verifiable receipts. That makes it a piece of Bitcoin-oriented developer infrastructure that other projects can run and build on.
