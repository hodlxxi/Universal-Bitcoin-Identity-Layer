# Milestones and Budget Framing

This budget framing avoids invented salary figures. The purpose is to give funders credible scopes for small, medium, and larger grants tied to concrete outputs.

## Version A: Small grant
**Duration:** ~2-3 months

### Work items
1. Stabilize and document the already-exposed runtime surfaces.
2. Clean up grant-critical documentation drift, especially around covenant and trust claims.
3. Add targeted tests for PoF, agent receipts, payment gating, and OIDC edge cases.
4. Improve contributor onboarding with a clearer local development path and example environment.

### Expected outputs
- Updated public docs aligned to code reality.
- Additional regression tests for the most externally visible routes.
- Cleaner setup instructions and example configuration.
- A tighter, more defensible public story for funders and developers.

### Why this matters
A small grant is enough to make the current implementation safer to evaluate and easier to reuse. It reduces the risk that outside developers or funders rely on overstated claims.

## Version B: Medium grant
**Duration:** ~4-6 months

### Work items
1. Complete the small-grant scope.
2. Refactor runtime-critical areas to reduce dependence on large legacy route files.
3. Harden PoF and OIDC flows for third-party integration and clearer failure handling.
4. Produce maintained example clients and integration walkthroughs.
5. Expand tests across payment settlement, attestation continuity, and Bitcoin-facing APIs.

### Expected outputs
- Better-separated modules for identity, payment, and verification surfaces.
- Improved integration examples for OAuth/OIDC, PoF, and paid agent requests.
- More reliable runtime behavior under failure and adversarial conditions.
- Stronger basis for external developers to self-host or integrate the stack.

### Why this matters
A medium grant moves the project from promising prototype toward dependable public infrastructure. It funds engineering quality, not just feature count.

## Version C: Larger grant
**Duration:** ~6-12 months

### Work items
1. Complete the medium-grant scope.
2. Substantially improve interoperability and protocol clarity across agent, OIDC, PoF, and Bitcoin descriptor surfaces.
3. Strengthen verification and observability around payment, receipt, and service-history flows.
4. Build a cleaner self-hosting/dev environment suitable for external contributors and evaluators.
5. Reduce protocol ambiguity around covenant-related surfaces and clearly distinguish inspected data from enforced guarantees.

### Expected outputs
- A more maintainable and auditable codebase.
- Better public infrastructure docs and reference integrations.
- More trustworthy machine-readable service surfaces.
- A clearer long-term roadmap grounded in what is actually implemented.

### Why this matters
A larger grant supports the transition from a strong experimental codebase into a reusable Bitcoin infrastructure project with lower integration risk and more credible public-good value.
