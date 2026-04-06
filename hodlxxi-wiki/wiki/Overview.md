# Overview

## Scope
HODLXXI is presented in-repo as a Bitcoin-native identity platform that combines web auth, agent discovery/execution surfaces, and Bitcoin-adjacent verification flows.

## Repository-indicated capabilities
- Flask service with OIDC/OAuth, LNURL-auth, and Bitcoin utility endpoints.
- Agent protocol/discovery surfaces exposed under `/.well-known/agent.json` and `/agent/*` routes.
- Proof-of-Funds pages and APIs under `/pof/*` and `/api/pof/*`.
- Real-time/web app interfaces and operational health endpoints.

## Conceptual Layer vs Runtime Layer
The repository contains both concrete implementation surfaces (routes, modules, tests) and broader conceptual framing (trust/covenant narrative). Conceptual framing should not be treated as proof of implemented runtime guarantees unless supported by code, tests, or captured runtime artifacts.

## Evidence grounding
This summary is synthesized from README, architecture docs, route modules, and test coverage. It is not a live production audit.

## Status framing
- **Repo-defined:** endpoint/module presence in source.
- **Test-verified:** behavior asserted by tests.
- **Runtime-verified:** behavior backed by captured runtime artifacts.
- **Unverified live:** external runtime status not directly evidenced here.

## See also
- [Trust Model](./Trust-Model.md)
- [Runtime State](./Runtime-State.md)
- [What Works Now](./What-Works-Now.md)
