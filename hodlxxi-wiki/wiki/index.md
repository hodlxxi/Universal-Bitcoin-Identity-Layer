# HODLXXI Wiki Index

## What this wiki is
This wiki is a repository-local knowledge layer that summarizes project evidence for reviewers, collaborators, and operators. It synthesizes repository truth; it does not replace code/tests/runtime evidence.

## Current-state summary (bootstrap)
- Repository evidence indicates a Flask monolith with partial factory/blueprint modularization.
- Implemented identity surfaces appear to include Bitcoin signature login, guest login, LNURL-auth endpoints, and OAuth2/OIDC endpoints.
- Implemented agent surfaces appear to include discovery, capabilities, skills, paid request/job endpoints, attestations, and trust pages.
- Proof-of-Funds routes and API surfaces are present, including `/pof/*` pages and `/api/pof/stats`.
- Live runtime verification is not part of this bootstrap pass.

## Canonical pages
- [Overview](./Overview.md)
- [Trust Model](./Trust-Model.md)
- [Runtime State](./Runtime-State.md)
- [Architecture](./Architecture.md)
- [Agent Capabilities](./Agent-Capabilities.md)
- [Auth Surfaces](./Auth-Surfaces.md)
- [Lightning Payments](./Lightning-Payments.md)
- [Covenant Model](./Covenant-Model.md)
- [Reputation Surface](./Reputation-Surface.md)
- [What Works Now](./What-Works-Now.md)
- [Experimental](./Experimental.md)
- [Roadmap](./Roadmap.md)
- [Change Log](./log.md)

## Warning on evidence hierarchy
When wiki text and source material diverge, treat `app/`, `tests/`, and primary docs as authoritative.
