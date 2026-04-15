# PUBLIC_SURFACES

This file documents what users and agents can currently see in the runtime, with conservative auth/status labeling.

Status legend:
- **Live now**: implemented in current branch/runtime code paths.
- **Transitional**: available, but still tied to legacy compatibility wiring.
- **Staging-confirmed**: proven in staging during migration work; do not assume universal deployment parity.

## Human-facing surfaces

| Path | Audience | Purpose | Auth requirement | Current status |
|---|---|---|---|---|
| `/login` | Human user | Browser login UI + challenge seeding | Public | Live now (blueprint-owned) |
| `/home` | Human user | Browser shell/home experience | Public in current blueprint handler; may be influenced by legacy guard behavior depending on runtime wiring | Live now, transitional runtime semantics |
| `/app` | Human user | Legacy chat/lounge entry | Session-adjacent behavior; route exists publicly but runtime behavior depends on chat handler registration | Live now, transitional |
| `/playground` | Human user / developer | Interactive demo/playground page | Public | Live now (blueprint-owned page render) |

## Machine/agent-facing surfaces

| Path | Audience | Purpose | Auth requirement | Current status |
|---|---|---|---|---|
| `/.well-known/agent.json` | Agent integrators | Canonical machine-readable agent identity/discovery doc | Public | Live now |
| `/agent/capabilities` | Agent integrators | Signed capability handshake (jobs, pricing, endpoints, limits) | Public | Live now |
| `/agent/request` | Agent clients | Submit job request for paid execution | Public submit; payment required before completion | Live now |
| `/agent/jobs/<job_id>` | Agent clients/verifiers | Fetch job status/result and receipt after settlement | Public read by job id | Live now |
| `/agent/verify/<job_id>` | Agent clients/verifiers | Verify signed receipt data for a job | Public read by job id | Live now |
| `/agent/attestations` | Agent clients/observers | Public receipt history surface | Public | Live now |
| `/agent/reputation` | Agent clients/observers | Aggregate runtime performance/history surface | Public | Live now |
| `/agent/skills` | Agent integrators | Discover installable/public skills | Public | Live now |

## Notes on auth labels

- **Public** means no session login token is required just to call/read the endpoint.
- **Paid** means execution completion is gated by invoice settlement (the request endpoint itself is callable without session auth).
- Where runtime is marked **transitional**, treat behavior as subject to deployment entrypoint and remaining monolith guard logic.
