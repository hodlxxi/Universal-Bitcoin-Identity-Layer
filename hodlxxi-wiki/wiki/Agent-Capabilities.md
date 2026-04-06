# Agent Capabilities

## Discovery surfaces
Repository code and tests indicate the following public agent discovery surfaces:
- `/.well-known/agent.json`
- `/agent/capabilities`
- `/agent/capabilities/schema`
- `/agent/skills`
- `/agent/marketplace/listing`

## Interaction surfaces
- `/agent/request` creates priced jobs (invoice-pending lifecycle).
- `/agent/jobs/<job_id>` resolves status and returns signed receipts when settled.
- `/agent/message` supports signed inter-agent message handling for supported job types.

## Public trust/reputation surfaces
- `/agent/attestations`
- `/agent/reputation`
- `/agent/chain/health`
- `/agent/trust/<agent_id>` and JSON trust summary/report routes

## Capability details observed
- Skills catalog is generated from `skills/public/`.
- Capabilities include schema URI, endpoint map, job type declarations, and signatures.
- Tests indicate support for at least `ping` and `verify_signature` jobs in the agent job surface.

## Boundaries
- Payment-required execution appears implemented in route and test flows, but production settlement reliability is not verified in this wiki pass.
