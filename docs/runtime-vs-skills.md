# Runtime vs. skills

## Why the runtime is the source of truth

The HODLXXI runtime API is the authoritative contract for supported jobs, request schemas, job states, receipts, and public behavior. Live endpoints such as `/agent/capabilities`, `/agent/capabilities/schema`, `/agent/request`, and `/agent/jobs/<job_id>` describe what the service currently supports. Static skill files should not override those live contracts.

## Why the skills layer exists

The skills layer is an interoperability, discovery, and documentation surface. Each skill packages one operator or agent intent into a portable folder that explains when to use a capability, how to call the runtime safely, and how to interpret results without overstating what the runtime proves.

## How to prevent drift

- Start discovery with `GET /agent/capabilities`, `GET /agent/capabilities/schema`, and `GET /agent/skills`.
- Keep SKILL.md files concise and route references explicit.
- Point example scripts back to the live runtime rather than duplicating large schemas.
- Update the runtime skill registry whenever skill folders are added, removed, or renamed.
- If static docs and runtime responses diverge, follow the runtime and then correct the docs.

## Why skills are task-oriented instead of route-oriented

The same runtime route can support multiple operator intents. For example, `POST /agent/request` can represent a generic job request, covenant decoding, or signature verification depending on `job_type`. Task-oriented skills keep the packaging aligned with operator goals, while the runtime remains the authoritative route-level implementation.
