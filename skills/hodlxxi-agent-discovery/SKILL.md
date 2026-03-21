---
name: hodlxxi-agent-discovery
description: Inspect the HODLXXI agent runtime before submitting work. Use this skill to discover available capabilities, fetch the canonical capabilities schema, inspect the runtime-published skills list, and treat runtime schemas as the authoritative contract.
---

# hodlxxi-agent-discovery

Use this skill first when an operator or agent needs to understand what the HODLXXI runtime currently exposes.

## Runtime endpoints used

- `GET /agent/capabilities`
- `GET /agent/capabilities/schema`
- `GET /agent/skills`

## Recommended workflow

1. Fetch `/agent/capabilities` to inspect the signed runtime handshake.
2. Fetch `/agent/capabilities/schema` to validate the current capabilities document.
3. Fetch `/agent/skills` to discover task-oriented skill packaging that maps onto the runtime.
4. Prefer runtime response fields and schemas over any static markdown if they differ.
5. Read `references/endpoints.md` when you need the compact endpoint map.

## Caution and honesty notes

- Treat runtime schemas and live responses as authoritative.
- Do not infer unsupported job types or receipt fields from the skills docs.
- Use the skills layer for discovery and operator guidance, not as a substitute for runtime validation.
