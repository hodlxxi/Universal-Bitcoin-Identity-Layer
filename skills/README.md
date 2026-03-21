# Skills

This folder contains task-oriented Agent Skills for integrating with the HODLXXI runtime.

Runtime discovery for these checked-in skills is exposed at `/agent/skills`, and the runtime registry points to the `SKILL.md` file for each top-level skill folder.

## Available skills

- `skills/hodlxxi-agent-discovery/SKILL.md`
- `skills/hodlxxi-job-request/SKILL.md`
- `skills/hodlxxi-covenant-decode/SKILL.md`
- `skills/hodlxxi-signature-verify/SKILL.md`
- `skills/hodlxxi-reputation-lookup/SKILL.md`
- `skills/hodlxxi-attestation-lookup/SKILL.md`
- `skills/hodlxxi-job-receipt-inspection/SKILL.md`

## Conventions

- Treat runtime endpoints and runtime schemas as authoritative.
- Keep skills task-oriented, concise, and explicit about endpoint use.
- Do not include secrets, private keys, or speculative capabilities.
