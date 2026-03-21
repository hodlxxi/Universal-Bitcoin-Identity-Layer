# Skills

This folder contains agent-friendly “skills” for integrating with HODLXXI / Universal Bitcoin Identity Layer (UBID).

Runtime discovery for these public skills is exposed at `/agent/skills`, so the checked-in files here are the source of truth for the machine-readable skill listing.

## Public skills

### hodlxxi-bitcoin-identity
Path: `skills/public/hodlxxi-bitcoin-identity/`

- **SKILL.md**: OAuth2/OIDC + LNURL-auth integration guide and code examples
- **HEARTBEAT.md**: health-check checklist for production monitoring
- **scripts/**: helper scripts (e.g., signature verification)
- **templates/**: JSON templates (e.g., OAuth client registration payload)

Quick link:
- `skills/public/hodlxxi-bitcoin-identity/SKILL.md`

Raw install link (for agents that can fetch skills from GitHub):
- `https://raw.githubusercontent.com/hodlxxi/Universal-Bitcoin-Identity-Layer/main/skills/public/hodlxxi-bitcoin-identity/SKILL.md`

## Conventions

- Skills should avoid secrets and never include private keys, macaroons, or environment values.
- Prefer copy/paste command blocks and small scripts.
- If a skill requires credentials, document the *variable names* and how to obtain them.


## Trust-model note

The skills catalog is a discovery surface, not a proof surface. Trust-model semantics for the agent runtime should stay centralized in `TRUST_MODEL.md`, `AGENT_PROTOCOL.md`, and the runtime `/.well-known/agent.json` document so skill docs do not become a second competing source of truth.
