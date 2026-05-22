# HODLXXI Agent Runtime Index

This is a compact index for the machine-readable HODLXXI agent runtime.

Canonical protocol and trust details remain in:

- `AGENT_PROTOCOL.md`
- `TRUST_MODEL.md`

## Discovery

- `/.well-known/agent.json`
- `/agent/discovery`
- `/agent/capabilities`
- `/agent/capabilities/schema`
- `/agent/skills`
- `/agent/marketplace/listing`
- `/agent/nostr/announcement`

## Paid Work

- `POST /agent/request`
- `GET /agent/jobs/<job_id>`
- `GET /agent/verify/<job_id>`

## Agent-to-Agent Message Flow

- `POST /agent/message`

## Trust Surfaces

- `/agent/trust/events`
- `/agent/attestations`
- `/agent/reputation`
- `/agent/chain/health`

## Runtime Rules

- no custody
- no pooled funds
- no escrow guarantees
- peer-to-peer settlement only
- public-key identity
- signed receipts
- machine-readable attestations
- verify, do not trust


## Nostr NIP-90 Compatibility

See `docs/AGENT_NIP90_COMPATIBILITY.md` for the current NIP-90 mapping and example request/feedback/result payloads.


## MCP Read-Only Wrapper

See `docs/MCP_READONLY_WRAPPER.md` and `examples/mcp/hodlxxi_mcp_readonly_tools.json` for a read-only MCP wrapper profile over public HODLXXI agent endpoints.


## External Agent Registry

See `docs/EXTERNAL_AGENT_REGISTRY.md` for the future external-agent registry profile and safety model.
