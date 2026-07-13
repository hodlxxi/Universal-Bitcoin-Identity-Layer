# MCP Sidecar Discovery Rollout

## Stage 9 — discovery contract merged, public transport disabled

This stage publishes truthful MCP discovery metadata for the dedicated read-only sidecar while keeping public transport disabled by default.

- Flask publishes the server card aliases:
  - `/.well-known/mcp.json`
  - `/.well-known/mcp/server-card.json`
  - `/.well-known/mcp/server-cards.json`
- Flask also embeds the same bounded `mcp` contract in:
  - `/.well-known/agent.json`
  - `/agent/capabilities`
- `HODLXXI_MCP_PUBLIC_ENABLED` defaults to `false`; only an explicit true value marks discovery as available.
- The monolith `POST /agent/mcp` route remains a fail-closed `501` stub. It does not proxy to the sidecar and does not execute MCP tools.

## Stage 10 — route public transport to the sidecar

After Stage 9 is deployed and verified, add nginx exact-location routing for `/agent/mcp` to the dedicated read-only sidecar. Then set `HODLXXI_MCP_PUBLIC_ENABLED=true` and restart or reload only the application process required for discovery metadata to reflect availability.

Do not couple this flag flip to payment, OAuth, wallet, LND, database, shell, private-key, arbitrary-URL, systemd, or MCP tool implementation changes.
