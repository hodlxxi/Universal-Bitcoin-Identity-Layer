# MCP Sidecar Discovery Rollout

## Current production contract — public sidecar live

The HODLXXI read-only MCP sidecar is live at `https://hodlxxi.com/agent/mcp`. nginx routes that public endpoint to the dedicated loopback sidecar separately from discovery metadata at `http://127.0.0.1:8765/mcp`; the Flask monolith publishes discovery metadata but does not execute MCP tools.

- Flask publishes the server card aliases:
  - `/.well-known/mcp.json`
  - `/.well-known/mcp/server-card.json`
  - `/.well-known/mcp/server-cards.json`
- Flask also embeds the same bounded `mcp` contract in:
  - `/.well-known/agent.json`
  - `/agent/capabilities`
- `HODLXXI_MCP_PUBLIC_ENABLED` defaults to `false`; production explicitly sets it true so discovery marks the public read-only sidecar available. A new deployment without the flag remains fail closed.
- The monolith `POST /agent/mcp` route remains a fail-closed `501` fallback. It does not proxy to the sidecar and does not execute MCP tools.
- The sidecar does not receive Flask, database, wallet, LND, operator-key, or agent-key credentials.
- Local stdio and localhost Streamable HTTP modes remain available for development and validation.

## Historical rollout note

Stage 9 originally published discovery while public transport was disabled, and Stage 10 routed public transport to the sidecar. Those stages are complete; do not treat the historical disabled-transport language as the current production contract.

Do not couple MCP discovery metadata changes to payment, OAuth, wallet, LND, database, shell, private-key, arbitrary-URL, systemd, or MCP tool implementation changes.
