# HODLXXI Read-Only MCP

Public remote MCP server and standalone FastMCP package wrapping 26 allowlisted HODLXXI machine-readable trust surfaces.

## Public remote server

Use this Streamable HTTP endpoint in any MCP host that supports remote servers:

```text
https://hodlxxi.com/agent/mcp
```

No API key or OAuth flow is required. The server is public and read-only.

Machine-readable discovery:

```text
https://hodlxxi.com/.well-known/mcp.json
https://hodlxxi.com/.well-known/agent.json
https://hodlxxi.com/agent/capabilities
```

A compatible client can initialize a session, list exactly 26 tools, and call tools such as:

- `hodlxxi_get_agent_discovery`
- `hodlxxi_get_capabilities`
- `hodlxxi_get_chain_health`
- `hodlxxi_get_reputation`
- `hodlxxi_get_attestations`
- `hodlxxi_get_operator_continuity`
- `hodlxxi_get_receipt`
- `hodlxxi_verify_receipt`

The canonical MCP Registry metadata is stored at the repository root in `server.json` under the name `io.github.hodlxxi/hodlxxi-readonly`.

## Security boundary

- fixed upstream origin: `https://hodlxxi.com`
- fixed endpoint enum; no generic URL tool
- GET-only access to allowlisted upstream runtime surfaces
- redirects disabled
- 10-second upstream timeout
- 2 MiB response ceiling
- JSON and `application/linkset+json` only
- strict identifier and pagination validation
- no Flask imports, database access, wallet access, LND access, keys, secrets, environment reads, payment initiation, receipt creation, or write calls
- dedicated systemd sidecar; the Flask monolith does not execute MCP tools
- public nginx route proxies only to the loopback sidecar

`GET /agent/jobs/<job_id>` and `GET /agent/readiness/self-scan` are intentionally excluded because they may mutate server state.

## Independent validation

The remote production path has been validated from an external macOS client and through a Claude custom connector:

```text
external client -> HTTPS -> nginx -> loopback MCP sidecar -> public HODLXXI runtime surfaces
```

The validation completed MCP initialization, `tools/list`, and live calls to capabilities, chain health, and reputation. See `docs/MCP_CLIENT_VALIDATION.md`.

## Development

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[test]"
pytest -q
```

## Run over stdio

```bash
hodlxxi-mcp
```

Equivalent:

```bash
python -m hodlxxi_mcp
```

For local client configuration, point the MCP host at the virtual-environment executable and use stdio transport.

## Run the sidecar over localhost Streamable HTTP

```bash
hodlxxi-mcp-http
```

The sidecar endpoint is fixed at:

```text
http://127.0.0.1:8765/mcp
```

The sidecar transport is intentionally locked to loopback, stateless JSON responses, Host/Origin protection, and the same 26 read-only tools. Public exposure is handled separately by the hardened production reverse proxy.
