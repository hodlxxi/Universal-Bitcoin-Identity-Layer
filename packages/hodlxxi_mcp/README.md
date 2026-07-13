# HODLXXI Standalone Read-Only MCP

Standalone FastMCP server wrapping 26 public machine-readable HODLXXI GET surfaces.

## Security boundary

- fixed upstream origin: `https://hodlxxi.com`
- fixed endpoint enum; no generic URL tool
- GET only
- redirects disabled
- 10-second timeout
- 2 MiB response ceiling
- JSON and `application/linkset+json` only
- strict identifier and pagination validation
- no Flask imports, database access, wallet access, keys, secrets, environment reads, payments, or write calls
- does not modify or replace the live `POST /agent/mcp` stub

`GET /agent/jobs/<job_id>` and `GET /agent/readiness/self-scan` are intentionally excluded because they may mutate server state.

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

For client configuration, point the MCP host at the virtual-environment executable and use stdio transport.

## Run over localhost Streamable HTTP

```bash
hodlxxi-mcp-http
```

The endpoint is fixed at `http://127.0.0.1:8765/mcp`.

The localhost transport is intentionally locked to loopback, stateless JSON responses, Host/Origin protection, and the existing 26 read-only tools. It does not create a public `/agent/mcp` route and does not modify nginx, systemd, the Flask runtime, the database, or payment behavior.
