# Publish HODLXXI to the Official MCP Registry

The public remote server is already live and independently validated:

```text
https://hodlxxi.com/agent/mcp
```

Registry publication makes it discoverable to MCP clients and downstream catalogs that consume the official registry.

## Canonical identity

```text
registry name: io.github.hodlxxi/hodlxxi-readonly
version: 0.1.0
transport: streamable-http
remote URL: https://hodlxxi.com/agent/mcp
metadata: server.json
```

The registry stores metadata only. HODLXXI remains hosted and operated at `hodlxxi.com`.

## Preflight

Run from the repository root on a clean checkout of the intended release commit:

```bash
git status --short
python -m json.tool server.json >/dev/null
curl -fsS https://hodlxxi.com/.well-known/mcp.json | jq '{name,version,enabled,availability,endpoint,tool_count}'
```

Expected discovery state:

```text
name=HODLXXI Read-Only
version=0.1.0
enabled=true
availability=available
endpoint=https://hodlxxi.com/agent/mcp
tool_count=26
```

Run the repository contract tests before publication:

```bash
pytest -q tests/unit/test_mcp_registry_metadata.py tests/unit/test_mcp_discovery_contract.py
```

## Install the official publisher

On macOS with Homebrew:

```bash
brew install mcp-publisher
mcp-publisher --help
```

Alternatively, install the current prebuilt binary from the official `modelcontextprotocol/registry` releases.

## Authenticate

The registry name uses the `io.github.hodlxxi/` namespace, so authenticate with the GitHub account that owns the `hodlxxi` namespace:

```bash
mcp-publisher login github
```

Complete the device authorization flow shown by the CLI.

## Publish

From the repository root:

```bash
mcp-publisher publish
```

Do not publish from an unmerged feature branch. Publish only after `server.json` and its tests are merged to `main`.

## Verify

```bash
curl -fsS 'https://registry.modelcontextprotocol.io/v0.1/servers?search=io.github.hodlxxi/hodlxxi-readonly' | jq .
```

The result must contain the exact registry name, version `0.1.0`, and remote URL `https://hodlxxi.com/agent/mcp`.

Then repeat a real remote protocol smoke test from a machine outside the server:

```text
initialize -> tools/list -> hodlxxi_get_capabilities -> hodlxxi_get_chain_health -> hodlxxi_get_reputation
```

## Release updates

For any future MCP release:

1. update the package version;
2. update discovery metadata and `server.json` to the same version;
3. run all MCP and registry-contract tests;
4. deploy and externally validate the remote endpoint;
5. publish the new registry version;
6. verify the registry API result.

Never publish registry metadata that advertises a version or endpoint not yet deployed and externally validated.
