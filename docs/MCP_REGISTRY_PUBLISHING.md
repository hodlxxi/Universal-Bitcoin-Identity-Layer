# Publish HODLXXI to the Official MCP Registry

The public remote server is already live and independently validated:

```text
https://hodlxxi.com/agent/mcp
```

Registry publication makes it discoverable to MCP clients and downstream catalogs that consume the official registry. The `0.1.1` metadata below is release-target metadata; publish it only after merge, deployment, and external validation of the `0.1.1` remote server.

## Published Registry state

```text
registry name: io.github.hodlxxi/hodlxxi-readonly
currently published version: 0.1.0
status: active
isLatest: true
published at: 2026-07-14T01:04:44.727282Z
published from commit: 0314e631a78ad7c91512beab407778885d1bf59c
remote URL: https://hodlxxi.com/agent/mcp
website URL: https://hodlxxi.com
pending release target: 0.1.1
```

The registry stores metadata only. HODLXXI remains hosted and operated at `hodlxxi.com`. The currently published Registry version is `0.1.0`; `0.1.1` is only the pending release target in this repository until the release order below is completed.

## Pending 0.1.1 canonical identity

```text
registry name: io.github.hodlxxi/hodlxxi-readonly
version: 0.1.1
transport: streamable-http
remote URL: https://hodlxxi.com/agent/mcp
website URL: https://hodlxxi.com
metadata: server.json
```

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
version=0.1.1
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

Do not publish from an unmerged feature branch. Do not publish `0.1.1` until all release-order steps below are complete.

Required `0.1.1` release order:

1. merge into `main`;
2. deploy runtime discovery metadata `0.1.1`;
3. deploy MCP sidecar package `0.1.1`;
4. run an external public MCP round trip;
5. confirm live discovery reports `0.1.1`;
6. run `mcp-publisher validate` from a clean checkout of the deployed commit;
7. publish Registry version `0.1.1`;
8. verify `0.1.1` becomes `isLatest: true`.

Only after those checks pass, publish from the repository root:

```bash
mcp-publisher publish
```

## Verify

```bash
curl -fsS 'https://registry.modelcontextprotocol.io/v0.1/servers?search=io.github.hodlxxi/hodlxxi-readonly' | jq .
```

After publication, the result must contain the exact registry name, version `0.1.1`, `isLatest: true`, website URL `https://hodlxxi.com`, and remote URL `https://hodlxxi.com/agent/mcp`.

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
