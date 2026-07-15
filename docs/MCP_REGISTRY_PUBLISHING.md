# Publish HODLXXI to the Official MCP Registry

The public remote server is already live and independently validated:

```text
https://hodlxxi.com/agent/mcp
```

Registry publication makes it discoverable to MCP clients and downstream catalogs that consume the official registry. This document records dated evidence plus the release order for future publication work. Re-query the live Registry API before any future publish step; do not assume the dated state below is still current.

## Dated Registry Evidence

As re-queried on 2026-07-14:

```text
registry name: io.github.hodlxxi/hodlxxi-readonly
latest published version: 0.1.1
latest status: active
latest isLatest: true
latest published at: 2026-07-14T03:45:07.915855Z
historical published version also present: 0.1.0
historical published at: 2026-07-14T01:04:44.727282Z
remote URL: https://hodlxxi.com/agent/mcp
website URL: https://hodlxxi.com
repository subfolder: packages/hodlxxi_mcp
```

The Registry stores metadata only. HODLXXI remains hosted and operated at `hodlxxi.com`.

## Current Canonical Identity

```text
registry name: io.github.hodlxxi/hodlxxi-readonly
version: 0.1.1
transport: streamable-http
remote URL: https://hodlxxi.com/agent/mcp
website URL: https://hodlxxi.com
metadata file: server.json
```

For any future publication after `0.1.1`, replace the target version only after the release order below is completed against the actually deployed commit and the Registry state has been re-queried.

## Preflight

Run from the repository root on a clean checkout of the intended release commit:

```bash
git status --short
python -m json.tool server.json >/dev/null
curl -fsS 'https://registry.modelcontextprotocol.io/v0.1/servers?search=io.github.hodlxxi/hodlxxi-readonly' | jq .
curl -fsS https://hodlxxi.com/.well-known/mcp.json | jq '{name,version,enabled,availability,endpoint,tool_count}'
```

Expected source/discovery target for the current published version:

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
python scripts/mcp_remote_verify.py \
  --endpoint https://hodlxxi.com/agent/mcp \
  --json-output /tmp/hodlxxi-mcp-verification.json \
  --markdown-output /tmp/hodlxxi-mcp-verification.md
```

## Install the Official Publisher

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

## Validate

Do not publish from an unmerged feature branch. Do not publish any future version until all release-order steps below are complete.

Required future release order:

1. merge into `main`;
2. deploy runtime discovery metadata for the target version;
3. deploy the MCP sidecar package for the target version;
4. run an external public MCP round trip;
5. confirm live discovery reports the target version;
6. re-query the official Registry read-only endpoint for the current published state;
7. run `mcp-publisher validate` from a clean checkout of the deployed commit;
8. publish the target Registry version;
9. verify the new version becomes `isLatest: true`.

Validation command:

```bash
mcp-publisher validate
```

## Publish

Only after the release-order checks pass, publish from the repository root:

```bash
mcp-publisher publish
```

## Post-Publication Checks

```bash
curl -fsS 'https://registry.modelcontextprotocol.io/v0.1/servers?search=io.github.hodlxxi/hodlxxi-readonly' | jq .
```

After publication, the result must contain the exact registry name, the target version, `isLatest: true`, website URL `https://hodlxxi.com`, remote URL `https://hodlxxi.com/agent/mcp`, and repository subfolder `packages/hodlxxi_mcp`.

Then repeat a real remote protocol smoke test from a machine outside the server:

```text
initialize -> tools/list -> hodlxxi_get_capabilities -> hodlxxi_get_chain_health -> hodlxxi_get_reputation
```

## Future Release Rules

For any future MCP release:

1. update the package version;
2. update discovery metadata and `server.json` to the same version;
3. run all MCP and registry-contract tests;
4. deploy and externally validate the remote endpoint;
5. re-query the Registry API to capture the current published state;
6. publish the new Registry version;
7. verify the Registry response after publication.

Never publish registry metadata that advertises a version or endpoint not yet deployed and externally validated.
