# HODLXXI MCP systemd sidecar

## Status

This file and the repository unit are deployment artifacts only.

Merging them does not:

- install a systemd unit;
- run `systemctl daemon-reload`;
- enable or start a service;
- install Python packages;
- create a public MCP route;
- modify nginx;
- modify the Flask production runtime.

The actual localhost rollout requires separate operator approval.

## Intended endpoint

```text
http://127.0.0.1:8765/mcp
```

The service entrypoint is:

```text
/opt/hodlxxi-mcp/current/venv/bin/hodlxxi-mcp-http
```

The sidecar must use a dedicated, versioned release directory under:

```text
/opt/hodlxxi-mcp/releases/<git-commit>/
```

`/opt/hodlxxi-mcp/current` should point to the reviewed release.

## Security boundary

The sidecar:

- uses `DynamicUser=yes`;
- runs as the isolated identity `hodlxxi-mcp`;
- receives no production environment file;
- receives no database, wallet, LND, operator-key, or agent-key credentials;
- cannot read `/srv/ubid`;
- cannot read `/srv/ubid-staging`;
- cannot read `/etc/hodlxxi`;
- cannot read `/var/lib/lnd`;
- cannot read `/home/lnd`;
- can bind only TCP port 8765;
- has no Linux capabilities;
- cannot gain new privileges;
- exposes only the existing read-only MCP tools.

`PrivateNetwork=yes` is intentionally not enabled because the wrapper must
make outbound HTTPS requests to the public HODLXXI origin.

## Later rollout preconditions

Before installation:

1. Verify the exact merged Git commit.
2. Verify port 8765 is unused.
3. Verify `hodlxxi-mcp.service` is not already installed.
4. Build a dedicated virtual environment under the versioned release.
5. Run the complete MCP package tests.
6. Make the release root-owned and non-writable by the service.
7. Verify production and operator continuity remain healthy.

## Later localhost validation

After a separately approved installation:

```bash
systemctl is-active hodlxxi-mcp.service
systemctl status hodlxxi-mcp.service --no-pager
ss -ltnp | grep '127.0.0.1:8765'
```

The following listeners must not exist:

```text
0.0.0.0:8765
[::]:8765
```

A real MCP client must verify:

```text
initialize
tools/list = 26
tools/call hodlxxi_get_capabilities
tools/call hodlxxi_get_chain_health
tools/call hodlxxi_get_reputation
```

No nginx route should exist at this stage.

## Rollback
The later localhost-only rollout can be removed with:

```bash
systemctl disable --now hodlxxi-mcp.service
rm -f /etc/systemd/system/hodlxxi-mcp.service
systemctl daemon-reload
systemctl reset-failed hodlxxi-mcp.service
```

The versioned release should be retained until rollback verification is
complete.
