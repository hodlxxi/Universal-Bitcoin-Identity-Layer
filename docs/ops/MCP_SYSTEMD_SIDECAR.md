# HODLXXI MCP systemd sidecar

## Status and production boundary

This repository contains deployment artifacts only and a fail-closed release procedure for the existing read-only MCP sidecar. Merging these files still requires separate operator approval and does **not** deploy production, edit `/srv/ubid`, alter nginx, change systemd policy, expose writable MCP tools, or touch secrets.

Production truth expected by this procedure:

- source checkout: `/srv/ubid`
- releases: `/opt/hodlxxi-mcp/releases/<release-id>`
- active symlink: `/opt/hodlxxi-mcp/current`
- service: `hodlxxi-mcp.service`
- entrypoint: `/opt/hodlxxi-mcp/current/venv/bin/hodlxxi-mcp-http`
- service identity: `hodlxxi-mcp:hodlxxi-mcp`
- listener: `127.0.0.1:8765` (`http://127.0.0.1:8765/mcp`)
- public route: `https://hodlxxi.com/agent/mcp`

## Critical safety rule

Never manually repoint `/opt/hodlxxi-mcp/current` at a candidate release before the release has been built and verified. A previous incident temporarily pointed `current` at an incomplete release with no `venv/bin/hodlxxi-mcp-http`, causing systemd restart loops. Activation must happen only through the atomic activation phase below.

## Operator preflight

Before any production run:

1. Confirm the intended Git commit is checked out in `/srv/ubid` and reviewed.
2. Confirm `git -C /srv/ubid status --porcelain` is empty.
3. Confirm `/opt/hodlxxi-mcp/current` points at the currently healthy release.
4. Confirm the unit is the expected `hodlxxi-mcp.service` and the existing service is healthy.
5. Confirm no operator intends to change Flask, nginx, LND, wallet, database, secrets, payments, or writable MCP behavior during this operation.
6. Prefer a dry run/check-only command first.

## Phased release procedure

The script is `scripts/mcp_release_deploy.py`. It separates build, verify, and activate so `current` is never modified by a build.

### 1. Build immutable release

```bash
python scripts/mcp_release_deploy.py \
  --source /srv/ubid \
  --releases-dir /opt/hodlxxi-mcp/releases \
  --current /opt/hodlxxi-mcp/current \
  build --wheelhouse /opt/hodlxxi-mcp/wheelhouse/<reviewed-wheelhouse-id>
```

Build behavior:

- sets `umask 022` to avoid unreadable artifacts from a restrictive caller umask;
- refuses a dirty source checkout unless `--allow-dirty-build` is explicitly supplied for a reviewed non-production test;
- records the exact source commit;
- creates a new versioned release directory that is not the active `current` target;
- does not modify `/opt/hodlxxi-mcp/current`;
- requires a reviewed wheelhouse and installs exact dependencies from `packages/hodlxxi_mcp/requirements/mcp-release.lock` with `--no-index --no-deps`;
- validates the reviewed offline wheelhouse before release creation and does not rely on pip caches;
- builds the local package wheel with exact locked build tools and `--no-build-isolation`, records the wheel SHA-256, and installs that wheel with `--no-deps`;
- records `INSTALLED_DISTRIBUTIONS.txt`;
- leaves release files readable/executable by the sidecar identity, root-owned in production, and not writable by `hodlxxi-mcp`;
- runs verification before the release is considered complete.

### 2. Verify release

```bash
python scripts/mcp_release_deploy.py \
  --source /srv/ubid \
  --current /opt/hodlxxi-mcp/current \
  verify /opt/hodlxxi-mcp/releases/<release-id> --write
```

Verification fails closed unless all required checks pass: release directory exists as a direct non-symlink child of the configured releases directory, it is not the active symlink target, identity evidence matches the source checkout and installed runtime, dependency-lock digest matches, the entrypoint exists and is executable, package imports succeed as the service user from `/tmp`, package version matches repository metadata, the in-memory FastMCP server reports `HODLXXI Read-Only` and the repository version, tool count is exactly `26` (`tools/list = 26`), resource and prompt counts are `0`, service-required files are readable by `hodlxxi-mcp`, and production release content is not writable by `hodlxxi-mcp`. The verifier prints only bounded status metadata and must not print secrets.

### 3. Activate release

Check-only first:

```bash
python scripts/mcp_release_deploy.py \
  --source /srv/ubid \
  --current /opt/hodlxxi-mcp/current \
  activate /opt/hodlxxi-mcp/releases/<release-id> --check-only
```

Actual activation:

```bash
python scripts/mcp_release_deploy.py \
  --source /srv/ubid \
  --current /opt/hodlxxi-mcp/current \
  activate /opt/hodlxxi-mcp/releases/<release-id>
```

Activation behavior:

- requires a previously verified release containing `VERIFY.json`;
- captures the previous `current` target;
- switches `current` with a temporary symlink on the same filesystem and atomic rename;
- restarts only `hodlxxi-mcp.service`;
- checks parsed `systemctl show` fields (`ActiveState=active`, `SubState=running`, `Result=success`, `ExecMainStatus=0`, and bounded `NRestarts`), enforces an exact loopback-only listener, and runs MCP initialize/list smoke checks;
- on post-switch failure, atomically restores the previous symlink, restarts the previous release, and returns non-zero;
- preserves both the previous and failed release directories for investigation;
- never uses broad process killing and never deletes rollback material automatically.

## Release evidence files

Each release contains:

- `RELEASE_IDENTITY.json` with source commit, package version, installed distribution version, module version, Python version, FastMCP version, MCP SDK version, dependency-lock path and SHA-256 digest, build-input SHA-256 digest, build timestamp, source tree, release directory, and installed-distribution manifest digest;
- `INSTALLED_DISTRIBUTIONS.txt` from `pip freeze --all`;
- `VERIFY.json` after successful explicit verification, bound to the exact `RELEASE_IDENTITY.json` by SHA-256 digest.

These files are operator evidence. They are not secrets.

## Rollback behavior

Automatic rollback is attempted only when activation switches the symlink and a post-switch health check fails. The script restores the previous symlink atomically and restarts `hodlxxi-mcp.service`. It does not delete the failed release. If manual rollback is required later, repoint `current` only to a known previously verified release using the same atomic activation procedure rather than hand-editing the symlink.

## Security boundary

For the earlier localhost-only rollout stage, No nginx route should exist at this stage. For current production, only the already-approved public nginx route is in scope; this procedure must not alter nginx.

The sidecar remains read-only and least-authority. The repository unit uses the isolated `hodlxxi-mcp` identity, receives no production environment file, has no wallet/LND/database/operator-key credentials, and exposes only the fixed read-only MCP tools.
