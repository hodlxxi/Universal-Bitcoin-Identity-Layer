# HODLXXI MCP Client Validation

Validated successfully over local stdio on 2026-07-12 and over the public remote production endpoint on 2026-07-13.

## Last externally validated production build

- Repository: `hodlxxi/Universal-Bitcoin-Identity-Layer`
- Production commit: `8d5281d49eb532187f32c81266b3beaff1069e9e`
- Package/server version: `hodlxxi-mcp` `0.1.0`
- FastMCP: `3.4.4`
- MCP Python SDK: `1.28.1`
- Negotiated protocol version: `2025-11-25`
- Tool count: `26`
- Python: `3.12.13`
- Public endpoint: `https://hodlxxi.com/agent/mcp`
- Server card: `https://hodlxxi.com/.well-known/mcp.json`
- Published Registry version: `0.1.0`
- Pending release target: `0.1.1`

## Pending release

Version `0.1.1` aligns package and discovery metadata with the live protocol audit. It must be merged, deployed, and externally revalidated before this document records `0.1.1` as the last externally validated production build.

## Public deployment path

```text
external MCP client
    -> HTTPS
    -> nginx on hodlxxi.com
    -> 127.0.0.1:8765/mcp
    -> hardened hodlxxi-mcp systemd sidecar
    -> allowlisted public HODLXXI GET surfaces
```

The sidecar listens only on loopback. The Flask monolith publishes discovery metadata but does not execute MCP tools.

## Protocol result

A real external macOS client completed MCP initialization, `tools/list`, and `tools/call` over Streamable HTTP:

```text
server_name=HODLXXI Read-Only
server_version=0.1.0
tool_count=26
unique_tool_count=26
hodlxxi_get_capabilities: is_error=False
hodlxxi_get_chain_health: is_error=False
hodlxxi_get_reputation: is_error=False
```

The same remote endpoint was connected as a Claude custom connector. Claude successfully called chain health and reputation and returned current runtime data.

One initial Claude tool call timed out before a successful retry. Server-side inspection found no MCP exception and no nginx `499`, `502`, or `504`; the successful protocol exchange completed normally. No production rollback or server change was required.

## Discovery result

The public server card advertises:

```text
name=HODLXXI Read-Only
version=0.1.0
enabled=true
availability=available
transport=streamable_http
authentication=none
tool_count=26
writes_enabled=false
payments_enabled=false
```

The official MCP Registry metadata lives at the repository root in `server.json` and identifies the remote server as:

```text
io.github.hodlxxi/hodlxxi-readonly
```

## Runtime data interpretation

The validation exposed two public-schema clarifications:

1. `total_jobs` counts all persisted requests, including unpaid or expired test invoices. It is not an execution success-rate denominator.
2. A 64-hex `requester_pubkey` in the Nostr proof flow is an x-only secp256k1 key, not a malformed compressed key.

At the time of remote validation, the job history was operator-generated testing rather than external-user traffic. The observed counters were:

```text
total_jobs=261
unpaid_or_expired_jobs=235
completed_jobs=26
evidenced_completed_jobs=26
external_users=0
```

Therefore, 26 of 26 completed test jobs had evidence. The ratio `26 / 261` must not be presented as a real-user conversion or runtime completion rate.

## Security boundary

The server exposes exactly 26 allowlisted tools and no MCP prompts or resources. It exposes no generic URL fetch, write method, shell, filesystem, database, wallet, LND, private-key, payment-initiation, or receipt-creation tool.

The production reverse proxy accepts only the MCP transport methods required by the deployment (`GET`, `POST`, and `DELETE`) and rejects unrelated methods such as `PUT` and `OPTIONS`.

## Conclusion

The HODLXXI MCP server is live, externally reachable, independently validated, and usable by remote MCP-capable agents without credentials. Registry publication is the remaining distribution step for broad ecosystem discovery.
