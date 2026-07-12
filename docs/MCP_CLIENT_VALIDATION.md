# HODLXXI MCP Client Validation

Validated successfully on 2026-07-12.

## Build

- Repository: `hodlxxi/Universal-Bitcoin-Identity-Layer`
- Merged commit: `7125eaeb0f04dad8207a520ab81d32c7ba6bf0b7`
- Package: `hodlxxi-mcp` `0.1.0`
- FastMCP: `3.4.4`
- MCP Python SDK: `1.28.1`
- Transport: local stdio
- Tool count: `26`
- MCP host: Claude Desktop for macOS
- Python: `3.12.13`
- Public upstream: `https://hodlxxi.com`

The package was installed from the exact merged commit.

## Protocol result

A real local stdio session completed MCP initialization, `tools/list`,
and `tools/call`:

```text
server=HODLXXI Read-Only
version=0.1.0
tool_count=26
tool_call=hodlxxi_get_capabilities
result=PASS
```

## Claude Desktop result

Claude Desktop discovered `hodlxxi-readonly` and successfully called:

- `hodlxxi_get_operator_continuity`
- `hodlxxi_get_capabilities`
- `hodlxxi_get_chain_health`
- `hodlxxi_get_reputation`
- `hodlxxi_get_attestations`

All answers were grounded in live MCP calls to the public runtime.

The client retrieved operator ID `E923`, the distinct operator and agent
keys, four paid job types, a continuous attestation chain, reputation
metrics, and recent signed attestations.

## Clarifications discovered

The validation exposed two public-schema ambiguities:

1. `total_jobs` counts all persisted requests, including unpaid or
   invoice-pending requests. It is not an execution success-rate
   denominator.
2. A 64-hex `requester_pubkey` in the Nostr proof flow is an x-only
   secp256k1 key, not a malformed compressed key.

A follow-up additive runtime change should publish explicit outcome
semantics and requester-key encoding. Historical signed receipts must
not be rewritten.

## Security boundary

The server exposed exactly 26 allowlisted tools and no MCP prompts or
resources. It exposed no generic URL fetch, write method, shell,
filesystem, database, wallet, LND, private-key, payment-initiation, or
receipt-creation tool.

## Conclusion

The standalone HODLXXI MCP package works in a real independent MCP host
over stdio. The stdio client-validation gate is complete.

No Streamable HTTP transport, public `/agent/mcp` route, systemd unit,
nginx route, or production deployment was used.
