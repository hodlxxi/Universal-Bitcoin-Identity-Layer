# HODLXXI MCP Read-Only Wrapper

This document defines a read-only Model Context Protocol wrapper profile for HODLXXI / Volya.ID.

## Status

This is a documentation and example profile only.

It does not implement an MCP server in this repository.

## Goal

Expose public HODLXXI agent runtime surfaces to MCP-compatible clients without granting write, shell, wallet, env, or private-key access.

## Read-only tools

A safe wrapper may expose these tools:

| Tool | HTTP method | HODLXXI endpoint |
|---|---:|---|
| hodlxxi_get_agent_discovery | GET | /agent/discovery |
| hodlxxi_get_capabilities | GET | /agent/capabilities |
| hodlxxi_get_nostr_announcement | GET | /agent/nostr/announcement |
| hodlxxi_get_trust_events | GET | /agent/trust/events |
| hodlxxi_get_reputation | GET | /agent/reputation |
| hodlxxi_get_chain_health | GET | /agent/chain/health |

See `examples/mcp/hodlxxi_mcp_readonly_tools.json` for a machine-readable example.

## Non-goals

The read-only wrapper must not:

- execute shell commands
- read environment variables
- read wallet files
- access private keys
- access LND macaroons
- auto-pay invoices
- call `POST /agent/request`
- custody funds

## Security model

The wrapper is a bridge from MCP clients to existing public GET endpoints.

All returned data should be treated as public runtime metadata and verified where possible using HODLXXI signatures, receipts, and trust-event surfaces.

## Future work

A later write-capable MCP profile may add paid job creation, but only with explicit user approval, invoice display, spending policy, and no automatic payment.
