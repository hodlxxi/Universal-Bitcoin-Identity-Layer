"""Shared MCP discovery contract for the dedicated read-only sidecar."""

from __future__ import annotations

from typing import Mapping
from urllib.parse import urlparse

from app.feature_flags import config_flag

MCP_PUBLIC_ENABLED_ENV = "HODLXXI_MCP_PUBLIC_ENABLED"
MCP_SERVER_NAME = "HODLXXI Read-Only"
MCP_SERVER_VERSION = "0.1.1"
MCP_PROTOCOL_VERSION = "2025-11-25"
MCP_TRANSPORT_TYPE = "streamable_http"
MCP_ENDPOINT_PATH = "/agent/mcp"
MCP_SERVER_CARD_PATH = "/.well-known/mcp.json"
MCP_TOOL_COUNT = 26
MCP_ACCESS_MODE = "public_read_only"


def mcp_public_enabled(config: Mapping[str, object] | None = None) -> bool:
    """Return true only when public MCP discovery is explicitly enabled."""

    return config_flag(
        MCP_PUBLIC_ENABLED_ENV,
        config,
        default=False,
    )


def public_base_url(base_url: str) -> str:
    """Return a public base URL suitable for discovery metadata."""

    candidate = (base_url or "").rstrip("/")
    parsed = urlparse(candidate)
    if parsed.hostname in {"localhost", "127.0.0.1", "::1"} or not parsed.scheme or not parsed.netloc:
        return "https://hodlxxi.com"
    return candidate


def mcp_contract(config: Mapping[str, object] | None = None) -> dict[str, object]:
    """Return the bounded MCP contract shared by agent discovery surfaces."""

    enabled = mcp_public_enabled(config)
    return {
        "server_card": MCP_SERVER_CARD_PATH,
        "endpoint": MCP_ENDPOINT_PATH,
        "transport": MCP_TRANSPORT_TYPE,
        "protocol_version": MCP_PROTOCOL_VERSION,
        "server_name": MCP_SERVER_NAME,
        "server_version": MCP_SERVER_VERSION,
        "tool_count": MCP_TOOL_COUNT,
        "enabled": enabled,
        "access_mode": MCP_ACCESS_MODE,
        "authentication": {"type": "none"},
        "writes_enabled": False,
        "payments_enabled": False,
    }


def mcp_server_card(base_url: str, config: Mapping[str, object] | None = None) -> dict[str, object]:
    """Return the public MCP server card for the dedicated sidecar."""

    base = public_base_url(base_url)
    contract = mcp_contract(config)
    endpoint = f"{base}{MCP_ENDPOINT_PATH}"
    enabled = bool(contract["enabled"])
    availability = "available" if enabled else "disabled"
    return {
        "$schema": "https://modelcontextprotocol.io/schemas/server-card.v1.json",
        "name": MCP_SERVER_NAME,
        "version": MCP_SERVER_VERSION,
        "serverInfo": {"name": MCP_SERVER_NAME, "version": MCP_SERVER_VERSION},
        "description": (
            "Dedicated read-only MCP sidecar for HODLXXI public discovery. "
            "The Flask monolith does not execute MCP tools."
        ),
        "protocolVersion": MCP_PROTOCOL_VERSION,
        "endpoint": endpoint,
        "transport": {"type": MCP_TRANSPORT_TYPE, "url": endpoint, "endpoint": endpoint},
        "transports": [{"type": MCP_TRANSPORT_TYPE, "url": endpoint, "endpoint": endpoint}],
        "capabilities": {"tools": {"listChanged": False, "count": MCP_TOOL_COUNT}},
        "tool_count": MCP_TOOL_COUNT,
        "authentication": {"type": "none"},
        "access_mode": MCP_ACCESS_MODE,
        "read_only": True,
        "writes_enabled": False,
        "payments_enabled": False,
        "documentation": f"{base}/docs",
        "status": f"{base}/api/public/status",
        "enabled": enabled,
        "availability": availability,
        "boundary": {
            "read_only": True,
            "writes_enabled": False,
            "payments_enabled": False,
            "monolith_executes_tools": False,
            "no_wallet_lnd_shell_database_private_key_or_arbitrary_url_access": True,
        },
        "public_paths": {"server_card": MCP_SERVER_CARD_PATH, "endpoint": MCP_ENDPOINT_PATH},
    }
