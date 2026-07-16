from __future__ import annotations

import fastmcp
from fastmcp import FastMCP
from mcp import types as mcp_types

from . import __version__
from .client import HODLXXIReadOnlyClient
from .tools import register_tools

EXPECTED_FASTMCP_VERSION = "3.4.4"
TOOLS_ONLY_DISABLED_REQUESTS = (
    mcp_types.ListPromptsRequest,
    mcp_types.ListResourcesRequest,
    mcp_types.ListResourceTemplatesRequest,
    mcp_types.GetPromptRequest,
    mcp_types.ReadResourceRequest,
)


def _enforce_tools_only_protocol_contract(server: FastMCP) -> FastMCP:
    """Strip FastMCP's empty prompt/resource handlers from the public MCP surface.

    FastMCP 3.4.4 always registers prompt and resource request handlers during
    server construction, even when the local catalogs are empty. The MCP SDK
    derives initialize capabilities from handler presence, so those no-op
    handlers cause the serialized initialize response to advertise prompt and
    resource capabilities that HODLXXI does not actually expose.

    This helper intentionally validates the expected FastMCP 3.4.4 internals
    and fails closed if they drift, rather than silently mutating an unknown
    framework structure.
    """

    if fastmcp.__version__ != EXPECTED_FASTMCP_VERSION:
        raise RuntimeError(
            f"Unsupported FastMCP version {fastmcp.__version__!r}; expected {EXPECTED_FASTMCP_VERSION!r}."
        )

    low_level = getattr(server, "_mcp_server", None)
    request_handlers = getattr(low_level, "request_handlers", None)
    notification_options = getattr(low_level, "notification_options", None)
    if not isinstance(request_handlers, dict) or notification_options is None:
        raise RuntimeError("FastMCP low-level server internals changed unexpectedly.")

    if mcp_types.ListToolsRequest not in request_handlers:
        raise RuntimeError("FastMCP tools/list handler is missing unexpectedly.")

    missing_handlers = [
        request_type.__name__ for request_type in TOOLS_ONLY_DISABLED_REQUESTS if request_type not in request_handlers
    ]
    if missing_handlers:
        raise RuntimeError(
            "FastMCP prompt/resource handler layout changed unexpectedly: " + ", ".join(sorted(missing_handlers))
        )

    if notification_options.prompts_changed is not True or notification_options.resources_changed is not True:
        raise RuntimeError("FastMCP notification defaults changed unexpectedly.")

    for request_type in TOOLS_ONLY_DISABLED_REQUESTS:
        request_handlers.pop(request_type, None)

    notification_options.prompts_changed = False
    notification_options.resources_changed = False
    return server


def build_server(client: HODLXXIReadOnlyClient | None = None) -> FastMCP:
    server = FastMCP(
        "HODLXXI Read-Only",
        version=__version__,
        website_url="https://hodlxxi.com",
        instructions=(
            "Public, read-only access to the fixed HODLXXI machine-readable GET surface. "
            "No generic URL fetch, write operation, wallet access, environment access, "
            "private-key access, payment action, or Flask-monolith tool execution is provided. "
            "The live public endpoint is routed by nginx to this separate read-only sidecar."
        ),
        on_duplicate="error",
        strict_input_validation=True,
        mask_error_details=True,
    )
    register_tools(server, client or HODLXXIReadOnlyClient())
    return _enforce_tools_only_protocol_contract(server)


mcp = build_server()


def main() -> None:
    mcp.run()
