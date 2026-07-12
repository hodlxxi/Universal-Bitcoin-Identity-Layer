from __future__ import annotations

from fastmcp import FastMCP

from . import __version__
from .client import HODLXXIReadOnlyClient
from .tools import register_tools


def build_server(client: HODLXXIReadOnlyClient | None = None) -> FastMCP:
    server = FastMCP(
        "HODLXXI Read-Only",
        version=__version__,
        instructions=(
            "Public, read-only access to the fixed HODLXXI machine-readable GET surface. "
            "No generic URL fetch, write operation, wallet access, environment access, "
            "private-key access, payment action, or live /agent/mcp integration is provided."
        ),
        on_duplicate="error",
        strict_input_validation=True,
        mask_error_details=True,
    )
    register_tools(server, client or HODLXXIReadOnlyClient())
    return server


mcp = build_server()


def main() -> None:
    mcp.run()
