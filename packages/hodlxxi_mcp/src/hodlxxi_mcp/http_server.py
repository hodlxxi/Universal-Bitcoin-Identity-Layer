from __future__ import annotations

from typing import Any, Final

from fastmcp import FastMCP

from .server import build_server

LOCAL_HTTP_HOST: Final[str] = "127.0.0.1"
LOCAL_HTTP_PORT: Final[int] = 8765
LOCAL_HTTP_PATH: Final[str] = "/mcp"
LOCAL_HTTP_ALLOWED_HOSTS: Final[tuple[str, ...]] = (
    f"{LOCAL_HTTP_HOST}:{LOCAL_HTTP_PORT}",
    f"localhost:{LOCAL_HTTP_PORT}",
)


def local_http_app_kwargs() -> dict[str, object]:
    """Return the fixed localhost Streamable HTTP application policy."""
    return {
        "path": LOCAL_HTTP_PATH,
        "transport": "streamable-http",
        "json_response": True,
        "stateless_http": True,
        "host_origin_protection": True,
        "allowed_hosts": list(LOCAL_HTTP_ALLOWED_HOSTS),
        "allowed_origins": [],
    }


def local_http_run_kwargs() -> dict[str, object]:
    """Return the fixed localhost runner policy."""
    return {
        **local_http_app_kwargs(),
        "host": LOCAL_HTTP_HOST,
        "port": LOCAL_HTTP_PORT,
        "log_level": "INFO",
        "show_banner": False,
    }


def build_local_http_app(server: FastMCP | None = None) -> Any:
    """Build the localhost-only ASGI app without binding a socket."""
    active_server = server or build_server()
    return active_server.http_app(**local_http_app_kwargs())


def main() -> None:
    """Run the read-only MCP server on the fixed loopback endpoint."""
    build_server().run(**local_http_run_kwargs())


if __name__ == "__main__":
    main()
