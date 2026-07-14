from __future__ import annotations

from typing import Any, Mapping

import httpx
import pytest
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

import hodlxxi_mcp.http_server as http_server
from hodlxxi_mcp.client import Endpoint
from hodlxxi_mcp.server import build_server
from hodlxxi_mcp.tools import TOOL_NAMES


class StubReadOnlyClient:
    """Deterministic upstream used by Streamable HTTP tests."""

    def __init__(self) -> None:
        self.calls: list[tuple[Endpoint, dict[str, str], dict[str, int]]] = []

    async def get_json(
        self,
        endpoint: Endpoint,
        *,
        path_params: Mapping[str, str] | None = None,
        query: Mapping[str, int] | None = None,
    ) -> dict[str, Any]:
        normalized_path = dict(path_params or {})
        normalized_query = dict(query or {})
        self.calls.append(
            (
                endpoint,
                normalized_path,
                normalized_query,
            )
        )
        return {
            "ok": True,
            "endpoint": endpoint.value,
            "path_params": normalized_path,
            "query": normalized_query,
        }


class FakeServer:
    def __init__(self) -> None:
        self.run_kwargs: dict[str, object] | None = None

    def run(self, **kwargs: object) -> None:
        self.run_kwargs = kwargs


def test_local_http_policy_is_fixed_and_loopback_only() -> None:
    assert http_server.local_http_app_kwargs() == {
        "path": "/mcp",
        "transport": "streamable-http",
        "json_response": True,
        "stateless_http": True,
        "host_origin_protection": True,
        "allowed_hosts": [
            "127.0.0.1:8765",
            "localhost:8765",
        ],
        "allowed_origins": [],
    }
    assert http_server.local_http_run_kwargs() == {
        **http_server.local_http_app_kwargs(),
        "host": "127.0.0.1",
        "port": 8765,
        "log_level": "INFO",
        "show_banner": False,
    }


def test_local_http_app_exposes_only_the_mcp_route() -> None:
    app = http_server.build_local_http_app(build_server())

    assert len(app.routes) == 1
    route = app.routes[0]
    assert route.path == "/mcp"
    assert route.methods == {"POST", "DELETE"}


def test_http_entrypoint_uses_fresh_server_and_locked_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_server = FakeServer()
    monkeypatch.setattr(
        http_server,
        "build_server",
        lambda: fake_server,
    )

    http_server.main()

    assert fake_server.run_kwargs == http_server.local_http_run_kwargs()


@pytest.mark.asyncio
async def test_streamable_http_protocol_round_trip() -> None:
    upstream = StubReadOnlyClient()
    server = build_server(upstream)  # type: ignore[arg-type]
    app = http_server.build_local_http_app(server)
    transport = httpx.ASGITransport(app=app)

    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://127.0.0.1:8765",
        ) as http_client:
            async with streamable_http_client(
                "http://127.0.0.1:8765/mcp",
                http_client=http_client,
                terminate_on_close=False,
            ) as (read_stream, write_stream, _get_session_id):
                async with ClientSession(
                    read_stream,
                    write_stream,
                ) as session:
                    initialization = await session.initialize()
                    tools = await session.list_tools()
                    result = await session.call_tool(
                        "hodlxxi_get_capabilities",
                        {},
                    )

                    assert initialization.serverInfo.name == ("HODLXXI Read-Only")
                    assert initialization.serverInfo.version == "0.1.1"
                    assert {tool.name for tool in tools.tools} == set(TOOL_NAMES)
                    assert len(tools.tools) == 26
                    assert getattr(result, "isError", False) is not True

    assert upstream.calls == [
        (
            Endpoint.CAPABILITIES,
            {},
            {},
        )
    ]
