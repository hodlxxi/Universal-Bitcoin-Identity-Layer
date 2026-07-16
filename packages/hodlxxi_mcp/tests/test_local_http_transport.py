from __future__ import annotations

from typing import Any, Mapping

import httpx
import pytest
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from starlette.testclient import TestClient

import hodlxxi_mcp.http_server as http_server
from hodlxxi_mcp.client import Endpoint
from hodlxxi_mcp.server import build_server
from hodlxxi_mcp.tools import TOOL_NAMES
from scripts import mcp_remote_verify as verifier


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


class VerifierResponseHandle:
    def __init__(self, response) -> None:
        self.status = response.status_code
        self.headers = {str(key).lower(): str(value) for key, value in response.headers.items()}
        self._body = response.content
        self._cursor = 0
        self._lines = self._body.splitlines(keepends=True)

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            result = self._body[self._cursor :]
            self._cursor = len(self._body)
            return result
        start = self._cursor
        end = min(len(self._body), start + size)
        self._cursor = end
        return self._body[start:end]

    def readline(self, size: int = -1) -> bytes:
        if not self._lines:
            return b""
        line = self._lines.pop(0)
        if size >= 0:
            return line[:size]
        return line

    def close(self) -> None:
        return None


class VerifierHTTPTransport:
    def __init__(self, client: TestClient) -> None:
        self._client = client

    def open(self, *, method: str, url: str, headers: Mapping[str, str], body: bytes | None, timeout: float):
        del timeout
        response = self._client.request(method, url, headers=dict(headers), content=body)
        return VerifierResponseHandle(response)


def jsonrpc_request_body(
    request_id: int | None,
    method: str,
    params: Mapping[str, object] | None,
) -> dict[str, object]:
    payload: dict[str, object] = {"jsonrpc": "2.0", "method": method}
    if request_id is not None:
        payload["id"] = request_id
    if params is not None:
        payload["params"] = dict(params)
    return payload


async def post_jsonrpc(
    client: httpx.AsyncClient,
    *,
    request_id: int | None,
    method: str,
    params: Mapping[str, object] | None,
    protocol_version: str | None = None,
    session_id: str | None = None,
) -> httpx.Response:
    headers = {"Accept": "application/json, text/event-stream"}
    if protocol_version is not None:
        headers["MCP-Protocol-Version"] = protocol_version
    if session_id is not None:
        headers["MCP-Session-Id"] = session_id
    return await client.post(
        "/mcp",
        json=jsonrpc_request_body(request_id, method, params),
        headers=headers,
    )


async def initialize_over_http(client: httpx.AsyncClient) -> tuple[dict[str, object], str, str | None]:
    response = await post_jsonrpc(
        client,
        request_id=1,
        method="initialize",
        params={
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "hodlxxi-mcp-tests", "version": "1.0.0"},
        },
    )
    payload = response.json()
    result = payload["result"]
    protocol_version = result["protocolVersion"]
    session_id = response.headers.get("mcp-session-id")
    notification = await post_jsonrpc(
        client,
        request_id=None,
        method="notifications/initialized",
        params={},
        protocol_version=protocol_version,
        session_id=session_id,
    )
    assert notification.status_code == 202
    return result, protocol_version, session_id


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


@pytest.mark.asyncio
async def test_streamable_http_initialize_serialized_capabilities_are_tools_only() -> None:
    app = http_server.build_local_http_app(build_server())
    transport = httpx.ASGITransport(app=app)

    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://127.0.0.1:8765",
        ) as http_client:
            result, _, _ = await initialize_over_http(http_client)
            capabilities = result["capabilities"]

    assert result["serverInfo"]["name"] == "HODLXXI Read-Only"
    assert result["serverInfo"]["version"] == "0.1.1"
    assert result["protocolVersion"] == "2025-11-25"
    assert "tools" in capabilities
    assert "prompts" not in capabilities
    assert "resources" not in capabilities


@pytest.mark.asyncio
async def test_streamable_http_tool_inventory_matches_exact_contract() -> None:
    app = http_server.build_local_http_app(build_server())
    transport = httpx.ASGITransport(app=app)

    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://127.0.0.1:8765",
        ) as http_client:
            _, protocol_version, session_id = await initialize_over_http(http_client)
            response = await post_jsonrpc(
                http_client,
                request_id=10,
                method="tools/list",
                params={},
                protocol_version=protocol_version,
                session_id=session_id,
            )
            payload = response.json()["result"]
            tool_names = [tool["name"] for tool in payload["tools"]]

    missing_tools = sorted(set(TOOL_NAMES) - set(tool_names))
    unexpected_tools = sorted(set(tool_names) - set(TOOL_NAMES))
    duplicate_tools = sorted(name for name in tool_names if tool_names.count(name) > 1)

    assert len(tool_names) == 26
    assert len(set(tool_names)) == 26
    assert missing_tools == []
    assert unexpected_tools == []
    assert duplicate_tools == []
    assert tool_names == list(TOOL_NAMES)


@pytest.mark.asyncio
async def test_streamable_http_safe_required_tool_calls_succeed() -> None:
    upstream = StubReadOnlyClient()
    app = http_server.build_local_http_app(build_server(upstream))  # type: ignore[arg-type]
    transport = httpx.ASGITransport(app=app)

    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://127.0.0.1:8765",
        ) as http_client:
            _, protocol_version, session_id = await initialize_over_http(http_client)
            for offset, tool_name in enumerate(
                (
                    "hodlxxi_get_mcp_server_card",
                    "hodlxxi_get_capabilities",
                    "hodlxxi_get_chain_health",
                    "hodlxxi_get_reputation",
                ),
                start=20,
            ):
                response = await post_jsonrpc(
                    http_client,
                    request_id=offset,
                    method="tools/call",
                    params={"name": tool_name, "arguments": {}},
                    protocol_version=protocol_version,
                    session_id=session_id,
                )
                result = response.json()["result"]
                assert result["isError"] is False


@pytest.mark.asyncio
async def test_streamable_http_prompt_and_resource_methods_are_not_found() -> None:
    app = http_server.build_local_http_app(build_server())
    transport = httpx.ASGITransport(app=app)

    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://127.0.0.1:8765",
        ) as http_client:
            _, protocol_version, session_id = await initialize_over_http(http_client)
            unsupported_requests = (
                ("prompts/list", {}),
                ("prompts/get", {"name": "missing"}),
                ("resources/list", {}),
                ("resources/read", {"uri": "https://hodlxxi.com/.well-known/agent.json"}),
                ("resources/templates/list", {}),
            )
            for request_id, (method, params) in enumerate(
                unsupported_requests,
                start=30,
            ):
                response = await post_jsonrpc(
                    http_client,
                    request_id=request_id,
                    method=method,
                    params=params,
                    protocol_version=protocol_version,
                    session_id=session_id,
                )
                payload = response.json()
                assert payload["error"]["code"] == -32601
                assert "method not found" in payload["error"]["message"].lower()


def test_local_http_app_verifies_with_remote_verifier() -> None:
    upstream = StubReadOnlyClient()
    app = http_server.build_local_http_app(build_server(upstream))  # type: ignore[arg-type]

    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        report = verifier.verify_remote_mcp(
            endpoint="http://127.0.0.1:8765/mcp",
            transport=VerifierHTTPTransport(client),
        )

    assert report.status == "VERIFIED"
    assert report.initialize["server_name"] == "HODLXXI Read-Only"
    assert report.initialize["server_version"] == "0.1.1"
    assert report.initialize["negotiated_protocol_version"] == "2025-11-25"
    assert report.tool_count == 26
    assert report.unique_tool_count == 26
    assert report.missing_tools == []
    assert report.unexpected_tools == []
    assert report.duplicate_tool_names == []
    assert report.prompts_capability_advertised is False
    assert report.resources_capability_advertised is False
    assert report.prompt_count == 0
    assert report.resource_count == 0
    assert all(item["ok"] is True and item["isError"] is False for item in report.required_calls.values())
