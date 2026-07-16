from __future__ import annotations

from typing import Any, Mapping

import pytest
from fastmcp import Client

from hodlxxi_mcp.client import Endpoint
from hodlxxi_mcp.server import build_server
from hodlxxi_mcp.tools import TOOL_NAMES


class StubReadOnlyClient:
    """Deterministic upstream used by protocol tests."""

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


@pytest.mark.asyncio
async def test_in_memory_mcp_protocol_round_trip() -> None:
    upstream = StubReadOnlyClient()
    server = build_server(upstream)  # type: ignore[arg-type]

    async with Client(server) as client:
        initialization = client.initialize_result

        assert initialization is not None
        assert initialization.serverInfo.name == "HODLXXI Read-Only"
        assert initialization.serverInfo.version == "0.1.1"
        assert initialization.serverInfo.websiteUrl == "https://hodlxxi.com"
        assert initialization.protocolVersion == "2025-11-25"
        capabilities = initialization.capabilities.model_dump(exclude_none=True)
        assert "tools" in capabilities
        assert "prompts" not in capabilities
        assert "resources" not in capabilities

        await client.ping()

        tools = await client.list_tools()
        names = {tool.name for tool in tools}

        assert len(names) == 26
        assert names == set(TOOL_NAMES)

        result = await client.call_tool(
            "hodlxxi_get_capabilities",
            {},
        )

        assert result.data == {
            "ok": True,
            "endpoint": "/agent/capabilities",
            "path_params": {},
            "query": {},
        }

    assert upstream.calls == [
        (
            Endpoint.CAPABILITIES,
            {},
            {},
        )
    ]


@pytest.mark.asyncio
async def test_protocol_validates_tool_arguments() -> None:
    upstream = StubReadOnlyClient()
    server = build_server(upstream)  # type: ignore[arg-type]

    async with Client(server) as client:
        with pytest.raises(Exception):
            await client.call_tool(
                "hodlxxi_get_capabilities",
                {"url": "https://example.com"},
            )

        result = await client.call_tool(
            "hodlxxi_get_attestations",
            {"limit": 5, "offset": 2},
        )

        assert result.data == {
            "ok": True,
            "endpoint": "/agent/attestations",
            "path_params": {},
            "query": {
                "limit": 5,
                "offset": 2,
            },
        }

    assert upstream.calls == [
        (
            Endpoint.ATTESTATIONS,
            {},
            {
                "limit": 5,
                "offset": 2,
            },
        )
    ]
