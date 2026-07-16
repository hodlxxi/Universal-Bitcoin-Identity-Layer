from __future__ import annotations

from collections import Counter

import pytest
from fastmcp import Client

from hodlxxi_mcp.server import build_server
from hodlxxi_mcp.tools import TOOL_NAMES

EXPECTED_PARAMETERS: dict[str, set[str]] = {name: set() for name in TOOL_NAMES}

EXPECTED_PARAMETERS.update(
    {
        "hodlxxi_get_attestations": {"limit", "offset"},
        "hodlxxi_get_trust_events": {"limit", "offset"},
        "hodlxxi_get_trust_summary": {"agent_id"},
        "hodlxxi_get_covenant": {"covenant_id"},
        "hodlxxi_get_report": {"report_id"},
        "hodlxxi_verify_receipt": {"job_id"},
        "hodlxxi_get_receipt": {"job_id"},
    }
)

EXPECTED_REQUIRED: dict[str, set[str]] = {name: set() for name in TOOL_NAMES}

EXPECTED_REQUIRED.update(
    {
        "hodlxxi_get_report": {"report_id"},
        "hodlxxi_verify_receipt": {"job_id"},
        "hodlxxi_get_receipt": {"job_id"},
    }
)

FORBIDDEN_GENERIC_ARGUMENTS = {
    "url",
    "uri",
    "host",
    "hostname",
    "origin",
    "path",
    "method",
    "headers",
    "body",
    "payload",
    "command",
    "shell",
    "query_string",
}


@pytest.mark.asyncio
async def test_exact_tool_name_and_argument_contract() -> None:
    server = build_server()

    async with Client(server) as client:
        tools = await client.list_tools()

    tool_names = [tool.name for tool in tools]
    duplicate_tools = sorted(name for name, count in Counter(tool_names).items() if count > 1)
    missing_tools = sorted(set(TOOL_NAMES) - set(tool_names))
    unexpected_tools = sorted(set(tool_names) - set(TOOL_NAMES))
    by_name = {tool.name: tool for tool in tools}

    assert len(TOOL_NAMES) == 26
    assert len(set(TOOL_NAMES)) == 26
    assert len(tool_names) == 26
    assert len(set(tool_names)) == 26
    assert missing_tools == []
    assert unexpected_tools == []
    assert duplicate_tools == []
    assert tool_names == list(TOOL_NAMES)
    assert set(by_name) == set(TOOL_NAMES)
    assert set(EXPECTED_PARAMETERS) == set(TOOL_NAMES)
    assert set(EXPECTED_REQUIRED) == set(TOOL_NAMES)

    for name in TOOL_NAMES:
        schema = by_name[name].inputSchema

        assert schema["type"] == "object"

        properties = set(schema.get("properties", {}))
        required = set(schema.get("required", []))

        assert properties == EXPECTED_PARAMETERS[name]
        assert required == EXPECTED_REQUIRED[name]

        assert not (properties & FORBIDDEN_GENERIC_ARGUMENTS)


@pytest.mark.asyncio
async def test_server_exposes_tools_only() -> None:
    server = build_server()

    tools = await server.list_tools()
    resources = await server.list_resources()
    prompts = await server.list_prompts()

    assert len(tools) == 26
    assert resources == []
    assert prompts == []
