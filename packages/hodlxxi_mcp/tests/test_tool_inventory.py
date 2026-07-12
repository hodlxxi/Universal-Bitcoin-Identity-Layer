import pytest

from hodlxxi_mcp.server import build_server
from hodlxxi_mcp.tools import TOOL_NAMES


@pytest.mark.asyncio
async def test_server_registers_exactly_26_tools() -> None:
    server = build_server()
    tools = await server.list_tools()
    names = {tool.name for tool in tools}

    assert len(TOOL_NAMES) == 26
    assert names == set(TOOL_NAMES)
