import httpx
import pytest

from hodlxxi_mcp.client import Endpoint, HODLXXIReadOnlyClient


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint", [Endpoint.ATTESTATIONS, Endpoint.TRUST_EVENTS])
async def test_paginated_endpoints_send_only_limit_and_offset(endpoint: Endpoint) -> None:
    observed = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        observed["params"] = dict(request.url.params)
        return httpx.Response(200, headers={"content-type": "application/json"}, json={"items": []})

    client = HODLXXIReadOnlyClient(transport=httpx.MockTransport(handler))
    await client.get_json(endpoint, query={"limit": 20, "offset": 5})

    assert observed["params"] == {"limit": "20", "offset": "5"}
