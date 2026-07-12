import httpx
import pytest

from hodlxxi_mcp.client import Endpoint, HODLXXIReadOnlyClient
from hodlxxi_mcp.config import ClientConfig
from hodlxxi_mcp.errors import (
    HODLXXIMCPError,
    ResponseTooLargeError,
    UpstreamContentTypeError,
    UpstreamHTTPError,
)


@pytest.mark.asyncio
async def test_client_uses_get_and_fixed_origin() -> None:
    observed = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        observed["method"] = request.method
        observed["host"] = request.url.host
        observed["path"] = request.url.path
        return httpx.Response(200, headers={"content-type": "application/json"}, json={"ok": True})

    client = HODLXXIReadOnlyClient(transport=httpx.MockTransport(handler))
    payload = await client.get_json(Endpoint.CAPABILITIES)

    assert payload == {"ok": True}
    assert observed == {
        "method": "GET",
        "host": "hodlxxi.com",
        "path": "/agent/capabilities",
    }


@pytest.mark.asyncio
async def test_redirects_are_not_followed() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://example.com/private"})

    client = HODLXXIReadOnlyClient(transport=httpx.MockTransport(handler))
    with pytest.raises(UpstreamHTTPError) as exc:
        await client.get_json(Endpoint.CAPABILITIES)
    assert exc.value.status_code == 302


@pytest.mark.asyncio
async def test_response_size_ceiling() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            content=b'{"value":"' + (b"x" * 2000) + b'"}',
        )

    config = ClientConfig(max_response_bytes=1024)
    client = HODLXXIReadOnlyClient(config, transport=httpx.MockTransport(handler))
    with pytest.raises(ResponseTooLargeError):
        await client.get_json(Endpoint.CAPABILITIES)


@pytest.mark.asyncio
async def test_content_type_allowlist() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "text/html"}, text="<html></html>")

    client = HODLXXIReadOnlyClient(transport=httpx.MockTransport(handler))
    with pytest.raises(UpstreamContentTypeError):
        await client.get_json(Endpoint.CAPABILITIES)


@pytest.mark.asyncio
async def test_query_parameters_are_endpoint_specific() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "application/json"}, json={"ok": True})

    client = HODLXXIReadOnlyClient(transport=httpx.MockTransport(handler))
    with pytest.raises(HODLXXIMCPError):
        await client.get_json(Endpoint.CAPABILITIES, query={"limit": 1})


def test_base_url_is_not_configurable_to_another_origin() -> None:
    with pytest.raises(ValueError):
        ClientConfig(base_url="https://example.com")
