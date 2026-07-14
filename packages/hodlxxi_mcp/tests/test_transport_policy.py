from __future__ import annotations

from typing import Any

import httpx
import pytest

import hodlxxi_mcp.client as client_module
from hodlxxi_mcp.client import Endpoint, HODLXXIReadOnlyClient


class FakeResponse:
    status_code = 200
    headers = {
        "content-type": "application/json",
    }

    async def aiter_bytes(self):
        yield b'{"ok":true}'


class FakeStreamContext:
    async def __aenter__(self) -> FakeResponse:
        return FakeResponse()

    async def __aexit__(
        self,
        exc_type: object,
        exc: object,
        traceback: object,
    ) -> None:
        return None


class FakeAsyncClient:
    captured_init: dict[str, Any] = {}
    captured_stream: dict[str, Any] = {}

    def __init__(self, **kwargs: Any) -> None:
        type(self).captured_init = kwargs

    async def __aenter__(self) -> "FakeAsyncClient":
        return self

    async def __aexit__(
        self,
        exc_type: object,
        exc: object,
        traceback: object,
    ) -> None:
        return None

    def stream(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, int],
    ) -> FakeStreamContext:
        type(self).captured_stream = {
            "method": method,
            "url": url,
            "params": params,
        }
        return FakeStreamContext()


@pytest.mark.asyncio
async def test_http_transport_policy_is_locked_down(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        client_module.httpx,
        "AsyncClient",
        FakeAsyncClient,
    )

    client = HODLXXIReadOnlyClient()
    result = await client.get_json(
        Endpoint.CAPABILITIES,
    )

    assert result == {"ok": True}

    initialization = FakeAsyncClient.captured_init
    request = FakeAsyncClient.captured_stream

    assert initialization["follow_redirects"] is False
    assert initialization["trust_env"] is False
    assert initialization["transport"] is None

    timeout = initialization["timeout"]
    assert isinstance(timeout, httpx.Timeout)
    assert timeout.connect == 10.0
    assert timeout.read == 10.0
    assert timeout.write == 10.0
    assert timeout.pool == 10.0

    headers = initialization["headers"]
    assert headers == {
        "Accept": (
            "application/json, "
            "application/linkset+json"
        ),
        "User-Agent": "hodlxxi-mcp/0.1.1",
    }

    assert request == {
        "method": "GET",
        "url": (
            "https://hodlxxi.com"
            "/agent/capabilities"
        ),
        "params": {},
    }
