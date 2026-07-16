from __future__ import annotations

import json
from enum import Enum
from typing import Any, Mapping

import httpx

from .config import ClientConfig
from .errors import (
    HODLXXIMCPError,
    InvalidJSONError,
    ResponseTooLargeError,
    UpstreamContentTypeError,
    UpstreamHTTPError,
)


class Endpoint(str, Enum):
    AGENT_IDENTITY = "/.well-known/agent.json"
    OPERATOR_CONTINUITY = "/.well-known/hodlxxi-operator.json"
    API_CATALOG = "/.well-known/api-catalog"
    AGENT_SKILLS_INDEX = "/.well-known/agent-skills/index.json"
    MCP_SERVER_CARD = "/.well-known/mcp.json"
    NOSTR_DM_POLICY = "/.well-known/nostr-dm-policy.json"
    OPENID_CONFIGURATION = "/.well-known/openid-configuration"
    OAUTH_AUTHORIZATION_SERVER = "/.well-known/oauth-authorization-server"
    OAUTH_PROTECTED_RESOURCE = "/.well-known/oauth-protected-resource"
    JWKS = "/oauth/jwks.json"
    AGENT_DISCOVERY = "/agent/discovery"
    CAPABILITIES = "/agent/capabilities"
    CAPABILITIES_SCHEMA = "/agent/capabilities/schema"
    SKILLS = "/agent/skills"
    MARKETPLACE_LISTING = "/agent/marketplace/listing"
    REPUTATION = "/agent/reputation"
    ATTESTATIONS = "/agent/attestations"
    TRUST_EVENTS = "/agent/trust/events"
    NOSTR_ANNOUNCEMENT = "/agent/nostr/announcement"
    CHAIN_HEALTH = "/agent/chain/health"
    COVENANT_COUNTDOWN = "/agent/covenant-countdown.json"
    TRUST_SUMMARY = "/agent/trust-summary/{agent_id}.json"
    COVENANT = "/agent/covenants/{covenant_id}.json"
    REPORT = "/reports/{report_id}.json"
    VERIFY_RECEIPT = "/agent/verify/{job_id}"
    RECEIPT = "/agent/receipts/{job_id}.json"


_QUERY_KEYS: dict[Endpoint, frozenset[str]] = {
    Endpoint.ATTESTATIONS: frozenset({"limit", "offset"}),
    Endpoint.TRUST_EVENTS: frozenset({"limit", "offset"}),
}
_ALLOWED_CONTENT_TYPES = frozenset({"application/json", "application/linkset+json"})


class HODLXXIReadOnlyClient:
    """Fixed-origin, GET-only client for the public HODLXXI surface allowlist."""

    def __init__(
        self,
        config: ClientConfig | None = None,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.config = config or ClientConfig()
        self._transport = transport

    async def get_json(
        self,
        endpoint: Endpoint,
        *,
        path_params: Mapping[str, str] | None = None,
        query: Mapping[str, int] | None = None,
    ) -> dict[str, Any]:
        path_params = dict(path_params or {})
        query = dict(query or {})

        allowed_keys = _QUERY_KEYS.get(endpoint, frozenset())
        if set(query) - allowed_keys:
            raise HODLXXIMCPError("query parameters are not allowed for this endpoint")

        try:
            path = endpoint.value.format(**path_params)
        except KeyError as exc:
            raise HODLXXIMCPError(f"missing path parameter: {exc.args[0]}") from exc

        if "{" in path or "}" in path:
            raise HODLXXIMCPError("unresolved endpoint path parameter")
        if not path.startswith("/") or "?" in path or "#" in path or ".." in path:
            raise HODLXXIMCPError("invalid allowlisted endpoint path")

        url = f"{self.config.base_url}{path}"
        timeout = httpx.Timeout(self.config.timeout_seconds)

        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
            transport=self._transport,
            headers={
                "Accept": "application/json, application/linkset+json",
                "User-Agent": self.config.user_agent,
            },
        ) as client:
            async with client.stream("GET", url, params=query) as response:
                if response.status_code != 200:
                    raise UpstreamHTTPError(response.status_code)

                content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                if content_type not in _ALLOWED_CONTENT_TYPES:
                    raise UpstreamContentTypeError(f"unexpected upstream content type: {content_type or 'missing'}")

                chunks: list[bytes] = []
                size = 0
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    if size > self.config.max_response_bytes:
                        raise ResponseTooLargeError("HODLXXI upstream response exceeded the byte ceiling")
                    chunks.append(chunk)

        try:
            decoded = b"".join(chunks).decode("utf-8")
            payload = json.loads(decoded)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise InvalidJSONError("HODLXXI upstream returned invalid JSON") from exc

        if not isinstance(payload, dict):
            raise InvalidJSONError("HODLXXI upstream JSON must be an object")
        return payload
