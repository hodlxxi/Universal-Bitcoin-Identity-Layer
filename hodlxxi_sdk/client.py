from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional
from urllib.parse import urljoin

import requests


class HODLXXIError(Exception):
    """Base SDK error."""


class HODLXXIHTTPError(HODLXXIError):
    """Raised when HODLXXI returns a non-2xx HTTP response."""

    def __init__(self, method: str, url: str, status_code: int, body: str):
        self.method = method
        self.url = url
        self.status_code = status_code
        self.body = body[:1000]
        super().__init__(f"{method} {url} failed with HTTP {status_code}: {self.body}")


@dataclass(frozen=True)
class HODLXXIClient:
    """
    Minimal Python SDK for public HODLXXI / UBID agent surfaces.

    This client intentionally does not require secrets for public discovery,
    reputation, chain health, or job creation flows that return Lightning invoices.
    """

    base_url: str = "https://hodlxxi.com"
    timeout: float = 20.0

    def __post_init__(self) -> None:
        normalized = self.base_url.rstrip("/") + "/"
        object.__setattr__(self, "base_url", normalized)

    def _url(self, path: str) -> str:
        return urljoin(self.base_url, path.lstrip("/"))

    def _request(
        self,
        method: str,
        path: str,
        *,
        json: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        url = self._url(path)
        resp = requests.request(method, url, json=json, timeout=self.timeout)

        if not 200 <= resp.status_code < 300:
            raise HODLXXIHTTPError(method, url, resp.status_code, resp.text)

        try:
            return resp.json()
        except ValueError as exc:
            raise HODLXXIError(f"{method} {url} did not return JSON") from exc

    def ready(self) -> Dict[str, Any]:
        return self._request("GET", "/health/ready")

    def oidc_configuration(self) -> Dict[str, Any]:
        return self._request("GET", "/.well-known/openid-configuration")

    def agent_manifest(self) -> Dict[str, Any]:
        return self._request("GET", "/.well-known/agent.json")

    def capabilities(self) -> Dict[str, Any]:
        return self._request("GET", "/agent/capabilities")

    def reputation(self) -> Dict[str, Any]:
        return self._request("GET", "/agent/reputation")

    def chain_health(self) -> Dict[str, Any]:
        return self._request("GET", "/agent/chain/health")

    def public_status(self) -> Dict[str, Any]:
        return self._request("GET", "/api/public/status")

    def create_job(self, job_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        return self._request(
            "POST",
            "/agent/request",
            json={"job_type": job_type, "payload": payload},
        )

    def get_job(self, job_id: str) -> Dict[str, Any]:
        if not job_id:
            raise ValueError("job_id is required")
        return self._request("GET", f"/agent/jobs/{job_id}")
