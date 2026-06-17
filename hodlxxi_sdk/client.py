from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Collection, Dict, Optional, Tuple
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
        allowed_statuses: Optional[Collection[int]] = None,
    ) -> Dict[str, Any]:
        return self._request_with_status(method, path, json=json, allowed_statuses=allowed_statuses)[1]

    def _request_with_status(
        self,
        method: str,
        path: str,
        *,
        json: Optional[Dict[str, Any]] = None,
        allowed_statuses: Optional[Collection[int]] = None,
    ) -> Tuple[int, Dict[str, Any]]:
        url = self._url(path)
        resp = requests.request(method, url, json=json, timeout=self.timeout)
        allowed_statuses = allowed_statuses or ()

        if not 200 <= resp.status_code < 300 and resp.status_code not in allowed_statuses:
            raise HODLXXIHTTPError(method, url, resp.status_code, resp.text)

        try:
            return resp.status_code, resp.json()
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

    def create_challenge(self, pubkey: str, *, method: Optional[str] = None) -> Dict[str, Any]:
        """Create a login/auth challenge for a compressed public key.

        The live API expects `pubkey`. It does not accept `public_key`, `npub`,
        or an empty body. The optional method is passed through for server-side
        flows such as `nostr`.
        """
        if not pubkey:
            raise ValueError("pubkey is required")

        body: Dict[str, Any] = {"pubkey": pubkey}
        if method:
            body["method"] = method

        return self._request("POST", "/api/challenge", json=body)

    def verify_challenge(
        self,
        challenge_id: str,
        *,
        pubkey: Optional[str] = None,
        signature: Optional[str] = None,
        nostr_event: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Verify a previously-created auth challenge.

        For the default Bitcoin-message flow, pass `pubkey` and `signature`.
        For the Nostr flow, pass `nostr_event`; `pubkey` may still be supplied
        for client-side clarity, but the server validates the Nostr event
        against the challenge record.
        """
        if not challenge_id:
            raise ValueError("challenge_id is required")

        body: Dict[str, Any] = {"challenge_id": challenge_id}

        if pubkey:
            body["pubkey"] = pubkey
        if signature:
            body["signature"] = signature
        if nostr_event is not None:
            body["nostr_event"] = nostr_event

        if not signature and nostr_event is None:
            raise ValueError("signature or nostr_event is required")

        return self._request("POST", "/api/verify", json=body)

    def get_job(self, job_id: str) -> Dict[str, Any]:
        if not job_id:
            raise ValueError("job_id is required")
        return self._request("GET", f"/agent/jobs/{job_id}")

    def verify_job(self, job_id: str) -> Dict[str, Any]:
        if not job_id:
            raise ValueError("job_id is required")

        status_code, result = self._request_with_status("GET", f"/agent/verify/{job_id}", allowed_statuses={409})
        if status_code != 409:
            return result

        if result.get("status") == "no_receipt" and result.get("reason") == "receipt_not_issued":
            return result

        raise HODLXXIHTTPError(
            "GET",
            self._url(f"/agent/verify/{job_id}"),
            status_code,
            "unexpected verifier conflict response",
        )
