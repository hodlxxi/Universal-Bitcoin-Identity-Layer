import pytest
import requests

from hodlxxi_sdk import HODLXXIClient, HODLXXIHTTPError


class FakeResponse:
    def __init__(self, status_code=200, data=None, text=""):
        self.status_code = status_code
        self._data = data if data is not None else {}
        self.text = text

    def json(self):
        return self._data


def test_sdk_normalizes_base_url():
    client = HODLXXIClient("https://hodlxxi.com")
    assert client.base_url == "https://hodlxxi.com/"


def test_ready_calls_health_ready(monkeypatch):
    calls = []

    def fake_request(method, url, json=None, timeout=None):
        calls.append((method, url, json, timeout))
        return FakeResponse(data={"status": "ready"})

    monkeypatch.setattr(requests, "request", fake_request)

    client = HODLXXIClient("https://hodlxxi.com", timeout=3)
    assert client.ready() == {"status": "ready"}
    assert calls == [("GET", "https://hodlxxi.com/health/ready", None, 3)]


def test_create_job_posts_agent_request(monkeypatch):
    calls = []

    def fake_request(method, url, json=None, timeout=None):
        calls.append((method, url, json, timeout))
        return FakeResponse(data={"job_id": "job_123", "status": "invoice_pending"})

    monkeypatch.setattr(requests, "request", fake_request)

    client = HODLXXIClient("https://hodlxxi.com")
    result = client.create_job("ping", {"hello": "world"})

    assert result["job_id"] == "job_123"
    assert calls[0][0] == "POST"
    assert calls[0][1] == "https://hodlxxi.com/agent/request"
    assert calls[0][2] == {"job_type": "ping", "payload": {"hello": "world"}}


def test_http_error_raises(monkeypatch):
    def fake_request(method, url, json=None, timeout=None):
        return FakeResponse(status_code=500, text="boom")

    monkeypatch.setattr(requests, "request", fake_request)

    client = HODLXXIClient("https://hodlxxi.com")
    with pytest.raises(HODLXXIHTTPError) as exc:
        client.ready()

    assert exc.value.status_code == 500
    assert "boom" in str(exc.value)


def test_get_job_requires_job_id():
    client = HODLXXIClient("https://hodlxxi.com")
    with pytest.raises(ValueError):
        client.get_job("")


def test_create_challenge_posts_pubkey(monkeypatch):
    calls = []

    def fake_request(method, url, json=None, timeout=None):
        calls.append((method, url, json, timeout))
        return FakeResponse(
            data={
                "ok": True,
                "challenge_id": "challenge-123",
                "challenge": "HODLXXI:login:1:abc",
                "expires_in": 300,
            }
        )

    monkeypatch.setattr(requests, "request", fake_request)

    client = HODLXXIClient("https://hodlxxi.com", timeout=7)
    result = client.create_challenge("02" + "a" * 64)

    assert result["ok"] is True
    assert result["challenge_id"] == "challenge-123"
    assert calls == [
        (
            "POST",
            "https://hodlxxi.com/api/challenge",
            {"pubkey": "02" + "a" * 64},
            7,
        )
    ]


def test_create_challenge_can_pass_method(monkeypatch):
    calls = []

    def fake_request(method, url, json=None, timeout=None):
        calls.append((method, url, json, timeout))
        return FakeResponse(data={"ok": True})

    monkeypatch.setattr(requests, "request", fake_request)

    client = HODLXXIClient("https://hodlxxi.com")
    client.create_challenge("02" + "a" * 64, method="nostr")

    assert calls[0][2] == {"pubkey": "02" + "a" * 64, "method": "nostr"}


def test_create_challenge_requires_pubkey():
    client = HODLXXIClient("https://hodlxxi.com")

    with pytest.raises(ValueError, match="pubkey is required"):
        client.create_challenge("")


def test_verify_challenge_posts_signature(monkeypatch):
    calls = []

    def fake_request(method, url, json=None, timeout=None):
        calls.append((method, url, json, timeout))
        return FakeResponse(
            data={
                "ok": True,
                "verified": True,
                "pubkey": "02" + "a" * 64,
                "access_level": "full",
            }
        )

    monkeypatch.setattr(requests, "request", fake_request)

    client = HODLXXIClient("https://hodlxxi.com")
    result = client.verify_challenge(
        "challenge-123",
        pubkey="02" + "a" * 64,
        signature="bitcoin-message-signature",
    )

    assert result["verified"] is True
    assert calls == [
        (
            "POST",
            "https://hodlxxi.com/api/verify",
            {
                "challenge_id": "challenge-123",
                "pubkey": "02" + "a" * 64,
                "signature": "bitcoin-message-signature",
            },
            20.0,
        )
    ]


def test_verify_challenge_posts_nostr_event(monkeypatch):
    calls = []
    event = {"id": "event-1", "pubkey": "a" * 64, "sig": "b" * 128, "tags": []}

    def fake_request(method, url, json=None, timeout=None):
        calls.append((method, url, json, timeout))
        return FakeResponse(data={"ok": True, "verified": True, "method": "nostr"})

    monkeypatch.setattr(requests, "request", fake_request)

    client = HODLXXIClient("https://hodlxxi.com")
    result = client.verify_challenge("challenge-123", nostr_event=event)

    assert result["method"] == "nostr"
    assert calls[0][0] == "POST"
    assert calls[0][1] == "https://hodlxxi.com/api/verify"
    assert calls[0][2] == {"challenge_id": "challenge-123", "nostr_event": event}


def test_verify_challenge_requires_challenge_id():
    client = HODLXXIClient("https://hodlxxi.com")

    with pytest.raises(ValueError, match="challenge_id is required"):
        client.verify_challenge("", signature="sig")


def test_verify_challenge_requires_signature_or_nostr_event():
    client = HODLXXIClient("https://hodlxxi.com")

    with pytest.raises(ValueError, match="signature or nostr_event is required"):
        client.verify_challenge("challenge-123", pubkey="02" + "a" * 64)


def test_verify_job_gets_agent_verify(monkeypatch):
    calls = []

    def fake_request(method, url, json=None, timeout=None):
        calls.append((method, url, json, timeout))
        return FakeResponse(data={"status": "verified", "valid": True})

    monkeypatch.setattr(requests, "request", fake_request)

    client = HODLXXIClient("https://hodlxxi.com", timeout=9)
    assert client.verify_job("job_123") == {"status": "verified", "valid": True}
    assert calls == [("GET", "https://hodlxxi.com/agent/verify/job_123", None, 9)]


def test_verify_job_requires_job_id():
    client = HODLXXIClient("https://hodlxxi.com")

    with pytest.raises(ValueError, match="job_id is required"):
        client.verify_job("")


def test_verify_job_returns_verified_receipt(monkeypatch):
    verified = {
        "status": "verified",
        "valid": True,
        "receipt": {"job_id": "job_paid"},
        "attestation": {"type": "agent_receipt"},
        "event_hash": "abc123",
        "agent_pubkey": "02" + "a" * 64,
    }

    def fake_request(method, url, json=None, timeout=None):
        return FakeResponse(status_code=200, data=verified)

    monkeypatch.setattr(requests, "request", fake_request)

    client = HODLXXIClient("https://hodlxxi.com")
    assert client.verify_job("job_paid") == verified


def test_verify_job_returns_no_receipt_conflict(monkeypatch):
    no_receipt = {
        "status": "no_receipt",
        "valid": False,
        "verification": "unavailable",
        "job_status": "invoice_pending",
        "receipt": None,
        "reason": "receipt_not_issued",
    }

    def fake_request(method, url, json=None, timeout=None):
        return FakeResponse(status_code=409, data=no_receipt, text="conflict")

    monkeypatch.setattr(requests, "request", fake_request)

    client = HODLXXIClient("https://hodlxxi.com")
    assert client.verify_job("job_unpaid") == no_receipt


def test_verify_job_raises_for_missing_job(monkeypatch):
    def fake_request(method, url, json=None, timeout=None):
        return FakeResponse(
            status_code=404,
            data={"error": "not_found", "verification": "unavailable"},
            text="not found",
        )

    monkeypatch.setattr(requests, "request", fake_request)

    client = HODLXXIClient("https://hodlxxi.com")
    with pytest.raises(HODLXXIHTTPError) as exc:
        client.verify_job("missing")

    assert exc.value.status_code == 404


def test_verify_job_raises_for_malformed_no_receipt_conflict(monkeypatch):
    def fake_request(method, url, json=None, timeout=None):
        return FakeResponse(status_code=409, data={"status": "conflict"}, text="conflict")

    monkeypatch.setattr(requests, "request", fake_request)

    client = HODLXXIClient("https://hodlxxi.com")
    with pytest.raises(HODLXXIHTTPError) as exc:
        client.verify_job("job_123")

    assert exc.value.status_code == 409


def test_generic_409_still_raises_for_other_methods(monkeypatch):
    def fake_request(method, url, json=None, timeout=None):
        return FakeResponse(status_code=409, data={"status": "conflict"}, text="conflict")

    monkeypatch.setattr(requests, "request", fake_request)

    client = HODLXXIClient("https://hodlxxi.com")
    with pytest.raises(HODLXXIHTTPError) as exc:
        client.get_job("job_123")

    assert exc.value.status_code == 409
