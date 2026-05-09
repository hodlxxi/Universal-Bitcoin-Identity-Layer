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
