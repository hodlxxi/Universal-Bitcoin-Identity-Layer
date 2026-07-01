from __future__ import annotations

import json

import pytest

from app.blueprints import qr_pointer
from app.blueprints.qr_pointer import is_allowed_qr_target


def _qr_routes(app):
    return [rule for rule in app.url_map.iter_rules() if rule.rule == "/qr/<token>" and "GET" in rule.methods]


def test_registers_exactly_one_qr_pointer_route(app):
    assert len(_qr_routes(app)) == 1


def test_active_pointer_returns_safe_landing_page(client):
    res = client.get("/qr/demo-active")

    assert res.status_code == 200
    body = res.get_data(as_text=True)
    assert "/agent/discovery" in body
    compact = " ".join(body.split())
    assert "QR discovery landing" in compact
    assert "browser will not redirect automatically" in compact
    assert "Open target" in compact
    assert "<meta http-equiv" not in body.lower()
    assert "refresh" not in body.lower()


def test_revoked_pointer_returns_gone_without_redirect(client):
    res = client.get("/qr/demo-revoked")

    assert res.status_code == 410
    assert 300 > res.status_code or res.status_code >= 400
    body = res.get_data(as_text=True).lower()
    assert "no longer active" in body
    assert 'href="/agent/discovery"' not in body
    assert "open target" not in body


def test_expired_pointer_returns_gone_without_redirect(client):
    res = client.get("/qr/demo-expired")

    assert res.status_code == 410
    body = res.get_data(as_text=True).lower()
    assert "no longer active" in body
    assert 'href="/agent/discovery"' not in body
    assert "open target" not in body


def test_unknown_pointer_returns_not_found(client):
    assert client.get("/qr/unknown").status_code == 404


def test_traversal_like_token_returns_not_found(client):
    assert client.get("/qr/..%2Fagent%2Fcapabilities").status_code == 404


def test_capabilities_do_not_advertise_qr_or_operator_qr(client):
    res = client.get("/agent/capabilities")

    assert res.status_code == 200
    serialized = json.dumps(res.get_json(), sort_keys=True)
    assert "/qr/" not in serialized
    assert "/operator/qr" not in serialized


def test_qr_landing_avoids_forbidden_authority_wording(client):
    forbidden_terms = [
        "verified by qr",
        "trusted",
        "approved",
        "paid",
        "authorized",
        "identity confirmed",
        "human present",
        "delegated",
    ]

    for path in ("/qr/demo-active", "/qr/demo-revoked", "/qr/demo-expired"):
        body = client.get(path).get_data(as_text=True).lower()
        for term in forbidden_terms:
            assert term not in body


@pytest.mark.parametrize(
    "target",
    [
        "/agent/verify/job_123",
        "/agent/verify/job-123",
        "/agent/verify/job.123",
        "/agent/verify/job:123",
    ],
)
def test_allows_bounded_verify_targets(target):
    assert is_allowed_qr_target(target)


def test_traversal_like_token_returns_not_found(client):
    assert client.get("/qr/..%2Fagent%2Fcapabilities").status_code == 404


def test_capabilities_do_not_advertise_qr_or_operator_qr(client):
    res = client.get("/agent/capabilities")

    assert res.status_code == 200
    serialized = json.dumps(res.get_json(), sort_keys=True)
    assert "/qr/" not in serialized
    assert "/operator/qr" not in serialized


def test_qr_landing_avoids_forbidden_authority_wording(client):
    forbidden_terms = [
        "verified by qr",
        "trusted",
        "approved",
        "paid",
        "authorized",
        "identity confirmed",
        "human present",
        "delegated",
    ]

    for path in ("/qr/demo-active", "/qr/demo-revoked", "/qr/demo-expired"):
        body = client.get(path).get_data(as_text=True).lower()
        for term in forbidden_terms:
            assert term not in body


@pytest.mark.parametrize(
    "target",
    [
        "/agent/verify",
        "/agent/verify/",
        "/agent/verify/../x",
        "/agent/verify/a/b",
        "/agent/verify/job?id=1",
        "/agent/verify/job#fragment",
        "https://example.com/agent/verify/job",
        "//example.com/agent/verify/job",
        "/agent/jobs/job_123",
    ],
)
def test_rejects_unbounded_or_external_targets(target):
    assert not is_allowed_qr_target(target)


def test_verify_pointer_is_safe_landing_and_does_not_call_verify(client, monkeypatch):
    calls = []

    def fail_if_called(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("verify route must not be called by QR landing")

    monkeypatch.setattr(qr_pointer, "render_template_string", qr_pointer.render_template_string)
    res = client.get("/qr/verify-demo")

    assert res.status_code == 200
    assert "/agent/verify/demo-job-001" in res.get_data(as_text=True)
    assert calls == []


@pytest.mark.parametrize(
    "payload",
    [
        "{malformed",
        json.dumps([{"token": "x"}]),
        json.dumps({"x": {"token": "mismatch", "status": "active", "target": "/agent/discovery"}}),
        json.dumps({"x": {"token": "x", "status": "pending", "target": "/agent/discovery"}}),
        json.dumps({"x": {"token": "x", "status": "active", "target": "https://example.com"}}),
        json.dumps({"x": {"token": "x", "status": "active", "target": "/agent/discovery", "api_key": "secret"}}),
    ],
)
def test_static_registry_fail_closed(monkeypatch, payload):
    class FakeResource:
        def joinpath(self, _name):
            return self

        def read_text(self):
            return payload

    monkeypatch.setattr(qr_pointer.resources, "files", lambda _package: FakeResource())
    qr_pointer.load_qr_pointers.cache_clear()
    try:
        assert qr_pointer.load_qr_pointers() == {}
    finally:
        qr_pointer.load_qr_pointers.cache_clear()
