import json
from datetime import datetime, timedelta, timezone

import pytest

from app.blueprints import qr_pointer


DISCOVERY_TOKEN = "discovery-target"
VERIFY_TOKEN = "verify-job-target"
VALID_JOB_ID = "job_123-ABC.def:456"
VALID_TARGET = f"/agent/verify/{VALID_JOB_ID}"
DISCOVERY_TARGET = "/agent/discovery"


def _write_pointer(tmp_path, token=VERIFY_TOKEN, target=VALID_TARGET, status="active", **extra):
    path = tmp_path / f"{token}.json"
    record = {"token": token, "status": status, "target": target, **extra}
    path.write_text(json.dumps(record), encoding="utf-8")
    return path


@pytest.fixture(autouse=True)
def qr_registry(tmp_path, monkeypatch):
    monkeypatch.setattr(qr_pointer, "POINTER_REGISTRY_DIR", tmp_path)
    return tmp_path


def test_factory_registers_exactly_one_qr_route(app):
    qr_rules = [rule for rule in app.url_map.iter_rules() if rule.rule == "/qr/<token>"]

    assert len(qr_rules) == 1


def test_existing_static_discovery_pointer_still_renders(client, qr_registry):
    _write_pointer(qr_registry, token=DISCOVERY_TOKEN, target=DISCOVERY_TARGET)

    response = client.get(f"/qr/{DISCOVERY_TOKEN}")

    assert response.status_code == 200
    assert response.location is None
    body = response.get_data(as_text=True)
    assert DISCOVERY_TARGET in body
    assert "Discovery-only warning" in body


def test_revoked_pointer_returns_410_safe_non_redirecting_page(client, qr_registry):
    _write_pointer(qr_registry, token=DISCOVERY_TOKEN, target=DISCOVERY_TARGET, status="revoked")

    response = client.get(f"/qr/{DISCOVERY_TOKEN}")

    assert response.status_code == 410
    assert response.location is None
    body = response.get_data(as_text=True)
    assert "Discovery-only warning" in body
    assert DISCOVERY_TARGET not in body


def test_expired_pointer_returns_410_safe_non_redirecting_page(client, qr_registry):
    expires_at = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    _write_pointer(qr_registry, token=DISCOVERY_TOKEN, target=DISCOVERY_TARGET, expires_at=expires_at)

    response = client.get(f"/qr/{DISCOVERY_TOKEN}")

    assert response.status_code == 410
    assert response.location is None
    body = response.get_data(as_text=True)
    assert "Discovery-only warning" in body
    assert DISCOVERY_TARGET not in body


def test_unknown_token_returns_404(client):
    response = client.get("/qr/unknown-token")

    assert response.status_code == 404


def test_verify_target_pointer_record_loads_for_conservative_local_job_id(qr_registry):
    _write_pointer(qr_registry)

    record = qr_pointer.load_pointer_record(VERIFY_TOKEN)

    assert record is not None
    assert record["target"] == VALID_TARGET


def test_active_verify_target_landing_is_discovery_only(client, qr_registry):
    _write_pointer(qr_registry)

    response = client.get(f"/qr/{VERIFY_TOKEN}")

    assert response.status_code == 200
    assert response.location is None
    body = response.get_data(as_text=True)
    body_lower = body.lower()
    assert VALID_TARGET in body
    assert "Discovery-only warning" in body
    assert "QR possession is not authority" in body
    for forbidden in (
        "receipt is valid",
        "valid receipt",
        "job is paid",
        "payment proved",
        "job is complete",
        "completion proved",
        "approved by qr",
        "delegated by qr",
        "authorized by qr",
        "trusted by qr",
        "reputation proved",
        "human-approved",
    ):
        assert forbidden not in body_lower


def test_verify_target_landing_does_not_call_verify_endpoint_or_redirect(client, qr_registry, monkeypatch):
    _write_pointer(qr_registry)
    calls = []

    def fake_verify(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("/qr/<token> must not call /agent/verify/<job_id>")

    monkeypatch.setitem(client.application.view_functions, "agent.verify_job_receipt", fake_verify)

    response = client.get(f"/qr/{VERIFY_TOKEN}")

    assert response.status_code == 200
    assert response.location is None
    assert calls == []
    assert VALID_TARGET in response.get_data(as_text=True)


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
def test_invalid_verify_targets_are_rejected(qr_registry, target):
    _write_pointer(qr_registry, target=target)

    assert qr_pointer.load_pointer_record(VERIFY_TOKEN) is None


def test_malformed_json_fails_closed_without_500(client, qr_registry):
    (qr_registry / f"{VERIFY_TOKEN}.json").write_text("{not-json", encoding="utf-8")

    assert qr_pointer.load_pointer_record(VERIFY_TOKEN) is None
    response = client.get(f"/qr/{VERIFY_TOKEN}")
    assert response.status_code == 404


def test_non_object_json_fails_closed_without_500(client, qr_registry):
    (qr_registry / f"{VERIFY_TOKEN}.json").write_text(json.dumps(["not", "object"]), encoding="utf-8")

    assert qr_pointer.load_pointer_record(VERIFY_TOKEN) is None
    response = client.get(f"/qr/{VERIFY_TOKEN}")
    assert response.status_code == 404


def test_mismatched_token_invalid_status_secret_field_and_invalid_target_rejected(qr_registry):
    _write_pointer(qr_registry, token="mismatch", target=DISCOVERY_TARGET)
    (qr_registry / f"{VERIFY_TOKEN}.json").write_text(
        json.dumps({"token": "other", "status": "active", "target": DISCOVERY_TARGET}),
        encoding="utf-8",
    )
    assert qr_pointer.load_pointer_record(VERIFY_TOKEN) is None

    _write_pointer(qr_registry, status="disabled")
    assert qr_pointer.load_pointer_record(VERIFY_TOKEN) is None

    (qr_registry / f"{VERIFY_TOKEN}.json").write_text(
        json.dumps({"token": VERIFY_TOKEN, "status": "active", "target": DISCOVERY_TARGET, "access_token": "x"}),
        encoding="utf-8",
    )
    assert qr_pointer.load_pointer_record(VERIFY_TOKEN) is None

    _write_pointer(qr_registry, target="/agent/jobs/job_123")
    assert qr_pointer.load_pointer_record(VERIFY_TOKEN) is None


def test_capabilities_still_do_not_advertise_qr(client):
    response = client.get("/agent/capabilities")

    assert response.status_code == 200
    assert "/qr/" not in response.get_data(as_text=True)
