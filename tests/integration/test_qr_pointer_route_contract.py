import json

import pytest

from app import qr_pointer


VALID_TOKEN = "verify-job-target"
VALID_JOB_ID = "job_123-ABC.def:456"
VALID_TARGET = f"/agent/verify/{VALID_JOB_ID}"


def _write_pointer(tmp_path, token=VALID_TOKEN, target=VALID_TARGET, status="active"):
    path = tmp_path / f"{token}.json"
    path.write_text(json.dumps({"token": token, "status": status, "target": target}), encoding="utf-8")
    return path


@pytest.fixture(autouse=True)
def qr_registry(tmp_path, monkeypatch):
    monkeypatch.setattr(qr_pointer, "POINTER_REGISTRY_DIR", tmp_path)
    return tmp_path


def test_verify_target_pointer_record_loads_for_conservative_local_job_id(qr_registry):
    _write_pointer(qr_registry)

    record = qr_pointer.load_pointer_record(VALID_TOKEN)

    assert record is not None
    assert record["target"] == VALID_TARGET


def test_active_verify_target_landing_is_discovery_only(client, qr_registry):
    _write_pointer(qr_registry)

    response = client.get(f"/qr/{VALID_TOKEN}")

    assert response.status_code == 200
    assert response.location is None
    body = response.get_data(as_text=True)
    assert VALID_TARGET in body
    assert "Discovery-only warning" in body
    assert "QR possession is not authority" in body
    assert "valid receipt" not in body.lower()
    for forbidden in ("paid", "completed", "trusted", "approved", "delegated", "authorized", "human-approved"):
        assert forbidden not in body.lower()


def test_verify_target_landing_does_not_call_verify_endpoint(client, qr_registry, monkeypatch):
    _write_pointer(qr_registry)

    def fail_if_called(*args, **kwargs):
        raise AssertionError("/qr/<token> must not call url routing or verify handlers")

    monkeypatch.setattr(qr_pointer, "abort", fail_if_called)
    response = client.get(f"/qr/{VALID_TOKEN}")

    assert response.status_code == 200
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
    ],
)
def test_invalid_verify_targets_are_rejected(qr_registry, target):
    _write_pointer(qr_registry, target=target)

    assert qr_pointer.load_pointer_record(VALID_TOKEN) is None


def test_malformed_json_fails_closed_without_500(client, qr_registry):
    (qr_registry / f"{VALID_TOKEN}.json").write_text("{not-json", encoding="utf-8")

    assert qr_pointer.load_pointer_record(VALID_TOKEN) is None
    response = client.get(f"/qr/{VALID_TOKEN}")
    assert response.status_code == 404


def test_non_object_json_fails_closed_without_500(client, qr_registry):
    (qr_registry / f"{VALID_TOKEN}.json").write_text(json.dumps(["not", "object"]), encoding="utf-8")

    assert qr_pointer.load_pointer_record(VALID_TOKEN) is None
    response = client.get(f"/qr/{VALID_TOKEN}")
    assert response.status_code == 404


def test_capabilities_still_do_not_advertise_qr(client):
    response = client.get("/agent/capabilities")

    assert response.status_code == 200
    assert "/qr/" not in response.get_data(as_text=True)
