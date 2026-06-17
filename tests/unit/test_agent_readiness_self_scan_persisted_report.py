"""Tests for persisted Agent Readiness self-scan report artifacts."""

import json

from app.factory import create_app
from app.services.agent_readiness_report import (
    SCHEMA,
    build_self_readiness_report,
    load_self_readiness_report,
    save_self_readiness_report,
)


def test_self_readiness_report_can_be_saved_and_loaded(tmp_path):
    app = create_app()
    report = build_self_readiness_report(
        app,
        base_url="https://hodlxxi.com",
        report_id="readiness-self-scan-unit",
        generated_at="2026-06-17T00:00:00Z",
    )

    path = save_self_readiness_report(report, storage_dir=tmp_path)
    loaded = load_self_readiness_report("readiness-self-scan-unit", storage_dir=tmp_path)

    assert path == tmp_path / "readiness-self-scan-unit.json"
    assert json.loads(path.read_text())["schema"] == SCHEMA
    assert loaded == report


def test_self_readiness_report_rejects_unsafe_report_ids(tmp_path):
    app = create_app()
    report = build_self_readiness_report(
        app,
        base_url="https://hodlxxi.com",
        report_id="readiness-self-scan-safe",
        generated_at="2026-06-17T00:00:00Z",
    )

    unsafe = dict(report)
    unsafe["report_id"] = "../escape"

    try:
        save_self_readiness_report(unsafe, storage_dir=tmp_path)
    except ValueError as exc:
        assert "invalid readiness report_id" in str(exc)
    else:
        raise AssertionError("unsafe report_id should be rejected")

    assert load_self_readiness_report("../escape", storage_dir=tmp_path) is None


def test_self_scan_endpoint_persists_report_and_verification_links_work(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENT_READINESS_REPORT_DIR", str(tmp_path))

    app = create_app()
    client = app.test_client()

    response = client.get("/agent/readiness/self-scan", base_url="https://hodlxxi.com")
    payload = response.get_json()

    assert response.status_code == 200
    assert payload["schema"] == SCHEMA
    assert payload["report_id"].startswith("readiness-self-scan-")

    raw_response = client.get(payload["verification"]["report_json_url"], base_url="https://hodlxxi.com")
    raw_payload = raw_response.get_json()

    assert raw_response.status_code == 200
    assert raw_payload["report_id"] == payload["report_id"]
    assert raw_payload["report_sha256"] == payload["report_sha256"]
    assert raw_payload["summary"]["status"] == "runtime_ready"

    verify_response = client.get(payload["verification"]["human_verify_url"], base_url="https://hodlxxi.com")
    verify_body = verify_response.get_data(as_text=True)

    assert verify_response.status_code == 200
    assert "Readiness Report Verification Surface" in verify_body
    assert payload["report_id"] in verify_body
    assert payload["report_sha256"] in verify_body
    assert "Local hash match:</strong> yes" in verify_body


def test_human_report_page_also_serves_persisted_readiness_report(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENT_READINESS_REPORT_DIR", str(tmp_path))

    app = create_app()
    client = app.test_client()

    response = client.get("/agent/readiness/self-scan", base_url="https://hodlxxi.com")
    payload = response.get_json()

    page_response = client.get(f"/reports/{payload['report_id']}", base_url="https://hodlxxi.com")
    page_body = page_response.get_data(as_text=True)

    assert page_response.status_code == 200
    assert "Readiness Report Verification Surface" in page_body
    assert payload["report_id"] in page_body
