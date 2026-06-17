"""Tests for the public Agent Readiness self-scan endpoint."""

from app.factory import create_app
from app.services.agent_readiness_report import SCHEMA


def test_agent_readiness_self_scan_endpoint_returns_report_json(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENT_READINESS_REPORT_DIR", str(tmp_path))

    app = create_app()
    client = app.test_client()

    response = client.get("/agent/readiness/self-scan", base_url="https://hodlxxi.com")
    payload = response.get_json()

    assert response.status_code == 200
    assert response.content_type.startswith("application/json")
    assert payload["schema"] == SCHEMA
    assert payload["target"]["base_url"] == "https://hodlxxi.com"
    assert payload["scanner"]["runtime"] == "https://hodlxxi.com"
    assert payload["summary"]["status"] == "runtime_ready"
    assert payload["summary"]["score"] == 100
    assert payload["summary"]["passed"] == 12
    assert payload["summary"]["failed"] == 0
    assert payload["receipt"]["status"] == "not_issued"
    assert payload["attestation"]["status"] == "not_issued"
    assert payload["verification"]["report_json_url"].startswith("/reports/")
    assert payload["verification"]["human_verify_url"].startswith("/verify/report/")
    assert payload["report_sha256"]


def test_agent_readiness_self_scan_endpoint_is_registered_in_capabilities():
    app = create_app()
    client = app.test_client()

    response = client.get("/agent/capabilities")
    payload = response.get_json()

    assert response.status_code == 200
    assert payload["endpoints"]["readiness_self_scan"] == "/agent/readiness/self-scan"


def test_agent_readiness_self_scan_endpoint_is_registered_in_flask_routes():
    app = create_app()
    paths = {str(rule) for rule in app.url_map.iter_rules()}

    assert "/agent/readiness/self-scan" in paths
