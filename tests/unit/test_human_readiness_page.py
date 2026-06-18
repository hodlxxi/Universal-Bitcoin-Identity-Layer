"""Tests for the human-readable readiness wrapper page."""

from app.factory import create_app

SCHEMA = "hodlxxi.agent_readiness_report.v1"


def test_human_readiness_page_renders_public_report():
    app = create_app()
    app.config.update(TESTING=True)
    client = app.test_client()

    response = client.get("/agent/readiness", base_url="https://hodlxxi.com")
    text = response.get_data(as_text=True)

    assert response.status_code == 200
    for marker in [
        "HODLXXI Readiness",
        "runtime_ready",
        "score",
        "passed",
        "failed",
        "warnings",
        "/agent/readiness/self-scan",
        "View machine-readable JSON",
        "Open reviewer packet",
        "Operator continuity",
        "Reputation",
        "Attestations",
        "Chain health",
        "does not prove legal identity",
        "does not prove KYC",
        "does not prove custody",
        "does not prove locked capital",
    ]:
        assert marker in text


def test_readiness_self_scan_remains_machine_readable_json():
    app = create_app()
    app.config.update(TESTING=True)
    client = app.test_client()

    response = client.get("/agent/readiness/self-scan", base_url="https://hodlxxi.com")

    assert response.status_code == 200
    assert response.is_json
    assert response.get_json()["schema"] == SCHEMA


def test_homepage_points_primary_readiness_cta_to_human_page():
    app = create_app()
    app.config.update(TESTING=True)
    client = app.test_client()

    response = client.get("/")
    text = response.get_data(as_text=True)

    assert response.status_code == 200
    assert 'href="/agent/readiness">Open readiness report' in text
    assert 'href="/agent/readiness/self-scan">Open readiness self-scan' not in text
