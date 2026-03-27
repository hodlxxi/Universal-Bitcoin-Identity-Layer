from app.services.nostr_reports import (
    build_daily_longform_report,
    build_execution_summary_note,
    build_heartbeat_note,
    build_relay_list_event,
    build_trust_signal_note,
)
from app.services.trust_surface import canonicalize_json, compute_report_hash


def test_trust_summary_json_route_has_expected_keys(client):
    res = client.get("/agent/trust-summary/hodlxxi-herald-01.json")
    assert res.status_code == 200
    body = res.get_json()
    for key in [
        "agent_id",
        "public_key",
        "runtime_status",
        "receipts_available",
        "attestations_available",
        "covenant_backed",
        "trust_lane",
        "verify_url",
    ]:
        assert key in body


def test_covenant_json_route_has_expected_keys(client):
    res = client.get("/agent/covenants/hodlxxi-herald-covenant-v1.json")
    assert res.status_code == 200
    body = res.get_json()
    for key in [
        "schema_version",
        "covenant_id",
        "status",
        "agent_id",
        "operator_pubkey",
        "agent_pubkey",
        "network",
        "anchor",
        "policy",
        "trust_interpretation",
        "artifacts",
        "created_at",
    ]:
        assert key in body


def test_report_hash_is_deterministic_under_canonicalization():
    report_a = {
        "schema_version": "1.0",
        "report_id": "r1",
        "metrics": {"completed_jobs": 1, "failed_jobs": 0},
        "notes": ["x"],
    }
    report_b = {
        "notes": ["x"],
        "metrics": {"failed_jobs": 0, "completed_jobs": 1},
        "report_id": "r1",
        "schema_version": "1.0",
    }
    assert canonicalize_json(report_a) == canonicalize_json(report_b)
    assert compute_report_hash(report_a) == compute_report_hash(report_b)


def test_trust_page_uses_safe_covenant_wording(client):
    res = client.get("/agent/trust/hodlxxi-herald-01")
    assert res.status_code == 200
    text = res.get_data(as_text=True)
    assert "does not prove uptime" in text
    assert "execution quality" in text
    assert "operator↔agent covenant" in text


def test_new_public_routes_are_accessible_without_login(client):
    routes = [
        "/agent/trust/hodlxxi-herald-01",
        "/agent/binding/hodlxxi-herald-01",
        "/reports/hodlxxi-herald-01-daily-test",
        "/reports/hodlxxi-herald-01-daily-test.json",
        "/verify/report/hodlxxi-herald-01-daily-test",
        "/verify/nostr/sample-event",
    ]
    for route in routes:
        res = client.get(route)
        assert res.status_code == 200
    head_res = client.head("/agent/trust-summary/hodlxxi-herald-01.json")
    assert head_res.status_code == 200


def test_nostr_builder_helpers_generate_expected_shapes():
    report = {
        "report_id": "r1",
        "agent_id": "hodlxxi-herald-01",
        "status": {"state": "healthy"},
        "metrics": {"completed_jobs": 3},
        "covenant": {"covenant_backed": True},
    }
    receipt = {"job_id": "j1", "job_type": "ping", "timestamp": "2026-01-01T00:00:00Z"}
    trust = {"agent_id": "hodlxxi-herald-01", "trust_lane": "covenant-backed"}

    assert "heartbeat" in build_heartbeat_note(report).lower()
    assert "job=j1" in build_execution_summary_note(receipt)
    assert "alignment signal" in build_trust_signal_note(trust)

    longform = build_daily_longform_report(report)
    assert longform["kind"] == 30023
    assert "does not by itself prove uptime" in longform["content"]

    relay_event = build_relay_list_event(["wss://relay.damus.io"])
    assert relay_event["kind"] == 10002
    assert relay_event["tags"] == [["r", "wss://relay.damus.io"]]
