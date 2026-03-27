from app.services.nostr_reports import (
    build_daily_longform_report,
    build_execution_summary_note,
    build_heartbeat_note,
    build_relay_list_event,
    build_trust_signal_note,
)
from app.services.trust_surface import canonicalize_json, compute_report_hash
from app.database import session_scope
from app.models import AgentJob


def _insert_agent_job(status: str, *, suffix: str) -> None:
    with session_scope() as session:
        session.add(
            AgentJob(
                id=f"job-{suffix}",
                job_type="ping",
                request_json={"job_type": "ping", "payload": {"suffix": suffix}},
                request_hash=f"req-{suffix}",
                sats=21,
                payment_request=f"lnbc1{suffix}",
                payment_lookup_id=f"lookup-{suffix}",
                payment_hash=f"hash-{suffix}",
                status=status,
            )
        )


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
        "covenant_present",
        "covenant_declared",
        "covenant_funded",
        "funding_status",
        "trust_lane",
        "verify_url",
    ]:
        assert key in body
    assert body["covenant_funded"] is False
    assert body["funding_status"] == "unfunded_declared"


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
        "funding_status",
        "anchor",
        "descriptor",
        "policy",
        "trust_interpretation",
        "artifacts",
        "created_at",
    ]:
        assert key in body
    assert body["status"] == "unfunded_declared"
    assert body["funding_status"] == "unfunded_declared"
    assert body["operator_pubkey"] == "023d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923"
    assert body["agent_pubkey"] == "02019e7a92d22e4467e0afb20ce62976e976d1558e553351e1fb1a886b4a149f92"
    assert body["anchor"]["type"] == "declared_address"
    assert body["anchor"]["address"] == "bc1qsrpjjn3w8ly8da7u59y7ywzly4he7lfnl8462qrxp3d368gexess3tjdz3"
    serialized = str(body).lower()
    assert "demo-txid" not in serialized
    assert "demo-operator-pubkey" not in serialized


def test_report_hash_is_deterministic_under_canonicalization():
    report_a = {
        "schema_version": "1.0",
        "report_id": "r1",
        "metrics": {"completed_jobs": 1, "unpaid_or_expired_jobs": 0, "execution_failed_jobs": 0, "expired_jobs": 0},
        "notes": ["x"],
    }
    report_b = {
        "notes": ["x"],
        "metrics": {"expired_jobs": 0, "execution_failed_jobs": 0, "unpaid_or_expired_jobs": 0, "completed_jobs": 1},
        "report_id": "r1",
        "schema_version": "1.0",
    }
    assert canonicalize_json(report_a) == canonicalize_json(report_b)
    assert compute_report_hash(report_a) == compute_report_hash(report_b)


def test_trust_page_uses_safe_covenant_wording(client):
    res = client.get("/agent/trust/hodlxxi-herald-01")
    assert res.status_code == 200
    text = res.get_data(as_text=True)
    assert "unfunded_declared" in text
    assert "declared Bitcoin address" in text
    assert "does not prove uptime" in text
    assert "execution quality" in text
    assert "operator↔agent covenant" in text


def test_binding_page_uses_declared_identity_wording(client):
    res = client.get("/agent/binding/hodlxxi-herald-01")
    assert res.status_code == 200
    text = res.get_data(as_text=True)
    assert "declared public Herald identity" in text
    assert "Funding attachment" in text
    assert "023d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923" in text
    assert "02019e7a92d22e4467e0afb20ce62976e976d1558e553351e1fb1a886b4a149f92" in text


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
        "covenant": {"covenant_present": True, "funding_status": "unfunded_declared"},
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


def test_report_json_does_not_overclaim_funded_status(client):
    res = client.get("/reports/hodlxxi-herald-01-daily-test.json")
    assert res.status_code == 200
    body = res.get_json()
    assert body["covenant"]["covenant_present"] is True
    assert body["covenant"]["covenant_declared"] is True
    assert body["covenant"]["covenant_funded"] is False
    assert body["covenant"]["funding_status"] == "unfunded_declared"


def test_report_metrics_are_categorized_and_not_single_failed_jobs(client):
    _insert_agent_job("done", suffix="done-1")
    _insert_agent_job("invoice_pending", suffix="pending-1")
    _insert_agent_job("failed", suffix="failed-1")
    _insert_agent_job("expired", suffix="expired-1")

    res = client.get("/reports/hodlxxi-herald-01-daily-test.json")
    assert res.status_code == 200
    body = res.get_json()
    metrics = body["metrics"]

    assert "failed_jobs" not in metrics
    for key in [
        "completed_jobs",
        "unpaid_or_expired_jobs",
        "execution_failed_jobs",
        "expired_jobs",
        "sats_earned",
        "sats_spent",
    ]:
        assert key in metrics

    assert metrics["completed_jobs"] >= 1
    assert metrics["unpaid_or_expired_jobs"] >= 1
    assert metrics["execution_failed_jobs"] >= 1
    assert metrics["expired_jobs"] >= 1


def test_report_page_wording_separates_unpaid_from_execution_failures(client):
    res = client.get("/reports/hodlxxi-herald-01-daily-test")
    assert res.status_code == 200
    text = res.get_data(as_text=True)
    assert "unpaid_or_expired_jobs" in text
    assert "execution_failed_jobs" in text
    assert "do not necessarily indicate execution errors" in text
