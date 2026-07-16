import hashlib
from datetime import datetime, timedelta, timezone

import pytest

import app.blueprints.agent as agent_routes
from app.services.nostr_reports import (
    build_daily_longform_report,
    build_execution_summary_note,
    build_heartbeat_note,
    build_relay_list_event,
    build_trust_signal_note,
)
from app.services.trust_surface import canonicalize_json, compute_report_hash
from app.database import session_scope
from app.models import AgentEvent, AgentJob

DAILY_REPORT_ID = "hodlxxi-herald-01-daily-20260716"
PERIOD_FROM = datetime(2026, 7, 15, 0, 0, tzinfo=timezone.utc)
PERIOD_TO = datetime(2026, 7, 16, 0, 0, tzinfo=timezone.utc)


def _agent_job(job_id: str, *, sats: int, status: str, created_at: datetime) -> AgentJob:
    suffix = job_id.removeprefix("job-")
    return AgentJob(
        id=job_id,
        job_type="ping",
        request_json={"job_type": "ping", "payload": {"suffix": suffix}},
        request_hash=hashlib.sha256(f"request-{suffix}".encode()).hexdigest(),
        sats=sats,
        payment_request=f"lnbc1{suffix}",
        payment_lookup_id=f"lookup-{suffix}",
        payment_hash=hashlib.sha256(f"payment-{suffix}".encode()).hexdigest(),
        status=status,
        created_at=created_at,
        updated_at=created_at,
    )


def _agent_event(job_id: str, *, suffix: str, created_at: datetime) -> AgentEvent:
    event_hash = hashlib.sha256(f"event-{suffix}".encode()).hexdigest()
    return AgentEvent(
        job_id=job_id,
        event_hash=event_hash,
        prev_event_hash=None,
        event_json={"event_type": "job_receipt", "job_id": job_id},
        signature=f"signature-{suffix}",
        created_at=created_at,
    )


@pytest.fixture
def isolated_agent_history():
    with session_scope() as session:
        session.query(AgentEvent).delete()
        session.query(AgentJob).delete()
    yield
    with session_scope() as session:
        session.query(AgentEvent).delete()
        session.query(AgentJob).delete()


def _seed_boundary_history() -> str:
    jobs = [
        _agent_job("job-before", sats=5, status="done", created_at=PERIOD_FROM - timedelta(seconds=1)),
        _agent_job("job-at-from", sats=7, status="failed", created_at=PERIOD_FROM),
        _agent_job("job-inside", sats=29, status="invoice_pending", created_at=PERIOD_FROM + timedelta(hours=1)),
        _agent_job("job-at-to", sats=101, status="done", created_at=PERIOD_TO),
        _agent_job("job-after", sats=211, status="done", created_at=PERIOD_TO + timedelta(hours=1)),
    ]
    latest_included = _agent_event(
        "job-inside",
        suffix="inside-latest",
        created_at=PERIOD_FROM + timedelta(hours=3),
    )
    latest_included_hash = latest_included.event_hash
    events = [
        _agent_event("job-before", suffix="before", created_at=PERIOD_FROM - timedelta(seconds=1)),
        _agent_event("job-at-from", suffix="at-from", created_at=PERIOD_FROM),
        _agent_event("job-inside", suffix="inside", created_at=PERIOD_FROM + timedelta(hours=2)),
        latest_included,
        _agent_event("job-at-to", suffix="at-to", created_at=PERIOD_TO),
        _agent_event("job-after", suffix="after", created_at=PERIOD_TO + timedelta(hours=1)),
    ]
    with session_scope() as session:
        session.add_all(jobs)
        session.flush()
        session.add_all(events)
    return latest_included_hash


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
        f"/reports/{DAILY_REPORT_ID}",
        f"/reports/{DAILY_REPORT_ID}.json",
        f"/verify/report/{DAILY_REPORT_ID}",
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
        "period": {"from": "2026-07-15T00:00:00Z", "to": "2026-07-16T00:00:00Z"},
        "metrics": {"completed_jobs": 3, "evidenced_completed_jobs": 3, "sats_evidenced": 84},
        "lifetime_snapshot": {"as_of": "2026-07-16T00:00:00Z"},
        "covenant": {"covenant_present": True, "funding_status": "unfunded_declared"},
    }
    receipt = {"job_id": "j1", "job_type": "ping", "timestamp": "2026-01-01T00:00:00Z"}
    trust = {"agent_id": "hodlxxi-herald-01", "funding_status": "unfunded_declared"}

    assert "heartbeat" in build_heartbeat_note(report).lower()
    assert "job=j1" in build_execution_summary_note(receipt)
    trust_signal = build_trust_signal_note(trust)
    assert "declared covenant policy signal" in trust_signal
    assert "unfunded_declared" in trust_signal
    assert "Bitcoin-anchored" not in trust_signal
    assert "covenant-backed" not in trust_signal.lower()

    longform = build_daily_longform_report(report)
    assert longform["kind"] == 30023
    assert "Period evidenced completed jobs: `3`" in longform["content"]
    assert "Period sats evidenced: `84`" in longform["content"]
    assert "unfunded_declared" in longform["content"]
    assert "declared" in longform["content"].lower()
    assert "Bitcoin-anchored" not in longform["content"]
    assert "covenant-backed" not in longform["content"].lower()
    assert "does not by itself prove uptime" in longform["content"]

    relay_event = build_relay_list_event(["wss://relay.damus.io"])
    assert relay_event["kind"] == 10002
    assert relay_event["tags"] == [["r", "wss://relay.damus.io"]]


def test_report_json_does_not_overclaim_funded_status(client):
    res = client.get(f"/reports/{DAILY_REPORT_ID}.json")
    assert res.status_code == 200
    body = res.get_json()
    assert body["covenant"]["covenant_present"] is True
    assert body["covenant"]["covenant_declared"] is True
    assert body["covenant"]["covenant_funded"] is False
    assert body["covenant"]["funding_status"] == "unfunded_declared"


def test_daily_report_is_stable_bounded_and_uses_actual_sats(client, isolated_agent_history):
    latest_included_hash = _seed_boundary_history()

    first = client.get(f"/reports/{DAILY_REPORT_ID}.json")
    second = client.get(f"/reports/{DAILY_REPORT_ID}.json")

    assert first.status_code == second.status_code == 200
    assert first.get_data() == second.get_data()

    first_body = first.get_json()
    second_body = second.get_json()
    assert first_body == second_body
    assert canonicalize_json(first_body) == canonicalize_json(second_body)
    assert first_body["report_sha256"] == second_body["report_sha256"]
    assert first_body["created_at"] == second_body["created_at"] == "2026-07-16T00:00:00Z"
    assert first_body["report_sha256"] == compute_report_hash(first_body)

    assert first_body["schema"] == "hodlxxi.daily_trust_report.v1"
    assert first_body["schema_version"] == "1.1"
    assert first_body["period"] == {
        "type": "closed_utc_day",
        "from": "2026-07-15T00:00:00Z",
        "to": "2026-07-16T00:00:00Z",
        "from_inclusive": True,
        "to_exclusive": True,
    }
    assert first_body["metrics_scope"] == "closed_utc_period"
    assert first_body["metrics"] == {
        "persisted_job_requests": 2,
        "evidenced_completed_jobs": 2,
        "completed_jobs": 2,
        "attestations_created": 3,
        "sats_evidenced": 36,
    }
    assert first_body["metric_definitions"]["completed_jobs"] == {
        "scope": "closed_utc_period",
        "semantics": "period_evidenced_completed_jobs",
        "compatibility_alias_of": "metrics.evidenced_completed_jobs",
    }
    assert first_body["lifetime_snapshot"] == {
        "scope": "lifetime_before_cutoff",
        "as_of": "2026-07-16T00:00:00Z",
        "persisted_job_requests": 3,
        "evidenced_completed_jobs": 3,
        "attestations_count": 4,
        "sats_evidenced": 41,
        "latest_event_timestamp": "2026-07-15T03:00:00Z",
        "latest_event_hash": latest_included_hash,
    }

    current_status_metrics = {
        "unpaid_or_expired_jobs",
        "execution_failed_jobs",
        "expired_jobs",
        "unclassified_jobs",
    }
    assert current_status_metrics.isdisjoint(first_body["metrics"])
    assert current_status_metrics.isdisjoint(first_body["lifetime_snapshot"])

    with session_scope() as session:
        post_cutoff_job = _agent_job(
            "job-post-cutoff-insert",
            sats=997,
            status="done",
            created_at=PERIOD_TO + timedelta(days=1),
        )
        session.add(post_cutoff_job)
        session.flush()
        session.add(
            _agent_event(
                post_cutoff_job.id,
                suffix="post-cutoff-insert",
                created_at=PERIOD_TO + timedelta(days=1),
            )
        )

    after_post_cutoff_insert = client.get(f"/reports/{DAILY_REPORT_ID}.json")
    assert after_post_cutoff_insert.status_code == 200
    assert after_post_cutoff_insert.get_data() == first.get_data()
    assert after_post_cutoff_insert.get_json() == first_body
    assert after_post_cutoff_insert.get_json()["report_sha256"] == first_body["report_sha256"]


def test_report_routes_reject_unsupported_ids_without_synthesis(client):
    future_date = (datetime.now(timezone.utc).date() + timedelta(days=1)).strftime("%Y%m%d")
    unsupported_ids = [
        "arbitrary-report",
        "hodlxxi-herald-01-daily-test",
        "hodlxxi-herald-01-daily-20260230",
        "other-agent-daily-20260716",
        f"hodlxxi-herald-01-daily-{future_date}",
    ]

    for report_id in unsupported_ids:
        for path in (
            f"/reports/{report_id}.json",
            f"/reports/{report_id}",
            f"/verify/report/{report_id}",
        ):
            response = client.get(path)
            assert response.status_code == 404
            assert response.get_json() == {"error": "report_not_found"}


def test_report_get_routes_do_not_mutate_runtime_state(client, isolated_agent_history, monkeypatch, tmp_path):
    monkeypatch.setenv("AGENT_READINESS_REPORT_DIR", str(tmp_path))

    def forbidden_write(*args, **kwargs):
        raise AssertionError("report GET invoked a mutating runtime path")

    for function_name in (
        "save_self_readiness_report",
        "build_self_readiness_report",
        "create_invoice",
        "check_invoice_paid",
        "_job_result",
        "_build_receipt",
        "_event_attestation",
    ):
        monkeypatch.setattr(agent_routes, function_name, forbidden_write)

    with session_scope() as session:
        before_counts = (session.query(AgentJob).count(), session.query(AgentEvent).count())
    before_files = sorted(path.relative_to(tmp_path) for path in tmp_path.rglob("*") if path.is_file())

    for path in (
        f"/reports/{DAILY_REPORT_ID}.json",
        f"/reports/{DAILY_REPORT_ID}",
        f"/verify/report/{DAILY_REPORT_ID}",
    ):
        assert client.get(path).status_code == 200

    with session_scope() as session:
        after_counts = (session.query(AgentJob).count(), session.query(AgentEvent).count())
    after_files = sorted(path.relative_to(tmp_path) for path in tmp_path.rglob("*") if path.is_file())

    assert after_counts == before_counts
    assert after_files == before_files == []


def test_report_page_shows_fixed_scopes_and_live_reputation_separately(client):
    res = client.get(f"/reports/{DAILY_REPORT_ID}")
    assert res.status_code == 200
    text = res.get_data(as_text=True)
    assert "Fixed UTC period" in text
    assert "Period metrics" in text
    assert "Lifetime snapshot" in text
    assert "exclusive cutoff" in text
    assert "Current job-outcome classifications are a separate live surface" in text
    assert "/agent/reputation" in text
    assert "execution_failed_jobs" not in text
