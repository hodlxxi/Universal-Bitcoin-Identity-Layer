"""Tests for the Agent Readiness Report v1 self-scan builder."""

from app.factory import create_app
from app.services.agent_readiness_report import (
    SCHEMA,
    build_self_readiness_report,
    compute_report_hash,
)

GENERATED_AT = "2026-06-16T00:00:00Z"
REPORT_ID = "readiness-self-scan-test"

EXPECTED_CHECK_IDS = {
    "well_known_agent_json",
    "agent_capabilities",
    "agent_capabilities_schema",
    "nostr_dm_policy",
    "public_status",
    "health_ready",
    "reputation_surface",
    "attestations_surface",
    "chain_health_surface",
    "receipt_verification_surface",
    "report_json_surface",
    "human_verify_report_surface",
}


def _build_report():
    app = create_app()
    return build_self_readiness_report(
        app,
        base_url="https://hodlxxi.com/",
        report_id=REPORT_ID,
        generated_at=GENERATED_AT,
    )


def test_self_readiness_report_has_v1_shape():
    report = _build_report()

    assert report["schema"] == SCHEMA
    assert report["report_id"] == REPORT_ID
    assert report["generated_at"] == GENERATED_AT
    assert report["target"]["base_url"] == "https://hodlxxi.com"
    assert report["target"]["normalized_origin"] == "https://hodlxxi.com"
    assert report["scanner"]["service"] == "HODLXXI"
    assert report["scanner"]["runtime"] == "https://hodlxxi.com"

    for key in [
        "target",
        "scanner",
        "summary",
        "checks",
        "receipt",
        "attestation",
        "verification",
        "report_sha256",
    ]:
        assert key in report


def test_self_readiness_report_checks_existing_runtime_surfaces():
    report = _build_report()
    checks = {check["id"]: check for check in report["checks"]}

    assert set(checks) == EXPECTED_CHECK_IDS
    assert report["summary"]["status"] == "runtime_ready"
    assert report["summary"]["score"] == 100
    assert report["summary"]["passed"] == len(EXPECTED_CHECK_IDS)
    assert report["summary"]["failed"] == 0

    for check in checks.values():
        assert check["status"] == "pass"
        assert check["method"] == "GET"
        assert check["url"].startswith("https://hodlxxi.com/")
        assert check["evidence"]["route_present"] is True
        assert check["evidence"]["get_supported"] is True
        assert check["evidence"]["endpoint"]


def test_self_readiness_report_does_not_issue_receipt_or_attestation():
    report = _build_report()

    assert report["receipt"]["status"] == "not_issued"
    assert report["receipt"]["job_id"] is None
    assert report["receipt"]["verify_url"] is None
    assert report["receipt"]["reason"] == "self_scan_builder_does_not_create_paid_runtime_job"

    assert report["attestation"]["status"] == "not_issued"
    assert report["attestation"]["attestations_url"] == "/agent/attestations"
    assert report["attestation"]["reputation_url"] == "/agent/reputation"
    assert report["attestation"]["chain_health_url"] == "/agent/chain/health"


def test_self_readiness_report_verification_links_are_deterministic():
    report = _build_report()

    assert report["verification"]["report_json_url"] == f"/reports/{REPORT_ID}.json"
    assert report["verification"]["human_verify_url"] == f"/verify/report/{REPORT_ID}"
    assert report["verification"]["receipt_verify_url"] is None


def test_self_readiness_report_hash_is_stable_and_excludes_itself():
    report = _build_report()

    original_hash = report["report_sha256"]
    assert original_hash == compute_report_hash(report)

    mutated = dict(report)
    mutated["report_sha256"] = "different"
    assert compute_report_hash(mutated) == original_hash
