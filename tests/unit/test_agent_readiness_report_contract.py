"""Contract tests for the Agent Readiness Report v1 spec."""

from pathlib import Path

from app.factory import create_app

ROOT = Path(__file__).resolve().parents[2]
DOC = ROOT / "docs" / "AGENT_READINESS_REPORT_V1.md"


def test_agent_readiness_report_v1_doc_exists_and_has_markers():
    text = DOC.read_text()

    assert "<!-- HODLXXI_AGENT_READINESS_REPORT_V1 -->" in text
    assert "<!-- END_HODLXXI_AGENT_READINESS_REPORT_V1 -->" in text
    assert "hodlxxi.agent_readiness_report.v1" in text
    assert (
        "scan target -> evaluate public agent surfaces -> produce report -> issue receipt -> expose attestation" in text
    )


def test_agent_readiness_report_v1_reuses_existing_runtime_surfaces():
    app = create_app()
    paths = {str(rule) for rule in app.url_map.iter_rules()}

    required_paths = {
        "/.well-known/agent.json",
        "/agent/capabilities",
        "/agent/capabilities/schema",
        "/.well-known/nostr-dm-policy.json",
        "/api/public/status",
        "/health/ready",
        "/agent/reputation",
        "/agent/attestations",
        "/agent/chain/health",
        "/agent/verify/<job_id>",
        "/reports/<report_id>.json",
        "/verify/report/<report_id>",
    }

    missing = sorted(required_paths - paths)
    assert not missing


def test_agent_readiness_report_v1_doc_names_required_checks():
    text = DOC.read_text()

    for check_id in [
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
    ]:
        assert check_id in text


def test_agent_readiness_report_v1_doc_defines_non_goals():
    text = DOC.read_text()

    for phrase in [
        "custody",
        "exchange execution",
        "P2P trade matching",
        "private-key handling",
        "private vulnerability scanning",
    ]:
        assert phrase in text
