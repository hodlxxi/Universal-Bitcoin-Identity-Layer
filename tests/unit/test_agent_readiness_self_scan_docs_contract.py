"""Documentation contract for the public readiness self-scan endpoint."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

README = ROOT / "README.md"
RUNTIME = ROOT / "docs" / "AGENT_RUNTIME.md"
READINESS = ROOT / "docs" / "AGENT_READINESS_REPORT_V1.md"

ENDPOINT = "/agent/readiness/self-scan"
SCHEMA = "hodlxxi.agent_readiness_report.v1"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_public_readiness_self_scan_endpoint_is_documented_in_core_docs():
    for path in (README, RUNTIME, READINESS):
        assert ENDPOINT in _read(path), f"{ENDPOINT} missing from {path}"


def test_readiness_self_scan_contract_documents_report_shape_and_statuses():
    text = _read(READINESS)

    assert SCHEMA in text
    assert "GET /agent/readiness/self-scan" in text
    assert "summary.status" in text
    assert "summary.score" in text
    assert "checks" in text
    assert "verification" in text
    assert "report_sha256" in text
    assert "receipt.status = not_issued" in text
    assert "attestation.status = not_issued" in text


def test_runtime_index_documents_self_scan_as_unpaid_public_json_surface():
    text = _read(RUNTIME)

    assert "GET /agent/readiness/self-scan" in text
    assert "live public JSON self-scan" in text
    assert "does not create a paid job" in text
    assert "receipt.status" in text
    assert "attestation.status" in text
    assert "not_issued" in text


def test_readme_lists_self_scan_with_runtime_readiness_summary():
    text = _read(README)

    assert "GET /agent/readiness/self-scan" in text
    assert "public machine-readable self-scan report" in text
    assert "report_sha256" in text
