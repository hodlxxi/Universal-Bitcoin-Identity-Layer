from __future__ import annotations

from pathlib import Path

from app.blueprints import agent as agent_module

REPO_ROOT = Path(__file__).resolve().parents[2]


DOC_FILES = [
    REPO_ROOT / "AGENT_PROTOCOL.md",
    REPO_ROOT / "docs" / "AGENT_SURFACES.md",
    REPO_ROOT / "docs" / "HODLXXI_AGENT_PROTOCOL_V0.2.md",
]


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_required_protocol_documents_exist() -> None:
    for path in DOC_FILES:
        assert path.exists(), f"missing required protocol document: {path}"


def test_documented_agent_endpoints_are_registered(app) -> None:
    routes = {rule.rule for rule in app.url_map.iter_rules()}
    expected = {
        "/.well-known/agent.json",
        "/agent/capabilities",
        "/agent/capabilities/schema",
        "/agent/request",
        "/agent/message",
        "/agent/jobs/<job_id>",
        "/agent/verify/<job_id>",
        "/agent/attestations",
        "/agent/reputation",
        "/agent/chain/health",
        "/agent/skills",
        "/agent/marketplace/listing",
        "/agent/trust/<agent_id>",
        "/agent/binding/<agent_id>",
        "/agent/trust-summary/<agent_id>.json",
        "/agent/covenants/<covenant_id>.json",
    }
    missing = expected - routes
    assert not missing, f"runtime missing documented endpoints: {sorted(missing)}"


def test_documented_job_types_match_runtime_registry() -> None:
    protocol_text = _read(REPO_ROOT / "AGENT_PROTOCOL.md")
    for job_type in sorted(agent_module.JOB_REGISTRY):
        assert f"### `{job_type}`" in protocol_text


def test_protocol_versions_are_documented_consistently() -> None:
    protocol_text = _read(REPO_ROOT / "AGENT_PROTOCOL.md")
    surfaces_text = _read(REPO_ROOT / "docs" / "AGENT_SURFACES.md")

    assert "runtime agent capabilities version `0.1`" in protocol_text
    assert f"`capability_schema.version`: `{agent_module.CAPABILITIES_SCHEMA_VERSION}`" in protocol_text
    assert f"`receipt.version`: `{agent_module.RECEIPT_VERSION}`" in protocol_text
    assert (
        f"`listing_version`: `{agent_module.MARKETPLACE_LISTING_VERSION}`" in protocol_text
        or f"`listing_version`: `{agent_module.MARKETPLACE_LISTING_VERSION}`" in surfaces_text
    )


def test_docs_preserve_conservative_trust_boundaries() -> None:
    protocol_text = _read(REPO_ROOT / "AGENT_PROTOCOL.md").lower()
    assert "does not claim verified on-chain backing" in protocol_text
    assert "does not claim verified" in protocol_text and "time-locked capital" in protocol_text


def test_v02_extension_is_labeled_partial_and_future_compatible() -> None:
    v02_text = _read(REPO_ROOT / "docs" / "HODLXXI_AGENT_PROTOCOL_V0.2.md").lower()
    assert "extends" in v02_text
    assert "subset" in v02_text or "partial" in v02_text
    assert "future" in v02_text


def test_inter_agent_demo_marked_as_dev_harness() -> None:
    demo_text = _read(REPO_ROOT / "docs" / "INTER_AGENT_DEMO.md").lower()
    assert "development harness" in demo_text
    assert "not a production deployment recipe" in demo_text
