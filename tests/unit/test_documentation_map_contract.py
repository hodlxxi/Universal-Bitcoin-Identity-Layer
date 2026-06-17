from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DOC_MAP = REPO_ROOT / "docs" / "DOCUMENTATION_MAP.md"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_documentation_map_exists():
    assert DOC_MAP.exists()


def test_entry_points_link_documentation_map():
    assert "docs/DOCUMENTATION_MAP.md" in read(REPO_ROOT / "README.md")
    assert "DOCUMENTATION_MAP.md" in read(REPO_ROOT / "docs" / "README.md")


def test_documentation_map_contains_required_status_sections():
    content = read(DOC_MAP)
    for phrase in (
        "Current runtime truth",
        "Production verification and ops",
        "SDK and external developer docs",
        "Historical checkpoints",
        "Experimental / staging / roadmap docs",
        "Static website and conceptual docs",
        "Archive candidates",
        "Safety / non-claims",
    ):
        assert phrase in content


def test_documentation_map_contains_current_verifier_semantics():
    content = read(DOC_MAP)
    for phrase in ("409", "no_receipt", "receipt_not_issued", "404", "not_found"):
        assert phrase in content


def test_documentation_map_mentions_current_public_docs_and_sdk():
    content = read(DOC_MAP)
    for phrase in (
        "scripts/smoke_public_agent_contract.sh",
        "docs/ops/PUBLIC_AGENT_CONTRACT_SMOKE.md",
        "docs/OPERATOR_CONTINUITY_E923.md",
        "docs/sdk/README.md",
    ):
        assert phrase in content


def test_documentation_map_does_not_delete_archive_candidates_in_this_pr():
    content = read(DOC_MAP)
    assert "Do not delete them in this PR" in content
