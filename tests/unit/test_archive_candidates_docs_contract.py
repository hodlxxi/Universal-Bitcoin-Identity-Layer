from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ARCHIVE_CANDIDATES = ROOT / "docs" / "ARCHIVE_CANDIDATES.md"
DOCUMENTATION_MAP = ROOT / "docs" / "DOCUMENTATION_MAP.md"

CANDIDATE_PATHS = [
    "docs/CI_PING.md",
    "docs/UI_UNIFICATION.md",
    "docs/agent_ubid_plan.md",
    "docs/clawhub/hodlxxi-bitcoin-identity/HEARTBEAT.operator.md",
    "docs/schemas/external_agent_record.schema.json",
    "examples/social/first_external_paid_call_post.md",
]

CURRENT_DOC_PATHS = [
    "docs/READINESS_EVALUATION.md",
    "docs/DOCUMENTATION_MAP.md",
    "AGENT_PROTOCOL.md",
    "docs/AGENT_RECEIPT_V1.md",
    "docs/ops/PUBLIC_AGENT_CONTRACT_SMOKE.md",
    "docs/sdk/README.md",
]

REQUIRED_PHRASES = [
    "not a deletion request",
    "must not be deleted without a separate focused review PR",
    "Review-before-removal schema",
    "Schema files require extra care",
    "git grep",
    "Do not mix archive cleanup with runtime changes",
]


def test_archive_candidates_doc_exists():
    assert ARCHIVE_CANDIDATES.exists()


def test_documentation_map_links_archive_candidates_index():
    documentation_map = DOCUMENTATION_MAP.read_text(encoding="utf-8")

    assert "docs/ARCHIVE_CANDIDATES.md" in documentation_map


def test_archive_candidates_doc_contains_required_contract_language():
    archive_candidates = ARCHIVE_CANDIDATES.read_text(encoding="utf-8")

    for phrase in REQUIRED_PHRASES:
        assert phrase in archive_candidates


def test_archive_candidates_doc_lists_all_candidate_paths():
    archive_candidates = ARCHIVE_CANDIDATES.read_text(encoding="utf-8")

    for candidate_path in CANDIDATE_PATHS:
        assert candidate_path in archive_candidates


def test_archive_candidates_doc_lists_current_docs_as_not_candidates():
    archive_candidates = ARCHIVE_CANDIDATES.read_text(encoding="utf-8")

    for current_doc_path in CURRENT_DOC_PATHS:
        assert current_doc_path in archive_candidates


def test_candidate_files_still_exist():
    for candidate_path in CANDIDATE_PATHS:
        assert (ROOT / candidate_path).exists()
