from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
STATIC_DOCS_DIR = REPO_ROOT / "app" / "static" / "docs" / "docs"
STATIC_DOCS_INDEX = STATIC_DOCS_DIR / "README.md"
DOCUMENTATION_MAP = REPO_ROOT / "docs" / "DOCUMENTATION_MAP.md"
HISTORICAL_STATUS_PHRASE = "Status:** Historical checkpoint"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_static_docs_index_exists():
    assert STATIC_DOCS_INDEX.exists()


def test_static_docs_index_declares_runtime_readiness_boundary():
    content = read(STATIC_DOCS_INDEX)

    for phrase in (
        "Runtime/readiness boundary",
        "conceptual and public-facing reference material",
        "not the authoritative source for current runtime behavior",
        "docs/READINESS_EVALUATION.md",
        "docs/DOCUMENTATION_MAP.md",
    ):
        assert phrase in content


def test_documentation_map_declares_static_docs_boundary():
    content = read(DOCUMENTATION_MAP)

    for phrase in (
        "app/static/docs/docs/README.md",
        "conceptual/public-facing reference docs",
        "not authoritative for current runtime behavior",
        "docs/READINESS_EVALUATION.md",
        "docs/DOCUMENTATION_MAP.md",
    ):
        assert phrase in content


def test_static_docs_are_not_historical_checkpoints():
    for path in STATIC_DOCS_DIR.glob("*.md"):
        assert HISTORICAL_STATUS_PHRASE not in read(path)


def test_boundary_note_is_required_only_on_static_docs_index():
    indexed_static_docs = [path for path in STATIC_DOCS_DIR.glob("*.md") if path != STATIC_DOCS_INDEX]
    assert indexed_static_docs

    for path in indexed_static_docs:
        assert "Runtime/readiness boundary" not in read(path)
