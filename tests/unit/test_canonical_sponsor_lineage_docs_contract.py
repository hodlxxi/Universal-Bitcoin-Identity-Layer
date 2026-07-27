from pathlib import Path


def test_lineage_document_is_published_and_dormant():
    document = Path("docs/CANONICAL_SPONSOR_LINEAGE_EVALUATOR_V1.md").read_text()
    index = Path("docs/README.md").read_text()
    status = Path("docs/CRT_MEMBERSHIP_IMPLEMENTATION_STATUS.md").read_text()
    bridge = Path("docs/CRT_RUNTIME_BRIDGE.md").read_text()
    assert "IMPLEMENTED_DORMANT" in document
    assert "CANONICAL_SPONSOR_LINEAGE_EVALUATOR_V1.md" in index
    assert "PR6.11" in status
    assert "no automatic storage lookup" in document.lower()
    assert "no automatic lookup" in bridge.lower()
    assert "PR6.12" in document
