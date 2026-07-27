from pathlib import Path


def test_primary_membership_document_is_published_and_dormant():
    primary = Path("docs/CANONICAL_CRT_MEMBERSHIP_EVALUATOR_V1.md").read_text()
    index = Path("docs/README.md").read_text()
    status = Path("docs/CRT_MEMBERSHIP_IMPLEMENTATION_STATUS.md").read_text()
    bridge = Path("docs/CRT_RUNTIME_BRIDGE.md").read_text()
    assert "PR6.12 `IMPLEMENTED_DORMANT`" in primary
    assert "CANONICAL_CRT_MEMBERSHIP_EVALUATOR_V1.md" in index
    assert "CRT membership-state evaluator" in status
    assert "IMPLEMENTED_DORMANT" in status
    assert "PR6.12" in status
    assert "FULL/LIMITED authorization policy mapping" in status
    assert "| MISSING |" in status
    assert "implemented dormant" in bridge.lower()
    assert "No production wiring was added" in bridge


def test_documented_boundary_excludes_runtime_and_authorization():
    text = Path("docs/CANONICAL_CRT_MEMBERSHIP_EVALUATOR_V1.md").read_text()
    for phrase in (
        "no storage lookup",
        "Bitcoin RPC",
        "route, API, MCP, CLI, scheduler",
        "FULL/LIMITED",
        "PR6.13",
        "target edge maps only to `edge_inactive`",
        "ancestor or genesis maps only to `lineage_inactive`",
    ):
        assert phrase in text
