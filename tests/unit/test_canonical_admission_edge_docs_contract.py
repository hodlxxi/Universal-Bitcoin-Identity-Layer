from pathlib import Path


def test_docs_state_exact_dormant_and_future_boundaries():
    primary = Path("docs/CANONICAL_ADMISSION_EDGE_REGISTRY_V1.md").read_text()
    assert "IMPLEMENTED_DORMANT" in primary
    assert "sponsor_lineage_evaluator_unavailable" in primary
    assert "complete lineage traversal" in primary
    assert "no route, API, command" in primary
    assert "Depth greater than one never returns active" in primary
    assert "one PR6.8 registration containing two legs" in primary
    assert "unapplied" in primary
    assert "No stronger ordinary human identifier" in primary
    bridge = Path("docs/CRT_RUNTIME_BRIDGE.md").read_text()
    inventory = Path("docs/CRT_MEMBERSHIP_IMPLEMENTATION_STATUS.md").read_text()
    index = Path("docs/README.md").read_text()
    assert "no production wiring or complete lineage traversal exists" in bridge
    assert "deeper edges fail closed pending complete lineage traversal" in inventory
    assert "CANONICAL_ADMISSION_EDGE_REGISTRY_V1.md" in index
