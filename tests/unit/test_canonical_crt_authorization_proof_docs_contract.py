from pathlib import Path


ROOT = Path(__file__).parents[2]


def test_primary_document_and_index_contract():
    document = (ROOT / "docs/CANONICAL_CRT_AUTHORIZATION_PROOF_V1.md").read_text()
    index = (ROOT / "docs/README.md").read_text()
    assert "IMPLEMENTED_DORMANT" in document
    assert "FULL" in document and "LIMITED" in document
    assert "PR6.15" in document
    assert "not a signature" in document
    assert "CANONICAL_CRT_AUTHORIZATION_PROOF_V1.md" in index


def test_inventory_truthful_split():
    inventory = (ROOT / "docs/CRT_MEMBERSHIP_IMPLEMENTATION_STATUS.md").read_text()
    assert "Canonical why-FULL/why-LIMITED proof artifact" in inventory
    assert "Public proof publication and verification surface" in inventory
    assert "IMPLEMENTED_DORMANT" in inventory
    assert "MISSING" in inventory
    assert "PR6.15" in inventory
