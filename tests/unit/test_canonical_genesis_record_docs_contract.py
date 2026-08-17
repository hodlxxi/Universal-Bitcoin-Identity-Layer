from pathlib import Path


def test_primary_and_inventory_docs_state_exact_dormant_boundary():
    primary = Path("docs/CANONICAL_E923_GENESIS_RECORD_V1.md").read_text()
    inventory = Path("docs/CRT_MEMBERSHIP_IMPLEMENTATION_STATUS.md").read_text()
    bridge = Path("docs/CRT_RUNTIME_BRIDGE.md").read_text()
    for value in (
        "Status: IMPLEMENTED_DORMANT",
        "docs/data/e923_canonical_genesis_record_v1.json",
        "hodlxxi.crt_membership_graph.v1",
        "023d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923",
        "legacy_777",
        "1777777",
        "777",
        "genesis_active",
        "not FULL",
        "has not been applied",
        "No production behavior changes",
        "df0445177ad8e913ef18dbf4670e8f8bc7a23f8adb14b9d87d4425dc3c5b1339",
        "fea957f51ad9a8c1962afa56f1e3da07ed533cc80368f9fd720fa52bede78b46",
        "self_canonical_digest_externally_pinned",
        "2026-07-26T07:12:51Z",
    ):
        assert value in primary
    assert "Canonical genesis record" in inventory
    assert "IMPLEMENTED_DORMANT" in inventory
    assert "sponsor/admission registry" not in primary
    assert "succession authority is unavailable" in primary
    assert "No production wiring" in bridge
