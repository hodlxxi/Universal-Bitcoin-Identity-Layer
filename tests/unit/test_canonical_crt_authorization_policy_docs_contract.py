from pathlib import Path


def test_primary_policy_document_is_published_and_dormant():
    primary = Path("docs/CANONICAL_CRT_AUTHORIZATION_POLICY_V1.md").read_text()
    index = Path("docs/README.md").read_text()
    status = Path("docs/CRT_MEMBERSHIP_IMPLEMENTATION_STATUS.md").read_text()
    bridge = Path("docs/CRT_RUNTIME_BRIDGE.md").read_text()
    assert "PR6.13 `IMPLEMENTED_DORMANT`" in primary
    assert "CANONICAL_CRT_AUTHORIZATION_POLICY_V1.md" in index
    assert (
        "| FULL/LIMITED authorization policy mapping "
        in status
        and "| IMPLEMENTED_DORMANT |" in status
    )
    public_row = next(
        line for line in status.splitlines() if "Public why-FULL proof" in line
    )
    assert "IMPLEMENTED_SOURCE_ONLY" in public_row
    assert "NOT_DEPLOYED" in public_row
    assert "PR6.13" in bridge
    assert "implemented dormant" in bridge.lower()


def test_documented_separation_and_all_seven_states():
    text = Path("docs/CANONICAL_CRT_AUTHORIZATION_POLICY_V1.md").read_text()
    for phrase in (
        "`genesis_active`", "`active`", "`provisional`", "`edge_inactive`",
        "`lineage_inactive`", "`disputed`", "`unknown`",
        "not runtime `IdentityClass`",
        "not the older covenant-relation field",
        "No runtime wiring exists",
        "ACTIVE_LEGACY_NON_CANONICAL",
        "PR6.14",
        "not automatic action permission",
        "writes no entitlement, role, session, or scope",
    ):
        assert phrase in text
