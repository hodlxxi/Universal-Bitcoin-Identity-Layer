from pathlib import Path

DOCS = Path(__file__).parents[2] / "docs"


def test_registration_document_locks_dormant_boundary_and_non_claims():
    text = " ".join((DOCS / "TRUSTED_COVENANT_REGISTRATION_V1.md").read_text().split())
    required = (
        "IMPLEMENTED_DORMANT",
        "Exact registration is not Canon admission",
        "Unequal positive incoming and outgoing amounts may be registered",
        "does not repair or alter PR6.5",
        "Only `active`",
        "Lifecycle transition orchestration",
        "does not decide admission",
        "genesis record",
        "sponsor",
        "lineage",
        "CRT membership states",
        "FULL and LIMITED",
        "route, CLI, MCP",
        "scheduler",
        "production",
        "current_144",
        "legacy_777",
        "one unfunded leg",
        "grants nothing",
        "`witness_script_sha256`",
        "`SHA256(raw witness Script bytes)`",
        "`TrustedCovenantOutpoint.script_sha256`",
        "`SHA256(serialized scriptPubKey bytes)`",
        "native P2WSH",
        "does not infer arbitrary output wrappers",
        "Pair digests are required but deliberately not unique",
        "Active-edge ambiguity",
    )
    assert all(value in text for value in required)


def test_inventory_and_bridge_report_registration_as_implemented_dormant():
    inventory = (DOCS / "CRT_MEMBERSHIP_IMPLEMENTATION_STATUS.md").read_text()
    bridge = (DOCS / "CRT_RUNTIME_BRIDGE.md").read_text()
    observation = (DOCS / "TRUSTED_COVENANT_OBSERVATION_V1.md").read_text()
    assert "| PR6.8 pure registration and injected append-only storage. | IMPLEMENTED_DORMANT |" in inventory
    assert "PR6.8 provides dormant exact registration" in bridge
    assert "PR6.8 trusted registration and exact outpoint binding is IMPLEMENTED_DORMANT" in observation
    assert "no admission registry" in bridge


def test_modified_runtime_docs_state_exact_source_bases():
    names = (
        "CANONICAL_COVENANT_RELATION_V1.md",
        "CRT_COVENANT_PROFILE_V1.md",
        "CRT_MEMBERSHIP_IMPLEMENTATION_STATUS.md",
        "CRT_RUNTIME_BRIDGE.md",
        "MIRRORED_COVENANT_PAIR_V1.md",
        "README.md",
        "TRUSTED_COVENANT_OBSERVATION_V1.md",
        "TRUSTED_COVENANT_REGISTRATION_V1.md",
    )
    canon = "152c87522a7d89cd5c0e7014d7915a19bf074e1a"
    branch_base = "fe333cdb5068a73b4dc57b875e1b0223b01855f7"
    for name in names:
        text = (DOCS / name).read_text()
        assert canon in text
        assert branch_base in text
    assert "**Last Updated:** July 25, 2026" in (DOCS / "README.md").read_text()
    for name in ("CRT_MEMBERSHIP_IMPLEMENTATION_STATUS.md", "CRT_RUNTIME_BRIDGE.md", "README.md"):
        text = (DOCS / name).read_text()
        assert "7df976c59742aa84fd79cfd41f12a34a33915259" in text
        assert "active-runtime audit basis" in text
