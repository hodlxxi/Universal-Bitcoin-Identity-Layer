from pathlib import Path

DOC = Path("docs/AGENT_DELEGATION_V0.md")


def test_delegation_runtime_endpoints_are_not_registered(app):
    rules = {rule.rule for rule in app.url_map.iter_rules()}

    assert "/.well-known/agent-delegation.json" not in rules
    assert "/agent/delegations" not in rules
    assert "/agent/delegations/<delegation_id>" not in rules
    assert "/agent/policy" not in rules


def test_delegation_docs_define_qr_as_discovery_only_non_authority():
    text = DOC.read_text(encoding="utf-8").lower()

    assert "contract-only" in text
    assert "discovery-only" in text
    assert "does not grant authority" in text
    assert "does not" in text
    for term in ("consent", "approval", "delegation", "execute work", "validate a receipt", "payment", "trust"):
        assert term in text


def test_delegation_docs_forbid_raw_command_and_unlimited_authority():
    text = DOC.read_text(encoding="utf-8").lower()

    for term in (
        "raw command execution",
        "shell execution",
        "arbitrary commands",
        "wildcard authority",
        "unrestricted filesystem/network/wallet access",
        "unbounded spend authority",
    ):
        assert term in text
