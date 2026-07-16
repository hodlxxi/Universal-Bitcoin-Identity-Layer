from pathlib import Path

DOC = Path("docs/MCP_CLIENT_VALIDATION.md")


def test_mcp_client_validation_latest_is_011_not_010():
    text = DOC.read_text()
    current = text.split("## Historical external production validation: 0.1.0", 1)[0]
    assert "Current external production validation: 0.1.1" in current
    assert "Version: `0.1.1`" in current
    assert "Registry version `0.1.1` is active and `isLatest=true`" in current
    assert "not the latest externally validated production version" in current
    assert "not the Registry-latest version" in current
    assert "Package/server version: `hodlxxi-mcp` `0.1.0`" not in current
    assert "Published Registry version: `0.1.0`" not in current


def test_mcp_client_validation_preserves_010_as_historical_evidence():
    text = DOC.read_text()
    assert "## Historical external production validation: 0.1.0" in text
    historical = text.split("## Historical external production validation: 0.1.0", 1)[1]
    assert "Package/server version: `hodlxxi-mcp` `0.1.0`" in historical
    assert "Published Registry version: `0.1.0`" in historical
