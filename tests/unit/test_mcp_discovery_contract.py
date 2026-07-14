import json
import sys
from pathlib import Path

from app.services.mcp_discovery import MCP_TOOL_COUNT

MCP_PACKAGE_SRC = Path(__file__).resolve().parents[2] / "packages" / "hodlxxi_mcp" / "src"
if str(MCP_PACKAGE_SRC) not in sys.path:
    sys.path.insert(0, str(MCP_PACKAGE_SRC))


def _assert_contract(mcp, *, enabled):
    assert mcp == {
        "server_card": "/.well-known/mcp.json",
        "endpoint": "/agent/mcp",
        "transport": "streamable_http",
        "protocol_version": "2025-11-25",
        "server_name": "HODLXXI Read-Only",
        "server_version": "0.1.1",
        "tool_count": 26,
        "enabled": enabled,
        "access_mode": "public_read_only",
        "authentication": {"type": "none"},
        "writes_enabled": False,
        "payments_enabled": False,
    }


def test_mcp_gate_defaults_false(client, monkeypatch):
    monkeypatch.delenv("HODLXXI_MCP_PUBLIC_ENABLED", raising=False)
    data = client.get("/.well-known/mcp.json").get_json()
    assert data["enabled"] is False
    assert data["availability"] == "disabled"
    assert data["status"].endswith("/api/public/status")


def test_mcp_gate_explicit_true_values_enable_metadata(client, monkeypatch):
    for value in ["true", "1", "yes", "on"]:
        monkeypatch.setenv("HODLXXI_MCP_PUBLIC_ENABLED", value)
        data = client.get("/.well-known/mcp.json").get_json()
        assert data["enabled"] is True
        assert data["availability"] == "available"
        assert data["status"].endswith("/api/public/status")


def test_mcp_gate_false_empty_and_malformed_values_remain_disabled(client, monkeypatch):
    for value in ["false", "0", "no", "", "definitely"]:
        monkeypatch.setenv("HODLXXI_MCP_PUBLIC_ENABLED", value)
        data = client.get("/.well-known/mcp.json").get_json()
        assert data["enabled"] is False
        assert data["availability"] == "disabled"


def test_all_mcp_server_card_aliases_are_semantically_identical(client):
    paths = ["/.well-known/mcp.json", "/.well-known/mcp/server-card.json", "/.well-known/mcp/server-cards.json"]
    documents = [client.get(path).get_json() for path in paths]
    assert documents[0] == documents[1] == documents[2]


def test_mcp_server_card_truthful_sidecar_contract(client):
    data = client.get("/.well-known/mcp.json").get_json()
    assert data["name"] == "HODLXXI Read-Only"
    assert data["serverInfo"] == {"name": "HODLXXI Read-Only", "version": "0.1.1"}
    assert data["version"] == "0.1.1"
    assert data["protocolVersion"] == "2025-11-25"
    assert data["endpoint"].endswith("/agent/mcp")
    assert data["transport"]["type"] == "streamable_http"
    assert data["tool_count"] == 26
    assert data["capabilities"]["tools"]["count"] == 26
    assert data["authentication"] == {"type": "none"}
    assert data["access_mode"] == "public_read_only"
    assert data["writes_enabled"] is False
    assert data["payments_enabled"] is False
    assert data["boundary"]["monolith_executes_tools"] is False
    assert data["documentation"].endswith("/docs")
    assert data["status"].endswith("/api/public/status")
    assert "oauth2" not in json.dumps(data).lower()
    assert "localhost" not in json.dumps(data).lower()
    assert "127.0.0.1" not in json.dumps(data).lower()


def test_agent_json_and_capabilities_expose_same_mcp_contract(client, monkeypatch):
    monkeypatch.setenv("HODLXXI_MCP_PUBLIC_ENABLED", "true")
    agent = client.get("/.well-known/agent.json").get_json()
    capabilities = client.get("/agent/capabilities").get_json()
    _assert_contract(agent["mcp"], enabled=True)
    _assert_contract(capabilities["mcp"], enabled=True)
    assert agent["mcp"] == capabilities["mcp"]
    assert agent["endpoints"]["capabilities"] == "/agent/capabilities"
    assert agent["endpoints"]["mcp"] == "/agent/mcp"
    assert agent["endpoints"]["mcp_server_card"] == "/.well-known/mcp.json"
    assert capabilities["endpoints"]["mcp"] == "/agent/mcp"
    assert capabilities["endpoints"]["mcp_server_card"] == "/.well-known/mcp.json"
    assert capabilities["service_name"] == "HODLXXI Agent UBID"


def test_direct_flask_mcp_post_remains_fail_closed(client):
    response = client.post("/agent/mcp", json={"jsonrpc": "2.0"})
    data = response.get_json()
    assert response.status_code == 501
    assert data["enabled"] is False
    assert data["error"] == "not_implemented"
    assert "monolith does not execute MCP tools" in data["error_description"]


def test_mcp_tool_count_matches_standalone_package_inventory():
    from hodlxxi_mcp.tools import TOOL_NAMES

    assert MCP_TOOL_COUNT == len(TOOL_NAMES)


def test_current_package_descriptions_do_not_call_public_mcp_a_disabled_stub():
    current_text = "\n".join(
        [
            Path("packages/hodlxxi_mcp/README.md").read_text(),
            Path("packages/hodlxxi_mcp/src/hodlxxi_mcp/server.py").read_text(),
            Path("packages/hodlxxi_mcp/src/hodlxxi_mcp/tools.py").read_text(),
        ]
    ).lower()
    assert "disabled production stub" not in current_text
    assert "no live /agent/mcp integration" not in current_text


def test_readme_examples_use_real_tool_names():
    from hodlxxi_mcp.tools import TOOL_NAMES

    readme = Path("packages/hodlxxi_mcp/README.md").read_text()
    assert "hodlxxi_get_job_receipt" not in readme
    assert "hodlxxi_get_verify_job" not in readme
    assert "hodlxxi_get_receipt" in TOOL_NAMES
    assert "hodlxxi_verify_receipt" in TOOL_NAMES
    assert "hodlxxi_get_receipt" in readme
    assert "hodlxxi_verify_receipt" in readme
