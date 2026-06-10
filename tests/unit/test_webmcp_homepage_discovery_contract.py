from pathlib import Path


def test_webmcp_discovery_script_is_static_and_safe():
    body = Path("app/static/js/webmcp_discovery.js").read_text(encoding="utf-8")

    assert "navigator.modelContext" in body
    assert "provideContext" in body
    assert "HODLXXI_WEBMCP_TOOLS" in body
    assert "hodlxxi_get_agent_descriptor" in body
    assert "hodlxxi_get_agent_capabilities" in body
    assert "hodlxxi_get_auth_metadata" in body
    assert "hodlxxi_get_mcp_server_card" in body
    assert "hodlxxi_get_agent_skills_index" in body
    assert "inputSchema" in body
    assert "execute" in body

    forbidden = [
        "fetch(",
        "XMLHttpRequest",
        "localStorage.setItem",
        "sessionStorage.setItem",
        "send(",
        "relay_publishing",
        "intake_enabled",
    ]
    for token in forbidden:
        assert token not in body


def test_homepage_template_loads_webmcp_discovery_script():
    body = Path("app/templates/home_agent.html").read_text(encoding="utf-8")

    assert "js/webmcp_discovery.js" in body


def test_homepage_html_references_webmcp_script(client):
    response = client.get("/", headers={"Accept": "text/html"})
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "js/webmcp_discovery.js" in body


def test_webmcp_discovery_script_is_served(client):
    response = client.get("/static/js/webmcp_discovery.js")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "navigator.modelContext" in body
    assert "provideContext" in body
    assert "hodlxxi_get_agent_skills_index" in body
