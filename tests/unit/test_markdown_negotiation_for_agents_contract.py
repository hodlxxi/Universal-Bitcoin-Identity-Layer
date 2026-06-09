"""P54 contract: Markdown negotiation for agents."""


def test_homepage_defaults_to_html_for_browsers(client):
    response = client.get("/")

    assert response.status_code == 200
    assert response.content_type.startswith("text/html")


def test_homepage_returns_markdown_when_requested_by_agent(client):
    response = client.get("/", headers={"Accept": "text/markdown"})

    assert response.status_code == 200
    assert response.content_type.startswith("text/markdown")
    assert response.headers.get("X-Markdown-Tokens")
    body = response.get_data(as_text=True)
    assert body.startswith("# HODLXXI")
    assert "/.well-known/agent.json" in body
    assert "/.well-known/api-catalog" in body
    assert "/agent/capabilities" in body
    assert "/api/public/status" in body
    assert "sending, intake, and relay publishing remain disabled" in body


def test_markdown_homepage_preserves_agent_discovery_link_headers(client):
    response = client.get("/", headers={"Accept": "text/markdown"})

    link_header = response.headers.get("Link", "")
    assert '</.well-known/api-catalog>; rel="api-catalog"' in link_header
    assert '</.well-known/agent.json>; rel="service-desc"' in link_header
    assert '</agent/capabilities>; rel="service-desc"' in link_header
    assert '</docs>; rel="service-doc"' in link_header
    assert '</api/public/status>; rel="status"' in link_header


def test_html_wins_when_agent_prefers_html_over_markdown(client):
    response = client.get("/", headers={"Accept": "text/html;q=1.0, text/markdown;q=0.5"})

    assert response.status_code == 200
    assert response.content_type.startswith("text/html")
