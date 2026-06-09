"""P53 contract: agent discovery Link headers and API catalog."""

import json


def test_homepage_advertises_agent_discovery_link_headers(client):
    response = client.get("/")

    assert response.status_code in {200, 302}
    link_header = response.headers.get("Link", "")
    assert '</.well-known/api-catalog>; rel="api-catalog"' in link_header
    assert '</.well-known/agent.json>; rel="service-desc"' in link_header
    assert '</agent/capabilities>; rel="service-desc"' in link_header
    assert '</docs>; rel="service-doc"' in link_header
    assert '</api/public/status>; rel="status"' in link_header


def test_robots_txt_declares_content_signals(client):
    response = client.get("/robots.txt")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert response.content_type.startswith("text/plain")
    assert "Content-Signal: ai-train=no, search=yes, ai-input=no" in body


def test_api_catalog_is_available_as_linkset_json(client):
    response = client.get("/.well-known/api-catalog")

    assert response.status_code == 200
    assert response.content_type.startswith("application/linkset+json")
    data = json.loads(response.get_data(as_text=True))
    assert "linkset" in data
    assert isinstance(data["linkset"], list)

    serialized = json.dumps(data, sort_keys=True)
    assert "https://hodlxxi.com/agent/capabilities" in serialized
    assert "https://hodlxxi.com/agent/capabilities/schema" in serialized
    assert "https://hodlxxi.com/.well-known/agent.json" in serialized
    assert "https://hodlxxi.com/api/public/status" in serialized
    assert "service-desc" in serialized
    assert "service-doc" in serialized
    assert "status" in serialized
