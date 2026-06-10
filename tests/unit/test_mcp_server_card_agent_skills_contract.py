import hashlib


def _path_from_url(url: str) -> str:
    if ".com" in url:
        return url.split(".com", 1)[-1]
    if ":5000" in url:
        return url.split(":5000", 1)[-1]
    return url


def test_mcp_server_card_is_available(client):
    for path in [
        "/.well-known/mcp/server-card.json",
        "/.well-known/mcp/server-cards.json",
        "/.well-known/mcp.json",
    ]:
        response = client.get(path)
        data = response.get_json()

        assert response.status_code == 200
        assert response.content_type.startswith("application/json")
        assert data["serverInfo"]["name"] == "HODLXXI"
        assert data["serverInfo"]["version"]
        assert data["endpoint"].endswith("/agent/mcp")
        assert data["transport"]["endpoint"].endswith("/agent/mcp")
        assert data["transports"][0]["endpoint"].endswith("/agent/mcp")
        assert "capabilities" in data
        assert data["authentication"]["type"] == "oauth2"


def test_mcp_transport_endpoint_is_safe_disabled_stub(client):
    response = client.post("/agent/mcp", json={})
    data = response.get_json()

    assert response.status_code == 501
    assert response.content_type.startswith("application/json")
    assert data["error"] == "not_implemented"
    assert data["enabled"] is False


def test_agent_skills_index_is_available_with_sha256_digests(client):
    response = client.get("/.well-known/agent-skills/index.json")
    data = response.get_json()

    assert response.status_code == 200
    assert response.content_type.startswith("application/json")
    assert data["$schema"]
    assert data["version"] == "0.2.0"
    assert data["skills"]
    assert len(data["skills"]) >= 3

    for skill in data["skills"]:
        assert skill["name"]
        assert skill["type"]
        assert skill["description"]
        assert skill["url"].endswith("/SKILL.md")
        assert len(skill["sha256"]) == 64

        doc_response = client.get(_path_from_url(skill["url"]))
        body = doc_response.get_data(as_text=True)

        assert doc_response.status_code == 200
        assert doc_response.content_type.startswith("text/markdown")
        assert hashlib.sha256(body.encode("utf-8")).hexdigest() == skill["sha256"]


def test_unknown_agent_skill_document_returns_404(client):
    response = client.get("/.well-known/agent-skills/unknown/SKILL.md")

    assert response.status_code == 404
    assert response.content_type.startswith("application/json")
