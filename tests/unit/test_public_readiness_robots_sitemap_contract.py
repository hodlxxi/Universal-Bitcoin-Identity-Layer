"""P52 contract: public robots.txt and sitemap.xml readiness surfaces."""


def test_public_robots_txt_is_available(client):
    response = client.get("/robots.txt")

    assert response.status_code == 200
    assert response.content_type.startswith("text/plain")
    body = response.get_data(as_text=True)
    assert "User-agent: *" in body
    assert "Allow: /" in body
    assert "Sitemap: https://hodlxxi.com/sitemap.xml" in body


def test_public_sitemap_xml_is_available(client):
    response = client.get("/sitemap.xml")

    assert response.status_code == 200
    assert response.content_type.startswith("application/xml")
    body = response.get_data(as_text=True)
    assert body.startswith("<?xml")
    assert "<urlset" in body
    assert "<loc>https://hodlxxi.com/</loc>" in body
    assert "<loc>https://hodlxxi.com/.well-known/agent.json</loc>" in body
    assert "<loc>https://hodlxxi.com/agent/capabilities</loc>" in body
    assert "<loc>https://hodlxxi.com/api/public/status</loc>" in body


def test_public_readiness_sitemap_includes_no_send_policy_surface(client):
    response = client.get("/sitemap.xml")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "<loc>https://hodlxxi.com/.well-known/nostr-dm-policy.json</loc>" in body
