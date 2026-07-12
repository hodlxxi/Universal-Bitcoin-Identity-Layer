from hodlxxi_mcp.client import Endpoint


def test_exact_endpoint_inventory() -> None:
    assert len(Endpoint) == 26
    values = {endpoint.value for endpoint in Endpoint}
    assert len(values) == 26
    assert "/agent/jobs/{job_id}" not in values
    assert "/agent/readiness/self-scan" not in values
    assert "/oauthx/status" not in values
    assert "/agent/mcp" not in values
    assert "/agent/covenants/countdown.json" not in values


def test_all_endpoints_are_relative_paths_without_inline_queries() -> None:
    for endpoint in Endpoint:
        assert endpoint.value.startswith("/")
        assert "://" not in endpoint.value
        assert "?" not in endpoint.value
        assert "#" not in endpoint.value
        assert ".." not in endpoint.value
