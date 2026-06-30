from pathlib import Path

DOC = Path("docs/QR_POINTER_V0.md")


def test_qr_pointer_v0_docs_define_discovery_only_non_authority_boundary():
    text = DOC.read_text(encoding="utf-8").lower()

    assert "discovery-only descriptor" in text
    assert "not" in text
    for term in (
        "identity",
        "human identity",
        "consent",
        "approval",
        "delegation",
        "authorization",
        "execution authority",
        "receipt validity by itself",
        "payment",
        "trust",
        "reputation",
        "human presence",
        "operator approval",
    ):
        assert term in text


def test_qr_pointer_v0_docs_keep_runtime_future_surfaces_closed():
    text = DOC.read_text(encoding="utf-8").lower()

    assert "does **not** expose `get /qr/<token>`" in text
    assert "not a bearer token" in text
    assert "not a route registration" in text
    assert "external urls are rejected" in text
    assert "`/agent/request` is not a default qr target" in text
    assert "delegation and policy targets remain disallowed" in text
