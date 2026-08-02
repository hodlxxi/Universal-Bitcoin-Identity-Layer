from pathlib import Path

from app.services.trusted_crt_authorization_source_plan import EXPLICIT_NON_CLAIMS, STATUS


def test_documentation_pins_status_nonclaims_and_snapshot_boundary():
    text = Path("docs/TRUSTED_CRT_AUTHORIZATION_SOURCE_PLAN_V1.md").read_text()
    assert all(value in text for value in STATUS)
    assert all(value in text for value in EXPLICIT_NON_CLAIMS)
    assert len(EXPLICIT_NON_CLAIMS) == 31
    assert "block height" in text and "best-block hash" in text and "observation window" in text
    assert "PR6.16 is pure proof composition" in text
    assert "PR6.17 only loads and consistency-checks" in text
