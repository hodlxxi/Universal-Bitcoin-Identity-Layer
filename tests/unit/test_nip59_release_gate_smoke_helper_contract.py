"""NIP-59 release gate smoke helper contract.

P39 wires the local/CI release helper to run the NIP-59 release gate before the
factory route release gate. It still does not call live staging/production.
"""

from pathlib import Path

SCRIPT = Path("scripts/release_gate_smoke_check.sh")
DOC = Path("docs/ops/RELEASE_GATE_SMOKE_MANUAL.md")


def test_release_gate_smoke_helper_runs_nip59_gate_before_route_gate():
    text = SCRIPT.read_text(encoding="utf-8")

    assert "python scripts/verify_nip59_release_gate.py" in text
    assert "python -m pytest -q tests/unit/test_release_gate_route_contract.py" in text
    assert text.index("python scripts/verify_nip59_release_gate.py") < text.index(
        "python -m pytest -q tests/unit/test_release_gate_route_contract.py"
    )


def test_release_gate_smoke_helper_remains_local_only():
    text = SCRIPT.read_text(encoding="utf-8")

    assert "Does not call staging/production endpoints." in text
    assert "curl" not in text
    assert "https://hodlxxi.com" not in text
    assert "https://staging.hodlxxi.com" not in text


def test_release_gate_manual_doc_mentions_local_ci_helper_and_nip59_gate():
    text = DOC.read_text(encoding="utf-8")

    assert "Local/CI release helper" in text
    assert "bash scripts/release_gate_smoke_check.sh" in text
    assert "python scripts/verify_nip59_release_gate.py" in text
    assert "test_release_gate_route_contract.py" in text
    assert "does **not** call staging or production endpoints" in text
