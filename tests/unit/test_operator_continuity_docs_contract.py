from __future__ import annotations

from pathlib import Path

OPERATOR_PUBKEY = "023d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923"


def test_operator_continuity_docs_contract():
    text = Path("docs/OPERATOR_CONTINUITY_E923.md").read_text(encoding="utf-8")
    lower = text.lower()

    assert "e923" in lower
    assert OPERATOR_PUBKEY in text
    assert "declared_unfunded" in text
    assert "private keys" in lower
    assert "no secrets" in lower
    assert "rotation policy" in lower
    assert "/.well-known/hodlxxi-operator.json" in text
    assert "scripts/verify_operator_continuity.sh" in text
