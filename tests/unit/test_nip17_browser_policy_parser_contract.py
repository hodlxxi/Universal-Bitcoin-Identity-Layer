"""NIP-17 browser policy parser contract.

The public policy endpoint returns a nested shape:

    {"nip17": {"enabled": true, "intake_enabled": true}}

The browser send path must read that nested object instead of only checking
top-level enabled/intake_enabled fields.
"""

from pathlib import Path

BROWSER_SHELL = Path("app/browser_shell_routes.py")


def _source() -> str:
    return BROWSER_SHELL.read_text(encoding="utf-8")


def test_browser_policy_parser_reads_nested_nip17_policy():
    text = _source()

    assert "async function fetchNip17Policy" in text
    assert "payload.nip17" in text
    assert "const nip17 =" in text
    assert "enabled: !!nip17.enabled" in text
    assert "intake_enabled: !!nip17.intake_enabled" in text
    assert "relay_publishing: !!nip17.relay_publishing" in text


def test_browser_send_policy_gate_uses_normalized_policy():
    text = _source()

    assert "!policy.enabled || !policy.intake_enabled" in text
    assert "encrypted site-local intake is disabled by server policy" in text
    assert "No POST was made." in text


def test_browser_policy_parser_preserves_raw_policy_for_operator_debugging():
    text = _source()

    assert "raw: payload" in text
    assert "JSON.stringify(policy.raw || policy, null, 2)" in text
