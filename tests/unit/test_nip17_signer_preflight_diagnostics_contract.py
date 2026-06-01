"""NIP-17 signer preflight diagnostics contract.

P16 adds safe client-side diagnostics only. It must not enable sending or POST
plaintext/envelopes to the server.
"""

from pathlib import Path


def test_nip17_preflight_diagnostics_are_rendered():
    text = Path("app/browser_routes.py").read_text(encoding="utf-8")

    assert 'id="nip17SignEventSupport"' in text
    assert 'id="nip17Nip44Support"' in text
    assert 'id="nip17Nip04Support"' in text
    assert 'id="nip17PreflightReady"' in text


def test_nip17_preflight_uses_timeout_safe_get_public_key():
    text = Path("app/browser_routes.py").read_text(encoding="utf-8")

    assert "function nip17Timeout(promise, ms, label)" in text
    assert "await nip17Timeout(signer.getPublicKey(), 5000, 'getPublicKey')" in text
    assert "permission timeout" in text


def test_nip17_preflight_checks_required_signer_capabilities():
    text = Path("app/browser_routes.py").read_text(encoding="utf-8")

    assert "function getNip17SignerCapabilities(pubkey)" in text
    assert "typeof signer.signEvent === 'function'" in text
    assert "typeof signer.nip44.encrypt === 'function'" in text
    assert "typeof signer.nip44.decrypt === 'function'" in text
    assert "typeof signer.nip04.encrypt === 'function'" in text
    assert "typeof signer.nip04.decrypt === 'function'" in text
    assert "pubkeyIs64Hex" in text
    assert "ready:" in text


def test_nip17_preflight_keeps_send_disabled_and_no_post():
    text = Path("app/browser_routes.py").read_text(encoding="utf-8")

    compose_region = text[
        text.index("function initNip17ComposeCapabilityPanel()") : text.index(
            "async function refreshNip17InboxStatus()"
        )
    ]

    assert "if (sendBtn) sendBtn.disabled = true;" in compose_region
    assert "fetch('/api/messages/nip17/envelopes'" not in compose_region
    assert 'fetch("/api/messages/nip17/envelopes"' not in compose_region
    assert "NIP17_MESSAGES_ENABLED" not in compose_region
    assert "No plaintext is sent to the server" in text
