"""Site-local encrypted NIP-17 send contract.

This is not relay publishing and not finalized NIP-59 gift-wrap generation.
It allows the authenticated browser to build an encrypted, signed, kind-1059
shaped envelope locally and POST only that opaque envelope to HODLXXI inbox
when server policy enables intake.
"""

from pathlib import Path

BROWSER_SHELL = Path("app/browser_shell_routes.py")


def _source() -> str:
    return BROWSER_SHELL.read_text(encoding="utf-8")


def test_site_local_send_builder_markers_exist():
    text = _source()

    assert "hodlxxi-site-local-v1" in text
    assert "function decodeNpubToXOnlyHex" in text
    assert "function normalizeNip17RecipientToXOnly" in text
    assert "function buildHodlxxiSiteLocalEnvelope" in text
    assert "function postHodlxxiSiteLocalEnvelope" in text


def test_site_local_send_uses_browser_signer_and_nip44():
    text = _source()

    assert "window.nostr.getPublicKey" in text
    assert "window.nostr.nip44.encrypt" in text
    assert "window.nostr.signEvent" in text
    assert "kind: 1059" in text
    assert "['p', draft.receiver_pubkey]" in text


def test_site_local_send_policy_gates_post():
    text = _source()

    assert "function fetchNip17Policy" in text
    assert "/.well-known/nostr-dm-policy.json" in text
    assert "!policy.enabled || !policy.intake_enabled" in text
    assert "No POST was made." in text


def test_site_local_send_posts_only_envelope_object():
    text = _source()

    assert "fetch('/api/messages/nip17/envelopes'" in text
    assert "body: JSON.stringify({envelope})" in text
    assert "plaintext_sent_to_server: false" in text
    assert "No plaintext fallback is allowed." in text


def test_site_local_send_does_not_claim_relay_or_key_custody():
    text = _source()

    assert "relay_publishing: false" in text
    assert "server_decrypts: false" in text
    assert "key_custody: false" in text
    assert "No relay publish was attempted." in text
