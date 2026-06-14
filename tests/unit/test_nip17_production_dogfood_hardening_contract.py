"""NIP-17 production dogfood hardening contract."""

from pathlib import Path

BLUEPRINT = Path("app/blueprints/nip17_messages.py")
BROWSER_SHELL = Path("app/browser_shell_routes.py")
APP_BROWSER = Path("app/browser_routes.py")
MILESTONE = Path("docs/milestones/NIP17_SITE_LOCAL_MESSAGING_V0.md")


def test_nip17_intake_requires_authenticated_session_source_contract():
    text = BLUEPRINT.read_text(encoding="utf-8")

    assert 'logged_in_pubkey = str(session.get("logged_in_pubkey")' in text
    assert '"error": "unauthorized"' in text
    assert '"message": "login required"' in text
    assert '"authenticated": True' in text
    assert '"sender_session_pubkey_tail": logged_in_pubkey[-8:]' in text


def test_nip17_intake_has_configurable_envelope_size_limit_source_contract():
    text = BLUEPRINT.read_text(encoding="utf-8")

    assert "NIP17_MAX_ENVELOPE_BYTES" in text
    assert "def _nip17_max_envelope_bytes" in text
    assert "def _json_size_bytes" in text
    assert "envelope_too_large" in text
    assert "max_envelope_bytes" in text
    assert "413" in text


def test_post_nip17_envelope_requires_login_when_enabled(client):
    client.application.config["NIP17_MESSAGES_ENABLED"] = True

    response = client.post("/api/messages/nip17/envelopes", json={"envelope": {}})

    assert response.status_code == 401
    payload = response.get_json()
    assert payload["error"] == "unauthorized"
    assert payload["message"] == "login required"


def test_post_nip17_envelope_rejects_large_authenticated_envelope(client):
    client.application.config["NIP17_MESSAGES_ENABLED"] = True
    client.application.config["NIP17_MAX_ENVELOPE_BYTES"] = 1024

    with client.session_transaction() as sess:
        sess["logged_in_pubkey"] = "a" * 64

    response = client.post(
        "/api/messages/nip17/envelopes",
        json={"envelope": {"content": "x" * 2048}},
    )

    assert response.status_code == 413
    payload = response.get_json()
    assert payload["error"] == "envelope_too_large"
    assert payload["max_envelope_bytes"] == 1024


def test_home_messages_copy_describes_policy_gated_site_local_messaging():
    text = BROWSER_SHELL.read_text(encoding="utf-8")

    assert "site-local encrypted private messages" in text
    assert "Sending is policy-gated" in text
    assert "plaintext never leaves this browser" in text
    assert "encrypted locally before upload" in text
    assert "Sending is intentionally disabled in this release" not in text


def test_global_chat_copy_points_private_messages_to_messages_panel_without_breaking_chat():
    text = APP_BROWSER.read_text(encoding="utf-8")

    assert "Private messages · site-local encrypted" in text
    assert "Open Private Messages" in text
    assert "/home#messages" in text

    # Existing live Global Chat contract must remain intact.
    assert "socket.on('chat:history'" in text
    assert "socket.on('chat:message'" in text
    assert "socket.emit('chat:send'" in text
    assert "chatInput" in text
    assert "sendMessage" in text


def test_milestone_doc_records_completed_v0_and_deferred_relay_publication():
    text = MILESTONE.read_text(encoding="utf-8")

    assert "NIP-17 Site-Local Messaging v0" in text
    assert "production dogfood ready" in text
    assert "Server does not receive plaintext" in text
    assert "Server does not decrypt" in text
    assert "Server does not custody private keys" in text
    assert "Server does not publish to Nostr relays" in text
    assert "Envelope intake requires an authenticated session" in text
    assert "configurable max envelope size" in text
    assert "Real relay publication" in text
    assert "/app` remains the Global Chat surface" in text
