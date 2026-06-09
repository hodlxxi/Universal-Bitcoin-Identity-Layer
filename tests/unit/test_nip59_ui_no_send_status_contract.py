"""P49 contract: /app exposes NIP-59 no-send UI status."""

from pathlib import Path

BROWSER_ROUTES = Path("app/browser_routes.py")


def test_chat_ui_exposes_nip59_no_send_status_fields():
    text = BROWSER_ROUTES.read_text(encoding="utf-8")

    assert "nip59BundleStatus" in text
    assert "nip59SendStatus" in text
    assert "nip59PostStatus" in text
    assert "nip59RelayStatus" in text
    assert "NIP-59 send:" in text
    assert "NIP-59 POST:" in text
    assert "NIP-59 relay:" in text


def test_chat_ui_marks_nip59_send_post_relay_as_disabled():
    text = BROWSER_ROUTES.read_text(encoding="utf-8")

    assert "client.sendEnabled === false ? 'disabled' : 'unexpected-enabled'" in text
    assert "client.canPostEnvelope === false ? 'disabled' : 'unexpected-enabled'" in text
    assert "client.relayPublishing === false ? 'disabled' : 'unexpected-enabled'" in text


def test_chat_ui_loads_nip59_bundle_without_delivery_endpoint():
    text = BROWSER_ROUTES.read_text(encoding="utf-8")

    assert "/static/js/nip59_client_bundle.js" in text
    assert "window.HODLXXI_NIP59_CLIENT" in text
    assert "socket.emit('chat:send'" in text
    assert "socket.emit('chat:send', { text, client_id: clientId })" in text
    assert "socket.emit('chat:send', { text, client_id: clientId, nip59" not in text
