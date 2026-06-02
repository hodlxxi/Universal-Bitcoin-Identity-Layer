"""NIP-59 client dependency decision contract.

P22 locks the implementation strategy before real browser-side finalization.
"""

from pathlib import Path

DOC = Path("docs/ops/NIP59_CLIENT_DEPENDENCY_DECISION.md")
BROWSER = Path("app/browser_routes.py")


def test_dependency_decision_doc_exists_and_rejects_hand_rolled_crypto():
    text = DOC.read_text(encoding="utf-8")

    assert "will not hand-roll browser-side NIP-59 finalization" in text
    assert "nostr-tools" in text
    assert "Noble" in text
    assert "Do not hand-roll" in text
    assert "Do not sign the final gift-wrap with the user's long-term Nostr signer key." in text


def test_dependency_decision_requires_pinned_local_bundle_not_cdn_crypto():
    text = DOC.read_text(encoding="utf-8")

    assert "pinned dependency versions" in text
    assert "lockfile committed" in text
    assert "documented build command" in text
    assert "generated browser bundle served from local static assets" in text
    assert "no CDN dependency for security-critical crypto" in text


def test_dependency_decision_keeps_send_and_production_intake_disabled():
    text = DOC.read_text(encoding="utf-8")

    assert "`Send sealed envelope` remains disabled" in text
    assert "production `NIP17_MESSAGES_ENABLED` remains absent/false" in text
    assert "relay publishing remains disabled" in text
    assert "plaintext is never sent to the server" in text


def test_dependency_decision_defines_finalized_gift_wrap_shape():
    text = DOC.read_text(encoding="utf-8")

    assert "`kind: 1059`" in text
    assert "64-hex `id`" in text
    assert "64-hex ephemeral wrapper `pubkey`" in text
    assert 'receiver `["p", receiver_pubkey]` tag' in text
    assert "128-hex `sig`" in text


def test_current_browser_compose_still_has_no_post_or_finalization():
    text = BROWSER.read_text(encoding="utf-8")
    region = text[
        text.index("async function buildNip17LocalEnvelopePreflight()") : text.index(
            "function initNip17ComposeCapabilityPanel()"
        )
    ]

    assert "Skeleton only" in region
    assert "Do not publish" in region
    assert "gift_wrap_id_hint" in region
    assert "fetch('/api/messages/nip17/envelopes'" not in region
    assert 'fetch("/api/messages/nip17/envelopes"' not in region
    assert "finalizeEvent" not in region
    assert "getEventHash" not in region
