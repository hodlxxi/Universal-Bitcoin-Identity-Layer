"""Real-key login must not preserve stale guest labels."""

from pathlib import Path


def test_legacy_verify_signature_clears_guest_label():
    text = Path("app/blueprints/auth.py").read_text(encoding="utf-8")

    assert 'session["logged_in_pubkey"] = matched_pubkey' in text
    assert 'session["access_level"] = access_level' in text
    assert 'session["login_method"] = "legacy"' in text
    assert 'session.pop("guest_label", None)' in text
    assert 'session.pop("guestLabel", None)' in text


def test_nostr_verify_clears_guest_label():
    text = Path("app/blueprints/api_auth.py").read_text(encoding="utf-8")

    assert 'get_save_and_check_balances_for_pubkey(rec["pubkey"])' in text
    assert 'access = "full" if ratio >= 1 else "limited"' in text
    assert 'session["logged_in_pubkey"] = rec["pubkey"]' in text
    assert 'session["access_level"] = access' in text
    assert 'session["login_method"] = "nostr"' in text
    assert 'session.pop("guest_label", None)' in text
    assert 'session.pop("guestLabel", None)' in text


def test_browser_presence_guest_label_is_guest_only():
    text = Path("app/browser_routes.py").read_text(encoding="utf-8")

    assert "function isGuestIdentity(pk)" in text
    assert "function isRealHexPubkey(pk)" in text

    assert "if (lbl && isGuestIdentity(pk)) return String(lbl);" in text
    assert "if (lbl && isGuestIdentity(pk)) return lbl;" in text
    assert "if (gl && my && pk === my && isGuestIdentity(my)) return gl;" in text
    assert "if (!my || !gl || !isGuestIdentity(my)) return;" in text
    assert "if (my && gl && isGuestIdentity(my)) {" in text
    assert "const isGuest = isGuestIdentity(pk);" in text


def test_browser_presence_real_e923_key_is_not_guest_by_source_contract():
    text = Path("app/browser_routes.py").read_text(encoding="utf-8")

    assert "s.startsWith('guest-')" in text
    assert "s.startsWith('guest_')" in text
    assert "s.startsWith('anon_')" in text
    assert "/^[0-9a-fA-F]{64}$/.test(s)" in text
    assert "/^(02|03)[0-9a-fA-F]{64}$/.test(s)" in text
