"""Balance-based full access contract.

A valid login signature proves key control only. Full RPC/descriptors access
requires the existing covenant/balance relation.
"""

from pathlib import Path

AUTH = Path("app/blueprints/auth.py")
API_AUTH = Path("app/blueprints/api_auth.py")
HOME = Path("app/browser_shell_routes.py")
LEGACY = Path("app/app.py")


def test_signature_login_uses_balance_ratio_for_full_access():
    text = AUTH.read_text(encoding="utf-8")

    assert "get_save_and_check_balances_for_pubkey(matched_pubkey)" in text
    assert 'access_level = "full" if ratio >= 1 else "limited"' in text
    assert "TEMP: keep login fast" not in text

    determine_block = text[text.index("# Determine access level") : text.index("# Set session")]
    assert 'access_level = "full"\n' not in determine_block


def test_nostr_login_uses_balance_ratio_for_full_access():
    text = API_AUTH.read_text(encoding="utf-8")

    assert 'get_save_and_check_balances_for_pubkey(rec["pubkey"])' in text
    assert 'access = "full" if ratio >= 1 else "limited"' in text
    assert 'session["access_level"] = "full"' not in text
    assert 'access_level="full"' not in text


def test_home_rpc_descriptor_panel_remains_full_only():
    text = HOME.read_text(encoding="utf-8")

    assert "{% if access_level == 'full' %}" in text
    assert "RPC Full Node Section" in text
    assert "Import Covenant Descriptor" in text
    assert "Set Checking Labels" in text
    assert "Descriptors" in text


def test_legacy_monolith_still_documents_balance_based_rule():
    text = LEGACY.read_text(encoding="utf-8")

    assert "get_save_and_check_balances_for_pubkey(matched_pubkey)" in text
    assert 'session["access_level"] = "full" if ratio >= 1 else "limited"' in text
