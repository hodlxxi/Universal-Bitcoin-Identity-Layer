"""Deprecated compatibility shim.

Runtime ownership now lives in app.factory:create_app.
This module remains only for compatibility with older imports and legacy auth helper tests.
"""

from app.factory import create_app
from app.legacy_auth import (
    ACTIVE_CHALLENGES,
    NOSTR_LOGIN_MAX_AGE_SECONDS,
    NOSTR_LOGIN_MAX_FUTURE_SKEW_SECONDS,
    _finish_login,
    _nostr_event_id,
    api_verify,
    api_whoami,
    get_rpc_connection,
    get_save_and_check_balances_for_pubkey,
    mint_access_token,
    special_login,
    verify_nostr_login_event,
)

app = create_app()

__all__ = [
    "ACTIVE_CHALLENGES",
    "NOSTR_LOGIN_MAX_AGE_SECONDS",
    "NOSTR_LOGIN_MAX_FUTURE_SKEW_SECONDS",
    "_finish_login",
    "_nostr_event_id",
    "api_verify",
    "api_whoami",
    "app",
    "create_app",
    "get_rpc_connection",
    "get_save_and_check_balances_for_pubkey",
    "mint_access_token",
    "special_login",
    "verify_nostr_login_event",
]
