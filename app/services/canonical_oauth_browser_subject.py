"""Canonical persistence and OAuth admission for verified browser identities."""

from dataclasses import dataclass
from typing import Callable

from app.auth_api_core import canonical_xonly_pubkey
from app.db_storage import create_user, get_user_by_pubkey


@dataclass(frozen=True, slots=True)
class OAuthBrowserSubject:
    subject: str


def _canonical_subject(value: object) -> str:
    if type(value) is not str:
        raise ValueError("invalid browser subject")
    canonical = canonical_xonly_pubkey(value)
    if type(canonical) is not str or canonical_xonly_pubkey(canonical) != canonical:
        raise ValueError("invalid canonical browser subject")
    return canonical


def _validated_user(user: object, canonical: str, expected_id: str | None = None) -> None:
    if type(user) is not dict:
        raise RuntimeError("canonical browser identity is unavailable")
    user_id = user.get("id")
    if (
        type(user_id) is not str
        or not user_id
        or (expected_id is not None and user_id != expected_id)
        or type(user.get("pubkey")) is not str
        or user.get("pubkey") != canonical
        or user.get("is_active") is not True
    ):
        raise RuntimeError("canonical browser identity is unavailable")


def persist_verified_browser_subject(
    verified_pubkey: object,
    *,
    create_user_fn: Callable[[str], object] | None = None,
    get_user_fn: Callable[[str], object] | None = None,
) -> str:
    """Persist and re-read one signature-verified canonical subject."""
    canonical = _canonical_subject(verified_pubkey)
    create_user_fn = create_user if create_user_fn is None else create_user_fn
    get_user_fn = get_user_by_pubkey if get_user_fn is None else get_user_fn
    user_id = create_user_fn(canonical)
    if type(user_id) is not str or not user_id:
        raise RuntimeError("canonical browser identity is unavailable")
    _validated_user(get_user_fn(canonical), canonical, user_id)
    return canonical


def resolve_oauth_browser_subject(
    logged_in_pubkey: object,
    login_method: object,
    access_level: object,
    *,
    get_user_fn: Callable[[str], object] | None = None,
) -> OAuthBrowserSubject:
    """Resolve an OAuth-admissible browser session, failing closed."""
    if type(login_method) is not str or login_method not in {"legacy", "nostr"}:
        raise ValueError("inadmissible browser session")
    if type(access_level) is not str or access_level not in {"limited", "full"}:
        raise ValueError("inadmissible browser session")
    canonical = _canonical_subject(logged_in_pubkey)
    get_user_fn = get_user_by_pubkey if get_user_fn is None else get_user_fn
    _validated_user(get_user_fn(canonical), canonical)
    return OAuthBrowserSubject(subject=canonical)
