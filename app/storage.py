"""In-memory storage backend for tests and local development.

This module provides a minimal storage layer that mirrors the interface of
``app.db_storage`` but keeps everything in Python dictionaries.  The unit and
integration tests rely on this module to avoid the need for external services
like PostgreSQL or Redis.
"""

from __future__ import annotations

import copy
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

# Public storage dictionary used by the test-suite fixtures.  The individual
# buckets are populated by ``init_storage``.
STORAGE: Dict[str, Dict[str, Dict[str, Any]]] = {}


def init_storage() -> None:
    """Initialise the in-memory storage buckets.

    The tests call this during setup to ensure a clean state.  Re-initialising
    recreates the bucket dictionaries but leaves the ``STORAGE`` object itself
    in place so references held by fixtures remain valid.
    """

    buckets = {
        "oauth_clients": {},
        "oauth_codes": {},
        "oauth_tokens": {},
        "sessions": {},
        "lnurl_challenges": {},
        "pof_challenges": {},
        "refresh_tokens": {},
        "generic_storage": {},
    }

    STORAGE.update(buckets)
    # Remove any buckets that might have existed previously but are no longer
    # defined.  This keeps the storage structure predictable between tests.
    for key in list(STORAGE.keys()):
        if key not in buckets:
            STORAGE.pop(key)


def _get_bucket(name: str) -> Dict[str, Dict[str, Any]]:
    if name not in STORAGE:
        init_storage()
    return STORAGE[name]


def _store_value(bucket_name: str, key: str, value: Any, ttl: Optional[int] = None) -> None:
    bucket = _get_bucket(bucket_name)
    expires_at: Optional[datetime] = None
    if ttl:
        expires_at = datetime.utcnow() + timedelta(seconds=ttl)

    bucket[key] = {
        "value": copy.deepcopy(value),
        "expires_at": expires_at,
    }


def _get_value(bucket_name: str, key: str) -> Optional[Any]:
    bucket = _get_bucket(bucket_name)
    entry = bucket.get(key)
    if not entry:
        return None

    expires_at = entry.get("expires_at")
    if isinstance(expires_at, datetime) and expires_at < datetime.utcnow():
        bucket.pop(key, None)
        return None

    return copy.deepcopy(entry.get("value"))


def _delete_value(bucket_name: str, key: str) -> None:
    bucket = _get_bucket(bucket_name)
    bucket.pop(key, None)


def store_oauth_client(client_id: str, client_data: Dict[str, Any]) -> None:
    _store_value("oauth_clients", client_id, client_data)


def get_oauth_client(client_id: str) -> Optional[Dict[str, Any]]:
    return _get_value("oauth_clients", client_id)


def store_oauth_code(code: str, code_data: Dict[str, Any], ttl: Optional[int] = None) -> None:
    _store_value("oauth_codes", code, code_data, ttl)


def get_oauth_code(code: str) -> Optional[Dict[str, Any]]:
    return _get_value("oauth_codes", code)


def delete_oauth_code(code: str) -> None:
    _delete_value("oauth_codes", code)


def store_session(session_id: str, session_data: Dict[str, Any], ttl: Optional[int] = None) -> None:
    _store_value("sessions", session_id, session_data, ttl)


def get_session(session_id: str) -> Optional[Dict[str, Any]]:
    return _get_value("sessions", session_id)


def delete_session(session_id: str) -> None:
    _delete_value("sessions", session_id)


def store_lnurl_challenge(session_id: str, challenge_data: Dict[str, Any], ttl: Optional[int] = None) -> None:
    _store_value("lnurl_challenges", session_id, challenge_data, ttl)


def get_lnurl_challenge(session_id: str) -> Optional[Dict[str, Any]]:
    return _get_value("lnurl_challenges", session_id)


def generic_store(key: str, value: Any, ttl: Optional[int] = None) -> None:
    _store_value("generic_storage", key, value, ttl)


def generic_get(key: str) -> Optional[Any]:
    return _get_value("generic_storage", key)


# Ensure buckets exist on import so fixtures can use STORAGE immediately.
init_storage()
