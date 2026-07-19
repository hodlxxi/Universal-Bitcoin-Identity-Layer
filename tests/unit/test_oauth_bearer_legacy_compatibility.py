from datetime import datetime, timedelta
import uuid

from app.database import session_scope
from app.db_storage import create_user, get_oauth_token, store_oauth_client, store_oauth_token
from app.models import OAuthToken, User


def _legacy(token="opaque-token", *, metadata=None):
    user_id = create_user("a" * 64)
    suffix = uuid.uuid4().hex
    client_id = f"legacy-client-{suffix}"
    token_id = f"legacy-id-{suffix}"
    if token == "opaque-token":
        token = f"opaque-token-{suffix}"
    store_oauth_client(
        client_id,
        {
            "client_secret": "secret",
            "client_name": "Legacy",
            "redirect_uris": ["https://example.test/cb"],
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "scope": "read_limited",
        },
    )
    store_oauth_token(
        token_id,
        {
            "access_token": token,
            "client_id": client_id,
            "user_id": user_id,
            "scope": "read_limited",
            "access_token_expires_at": (datetime.utcnow() + timedelta(hours=1)).isoformat(),
            "metadata": metadata,
        },
    )
    return user_id, token_id, token


def test_valid_non_jwt_opaque_token_remains_supported():
    _, _, token = _legacy()
    assert get_oauth_token(token)["scope"] == "read_limited"


def test_jwt_looking_input_never_falls_back():
    _legacy("abc.def.ghi")
    assert get_oauth_token("abc.def.ghi") is None


def test_canonical_metadata_and_digest_records_are_rejected():
    digest = "d" * 64
    _legacy(digest, metadata={"token_contract": "hodlxxi.oauth.access-token.v1"})
    assert get_oauth_token(digest) is None


def test_expired_revoked_missing_and_inactive_users_fail_closed():
    user_id, token_id, token = _legacy()
    with session_scope() as db:
        db.query(OAuthToken).filter_by(id=token_id).update({"is_revoked": True})
    assert get_oauth_token(token) is None
    with session_scope() as db:
        db.query(OAuthToken).filter_by(id=token_id).update({"is_revoked": False})
        db.query(User).filter_by(id=user_id).update({"is_active": False})
    assert get_oauth_token(token) is None
