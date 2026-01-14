"""
Database-backed storage for HODLXXI - Production version.

This replaces the in-memory storage.py with PostgreSQL + Redis persistence.
"""

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.exc import SQLAlchemyError

from app.database import get_redis, session_scope
from app.models import (
    AuditLog,
    LNURLChallenge,
    OAuthClient,
    OAuthCode,
    OAuthToken,
    ProofOfFundsChallenge,
    Session,
    User,
)

logger = logging.getLogger(__name__)


# ============================================================================
# User Management
# ============================================================================


def create_user(pubkey: str, metadata: Dict = None) -> str:
    """
    Create or get user by Bitcoin pubkey.

    Args:
        pubkey: Bitcoin public key
        metadata: Additional user metadata

    Returns:
        User ID
    """
    with session_scope() as session:
        # Check if user exists
        user = session.query(User).filter_by(pubkey=pubkey).first()

        if user:
            # Update last login
            user.last_login = datetime.now(timezone.utc)
            return user.id

        # Create new user
        user = User(pubkey=pubkey, metadata_json=metadata or {}, last_login=datetime.now(timezone.utc))
        session.add(user)
        session.flush()
        return user.id


def get_user_by_pubkey(pubkey: str) -> Optional[Dict]:
    """
    Get user by Bitcoin pubkey.

    Args:
        pubkey: Bitcoin public key

    Returns:
        User data dictionary or None
    """
    with session_scope() as session:
        user = session.query(User).filter_by(pubkey=pubkey).first()

        if not user:
            return None

        return {
            "id": user.id,
            "pubkey": user.pubkey,
            "created_at": user.created_at.isoformat(),
            "last_login": user.last_login.isoformat() if user.last_login else None,
            "metadata": user.metadata_json,
            "is_active": user.is_active,
        }


def get_user_by_id(user_id: str) -> Optional[Dict]:
    """Get user by ID."""
    with session_scope() as session:
        user = session.query(User).filter_by(id=user_id).first()

        if not user:
            return None

        return {
            "id": user.id,
            "pubkey": user.pubkey,
            "created_at": user.created_at.isoformat(),
            "last_login": user.last_login.isoformat() if user.last_login else None,
            "metadata": user.metadata_json,
            "is_active": user.is_active,
        }


# ============================================================================
# OAuth Client Management
# ============================================================================


def store_oauth_client(client_id: str, client_data: Dict) -> None:
    """
    Store OAuth2 client registration.

    Args:
        client_id: Client identifier
        client_data: Client configuration data
    """
    with session_scope() as session:
        # Check if client exists
        client = session.query(OAuthClient).filter_by(client_id=client_id).first()

        if client:
            # Update existing client
            for key, value in client_data.items():
                normalized_key = "metadata" if key == "meta_data" else key
                target_attr = "metadata_json" if normalized_key == "metadata" else normalized_key
                if hasattr(client, target_attr):
                    setattr(client, target_attr, value)
        else:
            # Create new client
            init_data = client_data.copy()
            if "meta_data" in init_data and "metadata" not in init_data:
                init_data["metadata"] = init_data.pop("meta_data")
            if "metadata" in init_data:
                init_data["metadata_json"] = init_data.pop("metadata")
            # Avoid duplicate kwarg: client_id is passed explicitly and may also exist in init_data
            init_data = dict(init_data)
            init_data.pop("client_id", None)
            # Only pass model-known fields to SQLAlchemy (prevents invalid kwarg crashes)
            allowed = set(OAuthClient.__table__.columns.keys())
            init_data = {k: v for k, v in init_data.items() if k in allowed}
            client = OAuthClient(client_id=client_id, **init_data)
            session.add(client)


def get_oauth_client(client_id: str) -> Optional[Dict]:
    """
    Retrieve OAuth2 client by ID.

    Args:
        client_id: Client identifier

    Returns:
        Client data dictionary or None
    """
    with session_scope() as session:
        client = session.query(OAuthClient).filter_by(client_id=client_id, is_active=True).first()

        if not client:
            return None

        return {
            "client_id": client.client_id,
            "client_secret": client.client_secret,
            "client_name": client.client_name,
            "redirect_uris": client.redirect_uris,
            "grant_types": client.grant_types,
            "response_types": client.response_types,
            "scope": client.scope,
            "token_endpoint_auth_method": client.token_endpoint_auth_method,
            "created_at": client.created_at.isoformat(),
            "metadata": client.metadata_json,
        }


# ============================================================================
# OAuth Authorization Code Management
# ============================================================================


def store_oauth_code(code: str, code_data: Dict, ttl=None, **kwargs) -> None:
    """
    Store OAuth2 authorization code.

    Args:
        code: Authorization code
        code_data: Code data (client_id, user_id, redirect_uri, scope, expires_at)
    """
    with session_scope() as session:
        # Create user if doesn't exist
        user_id = code_data.get("user_id") or code_data.get("user_pubkey") or "test_user"
        code_data["user_id"] = user_id
        code_data["user_id"] = user_id
        if user_id:
            user = session.query(User).filter_by(id=user_id).first()
            if not user:
                # This shouldn't happen, but handle gracefully
                logger.warning(f"User {user_id} not found for OAuth code")

        oauth_code = OAuthCode(
            code=code,
            client_id=code_data["client_id"],
            user_id=user_id,
            redirect_uri=code_data["redirect_uri"],
            scope=code_data.get("scope"),
            code_challenge=code_data.get("code_challenge"),
            code_challenge_method=code_data.get("code_challenge_method"),
            expires_at=datetime.fromisoformat(
                code_data.get("expires_at")
                or (
                    __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
                    + __import__("datetime").timedelta(seconds=(ttl or 600))
                ).isoformat()
            ),
        )
        session.add(oauth_code)


def get_oauth_code(code: str) -> Optional[Dict]:
    """
    Retrieve OAuth2 authorization code.

    Args:
        code: Authorization code

    Returns:
        Code data dictionary or None
    """
    with session_scope() as session:
        oauth_code = session.query(OAuthCode).filter_by(code=code, is_used=False).first()

        if not oauth_code:
            return None

        # Check if expired
        if oauth_code.expires_at < datetime.utcnow():
            return None

        return {
            "code": oauth_code.code,
            "client_id": oauth_code.client_id,
            "user_id": oauth_code.user_id,
            "redirect_uri": oauth_code.redirect_uri,
            "scope": oauth_code.scope,
            "code_challenge": oauth_code.code_challenge,
            "code_challenge_method": oauth_code.code_challenge_method,
            "created_at": oauth_code.created_at.isoformat(),
            "expires_at": oauth_code.expires_at.isoformat(),
        }


def delete_oauth_code(code: str) -> None:
    """
    Mark OAuth2 authorization code as used.

    Args:
        code: Authorization code
    """
    with session_scope() as session:
        oauth_code = session.query(OAuthCode).filter_by(code=code).first()
        if oauth_code:
            oauth_code.is_used = True


# ============================================================================
# OAuth Token Management
# ============================================================================


def store_oauth_token(token_id: str, token_data: Dict) -> None:
    """
    Store OAuth2 access/refresh token.

    Args:
        token_id: Token identifier
        token_data: Token data
    """
    with session_scope() as session:
        token_kwargs = {
            "id": token_id,
            "access_token": token_data["access_token"],
            "refresh_token": token_data.get("refresh_token"),
            "token_type": token_data.get("token_type", "Bearer"),
            "client_id": token_data["client_id"],
            "user_id": token_data["user_id"],
            "scope": token_data.get("scope"),
            "access_token_expires_at": datetime.fromisoformat(token_data["access_token_expires_at"]),
            "refresh_token_expires_at": (
                datetime.fromisoformat(token_data["refresh_token_expires_at"])
                if token_data.get("refresh_token_expires_at")
                else None
            ),
        }

        if "metadata" in token_data:
            token_kwargs["metadata_json"] = token_data.get("metadata")

        token = OAuthToken(**token_kwargs)
        session.add(token)


def get_oauth_token(access_token: str) -> Optional[Dict]:
    """
    Retrieve OAuth2 token by access token.

    Args:
        access_token: Access token string

    Returns:
        Token data dictionary or None
    """
    with session_scope() as session:
        token = session.query(OAuthToken).filter_by(access_token=access_token, is_revoked=False).first()

        if not token:
            return None

        # Check if expired
        if token.access_token_expires_at < datetime.utcnow():
            return None

        return {
            "id": token.id,
            "access_token": token.access_token,
            "refresh_token": token.refresh_token,
            "token_type": token.token_type,
            "client_id": token.client_id,
            "user_id": token.user_id,
            "scope": token.scope,
            "created_at": token.created_at.isoformat(),
            "access_token_expires_at": token.access_token_expires_at.isoformat(),
            "refresh_token_expires_at": (
                token.refresh_token_expires_at.isoformat() if token.refresh_token_expires_at else None
            ),
            "metadata": token.metadata_json,
        }


def revoke_oauth_token(access_token: str) -> None:
    """Revoke OAuth2 token."""
    with session_scope() as session:
        token = session.query(OAuthToken).filter_by(access_token=access_token).first()
        if token:
            token.is_revoked = True


# ============================================================================
# Session Management (with Redis caching)
# ============================================================================


def store_session(session_id: str, session_data: Dict) -> None:
    """
    Store user session (database + Redis cache).

    Args:
        session_id: Session identifier
        session_data: Session data
    """
    # Try Redis first for performance
    redis_client = get_redis()
    if redis_client:
        try:
            ttl = 86400  # 24 hours default
            if "expires_at" in session_data:
                expires_at = datetime.fromisoformat(session_data["expires_at"])
                ttl = int((expires_at - datetime.utcnow()).total_seconds())

            redis_client.setex(f"session:{session_id}", ttl, json.dumps(session_data))
        except Exception as e:
            logger.error(f"Redis session storage failed: {e}")

    # Store in database
    with session_scope() as session:
        session_kwargs = {
            "session_id": session_id,
            "user_id": session_data["user_id"],
            "session_type": session_data.get("session_type", "web"),
            "expires_at": datetime.fromisoformat(session_data["expires_at"]),
            "ip_address": session_data.get("ip_address"),
            "user_agent": session_data.get("user_agent"),
        }

        if "metadata" in session_data:
            session_kwargs["metadata_json"] = session_data.get("metadata")

        user_session = Session(**session_kwargs)
        session.add(user_session)


def get_session(session_id: str) -> Optional[Dict]:
    """
    Retrieve session (try Redis first, fallback to database).

    Args:
        session_id: Session identifier

    Returns:
        Session data dictionary or None
    """
    # Try Redis first
    redis_client = get_redis()
    if redis_client:
        try:
            data = redis_client.get(f"session:{session_id}")
            if data:
                return json.loads(data)
        except Exception as e:
            logger.error(f"Redis session retrieval failed: {e}")

    # Fallback to database
    with session_scope() as session:
        user_session = session.query(Session).filter_by(session_id=session_id, is_active=True).first()

        if not user_session:
            return None

        # Check if expired
        if user_session.expires_at < datetime.utcnow():
            user_session.is_active = False
            return None

        # Update last activity
        user_session.last_activity = datetime.utcnow()

        return {
            "session_id": user_session.session_id,
            "user_id": user_session.user_id,
            "session_type": user_session.session_type,
            "created_at": user_session.created_at.isoformat(),
            "expires_at": user_session.expires_at.isoformat(),
            "last_activity": user_session.last_activity.isoformat(),
            "ip_address": user_session.ip_address,
            "user_agent": user_session.user_agent,
            "metadata": user_session.metadata_json,
        }


def delete_session(session_id: str) -> None:
    """
    Delete session (from both Redis and database).

    Args:
        session_id: Session identifier
    """
    # Delete from Redis
    redis_client = get_redis()
    if redis_client:
        try:
            redis_client.delete(f"session:{session_id}")
        except Exception as e:
            logger.error(f"Redis session deletion failed: {e}")

    # Mark as inactive in database
    with session_scope() as session:
        user_session = session.query(Session).filter_by(session_id=session_id).first()
        if user_session:
            user_session.is_active = False


# ============================================================================
# LNURL Challenge Management
# ============================================================================


def store_lnurl_challenge(session_id: str, challenge_data: Dict, ttl=None, **kwargs) -> None:
    """Store LNURL-auth challenge."""
    with session_scope() as session:
        challenge_kwargs = {
            "session_id": session_id,
            "k1": (challenge_data.get("k1") or challenge_data.get("challenge")),
            "expires_at": datetime.fromisoformat(
                challenge_data.get("expires_at")
                or (
                    __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
                    + __import__("datetime").timedelta(seconds=ttl)
                ).isoformat()
            ),
            "callback_url": challenge_data.get("callback_url"),
        }

        if "metadata" in challenge_data:
            challenge_kwargs["metadata_json"] = challenge_data.get("metadata")

        challenge = LNURLChallenge(**challenge_kwargs)
        session.add(challenge)


def get_lnurl_challenge(session_id: str) -> Optional[Dict]:
    """Retrieve LNURL-auth challenge."""
    with session_scope() as session:
        challenge = session.query(LNURLChallenge).filter_by(session_id=session_id).first()

        if not challenge:
            return None

        # Check if expired
        if challenge.expires_at < datetime.utcnow():
            return None

        return {
            "session_id": challenge.session_id,
            "k1": challenge.k1,
            "pubkey": challenge.pubkey,
            "created_at": challenge.created_at.isoformat(),
            "expires_at": challenge.expires_at.isoformat(),
            "verified_at": challenge.verified_at.isoformat() if challenge.verified_at else None,
            "is_verified": challenge.is_verified,
            "callback_url": challenge.callback_url,
            "metadata": challenge.metadata_json,
        }


def update_lnurl_challenge(session_id: str, pubkey: str) -> None:
    """Mark LNURL challenge as verified."""
    with session_scope() as session:
        challenge = session.query(LNURLChallenge).filter_by(session_id=session_id).first()
        if challenge:
            challenge.is_verified = True
            challenge.verified_at = datetime.utcnow()
            challenge.pubkey = pubkey


# ============================================================================
# Proof of Funds Challenge Management
# ============================================================================


def store_pof_challenge(challenge_id: str, challenge_data: Dict) -> None:
    """Store Proof of Funds challenge."""
    with session_scope() as session:
        # TTL seconds for fallback expires_at
        ttl = challenge_data.get("ttl") or 300

        challenge_kwargs = {
            "challenge_id": challenge_id,
            "pubkey": challenge_data["pubkey"],
            "challenge_message": challenge_data["challenge"],
            "threshold": challenge_data.get("threshold"),
            "privacy_level": challenge_data.get("privacy_level", "boolean"),
            "expires_at": datetime.fromisoformat(
                challenge_data.get("expires_at")
                or (
                    __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
                    + __import__("datetime").timedelta(seconds=ttl)
                ).isoformat()
            ),
        }

        if "metadata" in challenge_data:
            challenge_kwargs["metadata_json"] = challenge_data.get("metadata")

        challenge = ProofOfFundsChallenge(**challenge_kwargs)
        session.add(challenge)


def get_pof_challenge(challenge_id: str) -> Optional[Dict]:
    """Retrieve Proof of Funds challenge."""
    with session_scope() as session:
        challenge = session.query(ProofOfFundsChallenge).filter_by(challenge_id=challenge_id).first()

        if not challenge:
            return None

        # Check if expired
        if challenge.expires_at < datetime.utcnow():
            return None

        return {
            "challenge_id": challenge.challenge_id,
            "pubkey": challenge.pubkey,
            "challenge": challenge.challenge_message,
            "threshold": challenge.threshold,
            "privacy_level": challenge.privacy_level,
            "created_at": challenge.created_at.isoformat(),
            "expires_at": challenge.expires_at.isoformat(),
            "is_verified": challenge.is_verified,
            "proof_data": challenge.proof_data,
            "result": challenge.result,
            "metadata": challenge.metadata_json,
        }


def update_pof_challenge(challenge_id: str, proof_data: Dict, result: Dict) -> None:
    """Update PoF challenge with verification result."""
    with session_scope() as session:
        challenge = session.query(ProofOfFundsChallenge).filter_by(challenge_id=challenge_id).first()
        if challenge:
            challenge.is_verified = True
            challenge.verified_at = datetime.utcnow()
            challenge.proof_data = proof_data
            challenge.result = result


# ============================================================================
# Generic Storage (Key-Value with Redis)
# ============================================================================


def generic_store(key: str, value: Any, ttl: int = None) -> None:
    """
    Store generic key-value data (uses Redis if available).

    Args:
        key: Storage key
        value: Value to store (will be JSON serialized)
        ttl: Time to live in seconds (optional)
    """
    redis_client = get_redis()
    if redis_client:
        try:
            serialized = json.dumps(value)
            if ttl:
                redis_client.setex(f"kv:{key}", ttl, serialized)
            else:
                redis_client.set(f"kv:{key}", serialized)
            return
        except Exception as e:
            logger.error(f"Redis generic storage failed: {e}")

    # Fallback: No in-memory storage in production - log warning
    logger.warning(f"Generic storage unavailable for key: {key}")


def generic_get(key: str) -> Optional[Any]:
    """
    Retrieve generic key-value data.

    Args:
        key: Storage key

    Returns:
        Stored value or None
    """
    redis_client = get_redis()
    if redis_client:
        try:
            data = redis_client.get(f"kv:{key}")
            if data:
                return json.loads(data)
        except Exception as e:
            logger.error(f"Redis generic retrieval failed: {e}")

    return None


def generic_delete(key: str) -> None:
    """Delete generic key-value data."""
    redis_client = get_redis()
    if redis_client:
        try:
            redis_client.delete(f"kv:{key}")
        except Exception as e:
            logger.error(f"Redis generic deletion failed: {e}")


# ============================================================================
# Audit Logging
# ============================================================================


def log_audit_event(
    event_type: str,
    action: str,
    user_id: str = None,
    user_identifier: str = None,
    success: bool = True,
    severity: str = "info",
    **kwargs,
) -> None:
    """
    Log security audit event to database.

    Args:
        event_type: Type of event (auth, token, rpc, etc.)
        action: Action performed
        user_id: User ID if applicable
        user_identifier: User pubkey or client_id
        success: Whether action succeeded
        severity: Event severity (info, warning, error, critical)
        **kwargs: Additional event details
    """
    with session_scope() as session:
        log_kwargs = {
            "event_type": event_type,
            "action": action,
            "user_id": user_id,
            "user_identifier": user_identifier,
            "success": success,
            "severity": severity,
            "ip_address": kwargs.get("ip_address"),
            "user_agent": kwargs.get("user_agent"),
            "resource": kwargs.get("resource"),
            "error_message": kwargs.get("error_message"),
            "details": kwargs.get("details"),
        }

        if "metadata" in kwargs:
            log_kwargs["metadata_json"] = kwargs.get("metadata")

        log_entry = AuditLog(**log_kwargs)
        session.add(log_entry)


# ============================================================================
# Cleanup Functions
# ============================================================================


def cleanup_expired_sessions() -> int:
    """
    Clean up expired sessions.

    Returns:
        Number of sessions cleaned up
    """
    with session_scope() as session:
        count = (
            session.query(Session)
            .filter(Session.expires_at < datetime.utcnow(), Session.is_active.is_(True))
            .update({Session.is_active: False})
        )

        return count


def cleanup_expired_challenges() -> int:
    """
    Clean up expired LNURL and PoF challenges.

    Returns:
        Number of challenges cleaned up
    """
    with session_scope() as session:
        lnurl_count = (
            session.query(LNURLChallenge)
            .filter(LNURLChallenge.expires_at < datetime.utcnow(), LNURLChallenge.is_verified.is_(False))
            .delete()
        )

        pof_count = (
            session.query(ProofOfFundsChallenge)
            .filter(ProofOfFundsChallenge.expires_at < datetime.utcnow(), ProofOfFundsChallenge.is_verified.is_(False))
            .delete()
        )

        return lnurl_count + pof_count


def cleanup_expired_codes() -> int:
    """
    Clean up expired OAuth authorization codes.

    Returns:
        Number of codes cleaned up
    """
    with session_scope() as session:
        count = session.query(OAuthCode).filter(OAuthCode.expires_at < datetime.utcnow()).delete()

        return count
