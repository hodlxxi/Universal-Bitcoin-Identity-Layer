"""
SQLAlchemy database models for HODLXXI.

Production-grade database schema for Bitcoin identity and OAuth2 operations.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


def generate_uuid():
    """Generate a UUID string for primary keys."""
    return str(uuid.uuid4())


def utc_now():
    """Generate timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


class User(Base):
    """
    User model - Bitcoin pubkey-based identity.
    """

    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    pubkey = Column(String(66), unique=True, nullable=False, index=True)  # Bitcoin public key
    created_at = Column(DateTime, default=utc_now, nullable=False)
    last_login = Column(DateTime)
    metadata_json = Column("metadata", JSON)  # Additional user metadata
    is_active = Column(Boolean, default=True)

    # Relationships
    sessions = relationship("Session", back_populates="user", cascade="all, delete-orphan")
    oauth_tokens = relationship("OAuthToken", back_populates="user", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_user_pubkey", "pubkey"),
        Index("idx_user_created", "created_at"),
    )

    def __repr__(self):
        return f"<User(id={self.id}, pubkey={self.pubkey[:16]}...)>"


class OAuthClient(Base):
    """
    OAuth2 client registration.
    """

    __tablename__ = "oauth_clients"

    client_id = Column(String(255), primary_key=True)
    client_secret = Column(String(255), nullable=False)
    client_name = Column(String(255), nullable=False)
    redirect_uris = Column(JSON, nullable=False)  # List of allowed redirect URIs
    grant_types = Column(JSON, nullable=False)  # List of allowed grant types
    response_types = Column(JSON, nullable=False)  # List of allowed response types
    scope = Column(Text)  # Space-separated scopes
    token_endpoint_auth_method = Column(String(50), default="client_secret_basic")
    created_at = Column(DateTime, default=utc_now, nullable=False)
    metadata_json = Column("metadata", JSON)  # Additional client metadata
    is_active = Column(Boolean, default=True)

    # Relationships
    authorization_codes = relationship("OAuthCode", back_populates="client", cascade="all, delete-orphan")
    tokens = relationship("OAuthToken", back_populates="client", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_client_name", "client_name"),
        Index("idx_client_created", "created_at"),
    )

    def __repr__(self):
        return f"<OAuthClient(client_id={self.client_id}, name={self.client_name})>"


class OAuthCode(Base):
    """
    OAuth2 authorization codes (short-lived).
    """

    __tablename__ = "oauth_codes"

    code = Column(String(255), primary_key=True)
    client_id = Column(String(255), ForeignKey("oauth_clients.client_id"), nullable=False)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    redirect_uri = Column(Text, nullable=False)
    scope = Column(Text)
    code_challenge = Column(String(255))  # PKCE
    code_challenge_method = Column(String(10))  # PKCE: 'plain' or 'S256'
    created_at = Column(DateTime, default=utc_now, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    is_used = Column(Boolean, default=False)

    # Relationships
    client = relationship("OAuthClient", back_populates="authorization_codes")

    __table_args__ = (
        Index("idx_code_expires", "expires_at"),
        Index("idx_code_client", "client_id"),
    )

    def __repr__(self):
        return f"<OAuthCode(code={self.code[:16]}..., client={self.client_id})>"


class OAuthToken(Base):
    """
    OAuth2 access and refresh tokens.
    """

    __tablename__ = "oauth_tokens"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    access_token = Column(String(255), unique=True, nullable=False, index=True)
    refresh_token = Column(String(255), unique=True, index=True)
    token_type = Column(String(50), default="Bearer")
    client_id = Column(String(255), ForeignKey("oauth_clients.client_id"), nullable=False)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    scope = Column(Text)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    access_token_expires_at = Column(DateTime, nullable=False)
    refresh_token_expires_at = Column(DateTime)
    is_revoked = Column(Boolean, default=False)
    metadata_json = Column("metadata", JSON)

    # Relationships
    client = relationship("OAuthClient", back_populates="tokens")
    user = relationship("User", back_populates="oauth_tokens")

    __table_args__ = (
        Index("idx_token_access", "access_token"),
        Index("idx_token_refresh", "refresh_token"),
        Index("idx_token_expires", "access_token_expires_at"),
        Index("idx_token_user", "user_id"),
    )

    def __repr__(self):
        return f"<OAuthToken(id={self.id}, user={self.user_id})>"


class Session(Base):
    """
    User sessions for web login and LNURL-auth.
    """

    __tablename__ = "sessions"

    session_id = Column(String(255), primary_key=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    session_type = Column(String(50), default="web")  # 'web', 'lnurl-auth', 'api'
    created_at = Column(DateTime, default=utc_now, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    last_activity = Column(DateTime, default=utc_now)
    ip_address = Column(String(45))  # IPv4 or IPv6
    user_agent = Column(Text)
    metadata_json = Column("metadata", JSON)
    is_active = Column(Boolean, default=True)

    # Relationships
    user = relationship("User", back_populates="sessions")

    __table_args__ = (
        Index("idx_session_user", "user_id"),
        Index("idx_session_expires", "expires_at"),
        Index("idx_session_active", "is_active", "expires_at"),
    )

    def __repr__(self):
        return f"<Session(id={self.session_id[:16]}..., user={self.user_id})>"


class LNURLChallenge(Base):
    """
    LNURL-auth challenges (LUD-04).
    """

    __tablename__ = "lnurl_challenges"

    session_id = Column(String(255), primary_key=True)
    k1 = Column(String(64), unique=True, nullable=False, index=True)  # Challenge hex
    pubkey = Column(String(66), index=True)  # Linking key (after verification)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    verified_at = Column(DateTime)
    is_verified = Column(Boolean, default=False)
    callback_url = Column(Text)
    metadata_json = Column("metadata", JSON)

    __table_args__ = (
        Index("idx_lnurl_k1", "k1"),
        Index("idx_lnurl_expires", "expires_at"),
        Index("idx_lnurl_pubkey", "pubkey"),
    )

    def __repr__(self):
        return f"<LNURLChallenge(session={self.session_id[:16]}..., verified={self.is_verified})>"


class ProofOfFundsChallenge(Base):
    """
    Proof of Funds (PoF) challenges.
    """

    __tablename__ = "pof_challenges"

    challenge_id = Column(String(255), primary_key=True)
    pubkey = Column(String(66), nullable=False, index=True)
    challenge_message = Column(Text, nullable=False)
    threshold = Column(Float)  # Minimum BTC amount
    privacy_level = Column(String(20), default="boolean")  # 'boolean', 'threshold', 'aggregate'
    created_at = Column(DateTime, default=utc_now, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    verified_at = Column(DateTime)
    is_verified = Column(Boolean, default=False)
    proof_data = Column(JSON)  # PSBT and verification data
    result = Column(JSON)  # Verification result
    metadata_json = Column("metadata", JSON)

    __table_args__ = (
        Index("idx_pof_pubkey", "pubkey"),
        Index("idx_pof_expires", "expires_at"),
        Index("idx_pof_verified", "is_verified"),
    )

    def __repr__(self):
        return f"<PoFChallenge(id={self.challenge_id[:16]}..., verified={self.is_verified})>"


class AuditLog(Base):
    """
    Security audit log entries.
    """

    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    timestamp = Column(DateTime, default=utc_now, nullable=False, index=True)
    event_type = Column(String(50), nullable=False, index=True)  # 'auth', 'token', 'rpc', etc.
    severity = Column(String(20), default="info")  # 'info', 'warning', 'error', 'critical'
    user_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"))
    user_identifier = Column(String(255))  # Pubkey or client_id
    action = Column(String(100), nullable=False)
    resource = Column(String(255))
    ip_address = Column(String(45))
    user_agent = Column(Text)
    success = Column(Boolean, default=True)
    error_message = Column(Text)
    details = Column(JSON)  # Additional event details
    metadata_json = Column("metadata", JSON)

    __table_args__ = (
        Index("idx_audit_timestamp", "timestamp"),
        Index("idx_audit_event_type", "event_type"),
        Index("idx_audit_user", "user_id"),
        Index("idx_audit_severity", "severity", "timestamp"),
    )

    def __repr__(self):
        return f"<AuditLog(id={self.id}, type={self.event_type}, action={self.action})>"


class BitcoinWallet(Base):
    """
    Bitcoin wallet descriptors (watch-only).
    """

    __tablename__ = "bitcoin_wallets"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    wallet_name = Column(String(255))
    descriptor = Column(Text, nullable=False)  # Bitcoin descriptor
    descriptor_type = Column(String(50))  # 'wpkh', 'wsh', 'tr', etc.
    xpub = Column(String(255), index=True)
    fingerprint = Column(String(8))
    derivation_path = Column(String(100))
    created_at = Column(DateTime, default=utc_now, nullable=False)
    last_sync = Column(DateTime)
    balance = Column(Float, default=0.0)
    metadata_json = Column("metadata", JSON)
    is_active = Column(Boolean, default=True)

    __table_args__ = (
        Index("idx_wallet_user", "user_id"),
        Index("idx_wallet_xpub", "xpub"),
        UniqueConstraint("user_id", "descriptor", name="uq_user_descriptor"),
    )

    def __repr__(self):
        return f"<BitcoinWallet(id={self.id}, user={self.user_id})>"


class RateLimit(Base):
    """
    Rate limiting tracking.
    """

    __tablename__ = "rate_limits"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    identifier = Column(String(255), nullable=False, index=True)  # IP, user_id, or api_key
    endpoint = Column(String(255), nullable=False, index=True)
    window_start = Column(DateTime, nullable=False, index=True)
    request_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    __table_args__ = (
        Index("idx_ratelimit_identifier", "identifier", "endpoint", "window_start"),
        UniqueConstraint("identifier", "endpoint", "window_start", name="uq_ratelimit_window"),
    )

    def __repr__(self):
        return f"<RateLimit(identifier={self.identifier}, endpoint={self.endpoint})>"


class ChatMessage(Base):
    """
    Chat message history.
    """

    __tablename__ = "chat_messages"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    sender_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    recipient_id = Column(String(36), ForeignKey("users.id"))  # NULL for broadcast/channel
    channel = Column(String(255), index=True)  # Channel or room name
    message_type = Column(String(50), default="text")  # 'text', 'file', 'system'
    content = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=utc_now, nullable=False, index=True)
    edited_at = Column(DateTime)
    is_deleted = Column(Boolean, default=False)
    metadata_json = Column("metadata", JSON)  # Attachments, reactions, etc.

    __table_args__ = (
        Index("idx_message_sender", "sender_id", "timestamp"),
        Index("idx_message_recipient", "recipient_id", "timestamp"),
        Index("idx_message_channel", "channel", "timestamp"),
    )

    def __repr__(self):
        return f"<ChatMessage(id={self.id}, sender={self.sender_id})>"


class ProofOfFunds(Base):
    """
    Proof of Funds attestations - cryptographic verification of Bitcoin holdings.
    """

    __tablename__ = "proof_of_funds"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)

    # Verification details
    total_btc = Column(Float, nullable=False)  # Total BTC verified
    address_count = Column(Integer, nullable=False)  # Number of addresses verified
    privacy_level = Column(String(20), nullable=False, default="threshold")
    # Privacy levels: 'boolean', 'threshold', 'aggregate', 'exact'

    # Status and timing
    status = Column(String(20), nullable=False, default="pending")
    # Status: 'pending', 'verified', 'expired', 'revoked'
    verified_at = Column(DateTime, default=utc_now)
    expires_at = Column(DateTime)  # Optional expiry

    # Shareable certificate
    certificate_id = Column(String(32), unique=True, index=True)

    # Metadata
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    # Relationship
    user = relationship("User", backref="proof_of_funds")

    __table_args__ = (
        Index("idx_pof_status", "status"),
        Index("idx_pof_verified_at", "verified_at"),
    )

    def __repr__(self):
        return f"<ProofOfFunds(user_id={self.user_id}, btc={self.total_btc}, level={self.privacy_level})>"
