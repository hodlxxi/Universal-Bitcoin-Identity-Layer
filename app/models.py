"""
SQLAlchemy database models for HODLXXI.

Production-grade database schema for Bitcoin identity and OAuth2 operations.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.sql.expression import ColumnElement

Base = declarative_base()


def generate_uuid():
    """Generate a UUID string for primary keys."""
    return str(uuid.uuid4())


def utc_now():
    """Generate timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


class _ActionOperationUuidDefault(ColumnElement):
    inherit_cache = True


@compiles(_ActionOperationUuidDefault)
def _compile_action_operation_uuid_default(_element, _compiler, **_kwargs):
    return "(gen_random_uuid())::text"


@compiles(_ActionOperationUuidDefault, "sqlite")
def _compile_action_operation_uuid_default_sqlite(_element, _compiler, **_kwargs):
    return "''"


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


class UbidClient(Base):
    """
    Billing record for OAuth client_id PAYG usage.
    """

    __tablename__ = "ubid_clients"

    client_id = Column(String(255), primary_key=True)
    payg_enabled = Column(Boolean, default=True, nullable=False)
    sats_balance = Column(BigInteger, default=0, nullable=False)
    free_quota_remaining = Column(BigInteger, default=0, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, nullable=False)
    last_quota_reset = Column(DateTime)

    __table_args__ = (Index("idx_ubid_clients_updated", "updated_at"),)

    def __repr__(self):
        return f"<UbidClient(client_id={self.client_id}, balance={self.sats_balance})>"


class ClientPayment(Base):
    """
    Lightning invoices and credits for OAuth client billing.
    """

    __tablename__ = "payments_clients"

    invoice_id = Column(String(255), primary_key=True)
    client_id = Column(String(255), ForeignKey("ubid_clients.client_id"), nullable=False)
    payment_request = Column(Text)
    amount_sats = Column(BigInteger, nullable=False, default=0)
    status = Column(String(32), default="pending")
    created_at = Column(DateTime, default=utc_now, nullable=False)
    paid_at = Column(DateTime)
    credited = Column(Boolean, default=False)

    __table_args__ = (Index("idx_payments_clients_client", "client_id"),)

    def __repr__(self):
        return f"<ClientPayment(invoice_id={self.invoice_id}, client={self.client_id})>"


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


class NIP17Envelope(Base):
    """
    Opaque NIP-17/NIP-59 gift-wrap envelope storage.

    Stores encrypted relay-visible kind-1059 envelopes only. This table must
    never contain plaintext kind-14/kind-15 message bodies or user private keys.
    """

    __tablename__ = "nip17_envelopes"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    event_id = Column(String(64), unique=True, nullable=False, index=True)
    envelope_hash = Column(String(64), unique=True, nullable=False, index=True)
    wrapper_pubkey = Column(String(64), nullable=False, index=True)
    receiver_pubkey = Column(String(64), nullable=False, index=True)
    kind = Column(Integer, nullable=False, default=1059)
    event_created_at = Column(BigInteger, nullable=False)
    envelope_json = Column(JSON, nullable=False)
    source = Column(String(64), nullable=False, default="api")
    status = Column(String(32), nullable=False, default="received", index=True)
    received_at = Column(DateTime, default=utc_now, nullable=False, index=True)
    metadata_json = Column("metadata", JSON)

    __table_args__ = (
        Index("idx_nip17_receiver_received", "receiver_pubkey", "received_at"),
        Index("idx_nip17_wrapper_received", "wrapper_pubkey", "received_at"),
        Index("idx_nip17_status_received", "status", "received_at"),
    )

    def __repr__(self):
        return f"<NIP17Envelope(event_id={self.event_id[:16]}..., receiver={self.receiver_pubkey[:16]}...)>"


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


class AgentJob(Base):
    """Paid agent job state for Agent UBID MVP."""

    __tablename__ = "agent_jobs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    job_type = Column(String(64), nullable=False)
    request_json = Column(JSON, nullable=False)
    request_hash = Column(String(64), nullable=False, index=True)
    sats = Column(Integer, nullable=False)
    payment_request = Column(Text, nullable=False)
    payment_lookup_id = Column(String(255), nullable=False)
    payment_hash = Column(String(64), nullable=False, index=True)
    status = Column(String(32), nullable=False, default="invoice_pending", index=True)
    result_json = Column(JSON)
    result_hash = Column(String(64))
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)


class AgentEvent(Base):
    """Signed attestation log entries for Agent UBID MVP."""

    __tablename__ = "agent_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String(36), ForeignKey("agent_jobs.id"), nullable=False, index=True)
    event_hash = Column(String(64), nullable=False, unique=True, index=True)
    prev_event_hash = Column(String(64), index=True)
    event_json = Column(JSON, nullable=False)
    signature = Column(Text, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False, index=True)


class ActionStepUpChallenge(Base):
    """Durable, bounded state for one canonical action step-up challenge."""

    __tablename__ = "action_step_up_challenges"

    challenge_id = Column(String(64), primary_key=True)
    contract_version = Column(String(64), nullable=False)
    signature_domain = Column(String(64), nullable=False)
    actor_pubkey = Column(String(64), nullable=False, index=True)
    oauth_client_id = Column(String(256), nullable=False, index=True)
    token_jti = Column(String(128), nullable=False, index=True)
    action = Column(String(64), nullable=False)
    resource_id = Column(String(256))
    request_sha256 = Column(String(64), nullable=False)
    nonce = Column(String(64), nullable=False, unique=True)
    issued_at = Column(DateTime(timezone=True), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    consumed_at = Column(DateTime(timezone=True), index=True)

    __table_args__ = (
        CheckConstraint("length(challenge_id) = 32", name="ck_action_step_up_challenge_id_length"),
        CheckConstraint("length(actor_pubkey) = 64", name="ck_action_step_up_actor_pubkey_length"),
        CheckConstraint("length(oauth_client_id) BETWEEN 1 AND 256", name="ck_action_step_up_client_id_length"),
        CheckConstraint("length(token_jti) BETWEEN 1 AND 128", name="ck_action_step_up_token_jti_length"),
        CheckConstraint("length(action) BETWEEN 1 AND 64", name="ck_action_step_up_action_length"),
        CheckConstraint(
            "resource_id IS NULL OR length(resource_id) BETWEEN 1 AND 256", name="ck_action_step_up_resource_id_length"
        ),
        CheckConstraint("length(request_sha256) = 64", name="ck_action_step_up_request_hash_length"),
        CheckConstraint("length(nonce) = 64", name="ck_action_step_up_nonce_length"),
        CheckConstraint("issued_at < expires_at", name="ck_action_step_up_time_order"),
        CheckConstraint(
            "consumed_at IS NULL OR (consumed_at >= issued_at AND consumed_at < expires_at)",
            name="ck_action_step_up_consumed_time",
        ),
        Index("idx_action_step_up_actor_action", "actor_pubkey", "action"),
        Index("idx_action_step_up_unconsumed_expiry", "consumed_at", "expires_at"),
    )


class ActionOperation(Base):
    """Dormant durable reservation and final-receipt state for an action."""

    __tablename__ = "action_operations"

    operation_id = Column(
        String(36), primary_key=True, default=generate_uuid, server_default=_ActionOperationUuidDefault()
    )
    contract_version = Column(String(64), nullable=False)
    actor_pubkey = Column(String(64), nullable=False)
    oauth_client_id = Column(String(256), nullable=False)
    token_jti = Column(String(128), nullable=False)
    token_reference_sha256 = Column(String(64), nullable=False)
    action = Column(String(64), nullable=False)
    resource_id = Column(String(256))
    request_sha256 = Column(String(64), nullable=False)
    idempotency_key_sha256 = Column(String(64), nullable=False)
    request_fingerprint_sha256 = Column(String(64), nullable=False)
    step_up_challenge_id = Column(String(32))
    step_up_verification_sha256 = Column(String(64))
    policy_version = Column(String(64), nullable=False)
    authorization_decision_sha256 = Column(String(64), nullable=False)
    state = Column(String(32), nullable=False)
    reserved_at = Column(DateTime(timezone=True), nullable=False)
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    failure_code = Column(String(64))
    result_sha256 = Column(String(64))
    receipt_json = Column(JSON)
    receipt_sha256 = Column(String(64))
    receipt_signature = Column(Text)
    signer_public_key = Column(String(66))
    updated_at = Column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "actor_pubkey",
            "oauth_client_id",
            "idempotency_key_sha256",
            name="uq_action_operations_idempotency_namespace",
        ),
        CheckConstraint("length(operation_id) = 36", name="ck_action_operations_operation_id_length"),
        CheckConstraint("length(actor_pubkey) = 64", name="ck_action_operations_actor_pubkey_length"),
        CheckConstraint("length(oauth_client_id) BETWEEN 1 AND 256", name="ck_action_operations_client_id_length"),
        CheckConstraint("length(token_jti) BETWEEN 1 AND 128", name="ck_action_operations_token_jti_length"),
        CheckConstraint("length(action) BETWEEN 1 AND 64", name="ck_action_operations_action_length"),
        CheckConstraint(
            "resource_id IS NULL OR length(resource_id) BETWEEN 1 AND 256",
            name="ck_action_operations_resource_id_length",
        ),
        CheckConstraint("length(token_reference_sha256) = 64", name="ck_action_operations_token_reference_hash_length"),
        CheckConstraint("length(request_sha256) = 64", name="ck_action_operations_request_hash_length"),
        CheckConstraint("length(idempotency_key_sha256) = 64", name="ck_action_operations_idempotency_hash_length"),
        CheckConstraint("length(request_fingerprint_sha256) = 64", name="ck_action_operations_fingerprint_hash_length"),
        CheckConstraint(
            "length(authorization_decision_sha256) = 64", name="ck_action_operations_authorization_hash_length"
        ),
        CheckConstraint(
            "step_up_challenge_id IS NULL OR length(step_up_challenge_id) = 32",
            name="ck_action_operations_step_up_challenge_length",
        ),
        CheckConstraint(
            "step_up_verification_sha256 IS NULL OR length(step_up_verification_sha256) = 64",
            name="ck_action_operations_step_up_hash_length",
        ),
        CheckConstraint(
            "result_sha256 IS NULL OR length(result_sha256) = 64", name="ck_action_operations_result_hash_length"
        ),
        CheckConstraint(
            "receipt_sha256 IS NULL OR length(receipt_sha256) = 64", name="ck_action_operations_receipt_hash_length"
        ),
        CheckConstraint(
            "signer_public_key IS NULL OR length(signer_public_key) = 66", name="ck_action_operations_signer_key_length"
        ),
        CheckConstraint(
            "state IN ('reserved','executing','completed','failed','indeterminate')", name="ck_action_operations_state"
        ),
        CheckConstraint(
            "(step_up_challenge_id IS NULL) = (step_up_verification_sha256 IS NULL)",
            name="ck_action_operations_step_up_pair",
        ),
        CheckConstraint("started_at IS NULL OR started_at >= reserved_at", name="ck_action_operations_started_order"),
        CheckConstraint(
            "completed_at IS NULL OR (started_at IS NOT NULL AND completed_at >= started_at)",
            name="ck_action_operations_completed_order",
        ),
        CheckConstraint(
            "(state = 'reserved' AND started_at IS NULL) OR (state != 'reserved' AND started_at IS NOT NULL)",
            name="ck_action_operations_state_started_at",
        ),
        CheckConstraint(
            "state != 'completed' OR (result_sha256 IS NOT NULL AND failure_code IS NULL)",
            name="ck_action_operations_completed_result",
        ),
        CheckConstraint(
            "state != 'failed' OR (failure_code IS NOT NULL AND length(failure_code) BETWEEN 1 AND 64 AND result_sha256 IS NULL)",
            name="ck_action_operations_failed_code",
        ),
        CheckConstraint(
            "state NOT IN ('reserved','executing','indeterminate') OR (completed_at IS NULL AND failure_code IS NULL AND result_sha256 IS NULL AND receipt_json IS NULL AND receipt_sha256 IS NULL AND receipt_signature IS NULL AND signer_public_key IS NULL)",
            name="ck_action_operations_nonterminal_no_receipt",
        ),
        CheckConstraint(
            "state NOT IN ('completed','failed') OR (completed_at IS NOT NULL AND receipt_json IS NOT NULL AND receipt_sha256 IS NOT NULL AND receipt_signature IS NOT NULL AND signer_public_key IS NOT NULL)",
            name="ck_action_operations_terminal_receipt",
        ),
        CheckConstraint(
            "(receipt_json IS NULL AND receipt_sha256 IS NULL AND receipt_signature IS NULL AND signer_public_key IS NULL) OR (receipt_json IS NOT NULL AND receipt_sha256 IS NOT NULL AND receipt_signature IS NOT NULL AND signer_public_key IS NOT NULL)",
            name="ck_action_operations_receipt_all_or_none",
        ),
        Index("idx_action_operations_operation_state", "state"),
        Index("idx_action_operations_updated_at", "updated_at"),
    )
