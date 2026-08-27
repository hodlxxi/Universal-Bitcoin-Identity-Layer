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
    ForeignKeyConstraint,
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


class _CanonicalLowerHex(ColumnElement):
    """Dialect-safe fixed lowercase hexadecimal check expression."""

    inherit_cache = True
    type = Boolean()

    def __init__(self, column_name, length):
        self.column_name = column_name
        self.length = length


@compiles(_CanonicalLowerHex)
@compiles(_CanonicalLowerHex, "postgresql")
def _compile_canonical_lower_hex(element, compiler, **_kwargs):
    column = compiler.preparer.quote(element.column_name)
    return f"{column} ~ '^[0-9a-f]{{{element.length}}}$'"


@compiles(_CanonicalLowerHex, "sqlite")
def _compile_canonical_lower_hex_sqlite(element, compiler, **_kwargs):
    column = compiler.preparer.quote(element.column_name)
    return f"{column} REGEXP '^[0-9a-f]{{{element.length}}}$'"


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


class CurrentEntitlementEvidence(Base):
    """Append-only persisted evidence for a subject's current entitlement."""

    __tablename__ = "current_entitlement_evidence"

    evidence_id = Column(String(36), primary_key=True)
    contract_version = Column(String(64), nullable=False)
    subject_pubkey = Column(String(64), nullable=False)
    identity_class = Column(String(7), nullable=False)
    current_full_relation_satisfied = Column(Boolean, nullable=False)
    evidence_source = Column(String(128), nullable=False)
    evidence_version = Column(String(64), nullable=False)
    source_evidence_sha256 = Column(String(64), nullable=False)
    observed_at = Column(DateTime(timezone=True), nullable=False)
    valid_until = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        CheckConstraint("length(evidence_id) = 36", name="ck_current_entitlement_evidence_id_length"),
        CheckConstraint(
            "contract_version = 'hodlxxi.current_entitlement_evidence.v1'",
            name="ck_current_entitlement_contract_version",
        ),
        CheckConstraint("length(subject_pubkey) = 64", name="ck_current_entitlement_subject_length"),
        CheckConstraint("identity_class IN ('limited','full')", name="ck_current_entitlement_identity_class"),
        CheckConstraint(
            "(identity_class = 'full' AND current_full_relation_satisfied = true) OR "
            "(identity_class = 'limited' AND current_full_relation_satisfied = false)",
            name="ck_current_entitlement_identity_relation",
        ),
        CheckConstraint("length(evidence_source) BETWEEN 1 AND 128", name="ck_current_entitlement_source_length"),
        CheckConstraint("evidence_source = trim(evidence_source)", name="ck_current_entitlement_source_canonical"),
        CheckConstraint("length(evidence_version) BETWEEN 1 AND 64", name="ck_current_entitlement_version_length"),
        CheckConstraint("evidence_version = trim(evidence_version)", name="ck_current_entitlement_version_canonical"),
        CheckConstraint("length(source_evidence_sha256) = 64", name="ck_current_entitlement_hash_length"),
        CheckConstraint("observed_at < valid_until", name="ck_current_entitlement_validity_order"),
        CheckConstraint("observed_at <= created_at", name="ck_current_entitlement_created_order"),
        CheckConstraint(
            "revoked_at IS NULL OR (revoked_at >= observed_at AND revoked_at <= created_at)",
            name="ck_current_entitlement_revoked_order",
        ),
        Index("idx_current_entitlement_subject", "subject_pubkey"),
        Index("idx_current_entitlement_valid_until", "valid_until"),
        Index("idx_current_entitlement_revoked_at", "revoked_at"),
        Index("idx_current_entitlement_subject_observed", "subject_pubkey", "observed_at"),
        Index("idx_current_entitlement_subject_created", "subject_pubkey", "created_at"),
    )


class TrustedCovenantRegistration(Base):
    """Dormant append-only trusted binding for one validated mirrored pair."""

    __tablename__ = "trusted_covenant_registrations"

    registration_id = Column(String(36), primary_key=True)
    schema = Column(String(48), nullable=False)
    registration_version = Column(String(56), nullable=False)
    network = Column(String(7), nullable=False)
    pair_sha256 = Column(String(64), nullable=False)
    registration_sha256 = Column(String(64), nullable=False, unique=True)
    validator_version = Column(String(56), nullable=False)
    subject_pubkey = Column(String(66), nullable=False)
    subject_xonly_pubkey = Column(String(64), nullable=False)
    counterparty_pubkey = Column(String(66), nullable=False)
    counterparty_xonly_pubkey = Column(String(64), nullable=False)
    template_family = Column(String(25), nullable=False)
    delta_profile = Column(String(11), nullable=False)
    delta_blocks = Column(Integer, nullable=False)
    lifecycle_state = Column(String(10), nullable=False)
    registered_at = Column(DateTime(timezone=True), nullable=False)
    lifecycle_changed_at = Column(DateTime(timezone=True), nullable=False)
    superseded_by_registration_id = Column(String(36))
    earlier_leg_script_hex = Column(Text, nullable=False)
    later_leg_script_hex = Column(Text, nullable=False)

    outpoints = relationship(
        "TrustedCovenantRegisteredOutpoint",
        back_populates="registration",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    __table_args__ = (
        CheckConstraint(
            "length(registration_id) = 36 AND registration_id = lower(registration_id)",
            name="ck_trusted_registration_id_canonical",
        ),
        CheckConstraint("schema = 'hodlxxi.trusted_covenant_registration.v1'", name="ck_trusted_registration_schema"),
        CheckConstraint(
            "registration_version = 'hodlxxi.trusted_covenant_registration_service.v1'",
            name="ck_trusted_registration_version",
        ),
        CheckConstraint("network = 'bitcoin'", name="ck_trusted_registration_network"),
        CheckConstraint(
            "length(pair_sha256) = 64 AND pair_sha256 = lower(pair_sha256)", name="ck_trusted_registration_pair_hash"
        ),
        CheckConstraint(
            "length(registration_sha256) = 64 AND registration_sha256 = lower(registration_sha256)",
            name="ck_trusted_registration_hash",
        ),
        CheckConstraint(
            "validator_version = 'hodlxxi.mirrored_covenant_pair_validator.v1'",
            name="ck_trusted_registration_validator",
        ),
        CheckConstraint(
            "length(subject_pubkey) = 66 AND subject_pubkey = lower(subject_pubkey)",
            name="ck_trusted_registration_subject",
        ),
        CheckConstraint(
            "length(subject_xonly_pubkey) = 64 AND subject_xonly_pubkey = lower(subject_xonly_pubkey)",
            name="ck_trusted_registration_subject_xonly",
        ),
        CheckConstraint(
            "length(counterparty_pubkey) = 66 AND counterparty_pubkey = lower(counterparty_pubkey)",
            name="ck_trusted_registration_counterparty",
        ),
        CheckConstraint(
            "length(counterparty_xonly_pubkey) = 64 AND counterparty_xonly_pubkey = lower(counterparty_xonly_pubkey)",
            name="ck_trusted_registration_counterparty_xonly",
        ),
        CheckConstraint(
            "subject_pubkey != counterparty_pubkey AND subject_xonly_pubkey != counterparty_xonly_pubkey",
            name="ck_trusted_registration_distinct_participants",
        ),
        CheckConstraint(
            "template_family IN ('cltv_only','cooperative_2_of_2_cltv')",
            name="ck_trusted_registration_family",
        ),
        CheckConstraint(
            "(delta_profile = 'current_144' AND delta_blocks = 144) OR "
            "(delta_profile = 'legacy_777' AND delta_blocks = 777)",
            name="ck_trusted_registration_profile_delta",
        ),
        CheckConstraint(
            "lifecycle_state IN ('active','revoked','superseded','disputed')",
            name="ck_trusted_registration_lifecycle",
        ),
        CheckConstraint(
            "lifecycle_changed_at >= registered_at",
            name="ck_trusted_registration_lifecycle_time",
        ),
        CheckConstraint(
            "(lifecycle_state = 'superseded' AND superseded_by_registration_id IS NOT NULL) OR "
            "(lifecycle_state != 'superseded' AND superseded_by_registration_id IS NULL)",
            name="ck_trusted_registration_superseded_consistency",
        ),
        CheckConstraint(
            "superseded_by_registration_id IS NULL OR "
            "(length(superseded_by_registration_id) = 36 AND superseded_by_registration_id = lower(superseded_by_registration_id) "
            "AND superseded_by_registration_id != registration_id)",
            name="ck_trusted_registration_superseded_id",
        ),
        CheckConstraint(
            "length(earlier_leg_script_hex) > 0 AND length(earlier_leg_script_hex) % 2 = 0 "
            "AND earlier_leg_script_hex = lower(earlier_leg_script_hex)",
            name="ck_trusted_registration_earlier_script",
        ),
        CheckConstraint(
            "length(later_leg_script_hex) > 0 AND length(later_leg_script_hex) % 2 = 0 "
            "AND later_leg_script_hex = lower(later_leg_script_hex)",
            name="ck_trusted_registration_later_script",
        ),
        CheckConstraint(
            "earlier_leg_script_hex != later_leg_script_hex",
            name="ck_trusted_registration_distinct_scripts",
        ),
        Index("idx_trusted_registration_pair", "pair_sha256"),
        Index("idx_trusted_registration_lifecycle", "lifecycle_state"),
        Index("idx_trusted_registration_subject", "subject_xonly_pubkey"),
        Index("idx_trusted_registration_counterparty", "counterparty_xonly_pubkey"),
    )


class CanonicalRootRegistrationBindingRow(Base):
    """Dormant canonical selection binding for a graph's root subject."""

    __tablename__ = "canonical_root_registration_bindings"

    binding_id = Column(String(36), primary_key=True)
    schema = Column(String(56), nullable=False)
    binding_version = Column(String(64), nullable=False)
    graph_or_protocol_id = Column(String(64), nullable=False)
    root_x_only_public_key = Column(String(64), nullable=False)
    trusted_registration_id = Column(String(36), nullable=False)
    trusted_registration_sha256 = Column(String(64), nullable=False)
    lifecycle_state = Column(String(10), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False)
    lifecycle_changed_at = Column(DateTime(timezone=True), nullable=False)
    effective_at = Column(DateTime(timezone=True))
    superseded_by_binding_id = Column(String(36))
    canonical_binding_sha256 = Column(String(64), nullable=False, unique=True)
    canonical_record_json = Column(Text, nullable=False)

    __table_args__ = (
        CheckConstraint(
            "schema = 'hodlxxi.canonical_root_registration_binding.v1'",
            name="ck_root_registration_binding_schema",
        ),
        CheckConstraint(
            "binding_version = 'hodlxxi.canonical_root_registration_binding_service.v1'",
            name="ck_root_registration_binding_version",
        ),
        CheckConstraint(
            "length(binding_id) = 36 AND binding_id = lower(binding_id)",
            name="ck_root_registration_binding_id",
        ),
        CheckConstraint(
            "length(root_x_only_public_key) = 64 AND root_x_only_public_key = lower(root_x_only_public_key)",
            name="ck_root_registration_binding_root",
        ),
        CheckConstraint(
            "length(trusted_registration_id) = 36 AND trusted_registration_id = lower(trusted_registration_id)",
            name="ck_root_registration_binding_registration_id",
        ),
        CheckConstraint(
            "length(trusted_registration_sha256) = 64 AND trusted_registration_sha256 = lower(trusted_registration_sha256)",
            name="ck_root_registration_binding_registration_digest",
        ),
        CheckConstraint(
            "length(canonical_binding_sha256) = 64 AND canonical_binding_sha256 = lower(canonical_binding_sha256)",
            name="ck_root_registration_binding_digest",
        ),
        CheckConstraint(
            "lifecycle_state IN ('proposed','effective','disputed','superseded','revoked')",
            name="ck_root_registration_binding_lifecycle",
        ),
        CheckConstraint(
            "lifecycle_changed_at >= created_at",
            name="ck_root_registration_binding_changed_order",
        ),
        CheckConstraint(
            "(lifecycle_state = 'proposed' AND effective_at IS NULL AND superseded_by_binding_id IS NULL) OR "
            "(lifecycle_state = 'effective' AND effective_at IS NOT NULL AND effective_at >= created_at "
            "AND lifecycle_changed_at >= effective_at AND superseded_by_binding_id IS NULL) OR "
            "(lifecycle_state = 'superseded' AND effective_at IS NOT NULL AND effective_at >= created_at "
            "AND lifecycle_changed_at >= effective_at AND superseded_by_binding_id IS NOT NULL) OR "
            "(lifecycle_state IN ('disputed','revoked') AND "
            "(effective_at IS NULL OR (effective_at >= created_at AND lifecycle_changed_at >= effective_at)) "
            "AND superseded_by_binding_id IS NULL)",
            name="ck_root_registration_binding_lifecycle_consistency",
        ),
        CheckConstraint(
            "superseded_by_binding_id IS NULL OR "
            "(length(superseded_by_binding_id) = 36 AND superseded_by_binding_id = lower(superseded_by_binding_id) "
            "AND superseded_by_binding_id != binding_id)",
            name="ck_root_registration_binding_successor",
        ),
        Index("idx_root_registration_binding_graph_root", "graph_or_protocol_id", "root_x_only_public_key"),
        Index("idx_root_registration_binding_registration", "trusted_registration_id"),
        Index(
            "uq_root_registration_binding_effective_root",
            "graph_or_protocol_id",
            "root_x_only_public_key",
            unique=True,
            postgresql_where=text("lifecycle_state = 'effective'"),
            sqlite_where=text("lifecycle_state = 'effective'"),
        ),
    )


class CanonicalGenesisRecordRow(Base):
    """Dormant append-only canonical genesis record publication."""

    __tablename__ = "canonical_genesis_records"

    record_id = Column(String(36), primary_key=True)
    schema = Column(String(44), nullable=False)
    record_version = Column(String(48), nullable=False)
    graph_or_protocol_id = Column(String(64), nullable=False)
    genesis_participant_id = Column(String(4), nullable=False)
    compressed_public_key = Column(String(66), nullable=False)
    x_only_public_key = Column(String(64), nullable=False)
    lifecycle_state = Column(String(10), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False)
    lifecycle_changed_at = Column(DateTime(timezone=True), nullable=False)
    effective_at = Column(DateTime(timezone=True))
    superseded_by_record_id = Column(String(36))
    canonical_record_sha256 = Column(String(64), nullable=False, unique=True)
    canonical_record_json = Column(Text, nullable=False)

    __table_args__ = (
        CheckConstraint(
            "length(record_id) = 36 AND record_id = lower(record_id)",
            name="ck_canonical_genesis_id",
        ),
        CheckConstraint(
            "schema = 'hodlxxi.canonical_genesis_record.v1'",
            name="ck_canonical_genesis_schema",
        ),
        CheckConstraint(
            "record_version = 'hodlxxi.canonical_genesis_record_service.v1'",
            name="ck_canonical_genesis_version",
        ),
        CheckConstraint(
            "graph_or_protocol_id = 'hodlxxi.crt_membership_graph.v1'",
            name="ck_canonical_genesis_graph",
        ),
        CheckConstraint(
            "genesis_participant_id = 'E923'",
            name="ck_canonical_genesis_participant",
        ),
        CheckConstraint(
            "compressed_public_key = " "'023d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923'",
            name="ck_canonical_genesis_compressed_key",
        ),
        CheckConstraint(
            "x_only_public_key = " "'3d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923'",
            name="ck_canonical_genesis_xonly_key",
        ),
        CheckConstraint(
            "lifecycle_state IN ('proposed','effective','disputed','superseded','revoked')",
            name="ck_canonical_genesis_lifecycle",
        ),
        CheckConstraint(
            "lifecycle_changed_at >= created_at",
            name="ck_canonical_genesis_changed_order",
        ),
        CheckConstraint(
            "(lifecycle_state = 'effective' AND effective_at IS NOT NULL "
            "AND effective_at >= created_at AND lifecycle_changed_at >= effective_at "
            "AND superseded_by_record_id IS NULL) OR "
            "(lifecycle_state = 'proposed' AND effective_at IS NULL "
            "AND superseded_by_record_id IS NULL) OR "
            "(lifecycle_state = 'superseded' AND superseded_by_record_id IS NOT NULL) OR "
            "(lifecycle_state IN ('disputed','revoked') "
            "AND superseded_by_record_id IS NULL)",
            name="ck_canonical_genesis_lifecycle_consistency",
        ),
        CheckConstraint(
            "superseded_by_record_id IS NULL OR "
            "(length(superseded_by_record_id) = 36 "
            "AND superseded_by_record_id = lower(superseded_by_record_id) "
            "AND superseded_by_record_id != record_id)",
            name="ck_canonical_genesis_successor",
        ),
        CheckConstraint(
            "length(canonical_record_sha256) = 64 " "AND canonical_record_sha256 = lower(canonical_record_sha256)",
            name="ck_canonical_genesis_digest",
        ),
        Index("idx_canonical_genesis_graph", "graph_or_protocol_id"),
        Index("idx_canonical_genesis_lifecycle", "lifecycle_state"),
        Index("idx_canonical_genesis_identity", "genesis_participant_id", "x_only_public_key"),
    )


class TrustedCovenantRegisteredOutpoint(Base):
    """One subject-relative exact outpoint binding owned by a registration."""

    __tablename__ = "trusted_covenant_registered_outpoints"

    id = Column(Integer, primary_key=True, autoincrement=True)
    registration_id = Column(
        String(36),
        ForeignKey("trusted_covenant_registrations.registration_id", ondelete="CASCADE"),
        nullable=False,
    )
    direction = Column(String(8), nullable=False)
    txid = Column(String(64), nullable=False)
    vout = Column(Integer, nullable=False)
    amount_sats = Column(BigInteger, nullable=False)
    witness_script_sha256 = Column(String(64), nullable=False)
    descriptor_sha256 = Column(String(64))

    registration = relationship("TrustedCovenantRegistration", back_populates="outpoints")

    __table_args__ = (
        UniqueConstraint("registration_id", "direction", name="uq_trusted_outpoint_registration_direction"),
        UniqueConstraint("txid", "vout", name="uq_trusted_outpoint_global_identity"),
        CheckConstraint("direction IN ('incoming','outgoing')", name="ck_trusted_outpoint_direction"),
        CheckConstraint("length(txid) = 64 AND txid = lower(txid)", name="ck_trusted_outpoint_txid"),
        CheckConstraint("vout >= 0 AND vout <= 4294967295", name="ck_trusted_outpoint_vout"),
        CheckConstraint(
            "amount_sats > 0 AND amount_sats <= 2100000000000000",
            name="ck_trusted_outpoint_amount",
        ),
        CheckConstraint(
            "length(witness_script_sha256) = 64 AND witness_script_sha256 = lower(witness_script_sha256)",
            name="ck_trusted_outpoint_witness_script_hash",
        ),
        CheckConstraint(
            "descriptor_sha256 IS NULL OR "
            "(length(descriptor_sha256) = 64 AND descriptor_sha256 = lower(descriptor_sha256))",
            name="ck_trusted_outpoint_descriptor_hash",
        ),
        Index("idx_trusted_outpoint_registration", "registration_id"),
        Index("idx_trusted_outpoint_identity", "txid", "vout"),
    )


class CanonicalCovenantFundingSetRow(Base):
    """Dormant immutable recognized-funding allowlist."""

    __tablename__ = "canonical_covenant_funding_sets"
    funding_set_id = Column(String(36), primary_key=True)
    schema = Column(String(64), nullable=False)
    funding_set_version = Column(String(72), nullable=False)
    trusted_registration_id = Column(String(36), nullable=False)
    trusted_registration_sha256 = Column(String(64), nullable=False)
    pair_sha256 = Column(String(64), nullable=False)
    subject_xonly_pubkey = Column(String(64), nullable=False)
    counterparty_xonly_pubkey = Column(String(64), nullable=False)
    lifecycle_state = Column(String(10), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False)
    lifecycle_changed_at = Column(DateTime(timezone=True), nullable=False)
    effective_at = Column(DateTime(timezone=True))
    superseded_by_funding_set_id = Column(String(36))
    canonical_funding_set_sha256 = Column(String(64), nullable=False, unique=True)
    canonical_record_json = Column(Text, nullable=False)
    recognized_outpoints = relationship(
        "CanonicalCovenantFundingOutpointRow",
        back_populates="funding_set",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    __table_args__ = (
        CheckConstraint(
            "schema = 'hodlxxi.canonical_recognized_covenant_funding_set.v1'", name="ck_funding_set_schema"
        ),
        CheckConstraint(
            "funding_set_version = 'hodlxxi.canonical_recognized_covenant_funding_set_service.v1'",
            name="ck_funding_set_version",
        ),
        CheckConstraint(
            "length(funding_set_id) = 36 AND funding_set_id = lower(funding_set_id)", name="ck_funding_set_id"
        ),
        CheckConstraint(
            "length(trusted_registration_id) = 36 AND trusted_registration_id = lower(trusted_registration_id)",
            name="ck_funding_set_registration_id",
        ),
        CheckConstraint(
            "length(trusted_registration_sha256) = 64 AND length(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(trusted_registration_sha256,'0',''),'1',''),'2',''),'3',''),'4',''),'5',''),'6',''),'7',''),'8',''),'9',''),'a',''),'b',''),'c',''),'d',''),'e',''),'f','')) = 0 AND length(pair_sha256) = 64 AND length(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(pair_sha256,'0',''),'1',''),'2',''),'3',''),'4',''),'5',''),'6',''),'7',''),'8',''),'9',''),'a',''),'b',''),'c',''),'d',''),'e',''),'f','')) = 0",
            name="ck_funding_set_source_digests",
        ),
        CheckConstraint(
            "length(subject_xonly_pubkey) = 64 AND length(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(subject_xonly_pubkey,'0',''),'1',''),'2',''),'3',''),'4',''),'5',''),'6',''),'7',''),'8',''),'9',''),'a',''),'b',''),'c',''),'d',''),'e',''),'f','')) = 0 AND length(counterparty_xonly_pubkey) = 64 AND length(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(counterparty_xonly_pubkey,'0',''),'1',''),'2',''),'3',''),'4',''),'5',''),'6',''),'7',''),'8',''),'9',''),'a',''),'b',''),'c',''),'d',''),'e',''),'f','')) = 0",
            name="ck_funding_set_participants",
        ),
        CheckConstraint(
            "lifecycle_state IN ('proposed','effective','disputed','superseded','revoked')",
            name="ck_funding_set_lifecycle",
        ),
        CheckConstraint("lifecycle_changed_at >= created_at", name="ck_funding_set_changed_order"),
        CheckConstraint(
            "(lifecycle_state = 'proposed' AND effective_at IS NULL AND superseded_by_funding_set_id IS NULL) OR (lifecycle_state = 'effective' AND effective_at IS NOT NULL AND effective_at >= created_at AND lifecycle_changed_at >= effective_at AND superseded_by_funding_set_id IS NULL) OR (lifecycle_state = 'superseded' AND effective_at IS NOT NULL AND effective_at >= created_at AND lifecycle_changed_at >= effective_at AND superseded_by_funding_set_id IS NOT NULL) OR (lifecycle_state IN ('disputed','revoked') AND (effective_at IS NULL OR (effective_at >= created_at AND lifecycle_changed_at >= effective_at)) AND superseded_by_funding_set_id IS NULL)",
            name="ck_funding_set_lifecycle_consistency",
        ),
        CheckConstraint(
            "superseded_by_funding_set_id IS NULL OR (length(superseded_by_funding_set_id) = 36 AND superseded_by_funding_set_id = lower(superseded_by_funding_set_id) AND superseded_by_funding_set_id != funding_set_id)",
            name="ck_funding_set_successor",
        ),
        CheckConstraint(
            "length(canonical_funding_set_sha256) = 64 AND length(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(canonical_funding_set_sha256,'0',''),'1',''),'2',''),'3',''),'4',''),'5',''),'6',''),'7',''),'8',''),'9',''),'a',''),'b',''),'c',''),'d',''),'e',''),'f','')) = 0",
            name="ck_funding_set_digest",
        ),
        Index("idx_funding_set_registration", "trusted_registration_id"),
        Index(
            "uq_funding_set_effective_registration",
            "trusted_registration_id",
            unique=True,
            sqlite_where=text("lifecycle_state = 'effective'"),
            postgresql_where=text("lifecycle_state = 'effective'"),
        ),
    )


class CanonicalCovenantFundingOutpointRow(Base):
    __tablename__ = "canonical_covenant_funding_outpoints"
    id = Column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    funding_set_id = Column(
        String(36), ForeignKey("canonical_covenant_funding_sets.funding_set_id", ondelete="CASCADE"), nullable=False
    )
    direction = Column(String(8), nullable=False)
    txid = Column(String(64), nullable=False)
    vout = Column(BigInteger, nullable=False)
    amount_sats = Column(BigInteger, nullable=False)
    witness_script_sha256 = Column(String(64), nullable=False)
    descriptor_sha256 = Column(String(64))
    funding_set = relationship("CanonicalCovenantFundingSetRow", back_populates="recognized_outpoints")
    __table_args__ = (
        UniqueConstraint("funding_set_id", "txid", "vout", name="uq_funding_outpoint_identity"),
        CheckConstraint("direction IN ('incoming','outgoing')", name="ck_funding_outpoint_direction"),
        CheckConstraint(
            "length(txid) = 64 AND length(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(txid,'0',''),'1',''),'2',''),'3',''),'4',''),'5',''),'6',''),'7',''),'8',''),'9',''),'a',''),'b',''),'c',''),'d',''),'e',''),'f','')) = 0",
            name="ck_funding_outpoint_txid",
        ),
        CheckConstraint("vout >= 0 AND vout <= 4294967295", name="ck_funding_outpoint_vout"),
        CheckConstraint("amount_sats > 0 AND amount_sats <= 2100000000000000", name="ck_funding_outpoint_amount"),
        CheckConstraint(
            "length(witness_script_sha256) = 64 AND length(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(witness_script_sha256,'0',''),'1',''),'2',''),'3',''),'4',''),'5',''),'6',''),'7',''),'8',''),'9',''),'a',''),'b',''),'c',''),'d',''),'e',''),'f','')) = 0",
            name="ck_funding_outpoint_script",
        ),
        CheckConstraint(
            "descriptor_sha256 IS NULL OR (length(descriptor_sha256) = 64 AND length(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(descriptor_sha256,'0',''),'1',''),'2',''),'3',''),'4',''),'5',''),'6',''),'7',''),'8',''),'9',''),'a',''),'b',''),'c',''),'d',''),'e',''),'f','')) = 0)",
            name="ck_funding_outpoint_descriptor",
        ),
        Index("idx_funding_outpoint_set", "funding_set_id"),
    )


class CanonicalAdmissionEdgeRow(Base):
    """Dormant append-only canonical human admission edge."""

    __tablename__ = "canonical_admission_edges"

    edge_id = Column(String(36), primary_key=True)
    schema = Column(String(64), nullable=False)
    edge_version = Column(String(64), nullable=False)
    graph_or_protocol_id = Column(String(64), nullable=False)
    network = Column(String(16), nullable=False)
    human_profile = Column(String(16), nullable=False)
    template_family = Column(String(16), nullable=False)
    delta_blocks = Column(Integer, nullable=False)
    sponsor_participant_id = Column(String(64), nullable=False)
    sponsor_compressed_public_key = Column(String(66), nullable=False)
    sponsor_x_only_public_key = Column(String(64), nullable=False)
    sponsor_depth = Column(Integer, nullable=False)
    child_participant_id = Column(String(64), nullable=False)
    child_compressed_public_key = Column(String(66), nullable=False)
    child_x_only_public_key = Column(String(64), nullable=False)
    child_depth = Column(Integer, nullable=False)
    early_height = Column(Integer, nullable=False)
    middle_height = Column(Integer, nullable=False)
    late_height = Column(Integer, nullable=False)
    trusted_registration_id = Column(String(36), nullable=False, unique=True)
    trusted_registration_sha256 = Column(String(64), nullable=False, unique=True)
    pair_sha256 = Column(String(64), nullable=False)
    validator_version = Column(String(64), nullable=False)
    sponsor_basis_kind = Column(String(32), nullable=False)
    sponsor_basis_record_id = Column(String(36), nullable=False)
    sponsor_basis_record_sha256 = Column(String(64), nullable=False)
    lifecycle_state = Column(String(10), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False)
    lifecycle_changed_at = Column(DateTime(timezone=True), nullable=False)
    effective_at = Column(DateTime(timezone=True))
    superseded_by_edge_id = Column(String(36))
    canonical_edge_sha256 = Column(String(64), nullable=False, unique=True)
    canonical_record_json = Column(Text, nullable=False)

    legs = relationship(
        "CanonicalAdmissionEdgeLegRow",
        back_populates="edge",
    )

    __table_args__ = (
        CheckConstraint(
            "schema = 'hodlxxi.canonical_admission_edge.v1'",
            name="ck_admission_edge_schema",
        ),
        CheckConstraint(
            "edge_version = 'hodlxxi.canonical_admission_edge_service.v1'",
            name="ck_admission_edge_version",
        ),
        CheckConstraint(
            "graph_or_protocol_id = 'hodlxxi.crt_membership_graph.v1'",
            name="ck_admission_edge_graph",
        ),
        CheckConstraint("network = 'bitcoin'", name="ck_admission_edge_network"),
        CheckConstraint(
            "human_profile = 'legacy_777' AND template_family = 'cltv_only' AND delta_blocks = 777",
            name="ck_admission_edge_profile",
        ),
        CheckConstraint(
            "sponsor_depth >= 0 AND child_depth = sponsor_depth + 1",
            name="ck_admission_edge_depth",
        ),
        CheckConstraint(
            "early_height > 0 AND middle_height = 1777777 - 777 * (child_depth - 1) AND early_height = middle_height - 777 AND late_height = middle_height + 777",
            name="ck_admission_edge_heights",
        ),
        CheckConstraint(
            "sponsor_participant_id != child_participant_id AND sponsor_compressed_public_key != child_compressed_public_key AND sponsor_x_only_public_key != child_x_only_public_key",
            name="ck_admission_edge_distinct_participants",
        ),
        CheckConstraint(
            "child_participant_id = child_x_only_public_key",
            name="ck_admission_edge_child_participant_convention",
        ),
        CheckConstraint(
            "(sponsor_depth = 0 AND sponsor_participant_id = 'E923' "
            "AND sponsor_compressed_public_key = "
            "'023d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923' "
            "AND sponsor_x_only_public_key = "
            "'3d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923' "
            "AND sponsor_basis_kind = 'canonical_genesis_record') OR "
            "(sponsor_depth > 0 AND sponsor_participant_id = sponsor_x_only_public_key "
            "AND sponsor_basis_kind = 'canonical_admission_edge')",
            name="ck_admission_edge_sponsor_convention",
        ),
        CheckConstraint(
            "length(edge_id) = 36 AND edge_id = lower(edge_id)",
            name="ck_admission_edge_id",
        ),
        CheckConstraint(
            "length(sponsor_compressed_public_key) = 66 "
            "AND substr(sponsor_compressed_public_key, 1, 2) IN ('02','03') "
            "AND sponsor_compressed_public_key = lower(sponsor_compressed_public_key) "
            "AND substr(sponsor_compressed_public_key, 3) = sponsor_x_only_public_key "
            "AND length(child_compressed_public_key) = 66 "
            "AND substr(child_compressed_public_key, 1, 2) IN ('02','03') "
            "AND child_compressed_public_key = lower(child_compressed_public_key) "
            "AND substr(child_compressed_public_key, 3) = child_x_only_public_key",
            name="ck_admission_edge_compressed_keys",
        ),
        CheckConstraint(
            "length(sponsor_x_only_public_key) = 64 AND sponsor_x_only_public_key = lower(sponsor_x_only_public_key) AND length(child_x_only_public_key) = 64 AND child_x_only_public_key = lower(child_x_only_public_key)",
            name="ck_admission_edge_xonly_keys",
        ),
        CheckConstraint(
            "lifecycle_state IN ('proposed','effective','disputed','superseded','revoked')",
            name="ck_admission_edge_lifecycle",
        ),
        CheckConstraint("lifecycle_changed_at >= created_at", name="ck_admission_edge_changed_order"),
        CheckConstraint(
            "(lifecycle_state = 'effective' AND effective_at IS NOT NULL AND effective_at >= created_at AND lifecycle_changed_at >= effective_at AND superseded_by_edge_id IS NULL) OR (lifecycle_state = 'proposed' AND effective_at IS NULL AND superseded_by_edge_id IS NULL) OR (lifecycle_state = 'superseded' AND superseded_by_edge_id IS NOT NULL) OR (lifecycle_state IN ('disputed','revoked') AND superseded_by_edge_id IS NULL)",
            name="ck_admission_edge_lifecycle_consistency",
        ),
        CheckConstraint(
            "sponsor_basis_kind IN ('canonical_genesis_record','canonical_admission_edge')",
            name="ck_admission_edge_basis_kind",
        ),
        CheckConstraint(
            "length(trusted_registration_id) = 36 AND trusted_registration_id = lower(trusted_registration_id) "
            "AND length(sponsor_basis_record_id) = 36 AND sponsor_basis_record_id = lower(sponsor_basis_record_id)",
            name="ck_admission_edge_source_ids",
        ),
        CheckConstraint(
            "length(trusted_registration_sha256) = 64 AND trusted_registration_sha256 = lower(trusted_registration_sha256) "
            "AND length(pair_sha256) = 64 AND pair_sha256 = lower(pair_sha256) "
            "AND length(sponsor_basis_record_sha256) = 64 AND sponsor_basis_record_sha256 = lower(sponsor_basis_record_sha256) "
            "AND length(canonical_edge_sha256) = 64 AND canonical_edge_sha256 = lower(canonical_edge_sha256)",
            name="ck_admission_edge_digests",
        ),
        CheckConstraint(
            "superseded_by_edge_id IS NULL OR "
            "(length(superseded_by_edge_id) = 36 AND superseded_by_edge_id = lower(superseded_by_edge_id) "
            "AND superseded_by_edge_id != edge_id)",
            name="ck_admission_edge_successor",
        ),
        Index("idx_admission_edge_graph", "graph_or_protocol_id"),
        Index(
            "idx_admission_edge_child",
            "graph_or_protocol_id",
            "child_x_only_public_key",
        ),
        Index(
            "idx_admission_edge_sponsor",
            "graph_or_protocol_id",
            "sponsor_x_only_public_key",
        ),
        Index(
            "uq_admission_edge_effective_child_id",
            "graph_or_protocol_id",
            "child_participant_id",
            unique=True,
            sqlite_where=text("lifecycle_state = 'effective'"),
            postgresql_where=text("lifecycle_state = 'effective'"),
        ),
        Index(
            "uq_admission_edge_effective_child_key",
            "graph_or_protocol_id",
            "child_x_only_public_key",
            unique=True,
            sqlite_where=text("lifecycle_state = 'effective'"),
            postgresql_where=text("lifecycle_state = 'effective'"),
        ),
    )


class CanonicalAdmissionEdgeLegRow(Base):
    """One normalized exact leg of a canonical admission edge."""

    __tablename__ = "canonical_admission_edge_legs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    edge_id = Column(
        String(36),
        ForeignKey("canonical_admission_edges.edge_id"),
        nullable=False,
    )
    direction = Column(String(32), nullable=False)
    sender_participant_id = Column(String(64), nullable=False)
    sender_compressed_public_key = Column(String(66), nullable=False)
    sender_x_only_public_key = Column(String(64), nullable=False)
    receiver_participant_id = Column(String(64), nullable=False)
    receiver_compressed_public_key = Column(String(66), nullable=False)
    receiver_x_only_public_key = Column(String(64), nullable=False)
    receiver_cltv_height = Column(Integer, nullable=False)
    sender_cltv_height = Column(Integer, nullable=False)
    raw_script_hex = Column(Text, nullable=False)
    txid = Column(String(64), nullable=False)
    vout = Column(Integer, nullable=False)
    amount_sats = Column(BigInteger, nullable=False)
    witness_script_sha256 = Column(String(64), nullable=False)
    descriptor_sha256 = Column(String(64))

    edge = relationship("CanonicalAdmissionEdgeRow", back_populates="legs")

    __table_args__ = (
        UniqueConstraint("edge_id", "direction", name="uq_admission_leg_edge_direction"),
        UniqueConstraint("txid", "vout", name="uq_admission_leg_global_outpoint"),
        CheckConstraint(
            "direction IN ('sponsor_to_child','child_to_sponsor')",
            name="ck_admission_leg_direction",
        ),
        CheckConstraint(
            "sender_participant_id != receiver_participant_id AND sender_compressed_public_key != receiver_compressed_public_key AND sender_x_only_public_key != receiver_x_only_public_key",
            name="ck_admission_leg_distinct_participants",
        ),
        CheckConstraint(
            "receiver_cltv_height > 0 AND sender_cltv_height > receiver_cltv_height",
            name="ck_admission_leg_heights",
        ),
        CheckConstraint(
            "length(raw_script_hex) > 0 AND length(raw_script_hex) % 2 = 0 AND raw_script_hex = lower(raw_script_hex)",
            name="ck_admission_leg_script",
        ),
        CheckConstraint("length(txid) = 64 AND txid = lower(txid)", name="ck_admission_leg_txid"),
        CheckConstraint("vout >= 0 AND vout <= 4294967295", name="ck_admission_leg_vout"),
        CheckConstraint(
            "amount_sats > 0 AND amount_sats <= 2100000000000000",
            name="ck_admission_leg_amount",
        ),
        CheckConstraint(
            "length(witness_script_sha256) = 64 AND witness_script_sha256 = lower(witness_script_sha256)",
            name="ck_admission_leg_hash",
        ),
        CheckConstraint(
            "descriptor_sha256 IS NULL OR "
            "(length(descriptor_sha256) = 64 AND descriptor_sha256 = lower(descriptor_sha256))",
            name="ck_admission_leg_descriptor",
        ),
        Index("idx_admission_leg_edge", "edge_id"),
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
        UniqueConstraint("step_up_challenge_id", name="uq_action_operations_step_up_challenge"),
        ForeignKeyConstraint(
            ["step_up_challenge_id"],
            ["action_step_up_challenges.challenge_id"],
            name="fk_action_operations_step_up_challenge",
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


class X25519IdentityBinding(Base):
    """Append-only identity-authorized X25519 lifecycle evidence."""

    __tablename__ = "x25519_identity_bindings"

    binding_id = Column(String(64), primary_key=True)
    contract_version = Column(String(64), nullable=False)
    subject_pubkey = Column(String(64), nullable=False)
    algorithm = Column(String(16), nullable=False)
    public_key = Column(String(64), nullable=False)
    binding_version = Column(BigInteger, nullable=False)
    valid_from = Column(DateTime(timezone=True), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    operation = Column(String(8), nullable=False)
    prior_binding_id = Column(
        String(64), ForeignKey("x25519_identity_bindings.binding_id", name="fk_x25519_binding_prior")
    )
    nonce = Column(String(64), nullable=False, unique=True)
    statement_sha256 = Column(String(64), nullable=False, unique=True)
    signature_format = Column(String(32), nullable=False)
    identity_signature = Column(String(128), nullable=False)
    active = Column(Boolean, nullable=False, default=False)
    retired_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)

    __table_args__ = (
        UniqueConstraint("subject_pubkey", "binding_version", name="uq_x25519_binding_subject_version"),
        CheckConstraint(
            "contract_version = 'hodlxxi.x25519_identity_binding_statement.v1'",
            name="ck_x25519_binding_contract",
        ),
        CheckConstraint("algorithm = 'x25519-v1'", name="ck_x25519_binding_algorithm"),
        CheckConstraint(_CanonicalLowerHex("binding_id", 64), name="ck_x25519_binding_id"),
        CheckConstraint(_CanonicalLowerHex("subject_pubkey", 64), name="ck_x25519_binding_subject"),
        CheckConstraint(_CanonicalLowerHex("public_key", 64), name="ck_x25519_binding_public_key"),
        CheckConstraint("binding_version BETWEEN 1 AND 9007199254740991", name="ck_x25519_binding_safe_version"),
        CheckConstraint("valid_from < expires_at", name="ck_x25519_binding_validity"),
        CheckConstraint("operation IN ('register','rotate','revoke')", name="ck_x25519_binding_operation"),
        CheckConstraint(
            "(operation = 'register' AND prior_binding_id IS NULL AND binding_version = 1) OR "
            "(operation IN ('rotate','revoke') AND prior_binding_id IS NOT NULL)",
            name="ck_x25519_binding_prior",
        ),
        CheckConstraint(_CanonicalLowerHex("nonce", 64), name="ck_x25519_binding_nonce"),
        CheckConstraint(
            _CanonicalLowerHex("statement_sha256", 64) & text("binding_id = statement_sha256"),
            name="ck_x25519_binding_digest",
        ),
        CheckConstraint(_CanonicalLowerHex("identity_signature", 128), name="ck_x25519_binding_signature"),
        CheckConstraint("signature_format = 'bip340_schnorr_sha256'", name="ck_x25519_binding_signature_format"),
        CheckConstraint(
            "(active = true AND operation IN ('register','rotate') AND retired_at IS NULL) OR "
            "(active = false AND retired_at IS NOT NULL)",
            name="ck_x25519_binding_active_state",
        ),
        Index(
            "uq_x25519_binding_active_subject",
            "subject_pubkey",
            unique=True,
            postgresql_where=text("active = true"),
            sqlite_where=text("active = 1"),
        ),
        Index(
            "uq_x25519_binding_active_public_key",
            "public_key",
            unique=True,
            postgresql_where=text("active = true"),
            sqlite_where=text("active = 1"),
        ),
        Index("idx_x25519_binding_current_order", "active", "subject_pubkey"),
        Index("idx_x25519_binding_expires_at", "expires_at"),
    )
