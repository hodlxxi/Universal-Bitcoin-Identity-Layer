"""Separate V2 mappings and guarded caller Connection; no runtime registration.

Only PostgreSQL 16 / READ COMMITTED is supported by this source. No native
execution or catalog/privilege proof is claimed by offline tests.
"""

from __future__ import annotations

import hashlib
import re

from sqlalchemy import BigInteger, Column, String, Text, select, text
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.sql.elements import quoted_name

from app.services.social_session_issuance_v2_contract import V2IssuanceUnavailable


class V2Base(DeclarativeBase):
    pass


class V2Offer(V2Base):
    __tablename__ = "social_session_v2_offers"
    __table_args__ = {"schema": "public"}
    operation_id = Column(String(64), primary_key=True)
    request_id = Column(String(64), nullable=False)
    authorization_digest = Column(String(64), nullable=False)
    wire = Column(Text, nullable=False)
    subject = Column(String(64), nullable=False)
    client_id = Column(String(255), nullable=False)
    backend_id = Column(String(255), nullable=False)
    service_principal = Column(String(255), nullable=False)
    issuer = Column(String(255), nullable=False)
    created_at = Column(BigInteger, nullable=False)
    expires_at = Column(BigInteger, nullable=False)
    birth_xid = Column(Text, nullable=False)


class V2Parent(V2Base):
    __tablename__ = "social_session_v2_parents"
    __table_args__ = {"schema": "public"}
    operation_id = Column(String(64), primary_key=True)
    token_id = Column(String(36), nullable=False)
    session_id = Column(String(255), nullable=False)
    browser_id = Column(String(64), nullable=False)
    user_id = Column(String(36), nullable=False)
    continuity = Column(String(64), nullable=False)


class V2Acceptance(V2Base):
    __tablename__ = "social_session_v2_acceptances"
    __table_args__ = {"schema": "public"}
    operation_id = Column(String(64), primary_key=True)
    acceptance_id = Column(String(64), nullable=False)
    approval_id = Column(String(64), nullable=False)
    approval_wire = Column(Text, nullable=False)
    wire = Column(Text, nullable=False)
    binding_id = Column(String(64), nullable=False)
    accepted_at = Column(BigInteger, nullable=False)
    possession_proof = Column(String(64), nullable=False)
    full_evidence_id = Column(String(36), nullable=False)
    full_evidence_version = Column(String(128), nullable=False)
    full_source_hash = Column(String(64), nullable=False)
    full_proof_id = Column(String(112), nullable=False)
    full_expires_at = Column(BigInteger, nullable=False)
    birth_xid = Column(Text, nullable=False)


class V2Issuance(V2Base):
    __tablename__ = "social_session_v2_issuances"
    __table_args__ = {"schema": "public"}
    operation_id = Column(String(64), primary_key=True)
    acceptance_id = Column(String(64), nullable=False)
    issuance_id = Column(String(64), nullable=False)
    token_id = Column(String(36), nullable=False)
    revision = Column(String(64), nullable=False)
    subject = Column(String(64), nullable=False)
    client_id = Column(String(255), nullable=False)
    backend_id = Column(String(255), nullable=False)
    service_principal = Column(String(255), nullable=False)
    issuer = Column(String(255), nullable=False)
    user_id = Column(String(36), nullable=False)
    delivery_commitment = Column(String(64), nullable=False)
    issued_at = Column(BigInteger, nullable=False)
    expires_at = Column(BigInteger, nullable=False)
    kid = Column(String(255), nullable=False)
    birth_xid = Column(Text, nullable=False)


class V2Invalidation(V2Base):
    __tablename__ = "social_session_v2_invalidations"
    __table_args__ = {"schema": "public"}
    operation_id = Column(String(64), primary_key=True)


class V2BindingBirth(V2Base):
    __tablename__ = "social_session_v2_binding_births"
    __table_args__ = {"schema": "public"}
    binding_id = Column(String(64), primary_key=True)
    operation_id = Column(String(64), nullable=False)
    birth_xid = Column(Text, nullable=False)


class V2TokenBirth(V2Base):
    __tablename__ = "social_session_v2_token_births"
    __table_args__ = {"schema": "public"}
    token_id = Column(String(36), primary_key=True)
    birth_xid = Column(Text, nullable=False)


class TransactionGuard:
    """Poison on any continuity failure; all SQL is bound to this Connection.

    Caller must use SQLAlchemy transaction APIs, never raw driver/savepoint SQL,
    and must roll back after failure. Backend XID authenticates the root only.
    """

    def __init__(self, session):
        # Only the repository's exact internal port participates in a shared
        # observation. Arbitrary session wrappers retain the ordinary checks.
        from app.services.social_session_issuance_v2_authority import BoundSession

        self.session = session
        self.poisoned = False
        self.parent_guard = session.guard if type(session) is BoundSession else None
        self.bound_session_type = BoundSession
        if self.parent_guard is not None and type(self.parent_guard) is not TransactionGuard:
            raise V2IssuanceUnavailable()
        self.root = session.get_transaction()
        self.nested = session.get_nested_transaction()
        self.connection = session.connection()
        self.connection_root = self.connection.get_transaction()
        self.connection_nested = self.connection.get_nested_transaction()
        self.physical = self.connection.connection.dbapi_connection
        self.xid = None
        self.check()

    def _check_objects(self):
        chain, seen = [], set()
        item = self
        while item is not None:
            if type(item) is not TransactionGuard or item in seen or len(chain) >= 16:
                raise ValueError
            seen.add(item)
            chain.append(item)
            s, c, parent = item.session, item.connection, item.parent_guard
            if (
                item.poisoned
                or item.root is None
                or not item.root.is_active
                or s.get_transaction() is not item.root
                or s.get_nested_transaction() is not item.nested
                or item.nested is not None
                and not item.nested.is_active
                or s.in_transaction() is not True
                or not s.is_active
                or s.new
                or s.dirty
                or s.deleted
                or s.get_bind().dialect.name != "postgresql"
                or c is not self.connection
                or c.closed
                or c.invalidated
                or c.in_transaction() is not True
                or item.connection_root is None
                or not item.connection_root.is_active
                or c.get_transaction() is not item.connection_root
                or c.get_nested_transaction() is not item.connection_nested
                or item.connection_nested is not None
                and not item.connection_nested.is_active
                or c.connection.dbapi_connection is not item.physical
                or getattr(item.physical, "autocommit", None) is not False
            ):
                raise ValueError
            if parent is None:
                connected = s.connection()
            else:
                if (
                    type(s) is not item.bound_session_type
                    or s.guard is not parent
                    or "connection" in vars(s)
                    or type(parent) is not TransactionGuard
                ):
                    raise ValueError
                connected = parent.connection
            if connected is not c:
                raise ValueError
            item = parent
        return tuple(chain)

    def check(self):
        chain = ()
        try:
            chain = self._check_objects()
            # One fresh statement authenticates the same physical backend for
            # every exact internal BoundSession layer. No result is reused by
            # another check; catalog reads and before/after boundaries remain.
            isolation, version, xid = self.connection.execute(
                text(
                    "SELECT pg_catalog.current_setting('transaction_isolation'), "
                    "pg_catalog.current_setting('server_version_num'), "
                    "pg_catalog.pg_current_xact_id()::text"
                )
            ).one()
            if type(isolation) is not str or isolation != "read committed":
                raise ValueError
            if type(version) is not str or not version.isdecimal() or not 160000 <= int(version) < 170000:
                raise ValueError
            if type(xid) is not str or re.fullmatch(r"[1-9][0-9]{0,19}", xid) is None or int(xid) >= 2**64:
                raise ValueError
            for item in chain:
                if item.xid is None:
                    item.xid = xid
                elif item.xid != xid:
                    raise ValueError
            if self._check_objects() != chain:
                raise ValueError
        except Exception:
            self.poisoned = True
            for item in chain:
                item.poisoned = True
            raise V2IssuanceUnavailable() from None

    def execute(self, statement):
        self.check()
        result = self.session.execute(
            statement.execution_options(populate_existing=True), bind_arguments={"bind": self.connection}
        )
        self.check()
        return result

    def row(self, model, column, value, *, lock=False, optional=False):
        statement = select(model).where(column == value)
        if lock:
            statement = statement.with_for_update()
        rows = self.execute(statement.limit(2)).scalars().all()
        if len(rows) != 1:
            if optional and not rows:
                return None
            raise V2IssuanceUnavailable()
        return rows[0]

    def sql(self, statement, values=None):
        self.check()
        result = self.connection.execute(text(statement), values or {})
        self.check()
        return result

    def flush(self):
        # Controlled producer writes are explicitly bound; no entity-routing escape.
        self.session.flush()
        self.check()


# Exact new trigger bodies are shared with the unapplied migration source.
# SECURITY DEFINER is needed only for causal owner-fence inserts/invalidation;
# qualified objects, pinned search paths, no dynamic SQL, no PUBLIC EXECUTE.
# Invalidation invokes unchanged legacy invoker guards during its token UPDATE;
# only it needs trusted public after pg_catalog, with pg_temp explicitly LAST.
GUARD_BODY = """
BEGIN
  IF TG_OP <> 'INSERT' THEN RAISE EXCEPTION 'social session issuance v2 unavailable'; END IF;
  IF TG_TABLE_NAME = 'social_session_v2_offers' THEN
    IF NEW.birth_xid <> pg_catalog.pg_current_xact_id()::text
       OR EXISTS (SELECT 1 FROM public.social_messaging_mobile_operations WHERE operation_id = NEW.operation_id)
    THEN RAISE EXCEPTION 'social session issuance v2 unavailable'; END IF;
    IF NOT COALESCE(
       NEW.wire::jsonb->>'method' = 'qr_desktop_pre_enrollment_v2'
       AND NEW.wire::jsonb->>'schema' = 'hodlxxi.social_messaging_device_authorization_method.v2'
       AND NEW.wire::jsonb->>'version' = '2'
       AND NEW.wire::jsonb->'context'->>'pairingId' = NEW.operation_id
       AND NEW.created_at = (extract(epoch FROM (NEW.wire::jsonb->'context'->>'createdAt')::timestamptz) * 1000)::bigint
       AND NEW.expires_at = (extract(epoch FROM (NEW.wire::jsonb->'context'->>'expiresAt')::timestamptz) * 1000)::bigint
       AND (NEW.wire::jsonb->>'content')::jsonb->'authorization'->>'operation' = 'register'
       AND (NEW.wire::jsonb->>'preEnrollment')::jsonb->>'transitionKind' = 'initial'
       AND floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint < NEW.expires_at
       AND (NEW.wire::jsonb->>'preEnrollment')::jsonb->>'subject' = NEW.subject
       AND (NEW.wire::jsonb->>'preEnrollment')::jsonb->>'requestId' = NEW.request_id
       AND NEW.authorization_digest = encode(sha256(convert_to(NEW.wire,'UTF8')),'hex'), FALSE)
    THEN RAISE EXCEPTION 'social session issuance v2 unavailable'; END IF;
    INSERT INTO public.social_messaging_device_authorization_requests(request_id,owner,digest)
      VALUES (NEW.request_id,'mobile',NEW.authorization_digest);
  ELSIF TG_TABLE_NAME = 'social_session_v2_parents' THEN
    PERFORM 1 FROM public.users WHERE id = NEW.user_id FOR UPDATE;
    PERFORM 1 FROM public.oauth_clients WHERE client_id IN (
      SELECT client_id FROM public.social_session_v2_offers WHERE operation_id = NEW.operation_id) FOR UPDATE;
    PERFORM 1 FROM public.social_session_issuers WHERE client_id IN (
      SELECT client_id FROM public.social_session_v2_offers WHERE operation_id = NEW.operation_id) FOR UPDATE;
    PERFORM 1 FROM public.oauth_browser_generations WHERE generation_id = NEW.browser_id FOR UPDATE;
    PERFORM 1 FROM public.oauth_tokens WHERE id = NEW.token_id FOR UPDATE;
    PERFORM 1 FROM public.sessions WHERE session_id = NEW.session_id FOR UPDATE;
    IF NOT EXISTS (
      SELECT 1 FROM public.social_session_v2_offers o
      JOIN public.oauth_session_generations g ON g.token_id = NEW.token_id
      JOIN public.users u ON u.id = g.user_id
      JOIN public.oauth_clients c ON c.client_id = g.client_id
      JOIN public.social_session_issuers r ON r.client_id = c.client_id
      JOIN public.oauth_browser_generations b ON b.generation_id = g.browser_generation_id
      JOIN public.oauth_tokens t ON t.id = g.token_id
      JOIN public.sessions s ON s.session_id = g.session_id
      WHERE o.operation_id = NEW.operation_id AND o.birth_xid = pg_catalog.pg_current_xact_id()::text
        AND g.session_id = NEW.session_id AND g.browser_generation_id = NEW.browser_id
        AND g.user_id = NEW.user_id AND g.subject = o.subject AND g.client_id = o.client_id
        AND r.backend_id = o.backend_id AND r.service_principal = o.service_principal
        AND u.is_active IS TRUE AND u.pubkey = o.subject AND c.is_active IS TRUE AND r.is_active IS TRUE
        AND b.is_active IS TRUE AND s.is_active IS TRUE AND t.is_revoked IS FALSE
        AND clock_timestamp() AT TIME ZONE 'UTC' < LEAST(b.expires_at,s.expires_at,t.access_token_expires_at)
    ) THEN RAISE EXCEPTION 'social session issuance v2 unavailable'; END IF;
  ELSIF TG_TABLE_NAME = 'social_session_v2_acceptances' THEN
    IF NOT EXISTS (
      SELECT 1 FROM public.social_session_v2_offers o
      JOIN public.social_session_v2_parents p USING(operation_id)
      JOIN public.social_messaging_device_bindings b ON b.binding_id = NEW.binding_id
      WHERE o.operation_id = NEW.operation_id AND b.subject_pubkey = o.subject
        AND b.request_id = o.request_id AND b.operation = 'register' AND b.binding_version = 1
        AND b.active IS TRUE AND EXISTS (
          SELECT 1 FROM public.social_session_v2_binding_births bb WHERE bb.binding_id = b.binding_id
            AND bb.operation_id = o.operation_id AND bb.birth_xid = pg_catalog.pg_current_xact_id()::text)
        AND NEW.accepted_at >= o.created_at AND NEW.accepted_at < o.expires_at
        AND NEW.approval_wire::jsonb->>'content' = o.wire
        AND NEW.approval_wire::jsonb->>'id' = NEW.approval_id
        AND NEW.wire::jsonb->>'acceptanceId' = NEW.acceptance_id
        AND NEW.wire::jsonb->>'approvalEventId' = NEW.approval_id
        AND NEW.wire::jsonb->>'authorizationDigest' = o.authorization_digest
        AND NEW.wire::jsonb->>'bindingId' = NEW.binding_id
        AND NEW.wire::jsonb->>'subject' = o.subject
        AND NEW.wire::jsonb->>'requestId' = o.request_id
        AND (o.wire::jsonb->>'preEnrollment')::jsonb->>'x25519BindingId' = NEW.binding_id
        AND b.device_id = (o.wire::jsonb->>'preEnrollment')::jsonb->>'deviceId'
        AND b.public_key = ((o.wire::jsonb->>'content')::jsonb->'authorization'->>'publicKey')
        AND b.valid_from = ((o.wire::jsonb->>'content')::jsonb->'authorization'->>'bindingValidFrom')::timestamptz
        AND b.expires_at = ((o.wire::jsonb->>'content')::jsonb->'authorization'->>'bindingExpiresAt')::timestamptz
        AND NEW.accepted_at < NEW.full_expires_at
        AND floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint < LEAST(o.expires_at,NEW.full_expires_at)
        AND NEW.accepted_at < ((o.wire::jsonb->>'preEnrollment')::jsonb->>'expiresAt')::bigint
        AND to_timestamp(NEW.accepted_at / 1000.0) < ((o.wire::jsonb->>'content')::jsonb->'authorization'->>'expiresAt')::timestamptz
        AND NEW.birth_xid = pg_catalog.pg_current_xact_id()::text
        AND NOT EXISTS (SELECT 1 FROM public.social_session_v2_invalidations WHERE operation_id = o.operation_id)
    ) THEN RAISE EXCEPTION 'social session issuance v2 unavailable'; END IF;
    INSERT INTO public.social_messaging_device_authorization_binding_owners(binding_id,request_id)
      SELECT NEW.binding_id,request_id FROM public.social_session_v2_offers WHERE operation_id = NEW.operation_id;
  ELSIF TG_TABLE_NAME = 'social_session_v2_issuances' THEN
    PERFORM 1 FROM public.users WHERE id = NEW.user_id FOR UPDATE;
    PERFORM 1 FROM public.oauth_clients WHERE client_id = NEW.client_id FOR UPDATE;
    PERFORM 1 FROM public.social_session_issuers WHERE client_id = NEW.client_id FOR UPDATE;
    PERFORM 1 FROM public.oauth_browser_generations WHERE generation_id IN (
      SELECT browser_id FROM public.social_session_v2_parents WHERE operation_id = NEW.operation_id) FOR UPDATE;
    PERFORM 1 FROM public.oauth_tokens WHERE id IN (
      SELECT token_id FROM public.social_session_v2_parents WHERE operation_id = NEW.operation_id) FOR UPDATE;
    PERFORM 1 FROM public.sessions WHERE session_id IN (
      SELECT session_id FROM public.social_session_v2_parents WHERE operation_id = NEW.operation_id) FOR UPDATE;
    PERFORM 1 FROM public.social_messaging_device_bindings WHERE binding_id IN (
      SELECT binding_id FROM public.social_session_v2_acceptances WHERE operation_id = NEW.operation_id) FOR UPDATE;
    IF NOT EXISTS (
      SELECT 1 FROM public.social_session_v2_offers o
      JOIN public.social_session_v2_parents p USING(operation_id)
      JOIN public.social_session_v2_acceptances a USING(operation_id)
      JOIN public.oauth_session_generations g ON g.token_id = p.token_id
      JOIN public.users u ON u.id = p.user_id
      JOIN public.oauth_clients c ON c.client_id = o.client_id
      JOIN public.social_session_issuers r ON r.client_id = o.client_id
      JOIN public.oauth_tokens t ON t.id = NEW.token_id
      JOIN public.oauth_tokens pt ON pt.id = p.token_id
      JOIN public.sessions s ON s.session_id = p.session_id
      JOIN public.oauth_browser_generations bg ON bg.generation_id = p.browser_id
      JOIN public.social_messaging_device_bindings b ON b.binding_id = a.binding_id
      WHERE o.operation_id = NEW.operation_id AND a.acceptance_id = NEW.acceptance_id
        AND NEW.subject = o.subject AND NEW.user_id = p.user_id
        AND NEW.client_id = o.client_id AND NEW.backend_id = o.backend_id
        AND NEW.service_principal = o.service_principal AND NEW.issuer = o.issuer
        AND r.backend_id = NEW.backend_id AND r.service_principal = NEW.service_principal
        AND u.pubkey = NEW.subject AND u.is_active IS TRUE AND c.is_active IS TRUE AND r.is_active IS TRUE
        AND pt.is_revoked IS FALSE AND s.is_active IS TRUE AND bg.is_active IS TRUE AND b.active IS TRUE
        AND g.session_id = p.session_id AND g.browser_generation_id = p.browser_id AND g.subject = NEW.subject
        AND a.accepted_at < (NEW.issued_at + 1) * 1000 AND NEW.expires_at * 1000 <= o.expires_at
        AND NEW.issuance_id NOT IN (o.operation_id,o.request_id,o.authorization_digest,a.acceptance_id,a.approval_id)
        AND NEW.expires_at * 1000 <= ((o.wire::jsonb->>'preEnrollment')::jsonb->>'expiresAt')::bigint
        AND to_timestamp(NEW.expires_at) <= ((o.wire::jsonb->>'content')::jsonb->'authorization'->>'expiresAt')::timestamptz
        AND b.valid_from <= to_timestamp(NEW.issued_at) AND to_timestamp(NEW.expires_at) <= b.expires_at
        AND to_timestamp(NEW.expires_at) AT TIME ZONE 'UTC' <= LEAST(pt.access_token_expires_at,s.expires_at,bg.expires_at)
        AND EXISTS (SELECT 1 FROM public.social_session_v2_token_births tb
          WHERE tb.token_id = t.id AND tb.birth_xid = pg_catalog.pg_current_xact_id()::text)
        AND a.birth_xid = pg_catalog.pg_current_xact_id()::text
        AND NEW.birth_xid = a.birth_xid
        AND t.user_id = NEW.user_id AND t.client_id = NEW.client_id AND t.is_revoked IS FALSE
        AND t.created_at = to_timestamp(NEW.issued_at) AT TIME ZONE 'UTC'
        AND t.access_token_expires_at = to_timestamp(NEW.expires_at) AT TIME ZONE 'UTC'
        AND t.scope = 'openid profile' AND t.token_type = 'Bearer'
        AND t.refresh_token IS NULL AND t.refresh_token_expires_at IS NULL
        AND t.access_token ~ '^[0-9a-f]{64}$'
        AND t.metadata->>'token_contract' = 'hodlxxi.oauth.access-token.v1'
        AND t.metadata->>'token_use' = 'access' AND t.metadata->>'issuer' = NEW.issuer
        AND t.metadata->>'audience' = NEW.client_id AND t.metadata->>'kid' = NEW.kid
        AND NOT EXISTS (SELECT 1 FROM public.oauth_session_generations WHERE token_id = NEW.token_id)
        AND NOT EXISTS (SELECT 1 FROM public.social_session_issuances WHERE token_id = NEW.token_id)
        AND NOT EXISTS (SELECT 1 FROM public.social_session_v2_invalidations WHERE operation_id = NEW.operation_id)
        AND clock_timestamp() AT TIME ZONE 'UTC' < t.access_token_expires_at
    ) THEN RAISE EXCEPTION 'social session issuance v2 unavailable'; END IF;
  END IF;
  RETURN NEW;
END;
"""
COMPLETE_BODY = """
BEGIN
  IF NOT EXISTS (SELECT 1 FROM public.social_session_v2_parents WHERE operation_id = NEW.operation_id)
  THEN RAISE EXCEPTION 'social session issuance v2 unavailable'; END IF;
  RETURN NULL;
END;
"""
IMMUTABLE_BODY = """
BEGIN
  RAISE EXCEPTION 'social session issuance v2 unavailable';
END;
"""
INVALIDATE_BODY = """
BEGIN
  IF TG_TABLE_NAME = 'oauth_tokens' THEN
    IF EXISTS (SELECT 1 FROM public.social_session_v2_issuances WHERE token_id = OLD.id) THEN
      IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'social session issuance v2 unavailable'; END IF;
      IF ROW(NEW.id,NEW.user_id,NEW.client_id,NEW.access_token,NEW.created_at,NEW.scope,NEW.token_type,
             NEW.refresh_token,NEW.refresh_token_expires_at,NEW.metadata::text)
        IS DISTINCT FROM ROW(OLD.id,OLD.user_id,OLD.client_id,OLD.access_token,OLD.created_at,OLD.scope,OLD.token_type,
             OLD.refresh_token,OLD.refresh_token_expires_at,OLD.metadata::text)
        OR NEW.access_token_expires_at > OLD.access_token_expires_at OR NEW.is_revoked IS NULL
        OR (OLD.is_revoked IS TRUE AND NEW.is_revoked IS NOT TRUE)
      THEN RAISE EXCEPTION 'social session issuance v2 unavailable'; END IF;
      IF NEW.access_token_expires_at < OLD.access_token_expires_at THEN NEW.is_revoked := TRUE; END IF;
      -- Child tokens never own an OAuth browser generation or grandchildren.
      -- Returning here also prevents BEFORE-trigger invalidation recursion.
      RETURN NEW;
    END IF;
    IF TG_OP = 'UPDATE' AND NEW.is_revoked IS FALSE AND NEW.access_token_expires_at = OLD.access_token_expires_at
    THEN RETURN NEW; END IF;
    INSERT INTO public.social_session_v2_invalidations(operation_id)
      SELECT operation_id FROM public.social_session_v2_parents WHERE token_id = OLD.id ON CONFLICT DO NOTHING;
  ELSIF TG_TABLE_NAME = 'sessions' THEN
    IF TG_OP = 'UPDATE' AND NEW.is_active IS TRUE AND NEW.expires_at = OLD.expires_at
       AND ROW(NEW.session_id,NEW.user_id,NEW.created_at,NEW.session_type)
         IS NOT DISTINCT FROM ROW(OLD.session_id,OLD.user_id,OLD.created_at,OLD.session_type) THEN RETURN NEW; END IF;
    INSERT INTO public.social_session_v2_invalidations(operation_id)
      SELECT operation_id FROM public.social_session_v2_parents WHERE session_id = OLD.session_id ON CONFLICT DO NOTHING;
  ELSIF TG_TABLE_NAME = 'oauth_browser_generations' THEN
    IF TG_OP = 'UPDATE' AND NEW.is_active IS TRUE AND NEW.expires_at = OLD.expires_at THEN RETURN NEW; END IF;
    INSERT INTO public.social_session_v2_invalidations(operation_id)
      SELECT operation_id FROM public.social_session_v2_parents WHERE browser_id = OLD.generation_id ON CONFLICT DO NOTHING;
  ELSIF TG_TABLE_NAME = 'users' THEN
    IF TG_OP = 'UPDATE' AND NEW.is_active IS TRUE AND NEW.pubkey = OLD.pubkey THEN RETURN NEW; END IF;
    INSERT INTO public.social_session_v2_invalidations(operation_id)
      SELECT operation_id FROM public.social_session_v2_parents WHERE user_id = OLD.id ON CONFLICT DO NOTHING;
  ELSIF TG_TABLE_NAME = 'oauth_clients' THEN
    IF TG_OP = 'UPDATE' AND NEW.is_active IS TRUE
       AND ROW(NEW.client_id,NEW.scope,NEW.metadata::text) IS NOT DISTINCT FROM ROW(OLD.client_id,OLD.scope,OLD.metadata::text)
    THEN RETURN NEW; END IF;
    INSERT INTO public.social_session_v2_invalidations(operation_id)
      SELECT operation_id FROM public.social_session_v2_offers WHERE client_id = OLD.client_id ON CONFLICT DO NOTHING;
  ELSIF TG_TABLE_NAME = 'social_session_issuers' THEN
    IF TG_OP = 'UPDATE' AND NEW IS NOT DISTINCT FROM OLD THEN RETURN NEW; END IF;
    INSERT INTO public.social_session_v2_invalidations(operation_id)
      SELECT operation_id FROM public.social_session_v2_offers WHERE client_id = OLD.client_id ON CONFLICT DO NOTHING;
  ELSIF TG_TABLE_NAME = 'social_messaging_device_bindings' THEN
    IF TG_OP = 'UPDATE' AND NEW IS NOT DISTINCT FROM OLD THEN RETURN NEW; END IF;
    INSERT INTO public.social_session_v2_invalidations(operation_id)
      SELECT operation_id FROM public.social_session_v2_acceptances WHERE binding_id = OLD.binding_id ON CONFLICT DO NOTHING;
  END IF;
  UPDATE public.oauth_tokens SET is_revoked = TRUE WHERE is_revoked IS FALSE AND id IN (
    SELECT i.token_id FROM public.social_session_v2_issuances i
    JOIN public.social_session_v2_invalidations v USING(operation_id));
  IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END;
"""
BIRTH_BODY = """
BEGIN
  IF TG_TABLE_NAME = 'oauth_tokens' THEN
    INSERT INTO public.social_session_v2_token_births(token_id,birth_xid)
      VALUES (NEW.id,pg_catalog.pg_current_xact_id()::text);
  ELSE
    INSERT INTO public.social_session_v2_binding_births(binding_id,operation_id,birth_xid)
      SELECT NEW.binding_id,operation_id,pg_catalog.pg_current_xact_id()::text
      FROM public.social_session_v2_offers WHERE request_id = NEW.request_id;
  END IF;
  RETURN NEW;
END;
"""
FUNCTIONS = {
    "social_session_v2_birth": BIRTH_BODY,
    "social_session_v2_guard": GUARD_BODY,
    "social_session_v2_complete": COMPLETE_BODY,
    "social_session_v2_immutable": IMMUTABLE_BODY,
    "social_session_v2_invalidate": INVALIDATE_BODY,
}
FUNCTION_CONFIGS = {
    "social_session_v2_birth": ("search_path=pg_catalog",),
    "social_session_v2_guard": ("search_path=pg_catalog",),
    "social_session_v2_complete": ("search_path=pg_catalog",),
    "social_session_v2_immutable": ("search_path=pg_catalog",),
    "social_session_v2_invalidate": ("search_path=pg_catalog, public, pg_temp",),
}


# Native OID values decode as integers on direct SELECT but as JSON strings.
# Cast only the closed identity fields to bigint before JSON serialization.
_CATALOG_SELECTS = {
    "role": (
        "SELECT r.rolsuper,r.rolcreaterole,r.rolcreatedb,r.rolreplication,r.rolbypassrls,\n        (SELECT count(*) FROM pg_catalog.pg_auth_members WHERE member = r.oid),\n        ARRAY(SELECT candidate.rolname::text FROM pg_catalog.pg_roles AS candidate\n            WHERE candidate.oid <> r.oid AND pg_catalog.pg_has_role(r.oid,candidate.oid,'MEMBER')\n            ORDER BY candidate.rolname) AS member_roles,\n        ARRAY(SELECT candidate.oid::bigint FROM pg_catalog.pg_roles AS candidate\n            WHERE candidate.oid <> r.oid AND pg_catalog.pg_has_role(r.oid,candidate.oid,'MEMBER')\n            ORDER BY candidate.rolname) AS member_role_oids,\n        r.oid::bigint,r.rolinherit,r.rolcanlogin,\n        EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members WHERE member = r.oid AND admin_option)\n        FROM pg_catalog.pg_roles r WHERE rolname = current_user",
        "SELECT pg_catalog.to_jsonb(ROW(r.rolsuper,r.rolcreaterole,r.rolcreatedb,r.rolreplication,r.rolbypassrls,\n        (SELECT count(*) FROM pg_catalog.pg_auth_members WHERE member = r.oid),\n        ARRAY(SELECT candidate.rolname::text FROM pg_catalog.pg_roles AS candidate\n            WHERE candidate.oid <> r.oid AND pg_catalog.pg_has_role(r.oid,candidate.oid,'MEMBER')\n            ORDER BY candidate.rolname),\n        ARRAY(SELECT candidate.oid::bigint FROM pg_catalog.pg_roles AS candidate\n            WHERE candidate.oid <> r.oid AND pg_catalog.pg_has_role(r.oid,candidate.oid,'MEMBER')\n            ORDER BY candidate.rolname),\n        r.oid::bigint,r.rolinherit,r.rolcanlogin,\n        EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members WHERE member = r.oid AND admin_option))) AS row_values, NULL::text AS row_order FROM pg_catalog.pg_roles r WHERE rolname = current_user",
        12,
    ),
    "schema": (
        "SELECT oid,nspowner,\n        current_user = session_user AND pg_catalog.current_setting('session_replication_role') = 'origin'\n        AND pg_catalog.has_schema_privilege(current_user,'public','USAGE')\n        AND NOT pg_catalog.has_schema_privilege(current_user,'public','CREATE')\n        AND NOT pg_catalog.pg_has_role(current_user,nspowner,'MEMBER')\n        FROM pg_catalog.pg_namespace WHERE nspname='public'",
        "SELECT pg_catalog.to_jsonb(ROW(oid::bigint,nspowner::bigint,current_user = session_user AND pg_catalog.current_setting('session_replication_role') = 'origin'\n        AND pg_catalog.has_schema_privilege(current_user,'public','USAGE')\n        AND NOT pg_catalog.has_schema_privilege(current_user,'public','CREATE')\n        AND NOT pg_catalog.pg_has_role(current_user,nspowner,'MEMBER'))) AS row_values, NULL::text AS row_order FROM pg_catalog.pg_namespace WHERE nspname='public'",
        3,
    ),
    "triggers": (
        "SELECT t.oid,t.tgfoid,t.tgname,p.proname,t.tgtype,t.tgdeferrable,t.tginitdeferred,\n        t.tgenabled,t.tgnargs,t.tgattr::text,t.tgqual,t.tgargs,t.tgoldtable,t.tgnewtable,t.tgparentid,\n        n.nspname FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_proc p ON p.oid=t.tgfoid\n        JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace\n        WHERE t.tgrelid=:oid AND NOT t.tgisinternal ORDER BY t.tgname",
        "SELECT pg_catalog.to_jsonb(ROW(t.oid::bigint,t.tgfoid::bigint,t.tgname,p.proname,t.tgtype,t.tgdeferrable,t.tginitdeferred,t.tgenabled,t.tgnargs,t.tgattr::text,t.tgqual,t.tgargs,t.tgoldtable,t.tgnewtable,t.tgparentid::bigint,n.nspname)) AS row_values, t.tgname AS row_order FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_proc p ON p.oid=t.tgfoid\n        JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace\n        WHERE t.tgrelid=:oid AND NOT t.tgisinternal ORDER BY t.tgname",
        16,
    ),
    "constraints": (
        "SELECT k.oid,k.conname,k.contype,pg_get_constraintdef(k.oid,false),k.conkey,\n        k.convalidated,k.condeferrable,k.condeferred,k.conislocal,k.coninhcount,k.conparentid,\n        k.confrelid,k.conindid,k.conbin::text FROM pg_catalog.pg_constraint k\n        WHERE k.conrelid=:oid ORDER BY k.conname",
        "SELECT pg_catalog.to_jsonb(ROW(k.oid::bigint,k.conname,k.contype,pg_get_constraintdef(k.oid,false),k.conkey,k.convalidated,k.condeferrable,k.condeferred,k.conislocal,k.coninhcount,k.conparentid::bigint,k.confrelid::bigint,k.conindid::bigint,k.conbin::text)) AS row_values, k.conname AS row_order FROM pg_catalog.pg_constraint k\n        WHERE k.conrelid=:oid ORDER BY k.conname",
        14,
    ),
    "function": (
        "SELECT p.oid,p.proowner,p.prosrc,p.prosecdef,p.proconfig,p.provolatile,\n            p.prorettype = 'pg_catalog.trigger'::regtype,p.pronargs,p.prokind,l.lanname,\n            pg_catalog.pg_has_role(current_user,p.proowner,'MEMBER'),\n            pg_catalog.has_function_privilege(current_user,p.oid,'EXECUTE')\n            FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace\n            JOIN pg_catalog.pg_language l ON l.oid=p.prolang\n            WHERE n.nspname='public' AND p.proname=:name",
        "SELECT pg_catalog.to_jsonb(ROW(p.oid::bigint,p.proowner::bigint,p.prosrc,p.prosecdef,p.proconfig,p.provolatile,p.prorettype = 'pg_catalog.trigger'::regtype,p.pronargs,p.prokind,l.lanname,pg_catalog.pg_has_role(current_user,p.proowner,'MEMBER'),pg_catalog.has_function_privilege(current_user,p.oid,'EXECUTE'))) AS row_values, NULL::text AS row_order FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace\n            JOIN pg_catalog.pg_language l ON l.oid=p.prolang\n            WHERE n.nspname='public' AND p.proname=:name",
        12,
    ),
    "table": (
        "SELECT c.oid,c.relowner,c.reltype,c.reltoastrelid,c.relkind,c.relrowsecurity,c.relforcerowsecurity,\n            pg_catalog.pg_has_role(current_user,c.relowner,'MEMBER'),\n            pg_catalog.has_table_privilege(current_user,c.oid,'SELECT'),\n            pg_catalog.has_table_privilege(current_user,c.oid,'INSERT'),\n            pg_catalog.has_any_column_privilege(current_user,c.oid,'UPDATE'),\n            pg_catalog.has_table_privilege(current_user,c.oid,'DELETE'),\n            pg_catalog.has_table_privilege(current_user,c.oid,'TRUNCATE'),\n            pg_catalog.has_table_privilege(current_user,c.oid,'TRIGGER')\n            FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace\n            WHERE n.nspname='public' AND c.relname=:name",
        "SELECT pg_catalog.to_jsonb(ROW(c.oid::bigint,c.relowner::bigint,c.reltype::bigint,c.reltoastrelid::bigint,c.relkind,c.relrowsecurity,c.relforcerowsecurity,pg_catalog.pg_has_role(current_user,c.relowner,'MEMBER'),pg_catalog.has_table_privilege(current_user,c.oid,'SELECT'),pg_catalog.has_table_privilege(current_user,c.oid,'INSERT'),pg_catalog.has_any_column_privilege(current_user,c.oid,'UPDATE'),pg_catalog.has_table_privilege(current_user,c.oid,'DELETE'),pg_catalog.has_table_privilege(current_user,c.oid,'TRUNCATE'),pg_catalog.has_table_privilege(current_user,c.oid,'TRIGGER'))) AS row_values, NULL::text AS row_order FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace\n            WHERE n.nspname='public' AND c.relname=:name",
        14,
    ),
    "columns": (
        "SELECT a.attname,pg_catalog.format_type(a.atttypid,a.atttypmod),a.attnotnull\n            FROM pg_catalog.pg_attribute a WHERE a.attrelid=:oid AND a.attnum>0 AND NOT a.attisdropped\n            ORDER BY a.attnum",
        "SELECT pg_catalog.to_jsonb(ROW(a.attname,pg_catalog.format_type(a.atttypid,a.atttypmod),a.attnotnull)) AS row_values, a.attnum AS row_order FROM pg_catalog.pg_attribute a WHERE a.attrelid=:oid AND a.attnum>0 AND NOT a.attisdropped\n            ORDER BY a.attnum",
        3,
    ),
    "toast": (
        "SELECT pg_has_role(current_user,relowner,'MEMBER') FROM pg_catalog.pg_class\n            WHERE oid = :oid",
        "SELECT pg_catalog.to_jsonb(ROW(pg_has_role(current_user,relowner,'MEMBER'))) AS row_values, NULL::text AS row_order FROM pg_catalog.pg_class\n            WHERE oid = :oid",
        1,
    ),
    "legacy_function": (
        "SELECT p.oid,p.proowner,p.prosrc,p.prosecdef,p.proconfig,p.provolatile,\n            p.prorettype='pg_catalog.trigger'::regtype,p.pronargs,p.prokind,l.lanname,\n            pg_has_role(current_user,p.proowner,'MEMBER')\n            FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace\n            JOIN pg_catalog.pg_language l ON l.oid=p.prolang\n            WHERE n.nspname='public' AND p.proname=:name",
        "SELECT pg_catalog.to_jsonb(ROW(p.oid::bigint,p.proowner::bigint,p.prosrc,p.prosecdef,p.proconfig,p.provolatile,p.prorettype='pg_catalog.trigger'::regtype,p.pronargs,p.prokind,l.lanname,pg_has_role(current_user,p.proowner,'MEMBER'))) AS row_values, NULL::text AS row_order FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace\n            JOIN pg_catalog.pg_language l ON l.oid=p.prolang\n            WHERE n.nspname='public' AND p.proname=:name",
        11,
    ),
    "legacy_table": (
        "SELECT c.oid,c.relowner,\n            to_regclass(:name)::oid = c.oid, pg_has_role(current_user,c.relowner,'MEMBER')\n            FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace\n            WHERE n.nspname='public' AND c.relname=:name",
        "SELECT pg_catalog.to_jsonb(ROW(c.oid::bigint,c.relowner::bigint,to_regclass(:name)::oid = c.oid,pg_has_role(current_user,c.relowner,'MEMBER'))) AS row_values, NULL::text AS row_order FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace\n            WHERE n.nspname='public' AND c.relname=:name",
        4,
    ),
    "column_privileges": (
        "SELECT has_any_column_privilege(current_user,:oid,'REFERENCES') OR\n            (has_any_column_privilege(current_user,:oid,'INSERT') AND :readonly)",
        "SELECT pg_catalog.to_jsonb(ROW(has_any_column_privilege(current_user,:oid,'REFERENCES') OR\n            (has_any_column_privilege(current_user,:oid,'INSERT') AND :readonly))) AS row_values, NULL::text AS row_order ",
        1,
    ),
    "target": (
        "SELECT to_regclass(:target)::oid",
        "SELECT pg_catalog.to_jsonb(ROW(to_regclass(:target)::oid::bigint)) AS row_values, NULL::text AS row_order ",
        1,
    ),
    "index": (
        "SELECT indisvalid,indisready,indislive,indisunique,indexprs,indpred,\n                am.amname FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid\n                JOIN pg_catalog.pg_am am ON am.oid=c.relam WHERE i.indexrelid=:oid",
        "SELECT pg_catalog.to_jsonb(ROW(indisvalid,indisready,indislive,indisunique,indexprs,indpred,\n                am.amname)) AS row_values, NULL::text AS row_order FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid\n                JOIN pg_catalog.pg_am am ON am.oid=c.relam WHERE i.indexrelid=:oid",
        7,
    ),
}


def _catalog_key(statement, values=None):
    values = values or {}
    if type(statement) is not str or type(values) is not dict:
        raise V2IssuanceUnavailable()
    # SQLAlchemy's own metadata uses this exact str subtype for table names.
    # Normalize only that known type; arbitrary subclasses remain rejected.
    values = {k: str(v) if type(v) is quoted_name else v for k, v in values.items()}
    if any(type(k) is not str or type(v) not in (str, int, bool) for k, v in values.items()):
        raise V2IssuanceUnavailable()
    return statement, tuple((k, type(v), v) for k, v in sorted(values.items()))


def _catalog_freeze(value):
    if type(value) is list:
        return tuple(_catalog_freeze(v) for v in value)
    if type(value) not in (str, int, bool, bytes, type(None)):
        raise V2IssuanceUnavailable()
    return value


def _catalog_copy(value):
    return [_catalog_copy(v) for v in value] if type(value) is tuple else value


class _CatalogRows:
    def __init__(self, rows):
        self._rows = tuple(tuple(_catalog_freeze(v) for v in row) for row in rows)

    def all(self):
        return [tuple(_catalog_copy(v) for v in row) for row in self._rows]

    def one(self):
        rows = self.all()
        if len(rows) != 1:
            raise V2IssuanceUnavailable()
        return rows[0]

    def scalar_one(self):
        row = self.one()
        if len(row) != 1:
            raise V2IssuanceUnavailable()
        return row[0]


class _CatalogObservation:
    """Three fresh bounded catalog batches, private to ONE attestation."""

    def __init__(self, guard):
        self.guard = guard
        self._rows = {}
        self._chain = guard._check_objects()
        first = [("role", {}), ("schema", {})]
        first += [("function", {"name": name}) for name in FUNCTIONS]
        first += [("legacy_function", {"name": name}) for name in LEGACY_FUNCTION_HASHES]
        first += [("table", {"name": table.name}) for table in V2Base.metadata.sorted_tables]
        first += [("legacy_table", {"name": name}) for name in OWNER_TRIGGERS]
        targets = sorted({c[4][0] for rows in CONSTRAINTS.values() for c in rows if c[4] is not None})
        first += [("target", {"target": "public." + name}) for name in targets]
        self._fetch(first)
        second = []
        for table in V2Base.metadata.sorted_tables:
            row = self.sql(_CATALOG_SELECTS["table"][0], {"name": table.name}).one()
            if len(row) != 14 or type(row[0]) is not int or type(row[3]) is not int:
                raise V2IssuanceUnavailable()
            insert_allowed = table.name not in (
                V2Invalidation.__tablename__,
                V2BindingBirth.__tablename__,
                V2TokenBirth.__tablename__,
            )
            second += [(tag, {"oid": row[0]}) for tag in ("columns", "constraints", "triggers")]
            second += [
                ("toast", {"oid": row[3]}),
                ("column_privileges", {"oid": row[0], "readonly": not insert_allowed}),
            ]
        for name in OWNER_TRIGGERS:
            row = self.sql(_CATALOG_SELECTS["legacy_table"][0], {"name": name}).one()
            if len(row) != 4 or type(row[0]) is not int:
                raise V2IssuanceUnavailable()
            second.append(("triggers", {"oid": row[0]}))
        self._fetch(second)
        indices = set()
        for table in V2Base.metadata.sorted_tables:
            oid = self.sql(_CATALOG_SELECTS["table"][0], {"name": table.name}).one()[0]
            for row in self.sql(_CATALOG_SELECTS["constraints"][0], {"oid": oid}).all():
                if len(row) != 14:
                    raise V2IssuanceUnavailable()
                if row[2] in ("p", "u", "f"):
                    if type(row[12]) is not int or row[12] <= 0:
                        raise V2IssuanceUnavailable()
                    indices.add(row[12])
        self._fetch([("index", {"oid": oid}) for oid in sorted(indices)])

    def _objects(self):
        if self.guard._check_objects() != self._chain:
            raise V2IssuanceUnavailable()

    def _fetch(self, specifications):
        # Several tables legitimately share the absent-TOAST OID zero. Merge
        # identical fixed selectors inside this invocation, never across calls.
        specifications = list(
            {_catalog_key(_CATALOG_SELECTS[tag][0], values): (tag, values) for tag, values in specifications}.values()
        )
        if not specifications:
            return
        if not 1 <= len(specifications) <= 96:
            raise V2IssuanceUnavailable()
        terms, parameters, expected = [], {}, []
        for i, (tag, values) in enumerate(specifications):
            source, query, width = _CATALOG_SELECTS[tag]
            key = _catalog_key(source, values)
            if key in self._rows or any(item[0] == key for item in expected):
                raise V2IssuanceUnavailable()
            names = set(re.findall(r"(?<!:):([a-z_]+)", query))
            if names != set(values):
                raise V2IssuanceUnavailable()
            query = re.sub(r"(?<!:):([a-z_]+)", lambda m: ":catalog_" + str(i) + "_" + m[1], query)
            parameters.update({"catalog_" + str(i) + "_" + name: value for name, value in values.items()})
            terms.append(
                "(SELECT COALESCE(pg_catalog.jsonb_agg(catalog_rows.row_values "
                "ORDER BY catalog_rows.row_order), '[]'::jsonb) "
                "FROM (" + query + ") AS catalog_rows)"
            )
            expected.append((key, tag, width))
        self._objects()
        observed = self.guard.sql(
            "SELECT pg_catalog.jsonb_build_array(" + ",".join(terms) + ")", parameters
        ).scalar_one()
        self._objects()
        if type(observed) is not list or len(observed) != len(expected):
            raise V2IssuanceUnavailable()
        for (key, tag, width), raw_rows in zip(expected, observed):
            if type(raw_rows) is not list or len(raw_rows) > 2048:
                raise V2IssuanceUnavailable()
            rows = []
            fields = {"f" + str(i) for i in range(1, width + 1)}
            for raw in raw_rows:
                if type(raw) is not dict or set(raw) != fields:
                    raise V2IssuanceUnavailable()
                row = [raw["f" + str(i)] for i in range(1, width + 1)]
                if tag == "triggers":
                    value = row[11]
                    if type(value) is not str or re.fullmatch(r"\\x(?:[0-9a-f]{2})*", value) is None:
                        raise V2IssuanceUnavailable()
                    row[11] = bytes.fromhex(value[2:])
                rows.append(tuple(row))
            self._rows[key] = _CatalogRows(rows)

    def sql(self, statement, values=None):
        self._objects()
        key = _catalog_key(statement, values)
        if key not in self._rows:
            raise V2IssuanceUnavailable()
        result = self._rows[key]
        self._objects()
        return result

    def check(self):
        self._objects()
        self.guard.check()
        self._objects()


def attest(guard):
    try:
        return _attest_catalog(_CatalogObservation(guard))
    except Exception:
        guard.poisoned = True
        raise V2IssuanceUnavailable() from None


def _runtime_role_identity(guard):
    """Two closed profiles; direct/effective memberships and identity are pinned."""
    role = guard.sql("""SELECT r.rolsuper,r.rolcreaterole,r.rolcreatedb,r.rolreplication,r.rolbypassrls,
        (SELECT count(*) FROM pg_catalog.pg_auth_members WHERE member = r.oid),
        ARRAY(SELECT candidate.rolname::text FROM pg_catalog.pg_roles AS candidate
            WHERE candidate.oid <> r.oid AND pg_catalog.pg_has_role(r.oid,candidate.oid,'MEMBER')
            ORDER BY candidate.rolname) AS member_roles,
        ARRAY(SELECT candidate.oid::bigint FROM pg_catalog.pg_roles AS candidate
            WHERE candidate.oid <> r.oid AND pg_catalog.pg_has_role(r.oid,candidate.oid,'MEMBER')
            ORDER BY candidate.rolname) AS member_role_oids,
        r.oid::bigint,r.rolinherit,r.rolcanlogin,
        EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members WHERE member = r.oid AND admin_option)
        FROM pg_catalog.pg_roles r WHERE rolname = current_user""").one()
    if len(role) != 12 or any(value is not False for value in role[:5]):
        raise V2IssuanceUnavailable()
    if (
        type(role[5]) is not int
        or type(role[6]) not in (list, tuple)
        or type(role[7]) not in (list, tuple)
        or type(role[8]) is not int
        or role[8] <= 0
        or type(role[9]) is not bool
        or role[10] is not True
        or role[11] is not False
    ):
        raise V2IssuanceUnavailable()
    names, oids = tuple(role[6]), tuple(role[7])
    standalone = role[5] == 0 and names == () and oids == ()
    composed = (
        role[5] == 1
        and names == ("pg_read_all_settings",)
        and len(oids) == 1
        and type(oids[0]) is int
        and oids[0] > 0
        and role[9] is True
    )
    if not (standalone or composed):
        raise V2IssuanceUnavailable()
    return (role[8], role[9], role[10], role[5], names, oids)


def _attest_catalog(guard):
    """Exact source/body/trigger and least-privilege checks, never name counts.

    DDL owners are trusted administrative principals. Runtime receives INSERT
    only on offers/parents/acceptances/issuances, SELECT on all seven, no UPDATE.
    """
    role_identity = _runtime_role_identity(guard)
    secure_role = guard.sql("""SELECT oid,nspowner,
        current_user = session_user AND pg_catalog.current_setting('session_replication_role') = 'origin'
        AND pg_catalog.has_schema_privilege(current_user,'public','USAGE')
        AND NOT pg_catalog.has_schema_privilege(current_user,'public','CREATE')
        AND NOT pg_catalog.pg_has_role(current_user,nspowner,'MEMBER')
        FROM pg_catalog.pg_namespace WHERE nspname='public'""").one()
    if secure_role[2] is not True:
        raise V2IssuanceUnavailable()
    # Pin the independently checked schema identity/owner across every recheck.
    identities = [tuple(secure_role[:2]), role_identity]
    for name, body in FUNCTIONS.items():
        row = guard.sql(
            """SELECT p.oid,p.proowner,p.prosrc,p.prosecdef,p.proconfig,p.provolatile,
            p.prorettype = 'pg_catalog.trigger'::regtype,p.pronargs,p.prokind,l.lanname,
            pg_catalog.pg_has_role(current_user,p.proowner,'MEMBER'),
            pg_catalog.has_function_privilege(current_user,p.oid,'EXECUTE')
            FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
            JOIN pg_catalog.pg_language l ON l.oid=p.prolang
            WHERE n.nspname='public' AND p.proname=:name""",
            {"name": name},
        ).all()
        if len(row) != 1:
            raise V2IssuanceUnavailable()
        row = row[0]
        if tuple(row[2:]) != (body, True, list(FUNCTION_CONFIGS[name]), "v", True, 0, "f", "plpgsql", False, False):
            raise V2IssuanceUnavailable()
        identities.append(tuple(row[:2]))
    identities.extend(_attest_legacy(guard))
    for table in V2Base.metadata.sorted_tables:
        name = table.name
        row = guard.sql(
            """SELECT c.oid,c.relowner,c.reltype,c.reltoastrelid,c.relkind,c.relrowsecurity,c.relforcerowsecurity,
            pg_catalog.pg_has_role(current_user,c.relowner,'MEMBER'),
            pg_catalog.has_table_privilege(current_user,c.oid,'SELECT'),
            pg_catalog.has_table_privilege(current_user,c.oid,'INSERT'),
            pg_catalog.has_any_column_privilege(current_user,c.oid,'UPDATE'),
            pg_catalog.has_table_privilege(current_user,c.oid,'DELETE'),
            pg_catalog.has_table_privilege(current_user,c.oid,'TRUNCATE'),
            pg_catalog.has_table_privilege(current_user,c.oid,'TRIGGER')
            FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname='public' AND c.relname=:name""",
            {"name": name},
        ).one()
        insert_allowed = name not in (
            V2Invalidation.__tablename__,
            V2BindingBirth.__tablename__,
            V2TokenBirth.__tablename__,
        )
        if tuple(row[4:]) != ("r", False, False, False, True, insert_allowed, False, False, False, False):
            raise V2IssuanceUnavailable()
        identities.append(tuple(row[:4]))
        columns = guard.sql(
            """SELECT a.attname,pg_catalog.format_type(a.atttypid,a.atttypmod),a.attnotnull
            FROM pg_catalog.pg_attribute a WHERE a.attrelid=:oid AND a.attnum>0 AND NOT a.attisdropped
            ORDER BY a.attnum""",
            {"oid": row[0]},
        ).all()
        expected = [
            (
                c.name,
                (
                    "bigint"
                    if isinstance(c.type, BigInteger)
                    else "text" if isinstance(c.type, Text) else f"character varying({c.type.length})"
                ),
                not c.nullable,
            )
            for c in table.columns
        ]
        if [tuple(c) for c in columns] != expected:
            raise V2IssuanceUnavailable()
        _attest_constraints(guard, name, row[0], identities)
        toast = guard.sql(
            """SELECT pg_has_role(current_user,relowner,'MEMBER') FROM pg_catalog.pg_class
            WHERE oid = :oid""",
            {"oid": row[3]},
        ).all()
        if toast and tuple(toast[0]) != (False,):
            raise V2IssuanceUnavailable()
        if (
            guard.sql(
                """SELECT has_any_column_privilege(current_user,:oid,'REFERENCES') OR
            (has_any_column_privilege(current_user,:oid,'INSERT') AND :readonly)""",
                {"oid": row[0], "readonly": not insert_allowed},
            ).scalar_one()
            is not False
        ):
            raise V2IssuanceUnavailable()
        # Exact complete non-internal trigger bindings; no WHEN/args/extra triggers.
        expected_triggers = {
            "v2_immutable": ("social_session_v2_immutable", 27, False, False),
            "v2_no_truncate": ("social_session_v2_immutable", 34, False, False),
        }
        if insert_allowed:
            expected_triggers["v2_insert"] = ("social_session_v2_guard", 7, False, False)
        if name == V2Offer.__tablename__:
            expected_triggers["v2_complete"] = ("social_session_v2_complete", 5, True, True)
        identities.extend(_attest_triggers(guard, row[0], expected_triggers))
    guard.check()
    return hashlib.sha256(repr(identities).encode("ascii")).hexdigest()


def trigger_definitions(table):
    result = [
        f"CREATE TRIGGER v2_immutable BEFORE DELETE OR UPDATE ON public.{table} "
        "FOR EACH ROW EXECUTE FUNCTION social_session_v2_immutable()",
        f"CREATE TRIGGER v2_no_truncate BEFORE TRUNCATE ON public.{table} "
        "FOR EACH STATEMENT EXECUTE FUNCTION social_session_v2_immutable()",
    ]
    if table not in (V2Invalidation.__tablename__, V2BindingBirth.__tablename__, V2TokenBirth.__tablename__):
        result.append(
            f"CREATE TRIGGER v2_insert BEFORE INSERT ON public.{table} "
            "FOR EACH ROW EXECUTE FUNCTION social_session_v2_guard()"
        )
    if table == V2Offer.__tablename__:
        result.append(
            f"CREATE CONSTRAINT TRIGGER v2_complete AFTER INSERT ON public.{table} "
            "DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION social_session_v2_complete()"
        )
    return result


# Closed native constraint inventory. Renderings are source expectations, not PG proof.
CONSTRAINTS: dict[str, list] = {
    "social_session_v2_offers": [
        ("social_session_v2_offers_pkey", "p", "PRIMARY KEY (operation_id)", [1], None),
        ("social_session_v2_offers_u0", "u", "UNIQUE (request_id)", [2], None),
        ("social_session_v2_offers_u1", "u", "UNIQUE (authorization_digest)", [3], None),
        (
            "social_session_v2_offers_c_operation_id",
            "c",
            "CHECK (((operation_id)::text ~ '^[0-9a-f]{64}$'::text))",
            [1],
            None,
        ),
        (
            "social_session_v2_offers_c_request_id",
            "c",
            "CHECK (((request_id)::text ~ '^[0-9a-f]{64}$'::text))",
            [2],
            None,
        ),
        (
            "social_session_v2_offers_c_authorization_digest",
            "c",
            "CHECK (((authorization_digest)::text ~ '^[0-9a-f]{64}$'::text))",
            [3],
            None,
        ),
        (
            "social_session_v2_offers_c_wire",
            "c",
            "CHECK ((((octet_length(wire) >= 1) AND (octet_length(wire) <= 16384)) AND (wire !~ '[^ -~]'::text)))",
            [4],
            None,
        ),
        ("social_session_v2_offers_c_subject", "c", "CHECK (((subject)::text ~ '^[0-9a-f]{64}$'::text))", [5], None),
        (
            "social_session_v2_offers_c_created_at",
            "c",
            "CHECK (((created_at >= 0) AND (created_at <= '9007199254740991'::bigint)))",
            [10],
            None,
        ),
        (
            "social_session_v2_offers_c_expires_at",
            "c",
            "CHECK (((expires_at >= 0) AND (expires_at <= '9007199254740991'::bigint)))",
            [11],
            None,
        ),
        (
            "social_session_v2_offers_c_interval",
            "c",
            "CHECK (((created_at < expires_at) AND (expires_at <= (created_at + 300000))))",
            [10, 11],
            None,
        ),
    ],
    "social_session_v2_parents": [
        ("social_session_v2_parents_pkey", "p", "PRIMARY KEY (operation_id)", [1], None),
        (
            "social_session_v2_parents_f0",
            "f",
            "FOREIGN KEY (operation_id) REFERENCES social_session_v2_offers(operation_id)",
            [1],
            ("social_session_v2_offers", ("operation_id",)),
        ),
        (
            "social_session_v2_parents_f1",
            "f",
            "FOREIGN KEY (token_id) REFERENCES oauth_session_generations(token_id)",
            [2],
            ("oauth_session_generations", ("token_id",)),
        ),
        (
            "social_session_v2_parents_f2",
            "f",
            "FOREIGN KEY (session_id) REFERENCES sessions(session_id)",
            [3],
            ("sessions", ("session_id",)),
        ),
        (
            "social_session_v2_parents_f3",
            "f",
            "FOREIGN KEY (browser_id) REFERENCES oauth_browser_generations(generation_id)",
            [4],
            ("oauth_browser_generations", ("generation_id",)),
        ),
        ("social_session_v2_parents_f4", "f", "FOREIGN KEY (user_id) REFERENCES users(id)", [5], ("users", ("id",))),
        (
            "social_session_v2_parents_c_operation_id",
            "c",
            "CHECK (((operation_id)::text ~ '^[0-9a-f]{64}$'::text))",
            [1],
            None,
        ),
        (
            "social_session_v2_parents_c_browser_id",
            "c",
            "CHECK (((browser_id)::text ~ '^[0-9a-f]{64}$'::text))",
            [4],
            None,
        ),
        (
            "social_session_v2_parents_c_continuity",
            "c",
            "CHECK (((continuity)::text ~ '^[0-9a-f]{64}$'::text))",
            [6],
            None,
        ),
    ],
    "social_session_v2_acceptances": [
        ("social_session_v2_acceptances_pkey", "p", "PRIMARY KEY (operation_id)", [1], None),
        ("social_session_v2_acceptances_u0", "u", "UNIQUE (acceptance_id)", [2], None),
        ("social_session_v2_acceptances_u1", "u", "UNIQUE (approval_id)", [3], None),
        ("social_session_v2_acceptances_u2", "u", "UNIQUE (binding_id)", [6], None),
        ("social_session_v2_acceptances_u3", "u", "UNIQUE (operation_id, acceptance_id)", [1, 2], None),
        (
            "social_session_v2_acceptances_f0",
            "f",
            "FOREIGN KEY (operation_id) REFERENCES social_session_v2_parents(operation_id)",
            [1],
            ("social_session_v2_parents", ("operation_id",)),
        ),
        (
            "social_session_v2_acceptances_f1",
            "f",
            "FOREIGN KEY (binding_id) REFERENCES social_messaging_device_bindings(binding_id)",
            [6],
            ("social_messaging_device_bindings", ("binding_id",)),
        ),
        (
            "social_session_v2_acceptances_c_operation_id",
            "c",
            "CHECK (((operation_id)::text ~ '^[0-9a-f]{64}$'::text))",
            [1],
            None,
        ),
        (
            "social_session_v2_acceptances_c_acceptance_id",
            "c",
            "CHECK (((acceptance_id)::text ~ '^[0-9a-f]{64}$'::text))",
            [2],
            None,
        ),
        (
            "social_session_v2_acceptances_c_approval_id",
            "c",
            "CHECK (((approval_id)::text ~ '^[0-9a-f]{64}$'::text))",
            [3],
            None,
        ),
        (
            "social_session_v2_acceptances_c_approval_wire",
            "c",
            "CHECK ((((octet_length(approval_wire) >= 1) AND (octet_length(approval_wire) <= 24576)) AND (approval_wire !~ '[^ -~]'::text)))",
            [4],
            None,
        ),
        (
            "social_session_v2_acceptances_c_wire",
            "c",
            "CHECK ((((octet_length(wire) >= 1) AND (octet_length(wire) <= 4096)) AND (wire !~ '[^ -~]'::text)))",
            [5],
            None,
        ),
        (
            "social_session_v2_acceptances_c_binding_id",
            "c",
            "CHECK (((binding_id)::text ~ '^[0-9a-f]{64}$'::text))",
            [6],
            None,
        ),
        (
            "social_session_v2_acceptances_c_accepted_at",
            "c",
            "CHECK (((accepted_at >= 0) AND (accepted_at <= '9007199254740991'::bigint)))",
            [7],
            None,
        ),
        (
            "social_session_v2_acceptances_c_possession_proof",
            "c",
            "CHECK (((possession_proof)::text ~ '^[0-9a-f]{64}$'::text))",
            [8],
            None,
        ),
        (
            "social_session_v2_acceptances_c_full_source_hash",
            "c",
            "CHECK (((full_source_hash)::text ~ '^[0-9a-f]{64}$'::text))",
            [11],
            None,
        ),
        (
            "social_session_v2_acceptances_c_full_expires_at",
            "c",
            "CHECK (((full_expires_at >= 0) AND (full_expires_at <= '9007199254740991'::bigint)))",
            [13],
            None,
        ),
    ],
    "social_session_v2_issuances": [
        ("social_session_v2_issuances_pkey", "p", "PRIMARY KEY (operation_id)", [1], None),
        ("social_session_v2_issuances_u0", "u", "UNIQUE (issuance_id)", [3], None),
        ("social_session_v2_issuances_u1", "u", "UNIQUE (token_id)", [4], None),
        (
            "social_session_v2_issuances_f0",
            "f",
            "FOREIGN KEY (operation_id, acceptance_id) REFERENCES social_session_v2_acceptances(operation_id, acceptance_id)",
            [1, 2],
            ("social_session_v2_acceptances", ("operation_id", "acceptance_id")),
        ),
        (
            "social_session_v2_issuances_f1",
            "f",
            "FOREIGN KEY (token_id, user_id, client_id) REFERENCES oauth_tokens(id, user_id, client_id)",
            [4, 11, 7],
            ("oauth_tokens", ("id", "user_id", "client_id")),
        ),
        (
            "social_session_v2_issuances_c_operation_id",
            "c",
            "CHECK (((operation_id)::text ~ '^[0-9a-f]{64}$'::text))",
            [1],
            None,
        ),
        (
            "social_session_v2_issuances_c_acceptance_id",
            "c",
            "CHECK (((acceptance_id)::text ~ '^[0-9a-f]{64}$'::text))",
            [2],
            None,
        ),
        (
            "social_session_v2_issuances_c_issuance_id",
            "c",
            "CHECK (((issuance_id)::text ~ '^[0-9a-f]{64}$'::text))",
            [3],
            None,
        ),
        (
            "social_session_v2_issuances_c_revision",
            "c",
            "CHECK (((revision)::text ~ '^[0-9a-f]{64}$'::text))",
            [5],
            None,
        ),
        ("social_session_v2_issuances_c_subject", "c", "CHECK (((subject)::text ~ '^[0-9a-f]{64}$'::text))", [6], None),
        (
            "social_session_v2_issuances_c_delivery_commitment",
            "c",
            "CHECK (((delivery_commitment)::text ~ '^[0-9a-f]{64}$'::text))",
            [12],
            None,
        ),
        (
            "social_session_v2_issuances_c_issued_at",
            "c",
            "CHECK (((issued_at >= 0) AND (issued_at <= '9007199254740991'::bigint)))",
            [13],
            None,
        ),
        (
            "social_session_v2_issuances_c_expires_at",
            "c",
            "CHECK (((expires_at >= 0) AND (expires_at <= '9007199254740991'::bigint)))",
            [14],
            None,
        ),
        (
            "social_session_v2_issuances_c_interval",
            "c",
            "CHECK (((issued_at < expires_at) AND (expires_at <= (issued_at + 300))))",
            [13, 14],
            None,
        ),
    ],
    "social_session_v2_invalidations": [
        ("social_session_v2_invalidations_pkey", "p", "PRIMARY KEY (operation_id)", [1], None),
        (
            "social_session_v2_invalidations_f0",
            "f",
            "FOREIGN KEY (operation_id) REFERENCES social_session_v2_offers(operation_id)",
            [1],
            ("social_session_v2_offers", ("operation_id",)),
        ),
        (
            "social_session_v2_invalidations_c_operation_id",
            "c",
            "CHECK (((operation_id)::text ~ '^[0-9a-f]{64}$'::text))",
            [1],
            None,
        ),
    ],
    "social_session_v2_binding_births": [
        ("social_session_v2_binding_births_pkey", "p", "PRIMARY KEY (binding_id)", [1], None),
        ("social_session_v2_binding_births_u0", "u", "UNIQUE (operation_id)", [2], None),
        (
            "social_session_v2_binding_births_f0",
            "f",
            "FOREIGN KEY (operation_id) REFERENCES social_session_v2_offers(operation_id)",
            [2],
            ("social_session_v2_offers", ("operation_id",)),
        ),
        (
            "social_session_v2_binding_births_f1",
            "f",
            "FOREIGN KEY (binding_id) REFERENCES social_messaging_device_bindings(binding_id)",
            [1],
            ("social_messaging_device_bindings", ("binding_id",)),
        ),
        (
            "social_session_v2_binding_births_c_binding_id",
            "c",
            "CHECK (((binding_id)::text ~ '^[0-9a-f]{64}$'::text))",
            [1],
            None,
        ),
        (
            "social_session_v2_binding_births_c_operation_id",
            "c",
            "CHECK (((operation_id)::text ~ '^[0-9a-f]{64}$'::text))",
            [2],
            None,
        ),
    ],
    "social_session_v2_token_births": [
        ("social_session_v2_token_births_pkey", "p", "PRIMARY KEY (token_id)", [1], None)
    ],
}

LEGACY_FUNCTION_HASHES = {
    "guard_social_mobile_operation_v1": "f23ede06c0d1d429ad36fc72daf0db04e046738b2e8bc78e6240c9fc73b4a51c",
    "reject_social_device_authorization_mutation_v1": "9c7e3f3f5da43f3f40b9d9a30d620a323db4beeece845331b71d7b35c37105f7",
    "validate_social_mobile_acceptance_v1": "368018b77cd129572988dc678c552261bb49fe18d917595ca3b0de4145752844",
    "oauth_session_generation_guard_v1": "a2fb95677d81cc8930b29f978a3a3e9ef2c088fc1ffde1a66aada6f103886846",
    "oauth_mapped_session_guard_v1": "aca0c43e0994561654157867e38c1bea6f153fe63e4e7aee806657f8257d5e56",
    "oauth_token_session_invalidation_v1": "995266bebb200bbc91cf94e2bfffadc4cbda52848dd00bf776ac6a4706b43541",
    "oauth_owner_session_invalidation_v1": "16e4a66a3f5c7b6b118440feef00cdb85902d3578cb2bf80461b3b4e771ba39b",
    "oauth_browser_generation_guard_v1": "75d4d41e8546e29a17b7833c07a8787bc094c9ef028bdaba232e0ab142b42d85",
    "social_session_token_guard_v1": "8b2db94015a5d1dc02d9822dcb8de44e5eb2464368c96431289eae2ac7ddd80b",
    "social_session_parent_invalidation_v1": "36fce2b9c74c046265e992ce8f41c5e5c7d0f3606828e272f679ebebdd735b03",
    "social_session_binding_invalidation_v1": "4a471e0c14345e10cc7f00b3699908d8a8151af878838af6cbfc27524e55ae98",
    "social_session_issuer_guard_v1": "153825471d3d631ffb39da6444b726fc4e365076be8849d458489723826c31fa",
    "social_session_client_invalidation_v1": "1ddcb52fb8b34f1c05cb3ce7d18855d55b8d2a9f23a9335b2d45cadcfd539647",
}
OWNER_TRIGGERS = {
    "current_entitlement_evidence": {},
    "social_messaging_mobile_operations": {
        "trg_social_mobile_operation_guard": ("guard_social_mobile_operation_v1", 31, False, False),
        "trg_social_mobile_operation_receipt": ("validate_social_mobile_acceptance_v1", 21, True, True),
    },
    "social_messaging_device_authorization_binding_owners": {
        "trg_social_binding_owner_immutable": ("reject_social_device_authorization_mutation_v1", 27, False, False)
    },
    "oauth_session_generations": {
        "trg_oauth_generation_guard": ("oauth_session_generation_guard_v1", 31, False, False)
    },
    "sessions": {
        "trg_oauth_mapped_session_guard": ("oauth_mapped_session_guard_v1", 19, False, False),
        "trg_social_session_parent_invalidation": ("social_session_parent_invalidation_v1", 19, False, False),
        "v2_invalidate": ("social_session_v2_invalidate", 27, False, False),
    },
    "oauth_tokens": {
        "trg_oauth_token_session_invalidation": ("oauth_token_session_invalidation_v1", 19, False, False),
        "trg_social_session_token_guard": ("social_session_token_guard_v1", 19, False, False),
        "v2_invalidate": ("social_session_v2_invalidate", 27, False, False),
        "v2_birth": ("social_session_v2_birth", 5, False, False),
    },
    "users": {
        "trg_oauth_user_session_invalidation": ("oauth_owner_session_invalidation_v1", 19, False, False),
        "v2_invalidate": ("social_session_v2_invalidate", 27, False, False),
    },
    "oauth_clients": {
        "trg_oauth_client_session_invalidation": ("oauth_owner_session_invalidation_v1", 19, False, False),
        "trg_social_session_client_invalidation": ("social_session_client_invalidation_v1", 19, False, False),
        "v2_invalidate": ("social_session_v2_invalidate", 27, False, False),
    },
    "oauth_browser_generations": {
        "trg_oauth_browser_generation_guard": ("oauth_browser_generation_guard_v1", 31, False, False),
        "v2_invalidate": ("social_session_v2_invalidate", 27, False, False),
    },
    "social_messaging_device_bindings": {
        "trg_social_session_binding_invalidation": ("social_session_binding_invalidation_v1", 19, False, False),
        "v2_invalidate": ("social_session_v2_invalidate", 27, False, False),
        "v2_birth": ("social_session_v2_birth", 5, False, False),
    },
    "social_session_issuers": {
        "trg_social_session_issuer_guard": ("social_session_issuer_guard_v1", 31, False, False),
        "v2_invalidate": ("social_session_v2_invalidate", 27, False, False),
    },
}


def _attest_triggers(guard, oid, expected):
    rows = guard.sql(
        """SELECT t.oid,t.tgfoid,t.tgname,p.proname,t.tgtype,t.tgdeferrable,t.tginitdeferred,
        t.tgenabled,t.tgnargs,t.tgattr::text,t.tgqual,t.tgargs,t.tgoldtable,t.tgnewtable,t.tgparentid,
        n.nspname FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_proc p ON p.oid=t.tgfoid
        JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
        WHERE t.tgrelid=:oid AND NOT t.tgisinternal ORDER BY t.tgname""",
        {"oid": oid},
    ).all()
    if len(rows) != len(expected):
        raise V2IssuanceUnavailable()
    for row in rows:
        if row[2] not in expected or tuple(row[3:7]) != expected[row[2]]:
            raise V2IssuanceUnavailable()
        if (
            tuple(row[7:11]) != ("O", 0, "", None)
            or bytes(row[11]) != b""
            or tuple(row[12:]) != (None, None, 0, "public")
        ):
            raise V2IssuanceUnavailable()
    return [tuple(row[:2]) for row in rows]


def _attest_legacy(guard):
    identities = []
    for name, source_hash in LEGACY_FUNCTION_HASHES.items():
        rows = guard.sql(
            """SELECT p.oid,p.proowner,p.prosrc,p.prosecdef,p.proconfig,p.provolatile,
            p.prorettype='pg_catalog.trigger'::regtype,p.pronargs,p.prokind,l.lanname,
            pg_has_role(current_user,p.proowner,'MEMBER')
            FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
            JOIN pg_catalog.pg_language l ON l.oid=p.prolang
            WHERE n.nspname='public' AND p.proname=:name""",
            {"name": name},
        ).all()
        if len(rows) != 1:
            raise V2IssuanceUnavailable()
        row = rows[0]
        if hashlib.sha256(row[2].encode()).hexdigest() != source_hash or tuple(row[3:]) != (
            False,
            None,
            "v",
            True,
            0,
            "f",
            "plpgsql",
            False,
        ):
            raise V2IssuanceUnavailable()
        identities.append(tuple(row[:2]))
    for table, expected in OWNER_TRIGGERS.items():
        row = guard.sql(
            """SELECT c.oid,c.relowner,
            to_regclass(:name)::oid = c.oid, pg_has_role(current_user,c.relowner,'MEMBER')
            FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname='public' AND c.relname=:name""",
            {"name": table},
        ).one()
        if tuple(row[2:]) != (True, False):
            raise V2IssuanceUnavailable()
        identities.append(tuple(row[:2]))
        identities.extend(_attest_triggers(guard, row[0], expected))
    return identities


def _attest_constraints(guard, table, oid, identities):
    rows = guard.sql(
        """SELECT k.oid,k.conname,k.contype,pg_get_constraintdef(k.oid,false),k.conkey,
        k.convalidated,k.condeferrable,k.condeferred,k.conislocal,k.coninhcount,k.conparentid,
        k.confrelid,k.conindid,k.conbin::text FROM pg_catalog.pg_constraint k
        WHERE k.conrelid=:oid ORDER BY k.conname""",
        {"oid": oid},
    ).all()
    expected = {c[0]: c for c in CONSTRAINTS[table]}
    # The one native constraint trigger is also a pg_constraint row.
    if table == V2Offer.__tablename__:
        atomic = [r for r in rows if r[2] == "t"]
        if (
            len(atomic) != 1
            or atomic[0][1] != "v2_complete"
            or tuple(atomic[0][5:11]) != (True, True, True, True, 0, 0)
        ):
            raise V2IssuanceUnavailable()
        identities.append((atomic[0][0], atomic[0][13]))
        rows = [r for r in rows if r[2] != "t"]
    if len(rows) != len(expected):
        raise V2IssuanceUnavailable()
    for row in rows:
        exp = expected.get(row[1])
        if exp is None or row[2] != exp[1] or list(row[4]) != exp[3]:
            raise V2IssuanceUnavailable()
        # Qualification may differ with search_path; exact FK target identity is
        # checked independently. No cast stripping or broad expression matching.
        definitions = {exp[2]}
        if exp[4] is not None:
            definitions.add(exp[2].replace("REFERENCES ", "REFERENCES public.", 1))
            target = guard.sql("SELECT to_regclass(:target)::oid", {"target": "public." + exp[4][0]}).scalar_one()
            if row[11] != target:
                raise V2IssuanceUnavailable()
        if row[3] not in definitions or tuple(row[5:11]) != (True, False, False, True, 0, 0):
            raise V2IssuanceUnavailable()
        if row[2] in ("p", "u", "f"):
            idx = guard.sql(
                """SELECT indisvalid,indisready,indislive,indisunique,indexprs,indpred,
                am.amname FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid
                JOIN pg_catalog.pg_am am ON am.oid=c.relam WHERE i.indexrelid=:oid""",
                {"oid": row[12]},
            ).one()
            if tuple(idx) != (True, True, True, True, None, None, "btree"):
                raise V2IssuanceUnavailable()
        identities.append((row[0], row[11], row[12], row[13]))


CONSTRAINTS["social_session_v2_parents"].append(
    ("v2_parent_token_shape", "c", "CHECK (((token_id)::text ~ '^[0-9a-f]{32}$'::text))", [2], None)
)
CONSTRAINTS["social_session_v2_issuances"].append(
    ("v2_child_token_shape", "c", "CHECK (((token_id)::text ~ '^[0-9a-f]{32}$'::text))", [4], None)
)
