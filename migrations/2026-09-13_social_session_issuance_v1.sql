-- Dormant. Apply atomically after mobile authorization and OAuth lifecycle V1.
-- No backfill or automatic issuer registration. Roll back uncommitted DDL normally.
-- After use, retain all ledgers/guards and revoke authority; dropping history is
-- not an operational rollback. Service credentials remain external infrastructure.
CREATE TABLE social_session_issuers (
    client_id VARCHAR(255) PRIMARY KEY REFERENCES oauth_clients(client_id),
    backend_id VARCHAR(255) NOT NULL CHECK (length(backend_id) > 0),
    service_principal VARCHAR(255) NOT NULL CHECK (length(service_principal) > 0),
    is_active BOOLEAN NOT NULL,
    UNIQUE (client_id, backend_id, service_principal)
);
CREATE TABLE social_session_pairing_parents (
    operation_id VARCHAR(64) PRIMARY KEY REFERENCES social_messaging_mobile_operations(operation_id),
    parent_token_id VARCHAR(36) NOT NULL REFERENCES oauth_session_generations(token_id),
    client_id VARCHAR(255) NOT NULL REFERENCES social_session_issuers(client_id),
    UNIQUE (operation_id, parent_token_id, client_id)
);
CREATE FUNCTION social_session_parent_guard_v1() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP <> 'INSERT' OR NOT EXISTS (
        SELECT 1 FROM social_messaging_mobile_operations o
        JOIN oauth_session_generations g ON g.token_id = NEW.parent_token_id
        JOIN sessions s ON s.session_id = g.session_id
        JOIN oauth_tokens t ON t.id = g.token_id
        WHERE o.operation_id = NEW.operation_id AND o.method = 'qr_desktop_v1'
          AND o.status = 'created' AND o.source IS NULL AND o.subject = g.subject
          AND g.client_id = NEW.client_id AND s.is_active IS TRUE AND t.is_revoked IS FALSE
          -- An old unscanned offer cannot be adopted: linkage is created by the
          -- SAME transaction that inserted the offer, before it is released.
          AND o.xmin = (pg_current_xact_id()::text::xid)
    ) THEN RAISE EXCEPTION 'Social session issuance unavailable'; END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER trg_social_session_parent_guard BEFORE INSERT OR UPDATE OR DELETE ON social_session_pairing_parents
FOR EACH ROW EXECUTE FUNCTION social_session_parent_guard_v1();

CREATE TABLE social_session_issuances (
    operation_id VARCHAR(64) PRIMARY KEY REFERENCES social_messaging_mobile_session_handoffs(operation_id),
    issuance_id VARCHAR(64) NOT NULL UNIQUE CHECK (issuance_id ~ '^[0-9a-f]{64}$'),
    token_id VARCHAR(36) NOT NULL UNIQUE,
    parent_token_id VARCHAR(36) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    backend_id VARCHAR(255) NOT NULL,
    service_principal VARCHAR(255) NOT NULL,
    user_id VARCHAR(36) NOT NULL,
    subject VARCHAR(64) NOT NULL CHECK (subject ~ '^[0-9a-f]{64}$'),
    binding_id VARCHAR(64) NOT NULL REFERENCES social_messaging_device_bindings(binding_id),
    device_id VARCHAR(64) NOT NULL CHECK (device_id ~ '^[0-9a-f]{64}$'),
    method VARCHAR(24) NOT NULL CHECK (method = 'qr_desktop_v1'),
    operation VARCHAR(8) NOT NULL CHECK (operation IN ('register','rotate','adopt')),
    request_id VARCHAR(64) NOT NULL UNIQUE CHECK (request_id ~ '^[0-9a-f]{64}$'),
    authorization_digest VARCHAR(64) NOT NULL UNIQUE CHECK (authorization_digest ~ '^[0-9a-f]{64}$'),
    revision VARCHAR(64) NOT NULL CHECK (revision ~ '^[0-9a-f]{64}$'),
    delivery_commitment VARCHAR(64) NOT NULL CHECK (delivery_commitment ~ '^[0-9a-f]{64}$'),
    issued_at BIGINT NOT NULL CHECK (issued_at >= 0),
    expires_at BIGINT NOT NULL CHECK (issued_at < expires_at AND expires_at <= issued_at + 300),
    FOREIGN KEY (operation_id, parent_token_id, client_id)
        REFERENCES social_session_pairing_parents(operation_id, parent_token_id, client_id),
    FOREIGN KEY (client_id, backend_id, service_principal)
        REFERENCES social_session_issuers(client_id, backend_id, service_principal),
    FOREIGN KEY (token_id, user_id, client_id) REFERENCES oauth_tokens(id, user_id, client_id)
);
CREATE INDEX idx_social_session_parent ON social_session_issuances(parent_token_id);
CREATE INDEX idx_social_session_binding ON social_session_issuances(binding_id);
CREATE FUNCTION social_session_issuance_guard_v1() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN RAISE EXCEPTION 'Social session issuance unavailable'; END IF;
    -- Lock the real owners as well as enforcing unique handoff/credential
    -- ownership. Service additionally holds the established advisory locks.
    PERFORM 1 FROM users WHERE id = NEW.user_id FOR UPDATE;
    PERFORM 1 FROM oauth_clients WHERE client_id = NEW.client_id FOR UPDATE;
    PERFORM 1 FROM oauth_tokens WHERE id = NEW.parent_token_id FOR UPDATE;
    PERFORM 1 FROM sessions WHERE session_id IN (
        SELECT session_id FROM oauth_session_generations WHERE token_id = NEW.parent_token_id) FOR UPDATE;
    PERFORM 1 FROM social_messaging_device_bindings WHERE binding_id = NEW.binding_id FOR UPDATE;
    IF NOT EXISTS (
        SELECT 1 FROM social_messaging_mobile_operations o
        JOIN social_messaging_mobile_acceptances a USING(operation_id)
        JOIN social_messaging_mobile_exchanges e USING(operation_id)
        JOIN social_messaging_mobile_session_handoffs h USING(operation_id)
        JOIN oauth_session_generations g ON g.token_id = NEW.parent_token_id
        JOIN oauth_browser_generations bg ON bg.generation_id = g.browser_generation_id
        JOIN oauth_tokens p ON p.id = g.token_id
        JOIN sessions s ON s.session_id = g.session_id
        JOIN users u ON u.id = g.user_id
        JOIN oauth_clients c ON c.client_id = g.client_id
        JOIN social_session_issuers issuer ON issuer.client_id = c.client_id
        JOIN social_messaging_device_bindings b ON b.binding_id = a.binding_id
        JOIN oauth_tokens t ON t.id = NEW.token_id
        WHERE o.operation_id = NEW.operation_id AND o.status = 'accepted' AND o.method = NEW.method
          AND o.subject = NEW.subject AND o.request_id = NEW.request_id AND o.revision = NEW.revision
          AND o.authorization_digest = NEW.authorization_digest AND a.binding_id = NEW.binding_id
          AND g.user_id = NEW.user_id AND g.subject = NEW.subject AND g.client_id = NEW.client_id
          AND b.subject_pubkey = NEW.subject AND b.device_id = NEW.device_id AND b.active IS TRUE
          AND coalesce((o.source::jsonb->>'content')::jsonb->'authorization'->>'operation', 'adopt') = NEW.operation
          AND u.is_active IS TRUE AND u.pubkey = NEW.subject AND c.is_active IS TRUE AND issuer.is_active IS TRUE
          AND bg.is_active IS TRUE AND s.is_active IS TRUE AND p.is_revoked IS FALSE
          AND h.consumed_at <= NEW.issued_at AND o.created_at <= NEW.issued_at
          AND NEW.expires_at <= LEAST(o.expires_at, e.expires_at)
          AND b.valid_from <= to_timestamp(NEW.issued_at) AND to_timestamp(NEW.expires_at) <= b.expires_at
          AND s.created_at <= to_timestamp(NEW.issued_at) AT TIME ZONE 'UTC'
          AND to_timestamp(NEW.expires_at) AT TIME ZONE 'UTC' <= LEAST(s.expires_at,p.access_token_expires_at,bg.expires_at)
          AND t.user_id = NEW.user_id AND t.client_id = NEW.client_id AND t.is_revoked IS FALSE
          AND t.created_at = to_timestamp(NEW.issued_at) AT TIME ZONE 'UTC'
          AND t.access_token_expires_at = to_timestamp(NEW.expires_at) AT TIME ZONE 'UTC'
          AND t.scope = 'openid profile' AND t.token_type = 'Bearer'
          AND t.refresh_token IS NULL AND t.refresh_token_expires_at IS NULL
          AND t.metadata->>'token_contract' = 'hodlxxi.oauth.access-token.v1'
          AND t.metadata->>'token_use' = 'access'
          AND NOT EXISTS (SELECT 1 FROM oauth_session_generations WHERE token_id = t.id)
    ) THEN RAISE EXCEPTION 'Social session issuance unavailable'; END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER trg_social_session_issuance_guard BEFORE INSERT OR UPDATE OR DELETE ON social_session_issuances
FOR EACH ROW EXECUTE FUNCTION social_session_issuance_guard_v1();

CREATE FUNCTION social_session_token_guard_v1() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM social_session_issuances WHERE token_id = OLD.id) THEN
        IF ROW(NEW.id,NEW.user_id,NEW.client_id,NEW.access_token,NEW.created_at,NEW.scope,NEW.token_type,
               NEW.refresh_token,NEW.refresh_token_expires_at,NEW.metadata::text)
          IS DISTINCT FROM ROW(OLD.id,OLD.user_id,OLD.client_id,OLD.access_token,OLD.created_at,OLD.scope,OLD.token_type,
               OLD.refresh_token,OLD.refresh_token_expires_at,OLD.metadata::text)
          OR NEW.access_token_expires_at > OLD.access_token_expires_at OR NEW.is_revoked IS NULL
          OR (OLD.is_revoked IS TRUE AND NEW.is_revoked IS NOT TRUE)
        THEN RAISE EXCEPTION 'Social session issuance unavailable'; END IF;
        IF NEW.access_token_expires_at < OLD.access_token_expires_at THEN NEW.is_revoked := TRUE; END IF;
    END IF;
    -- Direct token revocation and browser replacement converge here; child
    -- credentials are invalidated in the same transaction as their parent.
    IF NEW.is_revoked IS TRUE OR NEW.access_token_expires_at < OLD.access_token_expires_at THEN
        UPDATE oauth_tokens SET is_revoked = TRUE WHERE id IN (
            SELECT token_id FROM social_session_issuances WHERE parent_token_id = OLD.id);
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER trg_social_session_token_guard BEFORE UPDATE ON oauth_tokens
FOR EACH ROW EXECUTE FUNCTION social_session_token_guard_v1();

CREATE FUNCTION social_session_parent_invalidation_v1() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.is_active IS NOT TRUE OR NEW.expires_at < OLD.expires_at THEN
        UPDATE oauth_tokens SET is_revoked = TRUE WHERE id IN (
            SELECT i.token_id FROM social_session_issuances i
            JOIN oauth_session_generations g ON g.token_id = i.parent_token_id WHERE g.session_id = OLD.session_id);
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER trg_social_session_parent_invalidation BEFORE UPDATE ON sessions
FOR EACH ROW EXECUTE FUNCTION social_session_parent_invalidation_v1();

CREATE FUNCTION social_session_binding_invalidation_v1() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    -- Any change to the accepted exact binding ends its authority permanently.
    -- Existing legitimate retirement/rotation writes still run unchanged.
    IF NEW IS DISTINCT FROM OLD THEN
        UPDATE oauth_tokens SET is_revoked = TRUE WHERE id IN (
            SELECT token_id FROM social_session_issuances WHERE binding_id = OLD.binding_id);
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER trg_social_session_binding_invalidation BEFORE UPDATE ON social_messaging_device_bindings
FOR EACH ROW EXECUTE FUNCTION social_session_binding_invalidation_v1();

CREATE FUNCTION social_session_issuer_guard_v1() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' OR (TG_OP = 'UPDATE' AND (
        ROW(NEW.client_id,NEW.backend_id,NEW.service_principal) IS DISTINCT FROM ROW(OLD.client_id,OLD.backend_id,OLD.service_principal)
        OR (OLD.is_active IS FALSE AND NEW.is_active IS TRUE)))
    THEN RAISE EXCEPTION 'Social session issuance unavailable'; END IF;
    IF TG_OP = 'UPDATE' AND NEW.is_active IS FALSE THEN
        UPDATE oauth_tokens SET is_revoked = TRUE WHERE id IN (
            SELECT token_id FROM social_session_issuances WHERE client_id = OLD.client_id);
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER trg_social_session_issuer_guard BEFORE INSERT OR UPDATE OR DELETE ON social_session_issuers
FOR EACH ROW EXECUTE FUNCTION social_session_issuer_guard_v1();

CREATE FUNCTION social_session_client_invalidation_v1() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.is_active IS NOT TRUE OR ROW(NEW.scope,NEW.metadata::text) IS DISTINCT FROM ROW(OLD.scope,OLD.metadata::text) THEN
        UPDATE oauth_tokens SET is_revoked = TRUE WHERE id IN (
            SELECT token_id FROM social_session_issuances WHERE client_id = OLD.client_id);
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER trg_social_session_client_invalidation BEFORE UPDATE ON oauth_clients
FOR EACH ROW EXECUTE FUNCTION social_session_client_invalidation_v1();
