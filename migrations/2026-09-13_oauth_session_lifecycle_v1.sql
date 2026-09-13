-- Apply only in an explicitly authorized transaction. No backfill of authority.
ALTER TABLE oauth_tokens ADD CONSTRAINT uq_oauth_token_generation_owner UNIQUE (id, user_id, client_id);
ALTER TABLE sessions ADD CONSTRAINT uq_session_generation_owner UNIQUE (session_id, user_id);

CREATE TABLE oauth_browser_generations (
    generation_id VARCHAR(64) PRIMARY KEY CHECK (generation_id ~ '^[0-9a-f]{64}$'),
    user_id VARCHAR(36) NOT NULL REFERENCES users(id),
    client_id VARCHAR(255) NOT NULL REFERENCES oauth_clients(client_id),
    subject VARCHAR(64) NOT NULL CHECK (subject ~ '^[0-9a-f]{64}$'),
    proof_id VARCHAR(64) NOT NULL UNIQUE CHECK (proof_id ~ '^[0-9a-f]{64}$'),
    created_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    is_active BOOLEAN NOT NULL,
    CONSTRAINT ck_browser_generation_lifetime CHECK (created_at < expires_at),
    CONSTRAINT uq_browser_generation_owner UNIQUE (generation_id, user_id, client_id, subject)
);
CREATE INDEX idx_browser_generation_owner ON oauth_browser_generations(user_id, client_id);
CREATE UNIQUE INDEX uq_browser_generation_current ON oauth_browser_generations(user_id, client_id)
    WHERE is_active IS TRUE;

CREATE TABLE oauth_session_code_bindings (
    code VARCHAR(255) PRIMARY KEY REFERENCES oauth_codes(code) ON DELETE CASCADE,
    browser_generation_id VARCHAR(64) NOT NULL REFERENCES oauth_browser_generations(generation_id),
    subject VARCHAR(64) NOT NULL CHECK (subject ~ '^[0-9a-f]{64}$')
);
CREATE INDEX idx_oauth_code_browser ON oauth_session_code_bindings(browser_generation_id);

CREATE TABLE oauth_session_generations (
    token_id VARCHAR(36) PRIMARY KEY,
    browser_generation_id VARCHAR(64) NOT NULL,
    session_id VARCHAR(255) NOT NULL UNIQUE,
    user_id VARCHAR(36) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    subject VARCHAR(64) NOT NULL CHECK (subject ~ '^[0-9a-f]{64}$'),
    CONSTRAINT fk_oauth_generation_browser_owner FOREIGN KEY (browser_generation_id, user_id, client_id, subject)
        REFERENCES oauth_browser_generations(generation_id, user_id, client_id, subject),
    CONSTRAINT fk_oauth_generation_token_owner FOREIGN KEY (token_id, user_id, client_id)
        REFERENCES oauth_tokens(id, user_id, client_id),
    CONSTRAINT fk_oauth_generation_session_owner FOREIGN KEY (session_id, user_id)
        REFERENCES sessions(session_id, user_id)
);
CREATE INDEX idx_oauth_generation_owner ON oauth_session_generations(user_id, client_id);
CREATE INDEX idx_oauth_generation_browser ON oauth_session_generations(browser_generation_id);

CREATE FUNCTION oauth_session_generation_guard_v1() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'OAuth session lifecycle unavailable';
    END IF;
    -- Serialize even independent writers before checking the single-current
    -- boundary; active state continues to belong to the existing Session.
    PERFORM 1 FROM users WHERE id = NEW.user_id FOR UPDATE;
    IF EXISTS (
        SELECT 1 FROM oauth_session_generations g JOIN sessions s ON s.session_id = g.session_id
        WHERE g.user_id = NEW.user_id AND g.client_id = NEW.client_id AND s.is_active IS TRUE
    ) THEN
        RAISE EXCEPTION 'OAuth session lifecycle unavailable';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM oauth_tokens t JOIN sessions s ON s.session_id = NEW.session_id
        JOIN users u ON u.id = t.user_id JOIN oauth_clients c ON c.client_id = t.client_id
        JOIN oauth_browser_generations b ON b.generation_id = NEW.browser_generation_id
        WHERE t.id = NEW.token_id AND t.user_id = NEW.user_id AND s.user_id = NEW.user_id
          AND t.client_id = NEW.client_id AND u.pubkey = NEW.subject
          AND b.user_id = NEW.user_id AND b.client_id = NEW.client_id AND b.subject = NEW.subject
          AND b.is_active IS TRUE AND b.created_at <= s.created_at AND s.expires_at <= b.expires_at
          AND u.is_active IS TRUE AND c.is_active IS TRUE AND s.is_active IS TRUE
          AND t.is_revoked IS FALSE AND t.refresh_token IS NULL AND t.refresh_token_expires_at IS NULL
          AND t.token_type = 'Bearer' AND t.metadata->>'token_contract' = 'hodlxxi.oauth.access-token.v1'
          AND t.metadata->>'token_use' = 'access' AND s.session_type = 'web'
          AND s.created_at = t.created_at AND s.expires_at = t.access_token_expires_at
          AND s.created_at < s.expires_at AND s.metadata IS NULL
    ) THEN
        RAISE EXCEPTION 'OAuth session lifecycle unavailable';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER trg_oauth_generation_guard BEFORE INSERT OR UPDATE OR DELETE ON oauth_session_generations
FOR EACH ROW EXECUTE FUNCTION oauth_session_generation_guard_v1();

CREATE FUNCTION oauth_session_code_guard_v1() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_TABLE_NAME = 'oauth_session_code_bindings' THEN
        IF TG_OP = 'DELETE' THEN
            -- Permit only cleanup cascading from deletion of the parent code.
            IF EXISTS (SELECT 1 FROM oauth_codes WHERE code = OLD.code) THEN
                RAISE EXCEPTION 'OAuth session lifecycle unavailable';
            END IF;
            RETURN OLD;
        END IF;
        IF TG_OP <> 'INSERT' OR NOT EXISTS (
            SELECT 1 FROM oauth_codes c JOIN users u ON u.id = c.user_id
            JOIN oauth_clients client ON client.client_id = c.client_id
            JOIN oauth_browser_generations b ON b.generation_id = NEW.browser_generation_id
            WHERE c.code = NEW.code AND c.is_used IS FALSE AND u.is_active IS TRUE
              AND client.is_active IS TRUE AND u.pubkey = NEW.subject
              AND b.user_id = c.user_id AND b.client_id = c.client_id AND b.subject = NEW.subject
              AND b.is_active IS TRUE AND b.created_at <= c.created_at AND c.expires_at <= b.expires_at
        ) THEN
            RAISE EXCEPTION 'OAuth session lifecycle unavailable';
        END IF;
    ELSIF EXISTS (SELECT 1 FROM oauth_session_code_bindings WHERE code = OLD.code) THEN
        IF ROW(NEW.code, NEW.client_id, NEW.user_id, NEW.redirect_uri, NEW.scope,
               NEW.code_challenge, NEW.code_challenge_method, NEW.created_at, NEW.expires_at)
            IS DISTINCT FROM ROW(OLD.code, OLD.client_id, OLD.user_id, OLD.redirect_uri, OLD.scope,
               OLD.code_challenge, OLD.code_challenge_method, OLD.created_at, OLD.expires_at)
            OR NEW.is_used IS NULL OR (OLD.is_used IS TRUE AND NEW.is_used IS NOT TRUE) THEN
            RAISE EXCEPTION 'OAuth session lifecycle unavailable';
        END IF;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER trg_oauth_code_binding_guard BEFORE INSERT OR UPDATE OR DELETE ON oauth_session_code_bindings
FOR EACH ROW EXECUTE FUNCTION oauth_session_code_guard_v1();
CREATE TRIGGER trg_oauth_bound_code_guard BEFORE UPDATE ON oauth_codes
FOR EACH ROW EXECUTE FUNCTION oauth_session_code_guard_v1();

CREATE FUNCTION oauth_mapped_session_guard_v1() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM oauth_session_generations WHERE session_id = OLD.session_id) AND (
        ROW(NEW.session_id, NEW.user_id, NEW.session_type, NEW.created_at)
          IS DISTINCT FROM ROW(OLD.session_id, OLD.user_id, OLD.session_type, OLD.created_at)
        OR NEW.expires_at > OLD.expires_at OR NEW.is_active IS NULL
        OR (OLD.is_active IS NOT TRUE AND NEW.is_active IS TRUE)
        OR NEW.metadata IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'OAuth session lifecycle unavailable';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER trg_oauth_mapped_session_guard BEFORE UPDATE ON sessions
FOR EACH ROW EXECUTE FUNCTION oauth_mapped_session_guard_v1();

CREATE FUNCTION oauth_token_session_invalidation_v1() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM oauth_session_generations WHERE token_id = OLD.id) THEN
        IF ROW(NEW.id, NEW.user_id, NEW.client_id, NEW.access_token, NEW.created_at, NEW.scope,
               NEW.token_type, NEW.refresh_token, NEW.refresh_token_expires_at, NEW.metadata::text)
           IS DISTINCT FROM ROW(OLD.id, OLD.user_id, OLD.client_id, OLD.access_token, OLD.created_at, OLD.scope,
               OLD.token_type, OLD.refresh_token, OLD.refresh_token_expires_at, OLD.metadata::text)
           OR NEW.access_token_expires_at > OLD.access_token_expires_at
           OR NEW.is_revoked IS NULL OR (OLD.is_revoked IS TRUE AND NEW.is_revoked IS NOT TRUE) THEN
            RAISE EXCEPTION 'OAuth session lifecycle unavailable';
        END IF;
        IF NEW.is_revoked IS TRUE OR NEW.access_token_expires_at < OLD.access_token_expires_at THEN
            UPDATE sessions SET is_active = FALSE, expires_at = LEAST(expires_at, NEW.access_token_expires_at)
            WHERE session_id IN (SELECT session_id FROM oauth_session_generations WHERE token_id = OLD.id);
        END IF;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER trg_oauth_token_session_invalidation BEFORE UPDATE ON oauth_tokens
FOR EACH ROW EXECUTE FUNCTION oauth_token_session_invalidation_v1();

CREATE FUNCTION oauth_owner_session_invalidation_v1() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_TABLE_NAME = 'users' THEN
        IF NEW.is_active IS NOT TRUE OR NEW.pubkey IS DISTINCT FROM OLD.pubkey THEN
            UPDATE oauth_browser_generations SET is_active = FALSE WHERE user_id = OLD.id;
            UPDATE oauth_tokens SET is_revoked = TRUE WHERE id IN (
                SELECT token_id FROM oauth_session_generations WHERE user_id = OLD.id
            );
            UPDATE oauth_codes SET is_used = TRUE WHERE user_id = OLD.id AND code IN (
                SELECT code FROM oauth_session_code_bindings
            );
        END IF;
    ELSIF NEW.is_active IS NOT TRUE THEN
        UPDATE oauth_browser_generations SET is_active = FALSE WHERE client_id = OLD.client_id;
        UPDATE oauth_tokens SET is_revoked = TRUE WHERE id IN (
            SELECT token_id FROM oauth_session_generations WHERE client_id = OLD.client_id
        );
        UPDATE oauth_codes SET is_used = TRUE WHERE client_id = OLD.client_id AND code IN (
            SELECT code FROM oauth_session_code_bindings
        );
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER trg_oauth_user_session_invalidation BEFORE UPDATE ON users
FOR EACH ROW EXECUTE FUNCTION oauth_owner_session_invalidation_v1();
CREATE TRIGGER trg_oauth_client_session_invalidation BEFORE UPDATE ON oauth_clients
FOR EACH ROW EXECUTE FUNCTION oauth_owner_session_invalidation_v1();

-- Retained proof commitments prevent consumed verified-login replay, including
-- after logout or service recreation. Invalidation never deletes the fence.
CREATE FUNCTION oauth_browser_generation_guard_v1() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'OAuth session lifecycle unavailable';
    END IF;
    IF TG_OP = 'INSERT' THEN
        PERFORM 1 FROM users WHERE id = NEW.user_id FOR UPDATE;
        IF NEW.is_active IS NOT TRUE OR NOT EXISTS (
            SELECT 1 FROM users u JOIN oauth_clients c ON c.client_id = NEW.client_id
            WHERE u.id = NEW.user_id AND u.pubkey = NEW.subject
              AND u.is_active IS TRUE AND c.is_active IS TRUE
        ) THEN
            RAISE EXCEPTION 'OAuth session lifecycle unavailable';
        END IF;
    ELSE
        IF ROW(NEW.generation_id, NEW.user_id, NEW.client_id, NEW.subject, NEW.proof_id, NEW.created_at)
            IS DISTINCT FROM ROW(OLD.generation_id, OLD.user_id, OLD.client_id, OLD.subject, OLD.proof_id, OLD.created_at)
            OR NEW.expires_at > OLD.expires_at OR (OLD.is_active IS FALSE AND NEW.is_active IS TRUE) THEN
            RAISE EXCEPTION 'OAuth session lifecycle unavailable';
        END IF;
        IF NEW.is_active IS FALSE OR NEW.expires_at < OLD.expires_at THEN
            NEW.is_active := FALSE;
            UPDATE oauth_tokens SET is_revoked = TRUE WHERE id IN (
                SELECT token_id FROM oauth_session_generations WHERE browser_generation_id = OLD.generation_id
            );
            UPDATE oauth_codes SET is_used = TRUE WHERE code IN (
                SELECT code FROM oauth_session_code_bindings WHERE browser_generation_id = OLD.generation_id
            );
        END IF;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER trg_oauth_browser_generation_guard BEFORE INSERT OR UPDATE OR DELETE ON oauth_browser_generations
FOR EACH ROW EXECUTE FUNCTION oauth_browser_generation_guard_v1();
