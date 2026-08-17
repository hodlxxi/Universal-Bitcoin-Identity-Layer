-- HODLXXI sanitized production catalog baseline V1.
--
-- This is a deterministic, schema-only reconstruction of the four-table
-- catalog surface recorded by PR6.22.  It contains no production rows and is
-- not a complete clone of the production schema.  Column types are the
-- repository ORM-compatible types needed by the rehearsal; PR6.22 disclosed
-- column, primary-key, foreign-key, and index identity, not a full schema dump.

SET search_path = public;

CREATE TABLE users (
    id VARCHAR(36) NOT NULL,
    pubkey VARCHAR(66) NOT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    last_login TIMESTAMP WITHOUT TIME ZONE,
    metadata JSON,
    is_active BOOLEAN,
    CONSTRAINT users_pkey PRIMARY KEY (id)
);

CREATE TABLE oauth_clients (
    client_id VARCHAR(255) NOT NULL,
    client_secret VARCHAR(255) NOT NULL,
    client_name VARCHAR(255) NOT NULL,
    redirect_uris JSON NOT NULL,
    grant_types JSON NOT NULL,
    response_types JSON NOT NULL,
    scope TEXT,
    token_endpoint_auth_method VARCHAR(50),
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    metadata JSON,
    is_active BOOLEAN,
    owner_pubkey VARCHAR(66),
    plan VARCHAR(50),
    CONSTRAINT oauth_clients_pkey PRIMARY KEY (client_id)
);

CREATE TABLE oauth_codes (
    code VARCHAR(255) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    user_id VARCHAR(36) NOT NULL,
    redirect_uri TEXT NOT NULL,
    scope TEXT,
    code_challenge VARCHAR(255),
    code_challenge_method VARCHAR(10),
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    expires_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    is_used BOOLEAN,
    CONSTRAINT oauth_codes_pkey PRIMARY KEY (code),
    CONSTRAINT oauth_codes_client_id_fkey
        FOREIGN KEY (client_id) REFERENCES oauth_clients (client_id),
    CONSTRAINT oauth_codes_user_id_fkey
        FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE TABLE oauth_tokens (
    id VARCHAR(36) NOT NULL,
    access_token VARCHAR(255) NOT NULL,
    refresh_token VARCHAR(255),
    token_type VARCHAR(50),
    client_id VARCHAR(255) NOT NULL,
    user_id VARCHAR(36) NOT NULL,
    scope TEXT,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    access_token_expires_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    refresh_token_expires_at TIMESTAMP WITHOUT TIME ZONE,
    is_revoked BOOLEAN,
    metadata JSON,
    CONSTRAINT oauth_tokens_pkey PRIMARY KEY (id),
    CONSTRAINT oauth_tokens_client_id_fkey
        FOREIGN KEY (client_id) REFERENCES oauth_clients (client_id),
    CONSTRAINT oauth_tokens_user_id_fkey
        FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE INDEX idx_client_created ON oauth_clients (created_at);
CREATE INDEX idx_client_name ON oauth_clients (client_name);
CREATE INDEX idx_oauth_clients_owner ON oauth_clients (owner_pubkey);

CREATE INDEX idx_code_client ON oauth_codes (client_id);
CREATE INDEX idx_code_expires ON oauth_codes (expires_at);
CREATE INDEX idx_oauth_codes_client_id ON oauth_codes (client_id);
CREATE INDEX idx_oauth_codes_user_id ON oauth_codes (user_id);

CREATE INDEX idx_token_access ON oauth_tokens (access_token);
CREATE INDEX idx_token_expires ON oauth_tokens (access_token_expires_at);
CREATE INDEX idx_token_refresh ON oauth_tokens (refresh_token);
CREATE INDEX idx_token_user ON oauth_tokens (user_id);
CREATE UNIQUE INDEX ix_oauth_tokens_access_token ON oauth_tokens (access_token);
CREATE UNIQUE INDEX ix_oauth_tokens_refresh_token ON oauth_tokens (refresh_token);

CREATE INDEX idx_user_created ON users (created_at);
CREATE INDEX idx_user_pubkey ON users (pubkey);
CREATE UNIQUE INDEX ix_users_pubkey ON users (pubkey);
