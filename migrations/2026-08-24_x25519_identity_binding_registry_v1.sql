-- 2026-08-24: Empty durable identity-authorized X25519 binding registry V1.
-- Apply only through the repository's separately authorized migration process.

CREATE TABLE IF NOT EXISTS x25519_identity_bindings (
  binding_id VARCHAR(64) PRIMARY KEY,
  contract_version VARCHAR(64) NOT NULL,
  subject_pubkey VARCHAR(64) NOT NULL,
  algorithm VARCHAR(16) NOT NULL,
  public_key VARCHAR(64) NOT NULL,
  binding_version BIGINT NOT NULL,
  valid_from TIMESTAMP WITH TIME ZONE NOT NULL,
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  operation VARCHAR(8) NOT NULL,
  prior_binding_id VARCHAR(64),
  nonce VARCHAR(64) NOT NULL UNIQUE,
  statement_sha256 VARCHAR(64) NOT NULL UNIQUE,
  signature_format VARCHAR(32) NOT NULL,
  identity_signature VARCHAR(128) NOT NULL,
  active BOOLEAN NOT NULL,
  retired_at TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
  CONSTRAINT fk_x25519_binding_prior FOREIGN KEY (prior_binding_id)
    REFERENCES x25519_identity_bindings (binding_id),
  CONSTRAINT uq_x25519_binding_subject_version UNIQUE (subject_pubkey, binding_version),
  CONSTRAINT ck_x25519_binding_id CHECK (binding_id ~ '^[0-9a-f]{64}$'),
  CONSTRAINT ck_x25519_binding_contract CHECK
    (contract_version = 'hodlxxi.x25519_identity_binding_statement.v1'),
  CONSTRAINT ck_x25519_binding_subject CHECK (subject_pubkey ~ '^[0-9a-f]{64}$'),
  CONSTRAINT ck_x25519_binding_algorithm CHECK (algorithm = 'x25519-v1'),
  CONSTRAINT ck_x25519_binding_public_key CHECK (public_key ~ '^[0-9a-f]{64}$'),
  CONSTRAINT ck_x25519_binding_safe_version CHECK
    (binding_version BETWEEN 1 AND 9007199254740991),
  CONSTRAINT ck_x25519_binding_validity CHECK (valid_from < expires_at),
  CONSTRAINT ck_x25519_binding_operation CHECK (operation IN ('register','rotate','revoke')),
  CONSTRAINT ck_x25519_binding_prior CHECK
    ((operation = 'register' AND prior_binding_id IS NULL AND binding_version = 1)
      OR (operation IN ('rotate','revoke') AND prior_binding_id IS NOT NULL)),
  CONSTRAINT ck_x25519_binding_nonce CHECK (nonce ~ '^[0-9a-f]{64}$'),
  CONSTRAINT ck_x25519_binding_digest CHECK
    (statement_sha256 ~ '^[0-9a-f]{64}$' AND binding_id = statement_sha256),
  CONSTRAINT ck_x25519_binding_signature_format CHECK
    (signature_format = 'bip340_schnorr_sha256'),
  CONSTRAINT ck_x25519_binding_signature CHECK (identity_signature ~ '^[0-9a-f]{128}$'),
  CONSTRAINT ck_x25519_binding_active_state CHECK
    ((active = true AND operation IN ('register','rotate') AND retired_at IS NULL)
      OR (active = false AND retired_at IS NOT NULL))
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_x25519_binding_active_subject
  ON x25519_identity_bindings (subject_pubkey) WHERE active = true;
CREATE UNIQUE INDEX IF NOT EXISTS uq_x25519_binding_active_public_key
  ON x25519_identity_bindings (public_key) WHERE active = true;
CREATE INDEX IF NOT EXISTS idx_x25519_binding_current_order
  ON x25519_identity_bindings (active, subject_pubkey);
CREATE INDEX IF NOT EXISTS idx_x25519_binding_expires_at
  ON x25519_identity_bindings (expires_at);
