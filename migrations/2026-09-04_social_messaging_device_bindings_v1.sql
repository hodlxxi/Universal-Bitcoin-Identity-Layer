CREATE TABLE IF NOT EXISTS social_messaging_device_bindings (
  binding_id VARCHAR(64) PRIMARY KEY,

  contract_version VARCHAR(80) NOT NULL,

  subject_pubkey VARCHAR(64) NOT NULL,
  device_id VARCHAR(64) NOT NULL,

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

  CONSTRAINT fk_social_messaging_device_binding_prior
    FOREIGN KEY (prior_binding_id)
    REFERENCES social_messaging_device_bindings(binding_id),

  CONSTRAINT uq_social_messaging_device_binding_subject_device_version
    UNIQUE (subject_pubkey, device_id, binding_version),

  CONSTRAINT ck_social_messaging_device_binding_id
    CHECK (binding_id ~ '^[0-9a-f]{64}$'),

  CONSTRAINT ck_social_messaging_device_binding_contract
    CHECK (
      contract_version =
      'hodlxxi.social_messaging_device_binding_statement.v1'
    ),

  CONSTRAINT ck_social_messaging_device_binding_subject
    CHECK (subject_pubkey ~ '^[0-9a-f]{64}$'),

  CONSTRAINT ck_social_messaging_device_binding_device
    CHECK (device_id ~ '^[0-9a-f]{64}$'),

  CONSTRAINT ck_social_messaging_device_binding_algorithm
    CHECK (algorithm = 'x25519-v1'),

  CONSTRAINT ck_social_messaging_device_binding_public_key
    CHECK (public_key ~ '^[0-9a-f]{64}$'),

  CONSTRAINT ck_social_messaging_device_binding_version
    CHECK (binding_version BETWEEN 1 AND 1024),

  CONSTRAINT ck_social_messaging_device_binding_validity
    CHECK (valid_from < expires_at),

  CONSTRAINT ck_social_messaging_device_binding_operation
    CHECK (operation IN ('register','rotate','revoke')),

  CONSTRAINT ck_social_messaging_device_binding_prior
    CHECK (
      (
        operation = 'register'
        AND prior_binding_id IS NULL
        AND binding_version = 1
      )
      OR
      (
        operation IN ('rotate','revoke')
        AND prior_binding_id IS NOT NULL
        AND binding_version >= 2
      )
    ),

  CONSTRAINT ck_social_messaging_device_binding_nonce
    CHECK (nonce ~ '^[0-9a-f]{64}$'),

  CONSTRAINT ck_social_messaging_device_binding_digest
    CHECK (
      statement_sha256 ~ '^[0-9a-f]{64}$'
      AND binding_id = statement_sha256
    ),

  CONSTRAINT ck_social_messaging_device_binding_signature_format
    CHECK (signature_format = 'bip340_schnorr_sha256'),

  CONSTRAINT ck_social_messaging_device_binding_signature
    CHECK (identity_signature ~ '^[0-9a-f]{128}$'),

  CONSTRAINT ck_social_messaging_device_binding_active
    CHECK (
      (
        active = true
        AND operation IN ('register','rotate')
        AND retired_at IS NULL
      )
      OR
      (
        active = false
        AND retired_at IS NOT NULL
      )
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS
  uq_social_messaging_device_binding_active_device
ON social_messaging_device_bindings(subject_pubkey, device_id)
WHERE active = true;

CREATE UNIQUE INDEX IF NOT EXISTS
  uq_social_messaging_device_binding_active_public_key
ON social_messaging_device_bindings(public_key)
WHERE active = true;

CREATE INDEX IF NOT EXISTS
  idx_social_messaging_device_binding_subject
ON social_messaging_device_bindings(subject_pubkey, active, device_id);

CREATE INDEX IF NOT EXISTS
  idx_social_messaging_device_binding_expires
ON social_messaging_device_bindings(expires_at);
