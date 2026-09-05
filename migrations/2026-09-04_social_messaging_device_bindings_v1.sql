-- 2026-09-04: Durable multi-device Social messaging X25519 binding registry V1.
-- Apply only through the repository's separately authorized migration process.

CREATE TABLE IF NOT EXISTS social_messaging_device_bindings (
  binding_id VARCHAR(64) PRIMARY KEY,
  record_schema VARCHAR(64) NOT NULL,
  subject_pubkey VARCHAR(64) NOT NULL,
  device_id VARCHAR(64) NOT NULL,
  algorithm VARCHAR(16) NOT NULL,
  public_key VARCHAR(64) NOT NULL,
  binding_version BIGINT NOT NULL,
  valid_from TIMESTAMP WITH TIME ZONE NOT NULL,
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  operation VARCHAR(8) NOT NULL,
  prior_binding_id VARCHAR(64),
  request_id VARCHAR(64) NOT NULL,
  active BOOLEAN NOT NULL,
  retired_at TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
  CONSTRAINT fk_social_messaging_device_prior FOREIGN KEY (prior_binding_id)
    REFERENCES social_messaging_device_bindings (binding_id),
  CONSTRAINT uq_social_messaging_device_subject_device_version
    UNIQUE (subject_pubkey, device_id, binding_version),
  CONSTRAINT uq_social_messaging_device_subject_request
    UNIQUE (subject_pubkey, request_id),
  CONSTRAINT ck_social_messaging_device_schema CHECK
    (record_schema = 'hodlxxi.social_messaging_device_binding_record.v1'),
  CONSTRAINT ck_social_messaging_device_binding_id CHECK
    (binding_id ~ '^[0-9a-f]{64}$'),
  CONSTRAINT ck_social_messaging_device_subject CHECK
    (subject_pubkey ~ '^[0-9a-f]{64}$'),
  CONSTRAINT ck_social_messaging_device_device_id CHECK
    (device_id ~ '^[0-9a-f]{64}$'),
  CONSTRAINT ck_social_messaging_device_algorithm CHECK
    (algorithm = 'x25519-v1'),
  CONSTRAINT ck_social_messaging_device_public_key CHECK
    (public_key ~ '^[0-9a-f]{64}$'),
  CONSTRAINT ck_social_messaging_device_version CHECK
    (binding_version BETWEEN 1 AND 1024),
  CONSTRAINT ck_social_messaging_device_validity CHECK
    (valid_from < expires_at),
  CONSTRAINT ck_social_messaging_device_operation CHECK
    (operation IN ('register','rotate','revoke')),
  CONSTRAINT ck_social_messaging_device_prior CHECK
    ((operation = 'register' AND prior_binding_id IS NULL AND binding_version = 1)
      OR (operation IN ('rotate','revoke') AND prior_binding_id IS NOT NULL AND binding_version >= 2)),
  CONSTRAINT ck_social_messaging_device_request_id CHECK
    (request_id ~ '^[0-9a-f]{64}$'),
  CONSTRAINT ck_social_messaging_device_active_state CHECK
    ((active = true AND operation IN ('register','rotate') AND retired_at IS NULL)
      OR (active = false AND retired_at IS NOT NULL))
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_social_messaging_device_active_device
  ON social_messaging_device_bindings (subject_pubkey, device_id)
  WHERE active = true;
CREATE UNIQUE INDEX IF NOT EXISTS uq_social_messaging_device_active_public_key
  ON social_messaging_device_bindings (public_key)
  WHERE active = true;
CREATE INDEX IF NOT EXISTS idx_social_messaging_device_current_subject
  ON social_messaging_device_bindings (subject_pubkey, active, device_id);
CREATE INDEX IF NOT EXISTS idx_social_messaging_device_expires_at
  ON social_messaging_device_bindings (expires_at);
