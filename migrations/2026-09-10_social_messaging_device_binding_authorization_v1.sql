-- 2026-09-10: Durable identity authorization and global replay for Social device bindings V1.
-- Apply only through the repository's separately authorized migration process.

ALTER TABLE social_messaging_device_bindings
  ADD CONSTRAINT uq_social_messaging_device_authorization_identity
  UNIQUE (
    binding_id,
    subject_pubkey,
    device_id,
    public_key,
    binding_version,
    operation,
    valid_from,
    expires_at
  );

CREATE UNIQUE INDEX uq_social_messaging_device_historical_public_key
  ON social_messaging_device_bindings (public_key)
  WHERE operation IN ('register','rotate');

CREATE TABLE social_messaging_device_binding_authorization_evidence (
  binding_id VARCHAR(64) PRIMARY KEY,
  evidence_type VARCHAR(9) NOT NULL,
  action VARCHAR(8) NOT NULL,
  request_id VARCHAR(64) NOT NULL,
  digest VARCHAR(64) NOT NULL,
  canonical_payload TEXT NOT NULL,
  subject_pubkey VARCHAR(64) NOT NULL,
  device_id VARCHAR(64) NOT NULL,
  public_key VARCHAR(64) NOT NULL,
  binding_version BIGINT NOT NULL,
  binding_operation VARCHAR(8) NOT NULL,
  binding_valid_from TIMESTAMP WITH TIME ZONE NOT NULL,
  binding_expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  evidence_valid_from TIMESTAMP WITH TIME ZONE NOT NULL,
  evidence_expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
  CONSTRAINT fk_social_device_authorization_evidence_binding
    FOREIGN KEY (
      binding_id,
      subject_pubkey,
      device_id,
      public_key,
      binding_version,
      binding_operation,
      binding_valid_from,
      binding_expires_at
    )
    REFERENCES social_messaging_device_bindings (
      binding_id,
      subject_pubkey,
      device_id,
      public_key,
      binding_version,
      operation,
      valid_from,
      expires_at
    )
    ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
  CONSTRAINT uq_social_device_authorization_evidence_request UNIQUE (request_id),
  CONSTRAINT uq_social_device_authorization_evidence_digest UNIQUE (digest),
  CONSTRAINT uq_social_device_authorization_evidence_replay_identity
    UNIQUE (binding_id, request_id, digest, evidence_type, action),
  CONSTRAINT ck_social_device_authorization_evidence_type CHECK
    (evidence_type IN ('lifecycle','adoption')),
  CONSTRAINT ck_social_device_authorization_evidence_action CHECK
    ((evidence_type = 'lifecycle'
        AND action IN ('register','rotate','revoke')
        AND action = binding_operation)
      OR (evidence_type = 'adoption'
        AND action = 'adopt'
        AND binding_operation IN ('register','rotate'))),
  CONSTRAINT ck_social_device_authorization_evidence_binding_id CHECK
    (binding_id ~ '^[0-9a-f]{64}$'),
  CONSTRAINT ck_social_device_authorization_evidence_request_id CHECK
    (request_id ~ '^[0-9a-f]{64}$'),
  CONSTRAINT ck_social_device_authorization_evidence_digest CHECK
    (digest ~ '^[0-9a-f]{64}$'),
  CONSTRAINT ck_social_device_authorization_evidence_subject CHECK
    (subject_pubkey ~ '^[0-9a-f]{64}$'),
  CONSTRAINT ck_social_device_authorization_evidence_device CHECK
    (device_id ~ '^[0-9a-f]{64}$'),
  CONSTRAINT ck_social_device_authorization_evidence_public_key CHECK
    (public_key ~ '^[0-9a-f]{64}$'),
  CONSTRAINT ck_social_device_authorization_evidence_version CHECK
    (binding_version BETWEEN 1 AND 1024),
  CONSTRAINT ck_social_device_authorization_evidence_binding_validity CHECK
    (binding_valid_from < binding_expires_at),
  CONSTRAINT ck_social_device_authorization_evidence_validity CHECK
    (binding_valid_from <= evidence_valid_from
      AND evidence_valid_from < evidence_expires_at
      AND evidence_expires_at <= binding_expires_at),
  CONSTRAINT ck_social_device_authorization_evidence_payload CHECK
    (octet_length(canonical_payload) BETWEEN 1 AND 8192)
);

CREATE INDEX idx_social_device_authorization_evidence_subject_device
  ON social_messaging_device_binding_authorization_evidence
    (subject_pubkey, device_id, binding_version);
CREATE INDEX idx_social_device_authorization_evidence_public_key
  ON social_messaging_device_binding_authorization_evidence (public_key);
CREATE INDEX idx_social_device_authorization_evidence_window
  ON social_messaging_device_binding_authorization_evidence
    (evidence_valid_from, evidence_expires_at);

CREATE TABLE social_messaging_device_binding_authorization_replay (
  request_id VARCHAR(64) PRIMARY KEY,
  record_type VARCHAR(9) NOT NULL,
  action VARCHAR(8) NOT NULL,
  digest VARCHAR(64) NOT NULL,
  result_binding_id VARCHAR(64) NOT NULL,
  result_proof_id VARCHAR(112) NOT NULL,
  result_payload TEXT NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
  CONSTRAINT fk_social_device_authorization_replay_evidence
    FOREIGN KEY (result_binding_id, request_id, digest, record_type, action)
    REFERENCES social_messaging_device_binding_authorization_evidence
      (binding_id, request_id, digest, evidence_type, action)
    ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
  CONSTRAINT ck_social_device_authorization_replay_type CHECK
    (record_type IN ('lifecycle','adoption')),
  CONSTRAINT ck_social_device_authorization_replay_action CHECK
    ((record_type = 'lifecycle' AND action IN ('register','rotate','revoke'))
      OR (record_type = 'adoption' AND action = 'adopt')),
  CONSTRAINT ck_social_device_authorization_replay_request_id CHECK
    (request_id ~ '^[0-9a-f]{64}$'),
  CONSTRAINT ck_social_device_authorization_replay_digest CHECK
    (digest ~ '^[0-9a-f]{64}$'),
  CONSTRAINT ck_social_device_authorization_replay_binding_id CHECK
    (result_binding_id ~ '^[0-9a-f]{64}$'),
  CONSTRAINT ck_social_device_authorization_replay_proof_id CHECK
    (result_proof_id = 'hodlxxi-binding-authorization-v1-sha256:' || digest),
  CONSTRAINT ck_social_device_authorization_replay_payload CHECK
    (octet_length(result_payload) BETWEEN 1 AND 8192)
);

CREATE OR REPLACE FUNCTION reject_social_device_authorization_mutation_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'social messaging device authorization rows are immutable';
END;
$$;

CREATE TRIGGER trg_social_device_authorization_evidence_immutable
  BEFORE UPDATE OR DELETE
  ON social_messaging_device_binding_authorization_evidence
  FOR EACH ROW
  EXECUTE FUNCTION reject_social_device_authorization_mutation_v1();

CREATE TRIGGER trg_social_device_authorization_replay_immutable
  BEFORE UPDATE OR DELETE
  ON social_messaging_device_binding_authorization_replay
  FOR EACH ROW
  EXECUTE FUNCTION reject_social_device_authorization_mutation_v1();
