-- 2026-07-25: Dormant trusted covenant registration and exact-outpoint binding V1.
-- Apply separately through the repository's direct SQL migration process (psql -f).

CREATE TABLE IF NOT EXISTS trusted_covenant_registrations (
  registration_id VARCHAR(36) PRIMARY KEY,
  schema VARCHAR(48) NOT NULL,
  registration_version VARCHAR(56) NOT NULL,
  network VARCHAR(7) NOT NULL,
  pair_sha256 VARCHAR(64) NOT NULL,
  registration_sha256 VARCHAR(64) NOT NULL UNIQUE,
  validator_version VARCHAR(56) NOT NULL,
  subject_pubkey VARCHAR(66) NOT NULL,
  subject_xonly_pubkey VARCHAR(64) NOT NULL,
  counterparty_pubkey VARCHAR(66) NOT NULL,
  counterparty_xonly_pubkey VARCHAR(64) NOT NULL,
  template_family VARCHAR(25) NOT NULL,
  delta_profile VARCHAR(11) NOT NULL,
  delta_blocks INTEGER NOT NULL,
  lifecycle_state VARCHAR(10) NOT NULL,
  registered_at TIMESTAMP WITH TIME ZONE NOT NULL,
  lifecycle_changed_at TIMESTAMP WITH TIME ZONE NOT NULL,
  superseded_by_registration_id VARCHAR(36),
  earlier_leg_script_hex TEXT NOT NULL,
  later_leg_script_hex TEXT NOT NULL,
  CONSTRAINT ck_trusted_registration_id_canonical CHECK
    (registration_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
  CONSTRAINT ck_trusted_registration_schema CHECK
    (schema = 'hodlxxi.trusted_covenant_registration.v1'),
  CONSTRAINT ck_trusted_registration_version CHECK
    (registration_version = 'hodlxxi.trusted_covenant_registration_service.v1'),
  CONSTRAINT ck_trusted_registration_network CHECK (network = 'bitcoin'),
  CONSTRAINT ck_trusted_registration_pair_hash CHECK (pair_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT ck_trusted_registration_hash CHECK (registration_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT ck_trusted_registration_validator CHECK
    (validator_version = 'hodlxxi.mirrored_covenant_pair_validator.v1'),
  CONSTRAINT ck_trusted_registration_subject CHECK (subject_pubkey ~ '^(02|03)[0-9a-f]{64}$'),
  CONSTRAINT ck_trusted_registration_subject_xonly CHECK (subject_xonly_pubkey ~ '^[0-9a-f]{64}$'),
  CONSTRAINT ck_trusted_registration_counterparty CHECK (counterparty_pubkey ~ '^(02|03)[0-9a-f]{64}$'),
  CONSTRAINT ck_trusted_registration_counterparty_xonly CHECK
    (counterparty_xonly_pubkey ~ '^[0-9a-f]{64}$'),
  CONSTRAINT ck_trusted_registration_distinct_participants CHECK
    (subject_pubkey <> counterparty_pubkey AND subject_xonly_pubkey <> counterparty_xonly_pubkey),
  CONSTRAINT ck_trusted_registration_family CHECK
    (template_family IN ('cltv_only','cooperative_2_of_2_cltv')),
  CONSTRAINT ck_trusted_registration_profile_delta CHECK
    ((delta_profile = 'current_144' AND delta_blocks = 144) OR
     (delta_profile = 'legacy_777' AND delta_blocks = 777)),
  CONSTRAINT ck_trusted_registration_lifecycle CHECK
    (lifecycle_state IN ('active','revoked','superseded','disputed')),
  CONSTRAINT ck_trusted_registration_lifecycle_time CHECK (lifecycle_changed_at >= registered_at),
  CONSTRAINT ck_trusted_registration_superseded_consistency CHECK
    ((lifecycle_state = 'superseded' AND superseded_by_registration_id IS NOT NULL) OR
     (lifecycle_state <> 'superseded' AND superseded_by_registration_id IS NULL)),
  CONSTRAINT ck_trusted_registration_superseded_id CHECK
    (superseded_by_registration_id IS NULL OR
     (superseded_by_registration_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
      AND superseded_by_registration_id <> registration_id)),
  CONSTRAINT ck_trusted_registration_earlier_script CHECK
    (earlier_leg_script_hex ~ '^(?:[0-9a-f]{2})+$'),
  CONSTRAINT ck_trusted_registration_later_script CHECK
    (later_leg_script_hex ~ '^(?:[0-9a-f]{2})+$'),
  CONSTRAINT ck_trusted_registration_distinct_scripts CHECK
    (earlier_leg_script_hex <> later_leg_script_hex)
);

CREATE INDEX IF NOT EXISTS idx_trusted_registration_lifecycle
  ON trusted_covenant_registrations (lifecycle_state);
CREATE INDEX IF NOT EXISTS idx_trusted_registration_pair
  ON trusted_covenant_registrations (pair_sha256);
CREATE INDEX IF NOT EXISTS idx_trusted_registration_subject
  ON trusted_covenant_registrations (subject_xonly_pubkey);
CREATE INDEX IF NOT EXISTS idx_trusted_registration_counterparty
  ON trusted_covenant_registrations (counterparty_xonly_pubkey);

CREATE TABLE IF NOT EXISTS trusted_covenant_registered_outpoints (
  id BIGSERIAL PRIMARY KEY,
  registration_id VARCHAR(36) NOT NULL,
  direction VARCHAR(8) NOT NULL,
  txid VARCHAR(64) NOT NULL,
  vout BIGINT NOT NULL,
  amount_sats BIGINT NOT NULL,
  witness_script_sha256 VARCHAR(64) NOT NULL,
  descriptor_sha256 VARCHAR(64),
  CONSTRAINT fk_trusted_outpoint_registration FOREIGN KEY (registration_id)
    REFERENCES trusted_covenant_registrations (registration_id) ON DELETE CASCADE,
  CONSTRAINT uq_trusted_outpoint_registration_direction UNIQUE (registration_id, direction),
  CONSTRAINT uq_trusted_outpoint_global_identity UNIQUE (txid, vout),
  CONSTRAINT ck_trusted_outpoint_direction CHECK (direction IN ('incoming','outgoing')),
  CONSTRAINT ck_trusted_outpoint_txid CHECK (txid ~ '^[0-9a-f]{64}$'),
  CONSTRAINT ck_trusted_outpoint_vout CHECK (vout >= 0 AND vout <= 4294967295),
  CONSTRAINT ck_trusted_outpoint_amount CHECK
    (amount_sats > 0 AND amount_sats <= 2100000000000000),
  CONSTRAINT ck_trusted_outpoint_witness_script_hash CHECK
    (witness_script_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT ck_trusted_outpoint_descriptor_hash CHECK
    (descriptor_sha256 IS NULL OR descriptor_sha256 ~ '^[0-9a-f]{64}$')
);

CREATE INDEX IF NOT EXISTS idx_trusted_outpoint_registration
  ON trusted_covenant_registered_outpoints (registration_id);
CREATE INDEX IF NOT EXISTS idx_trusted_outpoint_identity
  ON trusted_covenant_registered_outpoints (txid, vout);
