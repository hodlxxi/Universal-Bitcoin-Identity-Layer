-- Additive dormant recognized covenant funding allowlist V1. No seed or activation.
CREATE TABLE IF NOT EXISTS canonical_covenant_funding_sets (
  funding_set_id VARCHAR(36) PRIMARY KEY,
  schema VARCHAR(64) NOT NULL CONSTRAINT ck_funding_set_schema CHECK (schema = 'hodlxxi.canonical_recognized_covenant_funding_set.v1'),
  funding_set_version VARCHAR(72) NOT NULL CONSTRAINT ck_funding_set_version CHECK (funding_set_version = 'hodlxxi.canonical_recognized_covenant_funding_set_service.v1'),
  trusted_registration_id VARCHAR(36) NOT NULL,
  trusted_registration_sha256 VARCHAR(64) NOT NULL,
  pair_sha256 VARCHAR(64) NOT NULL,
  subject_xonly_pubkey VARCHAR(64) NOT NULL,
  counterparty_xonly_pubkey VARCHAR(64) NOT NULL,
  lifecycle_state VARCHAR(10) NOT NULL CONSTRAINT ck_funding_set_lifecycle CHECK (lifecycle_state IN ('proposed','effective','disputed','superseded','revoked')),
  created_at TIMESTAMPTZ NOT NULL,
  lifecycle_changed_at TIMESTAMPTZ NOT NULL,
  effective_at TIMESTAMPTZ,
  superseded_by_funding_set_id VARCHAR(36),
  canonical_funding_set_sha256 VARCHAR(64) NOT NULL UNIQUE,
  canonical_record_json TEXT NOT NULL,
  CONSTRAINT ck_funding_set_id CHECK (length(funding_set_id) = 36 AND funding_set_id = lower(funding_set_id)),
  CONSTRAINT ck_funding_set_registration_id CHECK (length(trusted_registration_id) = 36 AND trusted_registration_id = lower(trusted_registration_id)),
  CONSTRAINT ck_funding_set_source_digests CHECK (trusted_registration_sha256 ~ '^[0-9a-f]{64}$' AND pair_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT ck_funding_set_participants CHECK (subject_xonly_pubkey ~ '^[0-9a-f]{64}$' AND counterparty_xonly_pubkey ~ '^[0-9a-f]{64}$'),
  CONSTRAINT ck_funding_set_changed_order CHECK (lifecycle_changed_at >= created_at),
  CONSTRAINT ck_funding_set_lifecycle_consistency CHECK (
    (lifecycle_state = 'proposed' AND effective_at IS NULL AND superseded_by_funding_set_id IS NULL) OR
    (lifecycle_state = 'effective' AND effective_at IS NOT NULL AND effective_at >= created_at AND lifecycle_changed_at >= effective_at AND superseded_by_funding_set_id IS NULL) OR
    (lifecycle_state = 'superseded' AND effective_at IS NOT NULL AND effective_at >= created_at AND lifecycle_changed_at >= effective_at AND superseded_by_funding_set_id IS NOT NULL) OR
    (lifecycle_state IN ('disputed','revoked') AND (effective_at IS NULL OR (effective_at >= created_at AND lifecycle_changed_at >= effective_at)) AND superseded_by_funding_set_id IS NULL)),
  CONSTRAINT ck_funding_set_successor CHECK (superseded_by_funding_set_id IS NULL OR (length(superseded_by_funding_set_id) = 36 AND superseded_by_funding_set_id = lower(superseded_by_funding_set_id) AND superseded_by_funding_set_id <> funding_set_id)),
  CONSTRAINT ck_funding_set_digest CHECK (canonical_funding_set_sha256 ~ '^[0-9a-f]{64}$')
);

CREATE INDEX IF NOT EXISTS idx_funding_set_registration ON canonical_covenant_funding_sets (trusted_registration_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_funding_set_effective_registration ON canonical_covenant_funding_sets (trusted_registration_id) WHERE lifecycle_state = 'effective';

CREATE TABLE IF NOT EXISTS canonical_covenant_funding_outpoints (
  id BIGSERIAL PRIMARY KEY,
  funding_set_id VARCHAR(36) NOT NULL REFERENCES canonical_covenant_funding_sets(funding_set_id) ON DELETE CASCADE,
  direction VARCHAR(8) NOT NULL CONSTRAINT ck_funding_outpoint_direction CHECK (direction IN ('incoming','outgoing')),
  txid VARCHAR(64) NOT NULL CONSTRAINT ck_funding_outpoint_txid CHECK (txid ~ '^[0-9a-f]{64}$'),
  vout BIGINT NOT NULL CONSTRAINT ck_funding_outpoint_vout CHECK (vout >= 0 AND vout <= 4294967295),
  amount_sats BIGINT NOT NULL CONSTRAINT ck_funding_outpoint_amount CHECK (amount_sats > 0 AND amount_sats <= 2100000000000000),
  witness_script_sha256 VARCHAR(64) NOT NULL CONSTRAINT ck_funding_outpoint_script CHECK (witness_script_sha256 ~ '^[0-9a-f]{64}$'),
  descriptor_sha256 VARCHAR(64) CONSTRAINT ck_funding_outpoint_descriptor CHECK (descriptor_sha256 IS NULL OR descriptor_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT uq_funding_outpoint_identity UNIQUE (funding_set_id, txid, vout)
);
CREATE INDEX IF NOT EXISTS idx_funding_outpoint_set ON canonical_covenant_funding_outpoints (funding_set_id);
