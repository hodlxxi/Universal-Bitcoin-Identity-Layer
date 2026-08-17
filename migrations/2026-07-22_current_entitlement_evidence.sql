-- 2026-07-22: Persisted current entitlement evidence V1.
-- Apply with the repository's direct SQL migration process (psql -f).

CREATE TABLE IF NOT EXISTS current_entitlement_evidence (
  evidence_id VARCHAR(36) PRIMARY KEY,
  contract_version VARCHAR(64) NOT NULL,
  subject_pubkey VARCHAR(64) NOT NULL,
  identity_class VARCHAR(7) NOT NULL,
  current_full_relation_satisfied BOOLEAN NOT NULL,
  evidence_source VARCHAR(128) NOT NULL,
  evidence_version VARCHAR(64) NOT NULL,
  source_evidence_sha256 VARCHAR(64) NOT NULL,
  observed_at TIMESTAMP WITH TIME ZONE NOT NULL,
  valid_until TIMESTAMP WITH TIME ZONE NOT NULL,
  revoked_at TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
  CONSTRAINT ck_current_entitlement_evidence_id_length CHECK (length(evidence_id) = 36),
  CONSTRAINT ck_current_entitlement_evidence_id_canonical CHECK (evidence_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
  CONSTRAINT ck_current_entitlement_contract_version CHECK (contract_version = 'hodlxxi.current_entitlement_evidence.v1'),
  CONSTRAINT ck_current_entitlement_subject_length CHECK (length(subject_pubkey) = 64),
  CONSTRAINT ck_current_entitlement_subject_canonical CHECK (subject_pubkey ~ '^[0-9a-f]{64}$'),
  CONSTRAINT ck_current_entitlement_identity_class CHECK (identity_class IN ('limited','full')),
  CONSTRAINT ck_current_entitlement_identity_relation CHECK ((identity_class = 'full' AND current_full_relation_satisfied = true) OR (identity_class = 'limited' AND current_full_relation_satisfied = false)),
  CONSTRAINT ck_current_entitlement_source_length CHECK (length(evidence_source) BETWEEN 1 AND 128),
  CONSTRAINT ck_current_entitlement_source_canonical CHECK (evidence_source = btrim(evidence_source)),
  CONSTRAINT ck_current_entitlement_version_length CHECK (length(evidence_version) BETWEEN 1 AND 64),
  CONSTRAINT ck_current_entitlement_version_canonical CHECK (evidence_version = btrim(evidence_version)),
  CONSTRAINT ck_current_entitlement_hash_length CHECK (length(source_evidence_sha256) = 64),
  CONSTRAINT ck_current_entitlement_hash_canonical CHECK (source_evidence_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT ck_current_entitlement_validity_order CHECK (observed_at < valid_until),
  CONSTRAINT ck_current_entitlement_validity_duration CHECK (valid_until <= observed_at + INTERVAL '900 seconds'),
  CONSTRAINT ck_current_entitlement_created_order CHECK (observed_at <= created_at),
  CONSTRAINT ck_current_entitlement_revoked_order CHECK (revoked_at IS NULL OR (revoked_at >= observed_at AND revoked_at <= created_at))
);

CREATE INDEX IF NOT EXISTS idx_current_entitlement_subject ON current_entitlement_evidence (subject_pubkey);
CREATE INDEX IF NOT EXISTS idx_current_entitlement_valid_until ON current_entitlement_evidence (valid_until);
CREATE INDEX IF NOT EXISTS idx_current_entitlement_revoked_at ON current_entitlement_evidence (revoked_at);
CREATE INDEX IF NOT EXISTS idx_current_entitlement_subject_observed ON current_entitlement_evidence (subject_pubkey, observed_at);
CREATE INDEX IF NOT EXISTS idx_current_entitlement_subject_created ON current_entitlement_evidence (subject_pubkey, created_at);
