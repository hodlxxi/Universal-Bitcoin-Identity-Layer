-- 2026-08-31: Durable confidential-service client-assertion replay markers V1.
-- Apply with the repository's direct SQL migration process (psql -f).

CREATE TABLE IF NOT EXISTS confidential_service_assertion_replay_markers (
  jti_sha256 VARCHAR(64) PRIMARY KEY,
  retention_deadline_exclusive BIGINT NOT NULL,
  CONSTRAINT ck_confidential_service_assertion_replay_digest_length
    CHECK (length(jti_sha256) = 64),
  CONSTRAINT ck_confidential_service_assertion_replay_digest_canonical
    CHECK (jti_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT ck_confidential_service_assertion_replay_deadline_positive
    CHECK (retention_deadline_exclusive > 0)
);

CREATE INDEX IF NOT EXISTS idx_confidential_service_assertion_replay_deadline
  ON confidential_service_assertion_replay_markers (retention_deadline_exclusive);
