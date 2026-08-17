-- Additive dormant storage only. This migration does not seed or activate a record.
CREATE TABLE IF NOT EXISTS canonical_genesis_records (
    record_id VARCHAR(36) PRIMARY KEY,
    schema VARCHAR(44) NOT NULL,
    record_version VARCHAR(48) NOT NULL,
    graph_or_protocol_id VARCHAR(64) NOT NULL,
    genesis_participant_id VARCHAR(4) NOT NULL,
    compressed_public_key VARCHAR(66) NOT NULL,
    x_only_public_key VARCHAR(64) NOT NULL,
    lifecycle_state VARCHAR(10) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    lifecycle_changed_at TIMESTAMPTZ NOT NULL,
    effective_at TIMESTAMPTZ,
    superseded_by_record_id VARCHAR(36),
    canonical_record_sha256 VARCHAR(64) NOT NULL UNIQUE,
    canonical_record_json TEXT NOT NULL,
    CONSTRAINT ck_canonical_genesis_id CHECK
        (length(record_id) = 36 AND record_id = lower(record_id)),
    CONSTRAINT ck_canonical_genesis_schema CHECK
        (schema = 'hodlxxi.canonical_genesis_record.v1'),
    CONSTRAINT ck_canonical_genesis_version CHECK
        (record_version = 'hodlxxi.canonical_genesis_record_service.v1'),
    CONSTRAINT ck_canonical_genesis_graph CHECK
        (graph_or_protocol_id = 'hodlxxi.crt_membership_graph.v1'),
    CONSTRAINT ck_canonical_genesis_participant CHECK
        (genesis_participant_id = 'E923'),
    CONSTRAINT ck_canonical_genesis_compressed_key CHECK
        (compressed_public_key = '023d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923'),
    CONSTRAINT ck_canonical_genesis_xonly_key CHECK
        (x_only_public_key = '3d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923'),
    CONSTRAINT ck_canonical_genesis_lifecycle CHECK
        (lifecycle_state IN ('proposed','effective','disputed','superseded','revoked')),
    CONSTRAINT ck_canonical_genesis_changed_order CHECK
        (lifecycle_changed_at >= created_at),
    CONSTRAINT ck_canonical_genesis_lifecycle_consistency CHECK (
        (lifecycle_state = 'effective' AND effective_at IS NOT NULL
         AND effective_at >= created_at AND lifecycle_changed_at >= effective_at
         AND superseded_by_record_id IS NULL)
        OR (lifecycle_state = 'proposed' AND effective_at IS NULL
            AND superseded_by_record_id IS NULL)
        OR (lifecycle_state = 'superseded' AND superseded_by_record_id IS NOT NULL)
        OR (lifecycle_state IN ('disputed','revoked')
            AND superseded_by_record_id IS NULL)
    ),
    CONSTRAINT ck_canonical_genesis_successor CHECK (
        superseded_by_record_id IS NULL
        OR (length(superseded_by_record_id) = 36
            AND superseded_by_record_id = lower(superseded_by_record_id)
            AND superseded_by_record_id != record_id)
    ),
    CONSTRAINT ck_canonical_genesis_digest CHECK
        (length(canonical_record_sha256) = 64
         AND canonical_record_sha256 = lower(canonical_record_sha256))
);

CREATE INDEX IF NOT EXISTS idx_canonical_genesis_graph
    ON canonical_genesis_records (graph_or_protocol_id);
CREATE INDEX IF NOT EXISTS idx_canonical_genesis_lifecycle
    ON canonical_genesis_records (lifecycle_state);
CREATE INDEX IF NOT EXISTS idx_canonical_genesis_identity
    ON canonical_genesis_records (genesis_participant_id, x_only_public_key);
