-- Additive dormant selection storage only. No seed, backfill, or activation.
CREATE TABLE IF NOT EXISTS canonical_root_registration_bindings (
    binding_id VARCHAR(36) PRIMARY KEY,
    schema VARCHAR(56) NOT NULL,
    binding_version VARCHAR(64) NOT NULL,
    graph_or_protocol_id VARCHAR(64) NOT NULL,
    root_x_only_public_key VARCHAR(64) NOT NULL,
    trusted_registration_id VARCHAR(36) NOT NULL,
    trusted_registration_sha256 VARCHAR(64) NOT NULL,
    lifecycle_state VARCHAR(10) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    lifecycle_changed_at TIMESTAMPTZ NOT NULL,
    effective_at TIMESTAMPTZ,
    superseded_by_binding_id VARCHAR(36),
    canonical_binding_sha256 VARCHAR(64) NOT NULL UNIQUE,
    canonical_record_json TEXT NOT NULL,
    CONSTRAINT ck_root_registration_binding_schema CHECK
        (schema = 'hodlxxi.canonical_root_registration_binding.v1'),
    CONSTRAINT ck_root_registration_binding_version CHECK
        (binding_version = 'hodlxxi.canonical_root_registration_binding_service.v1'),
    CONSTRAINT ck_root_registration_binding_id CHECK
        (length(binding_id) = 36 AND binding_id = lower(binding_id)),
    CONSTRAINT ck_root_registration_binding_root CHECK
        (root_x_only_public_key ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_root_registration_binding_registration_id CHECK
        (trusted_registration_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
    CONSTRAINT ck_root_registration_binding_registration_digest CHECK
        (trusted_registration_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_root_registration_binding_digest CHECK
        (canonical_binding_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_root_registration_binding_lifecycle CHECK
        (lifecycle_state IN ('proposed','effective','disputed','superseded','revoked')),
    CONSTRAINT ck_root_registration_binding_changed_order CHECK
        (lifecycle_changed_at >= created_at),
    CONSTRAINT ck_root_registration_binding_lifecycle_consistency CHECK (
        (lifecycle_state = 'proposed' AND effective_at IS NULL
         AND superseded_by_binding_id IS NULL)
        OR (lifecycle_state = 'effective' AND effective_at IS NOT NULL
            AND effective_at >= created_at AND lifecycle_changed_at >= effective_at
            AND superseded_by_binding_id IS NULL)
        OR (lifecycle_state = 'superseded' AND effective_at IS NOT NULL
            AND effective_at >= created_at AND lifecycle_changed_at >= effective_at
            AND superseded_by_binding_id IS NOT NULL)
        OR (lifecycle_state IN ('disputed','revoked')
            AND (effective_at IS NULL OR
                 (effective_at >= created_at AND lifecycle_changed_at >= effective_at))
            AND superseded_by_binding_id IS NULL)
    ),
    CONSTRAINT ck_root_registration_binding_successor CHECK (
        superseded_by_binding_id IS NULL OR
        (length(superseded_by_binding_id) = 36
         AND superseded_by_binding_id = lower(superseded_by_binding_id)
         AND superseded_by_binding_id != binding_id)
    )
);

CREATE INDEX IF NOT EXISTS idx_root_registration_binding_graph_root
    ON canonical_root_registration_bindings (graph_or_protocol_id, root_x_only_public_key);
CREATE INDEX IF NOT EXISTS idx_root_registration_binding_registration
    ON canonical_root_registration_bindings (trusted_registration_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_root_registration_binding_effective_root
    ON canonical_root_registration_bindings (graph_or_protocol_id, root_x_only_public_key)
    WHERE lifecycle_state = 'effective';

-- Repository convention preserves dormant evidence on application rollback.
-- Destructive table removal requires a separate reviewed operation.
