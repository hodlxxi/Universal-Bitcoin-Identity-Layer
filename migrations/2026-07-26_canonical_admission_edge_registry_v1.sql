-- PR6.10 additive, dormant canonical admission-edge registry V1. Unapplied.
CREATE TABLE canonical_admission_edges (
    edge_id VARCHAR(36) PRIMARY KEY,
    schema VARCHAR(64) NOT NULL CHECK (schema = 'hodlxxi.canonical_admission_edge.v1'),
    edge_version VARCHAR(64) NOT NULL CHECK (edge_version = 'hodlxxi.canonical_admission_edge_service.v1'),
    graph_or_protocol_id VARCHAR(64) NOT NULL CHECK (graph_or_protocol_id = 'hodlxxi.crt_membership_graph.v1'),
    network VARCHAR(16) NOT NULL CHECK (network = 'bitcoin'),
    human_profile VARCHAR(16) NOT NULL CHECK (human_profile = 'legacy_777'),
    template_family VARCHAR(16) NOT NULL CHECK (template_family = 'cltv_only'),
    delta_blocks INTEGER NOT NULL CHECK (delta_blocks = 777),
    sponsor_participant_id VARCHAR(64) NOT NULL,
    sponsor_compressed_public_key VARCHAR(66) NOT NULL,
    sponsor_x_only_public_key VARCHAR(64) NOT NULL,
    sponsor_depth INTEGER NOT NULL CHECK (sponsor_depth >= 0),
    child_participant_id VARCHAR(64) NOT NULL,
    child_compressed_public_key VARCHAR(66) NOT NULL,
    child_x_only_public_key VARCHAR(64) NOT NULL,
    child_depth INTEGER NOT NULL,
    early_height INTEGER NOT NULL,
    middle_height INTEGER NOT NULL,
    late_height INTEGER NOT NULL,
    trusted_registration_id VARCHAR(36) NOT NULL UNIQUE,
    trusted_registration_sha256 VARCHAR(64) NOT NULL UNIQUE,
    pair_sha256 VARCHAR(64) NOT NULL,
    validator_version VARCHAR(64) NOT NULL,
    sponsor_basis_kind VARCHAR(32) NOT NULL CHECK (sponsor_basis_kind IN ('canonical_genesis_record','canonical_admission_edge')),
    sponsor_basis_record_id VARCHAR(36) NOT NULL,
    sponsor_basis_record_sha256 VARCHAR(64) NOT NULL,
    lifecycle_state VARCHAR(10) NOT NULL CHECK (lifecycle_state IN ('proposed','effective','disputed','superseded','revoked')),
    created_at TIMESTAMPTZ NOT NULL,
    lifecycle_changed_at TIMESTAMPTZ NOT NULL,
    effective_at TIMESTAMPTZ,
    superseded_by_edge_id VARCHAR(36),
    canonical_edge_sha256 VARCHAR(64) NOT NULL UNIQUE,
    canonical_record_json TEXT NOT NULL,
    CONSTRAINT ck_admission_edge_id CHECK (length(edge_id) = 36 AND edge_id = lower(edge_id)),
    CONSTRAINT ck_admission_edge_profile CHECK (human_profile = 'legacy_777' AND template_family = 'cltv_only' AND delta_blocks = 777),
    CONSTRAINT ck_admission_edge_depth CHECK (child_depth = sponsor_depth + 1),
    CONSTRAINT ck_admission_edge_heights CHECK (early_height > 0 AND middle_height = 1777777 - 777 * (child_depth - 1) AND early_height = middle_height - 777 AND late_height = middle_height + 777),
    CONSTRAINT ck_admission_edge_distinct_participants CHECK (sponsor_participant_id <> child_participant_id AND sponsor_compressed_public_key <> child_compressed_public_key AND sponsor_x_only_public_key <> child_x_only_public_key),
    CONSTRAINT ck_admission_edge_child_participant_convention CHECK (child_participant_id = child_x_only_public_key),
    CONSTRAINT ck_admission_edge_sponsor_convention CHECK ((sponsor_depth = 0 AND sponsor_participant_id = 'E923' AND sponsor_compressed_public_key = '023d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923' AND sponsor_x_only_public_key = '3d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923' AND sponsor_basis_kind = 'canonical_genesis_record') OR (sponsor_depth > 0 AND sponsor_participant_id = sponsor_x_only_public_key AND sponsor_basis_kind = 'canonical_admission_edge')),
    CONSTRAINT ck_admission_edge_keys CHECK (length(sponsor_compressed_public_key) = 66 AND substr(sponsor_compressed_public_key, 1, 2) IN ('02','03') AND sponsor_compressed_public_key = lower(sponsor_compressed_public_key) AND substr(sponsor_compressed_public_key, 3) = sponsor_x_only_public_key AND length(child_compressed_public_key) = 66 AND substr(child_compressed_public_key, 1, 2) IN ('02','03') AND child_compressed_public_key = lower(child_compressed_public_key) AND substr(child_compressed_public_key, 3) = child_x_only_public_key AND length(sponsor_x_only_public_key) = 64 AND sponsor_x_only_public_key = lower(sponsor_x_only_public_key) AND length(child_x_only_public_key) = 64 AND child_x_only_public_key = lower(child_x_only_public_key)),
    CONSTRAINT ck_admission_edge_source_ids CHECK (length(trusted_registration_id) = 36 AND trusted_registration_id = lower(trusted_registration_id) AND length(sponsor_basis_record_id) = 36 AND sponsor_basis_record_id = lower(sponsor_basis_record_id)),
    CONSTRAINT ck_admission_edge_digests CHECK (length(trusted_registration_sha256) = 64 AND trusted_registration_sha256 = lower(trusted_registration_sha256) AND length(pair_sha256) = 64 AND pair_sha256 = lower(pair_sha256) AND length(sponsor_basis_record_sha256) = 64 AND sponsor_basis_record_sha256 = lower(sponsor_basis_record_sha256) AND length(canonical_edge_sha256) = 64 AND canonical_edge_sha256 = lower(canonical_edge_sha256)),
    CONSTRAINT ck_admission_edge_changed_order CHECK (lifecycle_changed_at >= created_at),
    CONSTRAINT ck_admission_edge_lifecycle_consistency CHECK ((lifecycle_state = 'effective' AND effective_at IS NOT NULL AND effective_at >= created_at AND lifecycle_changed_at >= effective_at AND superseded_by_edge_id IS NULL) OR (lifecycle_state = 'proposed' AND effective_at IS NULL AND superseded_by_edge_id IS NULL) OR (lifecycle_state = 'superseded' AND superseded_by_edge_id IS NOT NULL AND superseded_by_edge_id <> edge_id) OR (lifecycle_state IN ('disputed','revoked') AND superseded_by_edge_id IS NULL)),
    CONSTRAINT ck_admission_edge_successor CHECK (superseded_by_edge_id IS NULL OR (length(superseded_by_edge_id) = 36 AND superseded_by_edge_id = lower(superseded_by_edge_id) AND superseded_by_edge_id <> edge_id))
);

CREATE TABLE canonical_admission_edge_legs (
    id BIGSERIAL PRIMARY KEY,
    edge_id VARCHAR(36) NOT NULL REFERENCES canonical_admission_edges(edge_id),
    direction VARCHAR(32) NOT NULL CHECK (direction IN ('sponsor_to_child','child_to_sponsor')),
    sender_participant_id VARCHAR(64) NOT NULL,
    sender_compressed_public_key VARCHAR(66) NOT NULL,
    sender_x_only_public_key VARCHAR(64) NOT NULL,
    receiver_participant_id VARCHAR(64) NOT NULL,
    receiver_compressed_public_key VARCHAR(66) NOT NULL,
    receiver_x_only_public_key VARCHAR(64) NOT NULL,
    receiver_cltv_height INTEGER NOT NULL CHECK (receiver_cltv_height > 0),
    sender_cltv_height INTEGER NOT NULL CHECK (sender_cltv_height > receiver_cltv_height),
    raw_script_hex TEXT NOT NULL CHECK (length(raw_script_hex) > 0 AND length(raw_script_hex) % 2 = 0 AND raw_script_hex = lower(raw_script_hex)),
    txid VARCHAR(64) NOT NULL CHECK (length(txid) = 64 AND txid = lower(txid)),
    vout BIGINT NOT NULL CHECK (vout >= 0 AND vout <= 4294967295),
    amount_sats BIGINT NOT NULL CHECK (amount_sats > 0 AND amount_sats <= 2100000000000000),
    witness_script_sha256 VARCHAR(64) NOT NULL CHECK (length(witness_script_sha256) = 64 AND witness_script_sha256 = lower(witness_script_sha256)),
    descriptor_sha256 VARCHAR(64) CHECK (descriptor_sha256 IS NULL OR (length(descriptor_sha256) = 64 AND descriptor_sha256 = lower(descriptor_sha256))),
    CONSTRAINT uq_admission_leg_edge_direction UNIQUE (edge_id, direction),
    CONSTRAINT uq_admission_leg_global_outpoint UNIQUE (txid, vout),
    CONSTRAINT ck_admission_leg_distinct_participants CHECK (sender_participant_id <> receiver_participant_id AND sender_compressed_public_key <> receiver_compressed_public_key AND sender_x_only_public_key <> receiver_x_only_public_key)
);

CREATE INDEX idx_admission_edge_graph ON canonical_admission_edges (graph_or_protocol_id);
CREATE INDEX idx_admission_edge_child ON canonical_admission_edges (graph_or_protocol_id, child_x_only_public_key);
CREATE INDEX idx_admission_edge_sponsor ON canonical_admission_edges (graph_or_protocol_id, sponsor_x_only_public_key);
CREATE UNIQUE INDEX uq_admission_edge_effective_child_id ON canonical_admission_edges (graph_or_protocol_id, child_participant_id) WHERE lifecycle_state = 'effective';
CREATE UNIQUE INDEX uq_admission_edge_effective_child_key ON canonical_admission_edges (graph_or_protocol_id, child_x_only_public_key) WHERE lifecycle_state = 'effective';
CREATE INDEX idx_admission_leg_edge ON canonical_admission_edge_legs (edge_id);
