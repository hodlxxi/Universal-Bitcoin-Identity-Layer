-- Dormant, add-only Canon V2 CANDIDATE storage. NOT effective admission or Full.
-- Requires 2026-11-13_canonical_admission_consent_challenge_v2.sql.
-- No grants, runtime routes, ORMs, triggers granting access or deployment.
-- DO NOT APPLY IN PRODUCTION without a lifecycle/replacement/rollback policy.

CREATE TABLE public.canonical_admission_candidates_v2 (
    edge_id VARCHAR(36) PRIMARY KEY,
    proposal_sha256 CHAR(64) NOT NULL UNIQUE,
    edge_sha256 CHAR(64) NOT NULL UNIQUE,
    sponsor_compressed_pubkey CHAR(66) NOT NULL,
    sponsor_xonly_pubkey CHAR(64) NOT NULL,
    child_compressed_pubkey CHAR(66) NOT NULL,
    child_xonly_pubkey CHAR(64) NOT NULL UNIQUE,
    sponsor_depth INTEGER NOT NULL,
    child_depth INTEGER NOT NULL,
    basis_kind VARCHAR(24) NOT NULL,
    parent_edge_id VARCHAR(36),
    parent_proposal_sha256 CHAR(64),
    registration_id VARCHAR(36) NOT NULL UNIQUE,
    registration_sha256 CHAR(64) NOT NULL UNIQUE,
    funding_set_id VARCHAR(36) NOT NULL UNIQUE,
    funding_set_sha256 CHAR(64) NOT NULL UNIQUE,
    challenge_sha256 CHAR(64) NOT NULL UNIQUE
        REFERENCES public.canonical_admission_consent_challenges_v2(challenge_sha256),
    verification_sha256 CHAR(64) NOT NULL UNIQUE,
    sponsor_full_proof_id VARCHAR(128) NOT NULL,
    sponsor_full_evidence_id VARCHAR(36) NOT NULL,
    sponsor_full_evidence_sha256 CHAR(64) NOT NULL,
    sponsor_full_valid_until TIMESTAMPTZ NOT NULL,
    current_lineage_observed_at TIMESTAMPTZ NOT NULL,
    candidate_created_at TIMESTAMPTZ NOT NULL,
    candidate_state VARCHAR(24) NOT NULL DEFAULT 'candidate_only_no_full',
    CONSTRAINT ck_cav2_state CHECK (candidate_state = 'candidate_only_no_full'),
    CONSTRAINT ck_cav2_edge_uuid CHECK (
        edge_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    ),
    CONSTRAINT ck_cav2_proposal_sha CHECK (proposal_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_cav2_edge_sha CHECK (edge_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_cav2_sponsor CHECK (
        sponsor_compressed_pubkey ~ '^(02|03)[0-9a-f]{64}$'
        AND sponsor_xonly_pubkey = substr(sponsor_compressed_pubkey,3)
    ),
    CONSTRAINT ck_cav2_child CHECK (
        child_compressed_pubkey ~ '^(02|03)[0-9a-f]{64}$'
        AND child_xonly_pubkey = substr(child_compressed_pubkey,3)
        AND child_xonly_pubkey <> sponsor_xonly_pubkey
    ),
    CONSTRAINT ck_cav2_depth CHECK (
        sponsor_depth >= 0 AND child_depth = sponsor_depth + 1 AND child_depth <= 2288
    ),
    CONSTRAINT ck_cav2_basis CHECK (
        (sponsor_depth = 0 AND basis_kind = 'genesis_record'
            AND parent_edge_id IS NULL AND parent_proposal_sha256 IS NULL)
        OR (sponsor_depth > 0 AND basis_kind = 'parent_v2_proposal'
            AND parent_edge_id IS NOT NULL AND parent_proposal_sha256 IS NOT NULL)
    ),
    CONSTRAINT ck_cav2_registration_sha CHECK (registration_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_cav2_funding_sha CHECK (funding_set_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_cav2_challenge_sha CHECK (challenge_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_cav2_verification_sha CHECK (verification_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_cav2_sponsor_full_sha CHECK (sponsor_full_evidence_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_cav2_proof CHECK (
        sponsor_full_proof_id ~ '^hodlxxi-full-entitlement-v1-sha256:[0-9a-f]{64}$'
    ),
    CONSTRAINT ck_cav2_valid_times CHECK (
        sponsor_full_valid_until > candidate_created_at
        AND current_lineage_observed_at <= candidate_created_at
        AND candidate_created_at <= current_lineage_observed_at + INTERVAL '120 seconds'
    ),
    CONSTRAINT uq_cav2_edge_proposal UNIQUE (edge_id, proposal_sha256),
    CONSTRAINT fk_cav2_parent FOREIGN KEY (parent_edge_id, parent_proposal_sha256)
        REFERENCES public.canonical_admission_candidates_v2(edge_id, proposal_sha256)
);

CREATE INDEX idx_cav2_sponsor ON public.canonical_admission_candidates_v2(sponsor_xonly_pubkey);
CREATE INDEX idx_cav2_parent ON public.canonical_admission_candidates_v2(parent_edge_id);

CREATE TABLE public.canonical_admission_candidate_outpoints_v2 (
    edge_id VARCHAR(36) NOT NULL REFERENCES public.canonical_admission_candidates_v2(edge_id),
    leg_order VARCHAR(7) NOT NULL CHECK (leg_order IN ('earlier','later')),
    txid CHAR(64) NOT NULL CHECK (txid ~ '^[0-9a-f]{64}$'),
    vout BIGINT NOT NULL CHECK (vout >= 0 AND vout <= 4294967295),
    amount_sats BIGINT NOT NULL CHECK (amount_sats > 0 AND amount_sats <= 2100000000000000),
    witness_script_sha256 CHAR(64) NOT NULL
        CHECK (witness_script_sha256 ~ '^[0-9a-f]{64}$'),
    PRIMARY KEY (edge_id, leg_order),
    CONSTRAINT uq_cav2_global_outpoint UNIQUE (txid, vout)
);

-- Proposed candidates are immutable. This stage does not implement a
-- lifecycle transition; even a database row may NEVER be used as Full.
CREATE FUNCTION public.guard_canonical_admission_candidate_v2()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'canonical V2 candidate immutable: no UPDATE/DELETE';
END;
$$;

CREATE TRIGGER trg_guard_cav2_candidate
BEFORE UPDATE OR DELETE ON public.canonical_admission_candidates_v2
FOR EACH ROW EXECUTE FUNCTION public.guard_canonical_admission_candidate_v2();

CREATE TRIGGER trg_guard_cav2_outpoint
BEFORE UPDATE OR DELETE ON public.canonical_admission_candidate_outpoints_v2
FOR EACH ROW EXECUTE FUNCTION public.guard_canonical_admission_candidate_v2();

COMMENT ON TABLE public.canonical_admission_candidates_v2 IS
    'Dormant proposed-only admission candidate. Never an EFFECTIVE edge or Full.';
COMMENT ON TABLE public.canonical_admission_candidate_outpoints_v2 IS
    'Exactly two legs inserted by trusted future caller transaction; no entitlement.';
