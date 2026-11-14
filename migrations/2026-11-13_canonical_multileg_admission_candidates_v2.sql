-- Dormant Canon V2 multileg candidate intake. NO EFFECTIVE/FULL semantics.
-- Additive PostgreSQL 16 migration, never automatically applied.
-- Prerequisite: 2026-11-13_canonical_multileg_consent_challenge_v2.sql.
-- Not a live admission registry; lifecycle and legacy claim interoperability are unimplemented.

CREATE TABLE public.canonical_multileg_admission_candidates_v2 (
    proposal_id VARCHAR(36) PRIMARY KEY,
    proposal_sha256 CHAR(64) NOT NULL UNIQUE,
    mirror_sha256 CHAR(64) NOT NULL,
    sponsor_compressed_pubkey CHAR(66) NOT NULL,
    sponsor_xonly_pubkey CHAR(64) NOT NULL,
    child_compressed_pubkey CHAR(66) NOT NULL,
    child_xonly_pubkey CHAR(64) NOT NULL UNIQUE,
    sponsor_depth INTEGER NOT NULL,
    child_depth INTEGER NOT NULL,
    basis_kind VARCHAR(24) NOT NULL,
    basis_record_id VARCHAR(36) NOT NULL,
    basis_record_sha256 CHAR(64) NOT NULL,
    parent_proposal_id VARCHAR(36),
    parent_proposal_sha256 CHAR(64),
    challenge_sha256 CHAR(64) NOT NULL UNIQUE
        REFERENCES public.canonical_multileg_consent_challenges_v2(challenge_sha256),
    verification_sha256 CHAR(64) NOT NULL UNIQUE,
    sponsor_full_proof_id VARCHAR(128) NOT NULL,
    sponsor_full_evidence_id VARCHAR(36) NOT NULL,
    sponsor_full_evidence_sha256 CHAR(64) NOT NULL,
    sponsor_full_valid_until TIMESTAMPTZ NOT NULL,
    observation_sha256 CHAR(64) NOT NULL,
    observation_block_height INTEGER NOT NULL,
    snapshot_observed_at TIMESTAMPTZ NOT NULL,
    earlier_sats BIGINT NOT NULL,
    later_sats BIGINT NOT NULL,
    trust_ceiling_sats BIGINT NOT NULL,
    outpoint_count INTEGER NOT NULL,
    candidate_created_at TIMESTAMPTZ NOT NULL,
    state VARCHAR(32) NOT NULL DEFAULT 'candidate_only_no_full',
    CONSTRAINT ck_cmlac_state CHECK (state = 'candidate_only_no_full'),
    CONSTRAINT ck_cmlac_proposal_id CHECK (
        proposal_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    ),
    CONSTRAINT ck_cmlac_basis_id CHECK (
        basis_record_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    ),
    CONSTRAINT ck_cmlac_digests CHECK (
        proposal_sha256 ~ '^[0-9a-f]{64}$'
        AND mirror_sha256 ~ '^[0-9a-f]{64}$'
        AND basis_record_sha256 ~ '^[0-9a-f]{64}$'
        AND challenge_sha256 ~ '^[0-9a-f]{64}$'
        AND verification_sha256 ~ '^[0-9a-f]{64}$'
        AND sponsor_full_evidence_sha256 ~ '^[0-9a-f]{64}$'
        AND observation_sha256 ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT ck_cmlac_sponsor CHECK (
        sponsor_compressed_pubkey ~ '^(02|03)[0-9a-f]{64}$'
        AND sponsor_xonly_pubkey = substr(sponsor_compressed_pubkey, 3)
    ),
    CONSTRAINT ck_cmlac_child CHECK (
        child_compressed_pubkey ~ '^(02|03)[0-9a-f]{64}$'
        AND child_xonly_pubkey = substr(child_compressed_pubkey, 3)
        AND child_xonly_pubkey <> sponsor_xonly_pubkey
    ),
    CONSTRAINT ck_cmlac_depth CHECK (
        sponsor_depth >= 0 AND child_depth = sponsor_depth + 1 AND child_depth <= 2288
    ),
    CONSTRAINT ck_cmlac_basis CHECK (
        (sponsor_depth = 0 AND basis_kind = 'genesis_record'
            AND parent_proposal_id IS NULL AND parent_proposal_sha256 IS NULL)
        OR (sponsor_depth > 0 AND basis_kind = 'parent_v2_proposal'
            AND parent_proposal_id = basis_record_id
            AND parent_proposal_sha256 = basis_record_sha256)
    ),
    CONSTRAINT ck_cmlac_full_proof CHECK (
        sponsor_full_proof_id ~ '^hodlxxi-full-entitlement-v1-sha256:[0-9a-f]{64}$'
    ),
    CONSTRAINT ck_cmlac_amounts CHECK (
        earlier_sats > 0 AND later_sats > 0
        AND earlier_sats <= 2100000000000000 AND later_sats <= 2100000000000000
        AND trust_ceiling_sats = LEAST(earlier_sats, later_sats)
    ),
    CONSTRAINT ck_cmlac_outpoint_count CHECK (
        outpoint_count >= 2 AND outpoint_count <= 256
        AND observation_block_height >= 0
    ),
    CONSTRAINT ck_cmlac_times CHECK (
        candidate_created_at >= snapshot_observed_at
        AND candidate_created_at <= snapshot_observed_at + INTERVAL '120 seconds'
        AND candidate_created_at < sponsor_full_valid_until
    ),
    CONSTRAINT uq_cmlac_id_sha UNIQUE (proposal_id, proposal_sha256),
    CONSTRAINT fk_cmlac_parent FOREIGN KEY (parent_proposal_id, parent_proposal_sha256)
        REFERENCES public.canonical_multileg_admission_candidates_v2(proposal_id, proposal_sha256)
);

CREATE TABLE public.canonical_multileg_candidate_outpoints_v2 (
    proposal_id VARCHAR(36) NOT NULL
        REFERENCES public.canonical_multileg_admission_candidates_v2(proposal_id),
    leg_order VARCHAR(7) NOT NULL CHECK (leg_order IN ('earlier', 'later')),
    txid CHAR(64) NOT NULL CHECK (txid ~ '^[0-9a-f]{64}$'),
    vout BIGINT NOT NULL CHECK (vout >= 0 AND vout <= 4294967295),
    amount_sats BIGINT NOT NULL CHECK (amount_sats > 0 AND amount_sats <= 2100000000000000),
    script_pubkey_sha256 CHAR(64) NOT NULL CHECK (script_pubkey_sha256 ~ '^[0-9a-f]{64}$'),
    descriptor_sha256 CHAR(64) CHECK (
        descriptor_sha256 IS NULL OR descriptor_sha256 ~ '^[0-9a-f]{64}$'
    ),
    PRIMARY KEY (proposal_id, txid, vout),
    CONSTRAINT uq_cmlaco_outpoint UNIQUE (txid, vout)
);

CREATE INDEX idx_cmlac_parent ON public.canonical_multileg_admission_candidates_v2(parent_proposal_id);
CREATE INDEX idx_cmlac_sponsor ON public.canonical_multileg_admission_candidates_v2(sponsor_xonly_pubkey);

-- A statement can insert a header before its N outpoints. The deferred
-- constraint verifies the COMPLETE record at COMMIT (not at each INSERT).
CREATE FUNCTION public.validate_canonical_multileg_candidate_v2()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE
    n BIGINT;
    earlier_n BIGINT;
    later_n BIGINT;
    earlier_total NUMERIC;
    later_total NUMERIC;
BEGIN
    SELECT COUNT(*),
           COUNT(*) FILTER (WHERE leg_order = 'earlier'),
           COUNT(*) FILTER (WHERE leg_order = 'later'),
           COALESCE(SUM(amount_sats) FILTER (WHERE leg_order = 'earlier'), 0),
           COALESCE(SUM(amount_sats) FILTER (WHERE leg_order = 'later'), 0)
      INTO n, earlier_n, later_n, earlier_total, later_total
      FROM public.canonical_multileg_candidate_outpoints_v2
     WHERE proposal_id = NEW.proposal_id;

    IF n <> NEW.outpoint_count
       OR earlier_n < 1 OR later_n < 1
       OR earlier_total <> NEW.earlier_sats
       OR later_total <> NEW.later_sats
       OR LEAST(earlier_total, later_total) <> NEW.trust_ceiling_sats THEN
        RAISE EXCEPTION 'incomplete multileg candidate: exact output count/sums required at COMMIT';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER trg_cmlac_complete
AFTER INSERT ON public.canonical_multileg_admission_candidates_v2
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION public.validate_canonical_multileg_candidate_v2();

CREATE FUNCTION public.guard_canonical_multileg_candidate_immutable_v2()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'multileg candidate is immutable; no updates or deletes';
END;
$$;

CREATE TRIGGER trg_cmlac_immutable
BEFORE UPDATE OR DELETE ON public.canonical_multileg_admission_candidates_v2
FOR EACH ROW EXECUTE FUNCTION public.guard_canonical_multileg_candidate_immutable_v2();

CREATE TRIGGER trg_cmlaco_immutable
BEFORE UPDATE OR DELETE ON public.canonical_multileg_candidate_outpoints_v2
FOR EACH ROW EXECUTE FUNCTION public.guard_canonical_multileg_candidate_immutable_v2();

COMMENT ON TABLE public.canonical_multileg_admission_candidates_v2 IS
    'Dormant candidate ONLY; never effective admission or a Current Full identity.';
COMMENT ON TABLE public.canonical_multileg_candidate_outpoints_v2 IS
    'Every signed P2WSH mirror UTXO is materialized; unique only within this new table.';
