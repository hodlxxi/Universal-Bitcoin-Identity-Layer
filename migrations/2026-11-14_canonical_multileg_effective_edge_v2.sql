-- Issue #588, slice 1. An immutable EFFECTIVE admission/evidence binding.
-- This DORMANT migration is for disposable PostgreSQL 16 CI only.
-- Not a permission to enroll anybody, issue Full, run live migrations, or deploy.
-- Prerequisites: candidate, expiry, global outpoint claims V2 migrations
-- and public.current_entitlement_evidence. Apply transactionally.
--
-- A row is NOT independent proof of real Bitcoin validation. The later
-- trusted server-owned RPC + signer/session transaction must originate every
-- Full evidence record and the matching effective edge atomically.
CREATE TABLE public.canonical_multileg_effective_edges_v2 (
    proposal_id VARCHAR(36) PRIMARY KEY
        REFERENCES public.canonical_multileg_admission_candidates_v2(proposal_id),
    proposal_sha256 CHAR(64) NOT NULL CHECK (proposal_sha256 ~ '^[0-9a-f]{64}$'),
    sponsor_xonly_pubkey CHAR(64) NOT NULL CHECK (sponsor_xonly_pubkey ~ '^[0-9a-f]{64}$'),
    child_xonly_pubkey CHAR(64) NOT NULL UNIQUE CHECK (child_xonly_pubkey ~ '^[0-9a-f]{64}$'),
    child_depth INTEGER NOT NULL CHECK (child_depth BETWEEN 1 AND 2288),
    parent_proposal_id VARCHAR(36) REFERENCES public.canonical_multileg_effective_edges_v2(proposal_id),
    entitlement_evidence_id VARCHAR(36) NOT NULL UNIQUE
        REFERENCES public.current_entitlement_evidence(evidence_id),
    source_evidence_sha256 CHAR(64) NOT NULL CHECK (source_evidence_sha256 ~ '^[0-9a-f]{64}$'),
    checked_tip_hash CHAR(64) NOT NULL CHECK (checked_tip_hash ~ '^[0-9a-f]{64}$'),
    checked_mempool_sequence BIGINT NOT NULL CHECK (checked_mempool_sequence >= 0),
    observed_at TIMESTAMPTZ NOT NULL,
    effective_at TIMESTAMPTZ NOT NULL DEFAULT date_trunc('second', clock_timestamp()),
    CONSTRAINT ck_cmev2_parent_depth CHECK (
        (child_depth = 1 AND parent_proposal_id IS NULL)
        OR (child_depth > 1 AND parent_proposal_id IS NOT NULL)
    ),
    CONSTRAINT ck_cmev2_observation_window CHECK (
        observed_at <= effective_at
        AND effective_at <= observed_at + INTERVAL '60 seconds'
    )
);
CREATE INDEX idx_cmev2_parent ON public.canonical_multileg_effective_edges_v2(parent_proposal_id);

-- An independently authenticated writer must supply a coherent fresh chain
-- receipt, signer proof, and Current Full evidence in the SAME transaction.
-- PostgreSQL can check their bindings, not whether the RPC was trustworthy.
CREATE FUNCTION public.validate_canonical_multileg_effective_edge_v2()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE
    candidate RECORD;
    parent RECORD;
    evidence RECORD;
    matching_outpoints BIGINT;
    matching_global BIGINT;
    live_count BIGINT;
    observed_now TIMESTAMPTZ;
BEGIN
    observed_now := clock_timestamp();
    SELECT * INTO candidate
      FROM public.canonical_multileg_admission_candidates_v2
     WHERE proposal_id = NEW.proposal_id FOR UPDATE;
    IF NOT FOUND
       OR candidate.state <> 'candidate_only_no_full'
       OR candidate.proposal_sha256 <> NEW.proposal_sha256
       OR candidate.sponsor_xonly_pubkey <> NEW.sponsor_xonly_pubkey
       OR candidate.child_xonly_pubkey <> NEW.child_xonly_pubkey
       OR candidate.child_depth <> NEW.child_depth
       OR candidate.parent_proposal_id IS DISTINCT FROM NEW.parent_proposal_id
    THEN
        RAISE EXCEPTION 'effective edge candidate binding failed';
    END IF;

    IF NEW.effective_at > observed_now + INTERVAL '5 seconds'
       OR NEW.effective_at < observed_now - INTERVAL '10 seconds'
       OR NEW.observed_at < observed_now - INTERVAL '60 seconds'
       OR NEW.effective_at >= candidate.candidate_created_at + INTERVAL '7 days'
       OR EXISTS (
          SELECT 1 FROM public.canonical_multileg_candidate_expirations_v2
           WHERE proposal_id = NEW.proposal_id
       )
    THEN
        RAISE EXCEPTION 'effective edge expired or stale';
    END IF;

    -- Serialize against expiry's candidate and child-reservation locks.
    PERFORM 1 FROM public.canonical_multileg_live_child_claims_v2
     WHERE proposal_id = NEW.proposal_id
       AND child_xonly_pubkey = NEW.child_xonly_pubkey FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'candidate has no live child reservation';
    END IF;

    SELECT COUNT(*) INTO live_count
      FROM public.canonical_multileg_live_outpoint_claims_v2
     WHERE proposal_id = NEW.proposal_id;
    SELECT COUNT(*) INTO matching_global
      FROM public.canonical_global_outpoint_claims_v2
     WHERE claim_kind = 'multileg' AND multileg_proposal_id = NEW.proposal_id;
    SELECT COUNT(*) INTO matching_outpoints
      FROM public.canonical_multileg_candidate_outpoints_v2 AS u
      JOIN public.canonical_multileg_live_outpoint_claims_v2 AS l
        ON l.txid = u.txid AND l.vout = u.vout AND l.proposal_id = u.proposal_id
      JOIN public.canonical_global_outpoint_claims_v2 AS g
        ON g.txid = u.txid AND g.vout = u.vout
       AND g.claim_kind = 'multileg' AND g.multileg_proposal_id = u.proposal_id
     WHERE u.proposal_id = NEW.proposal_id;
    IF live_count <> candidate.outpoint_count
       OR matching_global <> candidate.outpoint_count
       OR matching_outpoints <> candidate.outpoint_count
    THEN
        RAISE EXCEPTION 'effective edge collateral reservation incomplete';
    END IF;

    PERFORM 1 FROM public.canonical_multileg_consent_challenges_v2
     WHERE challenge_sha256 = candidate.challenge_sha256
       AND verification_sha256 = candidate.verification_sha256
       AND proposal_sha256 = candidate.proposal_sha256
       AND consumed_at IS NOT NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'signed consent not consumed';
    END IF;

    IF candidate.sponsor_depth = 0 THEN
        IF NEW.parent_proposal_id IS NOT NULL THEN
            RAISE EXCEPTION 'root admission cannot claim parent';
        END IF;
    ELSE
        SELECT * INTO parent
          FROM public.canonical_multileg_effective_edges_v2
         WHERE proposal_id = NEW.parent_proposal_id FOR SHARE;
        IF NOT FOUND
           OR parent.child_xonly_pubkey <> NEW.sponsor_xonly_pubkey
           OR parent.child_depth + 1 <> NEW.child_depth
        THEN
            RAISE EXCEPTION 'sponsor has no exact effective parent';
        END IF;
    END IF;

    SELECT * INTO evidence
      FROM public.current_entitlement_evidence
     WHERE evidence_id = NEW.entitlement_evidence_id FOR SHARE;
    IF NOT FOUND
       OR evidence.subject_pubkey <> NEW.child_xonly_pubkey
       OR evidence.identity_class <> 'full'
       OR evidence.current_full_relation_satisfied IS NOT TRUE
       OR evidence.revoked_at IS NOT NULL
       OR evidence.evidence_source <> 'canonical_v2_effective_admission'
       OR evidence.evidence_version <> 'hodlxxi.canon_v2_effective.v1'
       OR evidence.source_evidence_sha256 <> NEW.source_evidence_sha256
       OR evidence.observed_at <> NEW.observed_at
       OR evidence.valid_until <= NEW.effective_at
       OR evidence.created_at < NEW.observed_at
    THEN
        RAISE EXCEPTION 'effective edge missing bound Current Full evidence';
    END IF;
    PERFORM 1 FROM public.users
     WHERE pubkey = NEW.child_xonly_pubkey AND is_active IS TRUE FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'effective child subject not active';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_cmev2_validate
BEFORE INSERT ON public.canonical_multileg_effective_edges_v2
FOR EACH ROW EXECUTE FUNCTION public.validate_canonical_multileg_effective_edge_v2();

CREATE FUNCTION public.guard_canonical_multileg_effective_edge_v2()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
BEGIN
    RAISE EXCEPTION 'effective edge history is immutable';
END;
$$;

CREATE TRIGGER trg_cmev2_immutable
BEFORE UPDATE OR DELETE ON public.canonical_multileg_effective_edges_v2
FOR EACH ROW EXECUTE FUNCTION public.guard_canonical_multileg_effective_edge_v2();

-- A future effective grant MUST keep both its live identity and every
-- global UTXO claim; a candidate-only 7-day TTL may never release it.
CREATE FUNCTION public.guard_effective_multileg_claim_release_v2()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM public.canonical_multileg_effective_edges_v2
         WHERE proposal_id = OLD.proposal_id
    ) THEN
        RAISE EXCEPTION 'effective admission collateral and identity are permanent';
    END IF;
    RETURN OLD;
END;
$$;

CREATE TRIGGER trg_cmev2_protect_live_outpoints
BEFORE DELETE ON public.canonical_multileg_live_outpoint_claims_v2
FOR EACH ROW EXECUTE FUNCTION public.guard_effective_multileg_claim_release_v2();

CREATE TRIGGER trg_cmev2_protect_live_child
BEFORE DELETE ON public.canonical_multileg_live_child_claims_v2
FOR EACH ROW EXECUTE FUNCTION public.guard_effective_multileg_claim_release_v2();

REVOKE INSERT, UPDATE, DELETE ON public.canonical_multileg_effective_edges_v2 FROM PUBLIC;
REVOKE ALL ON FUNCTION public.validate_canonical_multileg_effective_edge_v2() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.guard_canonical_multileg_effective_edge_v2() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.guard_effective_multileg_claim_release_v2() FROM PUBLIC;
COMMENT ON TABLE public.canonical_multileg_effective_edges_v2 IS
'Issue 588 dormant irreversible effective/evidence binding; never an RPC authority or independent Full grant.';