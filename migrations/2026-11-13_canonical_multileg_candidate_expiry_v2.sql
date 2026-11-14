-- Dormant, additive *candidate-only* expiration and reusable reservation ledger.
-- Stacked after 2026-11-13_canonical_multileg_admission_candidates_v2.sql.
-- No EFFECTIVE, Full, role grant, production migration, or background scheduler.
-- Historical candidate headers and outpoint evidence remain immutable.
-- This migration transfers exclusivity from historical UNIQUE keys to
-- live reservation tables, allowing *expired unpromoted candidates* to
-- release their claims without erasing evidence or reopening a nonce.
-- DO NOT DEPLOY: actual effective admission, trusted Bitcoin provenance,
-- cross-version global claims and live DB privilege separation are absent.

CREATE TABLE public.canonical_multileg_live_child_claims_v2 (
    child_xonly_pubkey CHAR(64) PRIMARY KEY,
    proposal_id VARCHAR(36) NOT NULL UNIQUE
        REFERENCES public.canonical_multileg_admission_candidates_v2(proposal_id)
);

CREATE TABLE public.canonical_multileg_live_outpoint_claims_v2 (
    txid CHAR(64) NOT NULL,
    vout BIGINT NOT NULL,
    proposal_id VARCHAR(36) NOT NULL
        REFERENCES public.canonical_multileg_admission_candidates_v2(proposal_id),
    PRIMARY KEY (txid, vout)
);

CREATE INDEX idx_cml_live_claim_owner
ON public.canonical_multileg_live_outpoint_claims_v2(proposal_id);

-- Backfill all currently existing candidate reservations BEFORE dropping
-- historical uniqueness. Any inconsistency fails migration atomically.
INSERT INTO public.canonical_multileg_live_child_claims_v2
    (child_xonly_pubkey, proposal_id)
SELECT child_xonly_pubkey, proposal_id
FROM public.canonical_multileg_admission_candidates_v2;

INSERT INTO public.canonical_multileg_live_outpoint_claims_v2
    (txid, vout, proposal_id)
SELECT txid, vout, proposal_id
FROM public.canonical_multileg_candidate_outpoints_v2;

-- PostgreSQL can shorten automatically generated constraint names. Find
-- exactly one UNIQUE(child_xonly_pubkey), otherwise fail rather than guess.
DO $$
DECLARE
    unique_name NAME;
    matches INTEGER;
BEGIN
    SELECT COUNT(*), MIN(conname::text)::name INTO matches, unique_name
      FROM pg_constraint
     WHERE conrelid = 'public.canonical_multileg_admission_candidates_v2'::regclass
       AND contype = 'u'
       AND pg_get_constraintdef(oid) LIKE 'UNIQUE (child_xonly_pubkey)%';
    IF matches <> 1 THEN
        RAISE EXCEPTION 'expected exactly one historical child unique constraint';
    END IF;
    EXECUTE format(
        'ALTER TABLE public.canonical_multileg_admission_candidates_v2 DROP CONSTRAINT %I',
        unique_name
    );
END;
$$;

ALTER TABLE public.canonical_multileg_candidate_outpoints_v2
    DROP CONSTRAINT uq_cmlaco_outpoint;

-- Forbid direct DML by later non-owner runtime principals. Owner and
-- superuser privileges remain a deployment/DB-role configuration concern.
REVOKE INSERT, UPDATE, DELETE
    ON public.canonical_multileg_live_child_claims_v2 FROM PUBLIC;
REVOKE INSERT, UPDATE, DELETE
    ON public.canonical_multileg_live_outpoint_claims_v2 FROM PUBLIC;

CREATE FUNCTION public.claim_canonical_multileg_child_v2()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
BEGIN
    IF NEW.parent_proposal_id IS NOT NULL THEN
        PERFORM 1
          FROM public.canonical_multileg_live_child_claims_v2 AS claim
         WHERE claim.proposal_id = NEW.parent_proposal_id
         FOR SHARE;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'parent candidate reservation has expired';
        END IF;
    END IF;
    INSERT INTO public.canonical_multileg_live_child_claims_v2
        (child_xonly_pubkey, proposal_id)
    VALUES (NEW.child_xonly_pubkey, NEW.proposal_id);
    RETURN NULL;
END;
$$;

CREATE TRIGGER trg_cml_claim_child
AFTER INSERT ON public.canonical_multileg_admission_candidates_v2
FOR EACH ROW EXECUTE FUNCTION public.claim_canonical_multileg_child_v2();

CREATE FUNCTION public.claim_canonical_multileg_outpoint_v2()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE
    header_count INTEGER;
    existing_count BIGINT;
BEGIN
    -- Serialize with expiration and any concurrent output insert, and
    -- reject the sixth outpoint of a completely committed five-output set.
    SELECT outpoint_count INTO header_count
      FROM public.canonical_multileg_admission_candidates_v2
     WHERE proposal_id = NEW.proposal_id
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'multileg candidate header missing';
    END IF;
    PERFORM 1
      FROM public.canonical_multileg_live_child_claims_v2
     WHERE proposal_id = NEW.proposal_id
     FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'candidate reservation has expired';
    END IF;
    SELECT COUNT(*) INTO existing_count
      FROM public.canonical_multileg_live_outpoint_claims_v2
     WHERE proposal_id = NEW.proposal_id;
    IF existing_count >= header_count THEN
        RAISE EXCEPTION 'multileg candidate already has complete outpoints';
    END IF;
    INSERT INTO public.canonical_multileg_live_outpoint_claims_v2
        (txid, vout, proposal_id)
    VALUES (NEW.txid, NEW.vout, NEW.proposal_id);
    RETURN NULL;
END;
$$;

CREATE TRIGGER trg_cml_claim_outpoint
AFTER INSERT ON public.canonical_multileg_candidate_outpoints_v2
FOR EACH ROW EXECUTE FUNCTION public.claim_canonical_multileg_outpoint_v2();

CREATE TABLE public.canonical_multileg_candidate_expirations_v2 (
    proposal_id VARCHAR(36) PRIMARY KEY
        REFERENCES public.canonical_multileg_admission_candidates_v2(proposal_id),
    proposal_sha256 CHAR(64) NOT NULL CHECK (proposal_sha256 ~ '^[0-9a-f]{64}$'),
    expired_at TIMESTAMPTZ NOT NULL,
    reason VARCHAR(48) NOT NULL DEFAULT 'candidate_ttl_expired_no_full',
    released_outpoint_count INTEGER NOT NULL CHECK (
        released_outpoint_count BETWEEN 2 AND 256
    ),
    CONSTRAINT ck_cml_expiry_reason CHECK (
        reason = 'candidate_ttl_expired_no_full'
    )
);

CREATE FUNCTION public.guard_canonical_multileg_candidate_expiry_v2()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'candidate expiration history is immutable';
END;
$$;

CREATE TRIGGER trg_cml_expiry_immutable
BEFORE UPDATE OR DELETE ON public.canonical_multileg_candidate_expirations_v2
FOR EACH ROW EXECUTE FUNCTION public.guard_canonical_multileg_candidate_expiry_v2();

-- No endpoint invokes this function. It can expire ONLY already-committed
-- PROPOSED-only reservations after seven days, never effective rights.
-- A parent's active children block retirement. Every record is historical.
CREATE FUNCTION public.expire_canonical_multileg_candidate_v2(p_proposal_id VARCHAR)
RETURNS TABLE (expired_proposal_id VARCHAR, released_outpoints INTEGER, at_time TIMESTAMPTZ)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE
    candidate RECORD;
    active_key VARCHAR(36);
    n INTEGER;
    freed INTEGER;
    today TIMESTAMPTZ;
BEGIN
    IF p_proposal_id IS NULL THEN
        RAISE EXCEPTION 'candidate identifier required';
    END IF;

    SELECT c.proposal_id, c.proposal_sha256, c.candidate_created_at,
           c.outpoint_count, c.child_xonly_pubkey, c.state
      INTO candidate
      FROM public.canonical_multileg_admission_candidates_v2 AS c
     WHERE c.proposal_id = p_proposal_id
     FOR UPDATE;
    IF NOT FOUND OR candidate.state <> 'candidate_only_no_full' THEN
        RAISE EXCEPTION 'candidate is not proposed-only';
    END IF;

    SELECT claim.proposal_id INTO active_key
      FROM public.canonical_multileg_live_child_claims_v2 AS claim
     WHERE claim.proposal_id = p_proposal_id
     FOR UPDATE;
    IF NOT FOUND OR active_key <> p_proposal_id THEN
        RAISE EXCEPTION 'candidate reservation not active';
    END IF;

    today := date_trunc('second', clock_timestamp());
    IF today < candidate.candidate_created_at + INTERVAL '7 days' THEN
        RAISE EXCEPTION 'candidate expiration deadline not reached';
    END IF;

    -- Parent may expire only after every direct child has independently
    -- expired. By induction this also excludes active descendants.
    PERFORM 1
      FROM public.canonical_multileg_admission_candidates_v2 AS child
      JOIN public.canonical_multileg_live_child_claims_v2 AS active
        ON active.proposal_id = child.proposal_id
     WHERE child.parent_proposal_id = p_proposal_id
       AND child.parent_proposal_sha256 = candidate.proposal_sha256
     LIMIT 1;
    IF FOUND THEN
        RAISE EXCEPTION 'candidate has active descendant';
    END IF;

    DELETE FROM public.canonical_multileg_live_outpoint_claims_v2
     WHERE proposal_id = p_proposal_id;
    GET DIAGNOSTICS freed = ROW_COUNT;
    IF freed <> candidate.outpoint_count THEN
        RAISE EXCEPTION 'candidate outpoint claims incomplete: rollback required';
    END IF;

    DELETE FROM public.canonical_multileg_live_child_claims_v2
     WHERE child_xonly_pubkey = candidate.child_xonly_pubkey
       AND proposal_id = p_proposal_id;
    GET DIAGNOSTICS n = ROW_COUNT;
    IF n <> 1 THEN
        RAISE EXCEPTION 'candidate child claim missing: rollback required';
    END IF;

    INSERT INTO public.canonical_multileg_candidate_expirations_v2 (
        proposal_id, proposal_sha256, expired_at,
        reason, released_outpoint_count
    ) VALUES (
        p_proposal_id, candidate.proposal_sha256, today,
        'candidate_ttl_expired_no_full', freed
    );

    RETURN QUERY SELECT p_proposal_id, freed, today;
END;
$$;

-- Until a dedicated, least-privilege internal service role is defined,
-- do NOT grant public executability or connect to live request routing.
REVOKE ALL ON FUNCTION public.expire_canonical_multileg_candidate_v2(VARCHAR) FROM PUBLIC;

COMMENT ON TABLE public.canonical_multileg_candidate_expirations_v2 IS
    'Historical terminal event for a never-effective multileg candidate; no Full and no admission.';
COMMENT ON TABLE public.canonical_multileg_live_child_claims_v2 IS
    'Exclusive current proposed-only child reservations, distinct from immutable candidate history.';
COMMENT ON TABLE public.canonical_multileg_live_outpoint_claims_v2 IS
    'Exclusive current proposed-only UTXO reservations within multileg V2 ONLY; not cross-version global.';
