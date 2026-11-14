-- DORMANT: one transaction-serialized UTXO index across strict-two and multileg V2.
-- Requires the strict-two candidate migration, the multileg candidate migration,
-- and the multileg candidate expiry migration. NOT for production execution.
-- No EFFECTIVE admission, Full entitlement, Bitcoin proof or live endpoint.
--
-- Apply as ONE PostgreSQL transaction. Exclusive source locks prevent writes
-- between backfill and trigger creation. Duplicate cross-version claims fail
-- the migration atomically, without choosing a winner or deleting history.
LOCK TABLE public.canonical_admission_candidate_outpoints_v2,
           public.canonical_multileg_live_outpoint_claims_v2
IN ACCESS EXCLUSIVE MODE;

CREATE TABLE public.canonical_global_outpoint_claims_v2 (
    txid CHAR(64) NOT NULL CHECK (txid ~ '^[0-9a-f]{64}$'),
    vout BIGINT NOT NULL CHECK (vout BETWEEN 0 AND 4294967295),
    claim_kind VARCHAR(16) NOT NULL CHECK (claim_kind IN ('strict_two', 'multileg')),
    strict_edge_id VARCHAR(36)
        REFERENCES public.canonical_admission_candidates_v2(edge_id),
    multileg_proposal_id VARCHAR(36)
        REFERENCES public.canonical_multileg_admission_candidates_v2(proposal_id),
    reserved_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (txid, vout),
    CONSTRAINT ck_cgoc_exact_owner CHECK (
        (claim_kind = 'strict_two'
            AND strict_edge_id IS NOT NULL AND multileg_proposal_id IS NULL)
        OR (claim_kind = 'multileg'
            AND multileg_proposal_id IS NOT NULL AND strict_edge_id IS NULL)
    )
);

CREATE INDEX idx_cgoc_strict_owner
    ON public.canonical_global_outpoint_claims_v2(strict_edge_id)
    WHERE claim_kind = 'strict_two';
CREATE INDEX idx_cgoc_multileg_owner
    ON public.canonical_global_outpoint_claims_v2(multileg_proposal_id)
    WHERE claim_kind = 'multileg';

-- Strict-two history is an indefinitely reserved claim until a separately
-- reviewed lifecycle exists. Multileg *live* claims (not expired history)
-- are the other source. A cross-format collision aborts the whole migration.
INSERT INTO public.canonical_global_outpoint_claims_v2
    (txid, vout, claim_kind, strict_edge_id)
SELECT txid, vout, 'strict_two', edge_id
FROM public.canonical_admission_candidate_outpoints_v2;

INSERT INTO public.canonical_global_outpoint_claims_v2
    (txid, vout, claim_kind, multileg_proposal_id)
SELECT txid, vout, 'multileg', proposal_id
FROM public.canonical_multileg_live_outpoint_claims_v2;

-- These are internal trigger functions only. No runtime role is granted DML
-- on the central index or EXECUTE on any function in this migration.
REVOKE INSERT, UPDATE, DELETE
    ON public.canonical_global_outpoint_claims_v2 FROM PUBLIC;

CREATE FUNCTION public.claim_global_strict_two_outpoint_v2()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
BEGIN
    INSERT INTO public.canonical_global_outpoint_claims_v2
        (txid, vout, claim_kind, strict_edge_id)
    VALUES (NEW.txid, NEW.vout, 'strict_two', NEW.edge_id);
    RETURN NULL;
END;
$$;

CREATE TRIGGER trg_cgoc_claim_strict_two
AFTER INSERT ON public.canonical_admission_candidate_outpoints_v2
FOR EACH ROW EXECUTE FUNCTION public.claim_global_strict_two_outpoint_v2();

CREATE FUNCTION public.claim_global_multileg_outpoint_v2()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
BEGIN
    INSERT INTO public.canonical_global_outpoint_claims_v2
        (txid, vout, claim_kind, multileg_proposal_id)
    VALUES (NEW.txid, NEW.vout, 'multileg', NEW.proposal_id);
    RETURN NULL;
END;
$$;

-- Insert into live claims is already part of the same candidate transaction.
-- An abort rewinds the global claim AND the signature nonce consumption.
CREATE TRIGGER trg_cgoc_claim_multileg
AFTER INSERT ON public.canonical_multileg_live_outpoint_claims_v2
FOR EACH ROW EXECUTE FUNCTION public.claim_global_multileg_outpoint_v2();

-- Global claims cannot be overwritten, or removed while an active live
-- reservation remains. Strict-two claims are deliberately non-releasable.
CREATE FUNCTION public.guard_global_outpoint_claim_v2()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
BEGIN
    IF TG_OP = 'UPDATE' OR OLD.claim_kind = 'strict_two' THEN
        RAISE EXCEPTION 'global outpoint claim is immutable or permanent';
    END IF;
    IF EXISTS (
        SELECT 1 FROM public.canonical_multileg_live_outpoint_claims_v2 AS live
        WHERE live.txid = OLD.txid AND live.vout = OLD.vout
          AND live.proposal_id = OLD.multileg_proposal_id
    ) THEN
        RAISE EXCEPTION 'active multileg collateral cannot be released';
    END IF;
    RETURN OLD;
END;
$$;

CREATE TRIGGER trg_cgoc_guard
BEFORE UPDATE OR DELETE ON public.canonical_global_outpoint_claims_v2
FOR EACH ROW EXECUTE FUNCTION public.guard_global_outpoint_claim_v2();

-- Only deleting the *matching* multileg live claim can release its global
-- reservation. The existing #585 expiry function deletes these live rows
-- inside its own transaction, then appends the immutable expiry event.
CREATE FUNCTION public.release_global_multileg_outpoint_v2()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE
    released INTEGER;
BEGIN
    DELETE FROM public.canonical_global_outpoint_claims_v2
     WHERE txid = OLD.txid AND vout = OLD.vout
       AND claim_kind = 'multileg'
       AND multileg_proposal_id = OLD.proposal_id;
    GET DIAGNOSTICS released = ROW_COUNT;
    IF released <> 1 THEN
        RAISE EXCEPTION 'missing or mismatched global collateral claim';
    END IF;
    RETURN NULL;
END;
$$;

CREATE TRIGGER trg_cgoc_release_multileg
AFTER DELETE ON public.canonical_multileg_live_outpoint_claims_v2
FOR EACH ROW EXECUTE FUNCTION public.release_global_multileg_outpoint_v2();

-- Fail closed at COMMIT if a live claim was deleted without its immutable
-- terminal event (the event is inserted *after* live releases in #585).
-- This deferred gate also rejects a partial/manual release.
CREATE FUNCTION public.validate_global_multileg_release_v2()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
BEGIN
    PERFORM 1
      FROM public.canonical_multileg_candidate_expirations_v2 AS expired
      JOIN public.canonical_multileg_admission_candidates_v2 AS candidate
        ON candidate.proposal_id = expired.proposal_id
     WHERE expired.proposal_id = OLD.proposal_id
       AND expired.proposal_sha256 = candidate.proposal_sha256
       AND expired.released_outpoint_count = candidate.outpoint_count;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'global collateral release requires a committed candidate expiry';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER trg_cgoc_release_audit
AFTER DELETE ON public.canonical_multileg_live_outpoint_claims_v2
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION public.validate_global_multileg_release_v2();

REVOKE ALL ON FUNCTION public.claim_global_strict_two_outpoint_v2() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.claim_global_multileg_outpoint_v2() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.guard_global_outpoint_claim_v2() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.release_global_multileg_outpoint_v2() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.validate_global_multileg_release_v2() FROM PUBLIC;

COMMENT ON TABLE public.canonical_global_outpoint_claims_v2 IS
    'Dormant cross-format proposed-only UTXO reservations. Strict-two permanent, multileg releasable only with immutable expiry. No Full.';
