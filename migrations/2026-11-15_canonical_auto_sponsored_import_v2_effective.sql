-- Apply transactionally, after the signed V2/global/effective migrations,
-- canonical_genesis_records, current_entitlement_evidence and auto-import V1.
-- Automatic sponsorship is authenticated import provenance, NOT signed consent.
-- No signed consent validator or signed EFFECTIVE trigger is weakened here.
LOCK TABLE public.canonical_admission_candidates_v2,
    public.canonical_multileg_live_child_claims_v2,
    public.canonical_global_outpoint_claims_v2 IN ACCESS EXCLUSIVE MODE;

-- Pending structural pairs do not permanently reserve a child. Only an atomic
-- EFFECTIVE transition (or a signed live reservation) owns the global claim.
ALTER TABLE public.canonical_auto_import_pairs_v1
    DROP CONSTRAINT canonical_auto_import_pairs_v1_child_xonly_pubkey_key;
CREATE INDEX idx_caipv1_child ON public.canonical_auto_import_pairs_v1(child_xonly_pubkey);

CREATE TABLE public.canonical_auto_effective_edges_v1 (
    pair_sha256 CHAR(64) PRIMARY KEY REFERENCES public.canonical_auto_import_pairs_v1(pair_sha256),
    sponsor_xonly_pubkey CHAR(64) NOT NULL CHECK (sponsor_xonly_pubkey ~ '^[0-9a-f]{64}$'),
    child_xonly_pubkey CHAR(64) NOT NULL UNIQUE CHECK (child_xonly_pubkey ~ '^[0-9a-f]{64}$'),
    child_depth INTEGER NOT NULL CHECK (child_depth BETWEEN 1 AND 2288),
    genesis_record_id VARCHAR(36) NOT NULL REFERENCES public.canonical_genesis_records(record_id),
    parent_auto_pair_sha256 CHAR(64) REFERENCES public.canonical_auto_effective_edges_v1(pair_sha256),
    parent_signed_proposal_id VARCHAR(36) REFERENCES public.canonical_multileg_effective_edges_v2(proposal_id),
    earlier_intent_id UUID NOT NULL REFERENCES public.canonical_auto_import_intents_v1(intent_id),
    later_intent_id UUID NOT NULL REFERENCES public.canonical_auto_import_intents_v1(intent_id),
    bundle_sha256 CHAR(64) NOT NULL CHECK (bundle_sha256 ~ '^[0-9a-f]{64}$'),
    bundle_json TEXT NOT NULL CHECK (octet_length(bundle_json) BETWEEN 1 AND 262144),
    initial_evidence_id VARCHAR(36) NOT NULL UNIQUE REFERENCES public.current_entitlement_evidence(evidence_id),
    network VARCHAR(7) NOT NULL CHECK (network IN ('main','test','signet','regtest')),
    earlier_sats BIGINT NOT NULL CHECK (earlier_sats BETWEEN 1 AND 2100000000000000),
    later_sats BIGINT NOT NULL CHECK (later_sats BETWEEN 1 AND 2100000000000000),
    trust_ceiling_sats BIGINT NOT NULL CHECK (trust_ceiling_sats = LEAST(earlier_sats,later_sats)),
    outpoint_count INTEGER NOT NULL CHECK (outpoint_count BETWEEN 2 AND 256),
    effective_at TIMESTAMPTZ NOT NULL,
    CHECK (sponsor_xonly_pubkey <> child_xonly_pubkey),
    CHECK (bundle_sha256 = encode(sha256(convert_to(bundle_json,'UTF8')),'hex')),
    CHECK ((child_depth=1 AND parent_auto_pair_sha256 IS NULL AND parent_signed_proposal_id IS NULL)
        OR (child_depth>1 AND ((parent_auto_pair_sha256 IS NOT NULL)::integer
            + (parent_signed_proposal_id IS NOT NULL)::integer)=1))
);
CREATE INDEX idx_caeav1_sponsor ON public.canonical_auto_effective_edges_v1(sponsor_xonly_pubkey);

CREATE VIEW public.canonical_effective_authority_edges_v1 AS
    SELECT 'automatic'::text AS kind,pair_sha256::text AS edge_id,sponsor_xonly_pubkey,
        child_xonly_pubkey,child_depth,
        CASE WHEN parent_auto_pair_sha256 IS NOT NULL THEN 'automatic'
             WHEN parent_signed_proposal_id IS NOT NULL THEN 'multileg' END AS parent_kind,
        COALESCE(parent_auto_pair_sha256::text,parent_signed_proposal_id::text) AS parent_id,
        genesis_record_id
    FROM public.canonical_auto_effective_edges_v1
    UNION ALL
    SELECT 'multileg',e.proposal_id::text,e.sponsor_xonly_pubkey,e.child_xonly_pubkey,e.child_depth,
        CASE WHEN e.parent_proposal_id IS NOT NULL THEN 'multileg' END,e.parent_proposal_id::text,
        CASE WHEN e.child_depth=1 THEN c.basis_record_id END
    FROM public.canonical_multileg_effective_edges_v2 e
    JOIN public.canonical_multileg_admission_candidates_v2 c USING(proposal_id);

CREATE TABLE public.canonical_auto_effective_outpoints_v1 (
    pair_sha256 CHAR(64) NOT NULL REFERENCES public.canonical_auto_effective_edges_v1(pair_sha256),
    txid CHAR(64) NOT NULL CHECK (txid ~ '^[0-9a-f]{64}$'),
    vout BIGINT NOT NULL CHECK (vout BETWEEN 0 AND 4294967295),
    leg_order VARCHAR(7) NOT NULL CHECK (leg_order IN ('earlier','later')),
    amount_sats BIGINT NOT NULL CHECK (amount_sats BETWEEN 1 AND 2100000000000000),
    script_pubkey_sha256 CHAR(64) NOT NULL CHECK (script_pubkey_sha256 ~ '^[0-9a-f]{64}$'),
    PRIMARY KEY(txid,vout),
    UNIQUE(pair_sha256,txid,vout)
);

CREATE TABLE public.canonical_authority_child_claims_v1 (
    child_xonly_pubkey CHAR(64) PRIMARY KEY CHECK (child_xonly_pubkey ~ '^[0-9a-f]{64}$'),
    claim_kind VARCHAR(16) NOT NULL CHECK (claim_kind IN ('strict_two','multileg','automatic')),
    owner_id TEXT NOT NULL CHECK (length(owner_id) IN (36,64))
);
INSERT INTO public.canonical_authority_child_claims_v1
    SELECT child_xonly_pubkey,'strict_two',edge_id FROM public.canonical_admission_candidates_v2;
INSERT INTO public.canonical_authority_child_claims_v1
    SELECT child_xonly_pubkey,'multileg',proposal_id FROM public.canonical_multileg_live_child_claims_v2;

ALTER TABLE public.canonical_global_outpoint_claims_v2
    ADD COLUMN auto_pair_sha256 CHAR(64) REFERENCES public.canonical_auto_effective_edges_v1(pair_sha256);
ALTER TABLE public.canonical_global_outpoint_claims_v2
    DROP CONSTRAINT canonical_global_outpoint_claims_v2_claim_kind_check,
    DROP CONSTRAINT ck_cgoc_exact_owner,
    ADD CONSTRAINT ck_cgoc_kind CHECK (claim_kind IN ('strict_two','multileg','automatic')),
    ADD CONSTRAINT ck_cgoc_exact_owner CHECK (
        (claim_kind='strict_two' AND strict_edge_id IS NOT NULL AND multileg_proposal_id IS NULL AND auto_pair_sha256 IS NULL)
        OR (claim_kind='multileg' AND multileg_proposal_id IS NOT NULL AND strict_edge_id IS NULL AND auto_pair_sha256 IS NULL)
        OR (claim_kind='automatic' AND auto_pair_sha256 IS NOT NULL AND strict_edge_id IS NULL AND multileg_proposal_id IS NULL));

CREATE TABLE public.canonical_auto_entitlement_observations_v1 (
    evidence_id VARCHAR(36) PRIMARY KEY REFERENCES public.current_entitlement_evidence(evidence_id),
    pair_sha256 CHAR(64) NOT NULL REFERENCES public.canonical_auto_effective_edges_v1(pair_sha256),
    source_evidence_sha256 CHAR(64) NOT NULL CHECK (source_evidence_sha256 ~ '^[0-9a-f]{64}$'),
    current_eligible BOOLEAN NOT NULL,
    receipt_json TEXT NOT NULL CHECK (octet_length(receipt_json) BETWEEN 1 AND 2048),
    CHECK (source_evidence_sha256 = encode(sha256(convert_to(receipt_json,'UTF8')),'hex')),
    checked_tip_hash CHAR(64) CHECK (checked_tip_hash ~ '^[0-9a-f]{64}$'),
    checked_mempool_sequence BIGINT CHECK (checked_mempool_sequence >= 0),
    observed_at TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ NOT NULL,
    CHECK (observed_at < valid_until AND valid_until <= observed_at + INTERVAL '120 seconds'),
    CHECK (NOT current_eligible OR (checked_tip_hash IS NOT NULL AND checked_mempool_sequence IS NOT NULL))
);
CREATE INDEX idx_caeov1_pair ON public.canonical_auto_entitlement_observations_v1(pair_sha256,observed_at DESC);

CREATE TABLE public.canonical_auto_admission_revocations_v1 (
    pair_sha256 CHAR(64) PRIMARY KEY REFERENCES public.canonical_auto_effective_edges_v1(pair_sha256),
    revoked_at TIMESTAMPTZ NOT NULL,
    reason VARCHAR(64) NOT NULL CHECK (reason IN ('sponsorship_revoked','controlling_dispute'))
);

CREATE FUNCTION public.claim_canonical_authority_child_v1()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
    IF TG_TABLE_NAME='canonical_admission_candidates_v2' THEN
        INSERT INTO public.canonical_authority_child_claims_v1 VALUES(NEW.child_xonly_pubkey,'strict_two',NEW.edge_id);
    ELSIF TG_TABLE_NAME='canonical_multileg_live_child_claims_v2' THEN
        INSERT INTO public.canonical_authority_child_claims_v1 VALUES(NEW.child_xonly_pubkey,'multileg',NEW.proposal_id);
    ELSE
        INSERT INTO public.canonical_authority_child_claims_v1 VALUES(NEW.child_xonly_pubkey,'automatic',NEW.pair_sha256);
    END IF;
    RETURN NULL;
END;
$$;
CREATE TRIGGER trg_cacv1_strict AFTER INSERT ON public.canonical_admission_candidates_v2
    FOR EACH ROW EXECUTE FUNCTION public.claim_canonical_authority_child_v1();
CREATE TRIGGER trg_cacv1_multileg AFTER INSERT ON public.canonical_multileg_live_child_claims_v2
    FOR EACH ROW EXECUTE FUNCTION public.claim_canonical_authority_child_v1();
CREATE TRIGGER trg_cacv1_auto AFTER INSERT ON public.canonical_auto_effective_edges_v1
    FOR EACH ROW EXECUTE FUNCTION public.claim_canonical_authority_child_v1();

CREATE FUNCTION public.guard_canonical_authority_child_v1()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
    IF TG_OP='UPDATE' OR OLD.claim_kind <> 'multileg' OR EXISTS (
        SELECT 1 FROM public.canonical_multileg_live_child_claims_v2
        WHERE child_xonly_pubkey=OLD.child_xonly_pubkey AND proposal_id=OLD.owner_id
    ) THEN RAISE EXCEPTION 'active or permanent child claim cannot be changed'; END IF;
    RETURN OLD;
END;
$$;
CREATE TRIGGER trg_cacv1_guard BEFORE UPDATE OR DELETE ON public.canonical_authority_child_claims_v1
    FOR EACH ROW EXECUTE FUNCTION public.guard_canonical_authority_child_v1();
CREATE FUNCTION public.release_canonical_authority_child_v1()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
    DELETE FROM public.canonical_authority_child_claims_v1
    WHERE child_xonly_pubkey=OLD.child_xonly_pubkey AND claim_kind='multileg' AND owner_id=OLD.proposal_id;
    IF NOT FOUND THEN RAISE EXCEPTION 'missing global child claim'; END IF;
    RETURN NULL;
END;
$$;
CREATE TRIGGER trg_cacv1_release AFTER DELETE ON public.canonical_multileg_live_child_claims_v2
    FOR EACH ROW EXECUTE FUNCTION public.release_canonical_authority_child_v1();

CREATE OR REPLACE FUNCTION public.guard_global_outpoint_claim_v2()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
    IF TG_OP='UPDATE' OR OLD.claim_kind IN ('strict_two','automatic') THEN
        RAISE EXCEPTION 'global outpoint claim is immutable or permanent';
    END IF;
    IF EXISTS (SELECT 1 FROM public.canonical_multileg_live_outpoint_claims_v2
        WHERE txid=OLD.txid AND vout=OLD.vout AND proposal_id=OLD.multileg_proposal_id)
    THEN RAISE EXCEPTION 'active multileg collateral cannot be released'; END IF;
    RETURN OLD;
END;
$$;
CREATE FUNCTION public.claim_global_auto_outpoint_v1()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
    INSERT INTO public.canonical_global_outpoint_claims_v2(txid,vout,claim_kind,auto_pair_sha256)
    VALUES(NEW.txid,NEW.vout,'automatic',NEW.pair_sha256);
    RETURN NULL;
END;
$$;
CREATE TRIGGER trg_cgoc_auto AFTER INSERT ON public.canonical_auto_effective_outpoints_v1
    FOR EACH ROW EXECUTE FUNCTION public.claim_global_auto_outpoint_v1();

-- Deferred checks allow the owner to insert evidence, header, claims and the
-- observation in any documented order, but require the COMPLETE unit at COMMIT.
CREATE FUNCTION public.validate_canonical_auto_effective_v1()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
    pair RECORD; evidence RECORD; sponsor RECORD; parent RECORD; genesis RECORD;
    n BIGINT; early_total NUMERIC; late_total NUMERIC; bound_claims BIGINT;
BEGIN
    SELECT * INTO pair FROM public.canonical_auto_import_pairs_v1 WHERE pair_sha256=NEW.pair_sha256 FOR SHARE;
    IF NOT FOUND OR pair.sponsor_xonly_pubkey<>NEW.sponsor_xonly_pubkey
        OR pair.child_xonly_pubkey<>NEW.child_xonly_pubkey OR pair.child_depth<>NEW.child_depth
        OR NEW.effective_at < clock_timestamp()-INTERVAL '60 seconds'
        OR NEW.effective_at > clock_timestamp()+INTERVAL '5 seconds'
    THEN RAISE EXCEPTION 'automatic effective binding or freshness failed'; END IF;
    PERFORM 1 FROM public.canonical_auto_import_intents_v1
        WHERE intent_id=NEW.earlier_intent_id AND sponsor_xonly_pubkey=NEW.sponsor_xonly_pubkey
        AND script_sha256=pair.earlier_script_sha256 AND sponsor_depth=NEW.child_depth-1
        AND authorized_at<=NEW.effective_at AND recover_until>NEW.effective_at;
    IF NOT FOUND THEN RAISE EXCEPTION 'missing authenticated earlier import'; END IF;
    PERFORM 1 FROM public.canonical_auto_import_intents_v1
        WHERE intent_id=NEW.later_intent_id AND sponsor_xonly_pubkey=NEW.sponsor_xonly_pubkey
        AND script_sha256=pair.later_script_sha256 AND sponsor_depth=NEW.child_depth-1
        AND authorized_at<=NEW.effective_at AND recover_until>NEW.effective_at;
    IF NOT FOUND THEN RAISE EXCEPTION 'missing authenticated later import'; END IF;
    SELECT * INTO genesis FROM public.canonical_genesis_records WHERE record_id=NEW.genesis_record_id FOR SHARE;
    IF NOT FOUND OR genesis.lifecycle_state<>'effective' OR genesis.effective_at>NEW.effective_at
        OR (SELECT count(*) FROM public.canonical_genesis_records WHERE graph_or_protocol_id=genesis.graph_or_protocol_id)<>1
    THEN RAISE EXCEPTION 'genesis is inactive or ambiguous'; END IF;
    IF NEW.child_depth=1 THEN
        IF NEW.sponsor_xonly_pubkey<>genesis.x_only_public_key THEN RAISE EXCEPTION 'wrong root sponsor'; END IF;
    ELSIF NEW.parent_auto_pair_sha256 IS NOT NULL THEN
        SELECT * INTO parent FROM public.canonical_auto_effective_edges_v1 WHERE pair_sha256=NEW.parent_auto_pair_sha256 FOR SHARE;
        IF NOT FOUND OR parent.child_xonly_pubkey<>NEW.sponsor_xonly_pubkey OR parent.child_depth+1<>NEW.child_depth
            OR EXISTS(SELECT 1 FROM public.canonical_auto_admission_revocations_v1 WHERE pair_sha256=parent.pair_sha256)
        THEN RAISE EXCEPTION 'automatic parent is not exact and active'; END IF;
    ELSE
        SELECT * INTO parent FROM public.canonical_multileg_effective_edges_v2 WHERE proposal_id=NEW.parent_signed_proposal_id FOR SHARE;
        IF NOT FOUND OR parent.child_xonly_pubkey<>NEW.sponsor_xonly_pubkey OR parent.child_depth+1<>NEW.child_depth
        THEN RAISE EXCEPTION 'signed parent is not exact'; END IF;
    END IF;
    SELECT e.* INTO sponsor FROM public.current_entitlement_evidence e
        JOIN public.users u ON u.pubkey=e.subject_pubkey AND u.is_active IS TRUE
        WHERE e.subject_pubkey=NEW.sponsor_xonly_pubkey
        ORDER BY e.observed_at DESC,e.created_at DESC,e.evidence_id DESC LIMIT 1;
    IF NOT FOUND OR sponsor.identity_class<>'full' OR sponsor.current_full_relation_satisfied IS NOT TRUE
        OR sponsor.revoked_at IS NOT NULL OR sponsor.observed_at>clock_timestamp()
        OR sponsor.valid_until<=clock_timestamp()
    THEN RAISE EXCEPTION 'sponsor is not currently Full'; END IF;
    SELECT count(*),COALESCE(sum(amount_sats) FILTER(WHERE leg_order='earlier'),0),
        COALESCE(sum(amount_sats) FILTER(WHERE leg_order='later'),0)
        INTO n,early_total,late_total FROM public.canonical_auto_effective_outpoints_v1 WHERE pair_sha256=NEW.pair_sha256;
    SELECT count(*) INTO bound_claims FROM public.canonical_auto_effective_outpoints_v1 o
        JOIN public.canonical_global_outpoint_claims_v2 g USING(txid,vout)
        WHERE o.pair_sha256=NEW.pair_sha256 AND g.claim_kind='automatic' AND g.auto_pair_sha256=NEW.pair_sha256;
    IF n<>NEW.outpoint_count OR bound_claims<>n OR early_total<>NEW.earlier_sats OR late_total<>NEW.later_sats
    THEN RAISE EXCEPTION 'incomplete automatic collateral claims'; END IF;
    PERFORM 1 FROM public.canonical_authority_child_claims_v1
        WHERE child_xonly_pubkey=NEW.child_xonly_pubkey AND claim_kind='automatic' AND owner_id=NEW.pair_sha256;
    IF NOT FOUND THEN RAISE EXCEPTION 'missing global child claim'; END IF;
    SELECT e.* INTO evidence FROM public.current_entitlement_evidence e
        JOIN public.canonical_auto_entitlement_observations_v1 o USING(evidence_id)
        WHERE e.evidence_id=NEW.initial_evidence_id AND o.pair_sha256=NEW.pair_sha256 AND o.current_eligible IS TRUE;
    IF NOT FOUND OR evidence.subject_pubkey<>NEW.child_xonly_pubkey OR evidence.identity_class<>'full'
        OR evidence.valid_until> sponsor.valid_until OR evidence.valid_until<=clock_timestamp()
    THEN RAISE EXCEPTION 'missing atomic child Full evidence'; END IF;
    RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER trg_caev1_complete AFTER INSERT ON public.canonical_auto_effective_edges_v1
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.validate_canonical_auto_effective_v1();

CREATE FUNCTION public.validate_canonical_auto_observation_v1()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE evidence RECORD; edge RECORD;
BEGIN
    SELECT * INTO evidence FROM public.current_entitlement_evidence WHERE evidence_id=NEW.evidence_id;
    SELECT * INTO edge FROM public.canonical_auto_effective_edges_v1 WHERE pair_sha256=NEW.pair_sha256;
    IF evidence.subject_pubkey IS DISTINCT FROM edge.child_xonly_pubkey
        OR evidence.evidence_source<>'canonical_auto_sponsored_import'
        OR evidence.evidence_version<>'hodlxxi.auto_effective.v1'
        OR evidence.source_evidence_sha256<>NEW.source_evidence_sha256
        OR (NEW.receipt_json::jsonb->>'pair') IS DISTINCT FROM NEW.pair_sha256::text
        OR (NEW.current_eligible AND ((NEW.receipt_json::jsonb->>'bundle_sha256') IS DISTINCT FROM edge.bundle_sha256::text
            OR (NEW.receipt_json::jsonb->>'network') IS DISTINCT FROM edge.network))
        OR evidence.current_full_relation_satisfied<>NEW.current_eligible
        OR (evidence.identity_class='full')<>NEW.current_eligible
        OR evidence.revoked_at IS NOT NULL OR evidence.observed_at<>NEW.observed_at
        OR evidence.valid_until<>NEW.valid_until
        OR NEW.observed_at < clock_timestamp()-INTERVAL '60 seconds'
        OR NEW.observed_at > clock_timestamp()+INTERVAL '5 seconds'
        OR (NEW.current_eligible AND EXISTS(SELECT 1 FROM public.canonical_auto_admission_revocations_v1 WHERE pair_sha256=NEW.pair_sha256))
    THEN RAISE EXCEPTION 'automatic evidence observation binding failed'; END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER trg_caeov1_bound BEFORE INSERT ON public.canonical_auto_entitlement_observations_v1
    FOR EACH ROW EXECUTE FUNCTION public.validate_canonical_auto_observation_v1();
CREATE FUNCTION public.require_canonical_auto_observation_v1()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
    IF NEW.evidence_source='canonical_auto_sponsored_import' AND NOT EXISTS (
        SELECT 1 FROM public.canonical_auto_entitlement_observations_v1 WHERE evidence_id=NEW.evidence_id)
    THEN RAISE EXCEPTION 'automatic evidence requires its observation in the same transaction'; END IF;
    RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER trg_caeov1_required AFTER INSERT ON public.current_entitlement_evidence
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.require_canonical_auto_observation_v1();

CREATE TRIGGER trg_caev1_immutable BEFORE UPDATE OR DELETE ON public.canonical_auto_effective_edges_v1
    FOR EACH ROW EXECUTE FUNCTION public.reject_canonical_auto_import_mutation_v1();
CREATE TRIGGER trg_caeov1_immutable BEFORE UPDATE OR DELETE ON public.canonical_auto_effective_outpoints_v1
    FOR EACH ROW EXECUTE FUNCTION public.reject_canonical_auto_import_mutation_v1();
CREATE TRIGGER trg_caobv1_immutable BEFORE UPDATE OR DELETE ON public.canonical_auto_entitlement_observations_v1
    FOR EACH ROW EXECUTE FUNCTION public.reject_canonical_auto_import_mutation_v1();
CREATE TRIGGER trg_carv1_immutable BEFORE UPDATE OR DELETE ON public.canonical_auto_admission_revocations_v1
    FOR EACH ROW EXECUTE FUNCTION public.reject_canonical_auto_import_mutation_v1();
CREATE TRIGGER trg_caeov1_evidence_immutable BEFORE UPDATE OR DELETE ON public.current_entitlement_evidence
    FOR EACH ROW WHEN (OLD.evidence_source='canonical_auto_sponsored_import')
    EXECUTE FUNCTION public.reject_canonical_auto_import_mutation_v1();
REVOKE ALL ON public.canonical_auto_effective_edges_v1,public.canonical_auto_effective_outpoints_v1,
    public.canonical_authority_child_claims_v1,public.canonical_auto_entitlement_observations_v1,
    public.canonical_auto_admission_revocations_v1,public.canonical_effective_authority_edges_v1 FROM PUBLIC;
REVOKE ALL ON FUNCTION public.claim_canonical_authority_child_v1(),public.guard_canonical_authority_child_v1(),
    public.release_canonical_authority_child_v1(),public.claim_global_auto_outpoint_v1(),
    public.validate_canonical_auto_effective_v1(),public.validate_canonical_auto_observation_v1(),
    public.require_canonical_auto_observation_v1() FROM PUBLIC;

-- Mutable scheduler cursor only; it confers no authority or history ownership.
CREATE TABLE public.canonical_auto_refresh_progress_v1 (
    singleton BOOLEAN PRIMARY KEY CHECK (singleton),
    child_depth INTEGER NOT NULL CHECK (child_depth BETWEEN 0 AND 2288),
    pair_sha256 VARCHAR(64) NOT NULL
);
INSERT INTO public.canonical_auto_refresh_progress_v1 VALUES(TRUE,0,'');
REVOKE ALL ON public.canonical_auto_refresh_progress_v1 FROM PUBLIC;
