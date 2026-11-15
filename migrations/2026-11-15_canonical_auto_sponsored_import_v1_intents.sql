-- Apply after canonical_auto_sponsored_import_v1. No authority is granted.
-- A committed authenticated intent precedes any Core import. This preserves
-- sponsor provenance if Core succeeds and the post-import journal commit fails.
CREATE TABLE public.canonical_auto_import_intents_v1 (
    intent_id UUID PRIMARY KEY,
    sponsor_xonly_pubkey CHAR(64) NOT NULL CHECK (sponsor_xonly_pubkey ~ '^[0-9a-f]{64}$'),
    script_sha256 CHAR(64) NOT NULL CHECK (script_sha256 ~ '^[0-9a-f]{64}$'),
    script_hex TEXT NOT NULL CHECK (script_hex ~ '^[0-9a-f]+$' AND length(script_hex) BETWEEN 2 AND 2048 AND length(script_hex) % 2 = 0),
    sponsor_depth INTEGER NOT NULL CHECK (sponsor_depth BETWEEN 0 AND 2287),
    sponsor_evidence_id VARCHAR(36) NOT NULL REFERENCES public.current_entitlement_evidence(evidence_id),
    sponsor_evidence_sha256 CHAR(64) NOT NULL CHECK (sponsor_evidence_sha256 ~ '^[0-9a-f]{64}$'),
    authorized_at TIMESTAMPTZ NOT NULL,
    recover_until TIMESTAMPTZ NOT NULL,
    CHECK (recover_until = authorized_at + INTERVAL '7 days'),
    CHECK (script_sha256 = encode(sha256(decode(script_hex, 'hex')), 'hex'))
);
CREATE INDEX idx_caiiv1_sponsor_script_time
    ON public.canonical_auto_import_intents_v1(sponsor_xonly_pubkey, script_sha256, authorized_at DESC);
CREATE INDEX idx_caiiv1_pending_time
    ON public.canonical_auto_import_intents_v1(recover_until, authorized_at);
CREATE TRIGGER trg_caiiv1_append_only
    BEFORE UPDATE OR DELETE ON public.canonical_auto_import_intents_v1
    FOR EACH ROW EXECUTE FUNCTION public.reject_canonical_auto_import_mutation_v1();
REVOKE ALL ON public.canonical_auto_import_intents_v1 FROM PUBLIC;
COMMENT ON TABLE public.canonical_auto_import_intents_v1 IS
    'Authenticated sponsor action only; Core success and fresh collateral must be checked independently; never a Full grant';
