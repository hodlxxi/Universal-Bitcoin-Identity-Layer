-- Automatic sponsored descriptor import journal for Issue #588.
-- Staging migration ONLY after an explicit isolated DB dry run.
-- This schema records one authenticated Full sponsor's successful watch-only
-- imports and exact structural mirror pairs. It grants NO membership and has
-- NO trigger that inserts CurrentEntitlementEvidence.
-- The UTXO proof / consent-free EFFECTIVE coordinator is a later boundary.

CREATE TABLE public.canonical_auto_import_scripts_v1 (
    sponsor_xonly_pubkey CHAR(64) NOT NULL
        CHECK (sponsor_xonly_pubkey ~ '^[0-9a-f]{64}$'),
    script_sha256 CHAR(64) NOT NULL
        CHECK (script_sha256 ~ '^[0-9a-f]{64}$'),
    script_hex TEXT NOT NULL
        CHECK (script_hex ~ '^[0-9a-f]+$' AND length(script_hex) BETWEEN 2 AND 2048 AND length(script_hex) % 2 = 0),
    imported_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (sponsor_xonly_pubkey, script_sha256),
    CHECK (script_sha256 = encode(sha256(decode(script_hex, 'hex')), 'hex'))
);
CREATE INDEX idx_caisv1_sponsor_created
    ON public.canonical_auto_import_scripts_v1(sponsor_xonly_pubkey, imported_at);

CREATE TABLE public.canonical_auto_import_pairs_v1 (
    pair_sha256 CHAR(64) PRIMARY KEY CHECK (pair_sha256 ~ '^[0-9a-f]{64}$'),
    sponsor_xonly_pubkey CHAR(64) NOT NULL
        CHECK (sponsor_xonly_pubkey ~ '^[0-9a-f]{64}$'),
    child_xonly_pubkey CHAR(64) NOT NULL UNIQUE
        CHECK (child_xonly_pubkey ~ '^[0-9a-f]{64}$'),
    child_depth INTEGER NOT NULL CHECK (child_depth BETWEEN 1 AND 2288),
    earlier_script_sha256 CHAR(64) NOT NULL
        CHECK (earlier_script_sha256 ~ '^[0-9a-f]{64}$'),
    later_script_sha256 CHAR(64) NOT NULL
        CHECK (later_script_sha256 ~ '^[0-9a-f]{64}$'),
    discovered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    state TEXT NOT NULL DEFAULT 'pending_confirmed_utxo_verification'
        CHECK (state = 'pending_confirmed_utxo_verification'),
    CHECK (sponsor_xonly_pubkey <> child_xonly_pubkey),
    CHECK (earlier_script_sha256 <> later_script_sha256),
    FOREIGN KEY (sponsor_xonly_pubkey, earlier_script_sha256)
        REFERENCES public.canonical_auto_import_scripts_v1(sponsor_xonly_pubkey, script_sha256),
    FOREIGN KEY (sponsor_xonly_pubkey, later_script_sha256)
        REFERENCES public.canonical_auto_import_scripts_v1(sponsor_xonly_pubkey, script_sha256)
);
CREATE INDEX idx_caipv1_sponsor_created
    ON public.canonical_auto_import_pairs_v1(sponsor_xonly_pubkey, discovered_at);

CREATE FUNCTION public.reject_canonical_auto_import_mutation_v1()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
BEGIN
    RAISE EXCEPTION 'automatic import provenance is immutable';
END;
$$;
CREATE TRIGGER trg_caisv1_append_only
    BEFORE UPDATE OR DELETE ON public.canonical_auto_import_scripts_v1
    FOR EACH ROW EXECUTE FUNCTION public.reject_canonical_auto_import_mutation_v1();
CREATE TRIGGER trg_caipv1_append_only
    BEFORE UPDATE OR DELETE ON public.canonical_auto_import_pairs_v1
    FOR EACH ROW EXECUTE FUNCTION public.reject_canonical_auto_import_mutation_v1();

REVOKE ALL ON public.canonical_auto_import_scripts_v1 FROM PUBLIC;
REVOKE ALL ON public.canonical_auto_import_pairs_v1 FROM PUBLIC;
REVOKE ALL ON FUNCTION public.reject_canonical_auto_import_mutation_v1() FROM PUBLIC;
COMMENT ON TABLE public.canonical_auto_import_pairs_v1 IS
    'Pending automatic sponsor/child script correlation only; not effective and never a Full grant';
