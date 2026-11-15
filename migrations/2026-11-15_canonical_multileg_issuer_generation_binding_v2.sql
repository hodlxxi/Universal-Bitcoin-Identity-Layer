-- Issue #588: durable provenance of the sponsor browser generation that issued
-- an N+M consent nonce. Dormant PostgreSQL 16 migration for disposable CI.
-- Prerequisites: OAuth browser generation tables and multileg consent ledger.
-- NOT an admission, EFFECTIVE/Full grant or production migration authorization.
CREATE TABLE public.canonical_multileg_consent_browser_bindings_v2 (
    challenge_sha256 CHAR(64) PRIMARY KEY
      REFERENCES public.canonical_multileg_consent_challenges_v2(challenge_sha256),
    sponsor_generation_id VARCHAR(64) NOT NULL
      REFERENCES public.oauth_browser_generations(generation_id),
    sponsor_subject CHAR(64) NOT NULL CHECK (sponsor_subject ~ '^[0-9a-f]{64}$'),
    client_id VARCHAR(255) NOT NULL
      REFERENCES public.oauth_clients(client_id),
    issuer_user_id VARCHAR(36) NOT NULL REFERENCES public.users(id),
    bound_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT ck_cmlcbv2_generation_hex CHECK (sponsor_generation_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_cmlcbv2_client_not_blank CHECK (length(trim(client_id)) > 0)
);

CREATE FUNCTION public.validate_canonical_multileg_browser_binding_v2()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE
    nonce RECORD;
    generation RECORD;
BEGIN
    SELECT * INTO nonce
      FROM public.canonical_multileg_consent_challenges_v2
     WHERE challenge_sha256 = NEW.challenge_sha256 FOR SHARE;
    IF NOT FOUND
       OR nonce.issuer_session_pubkey <> nonce.sponsor_compressed_pubkey
       OR substring(nonce.sponsor_compressed_pubkey FROM 3) <> NEW.sponsor_subject
       OR nonce.issued_at <> NEW.bound_at
       OR nonce.consumed_at IS NOT NULL
    THEN
        RAISE EXCEPTION 'browser binding and issued challenge mismatch';
    END IF;
    SELECT * INTO generation
      FROM public.oauth_browser_generations
     WHERE generation_id = NEW.sponsor_generation_id FOR SHARE;
    IF NOT FOUND
       OR generation.subject <> NEW.sponsor_subject
       OR generation.client_id <> NEW.client_id
       OR generation.user_id <> NEW.issuer_user_id
       OR generation.is_active IS NOT TRUE
       OR generation.created_at > NEW.bound_at
       OR generation.expires_at <= NEW.bound_at
    THEN
        RAISE EXCEPTION 'browser binding and verified sponsor generation mismatch';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_cmlcbv2_validate
BEFORE INSERT ON public.canonical_multileg_consent_browser_bindings_v2
FOR EACH ROW EXECUTE FUNCTION public.validate_canonical_multileg_browser_binding_v2();

CREATE FUNCTION public.guard_canonical_multileg_browser_binding_v2()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
BEGIN
    RAISE EXCEPTION 'canonical multileg issuer generation provenance is immutable';
END;
$$;

CREATE TRIGGER trg_cmlcbv2_immutable
BEFORE UPDATE OR DELETE ON public.canonical_multileg_consent_browser_bindings_v2
FOR EACH ROW EXECUTE FUNCTION public.guard_canonical_multileg_browser_binding_v2();

REVOKE INSERT, UPDATE, DELETE ON public.canonical_multileg_consent_browser_bindings_v2 FROM PUBLIC;
REVOKE ALL ON FUNCTION public.validate_canonical_multileg_browser_binding_v2() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.guard_canonical_multileg_browser_binding_v2() FROM PUBLIC;

COMMENT ON TABLE public.canonical_multileg_consent_browser_bindings_v2 IS
'Issue #588: immutable challenge→OAuth issuer generation evidence, NOT independent Full authority.';
