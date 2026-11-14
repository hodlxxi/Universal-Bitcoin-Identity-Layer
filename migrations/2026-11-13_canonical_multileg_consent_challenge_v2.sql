-- Dormant/additive multileg consent ledger. Separate from strict two-UTXO V2.
-- No live migrations, routes, current Full grants or production writes.
-- Requires PostgreSQL 16+. Only a caller-owned transaction may commit.
CREATE TABLE public.canonical_multileg_consent_challenges_v2 (
    challenge_sha256 CHAR(64) PRIMARY KEY,
    proposal_schema VARCHAR(96) NOT NULL DEFAULT 'hodlxxi.canonical_multi_outpoint_admission_proposal.v2',
    proposal_sha256 CHAR(64) NOT NULL,
    nonce_hex CHAR(64) NOT NULL UNIQUE,
    sponsor_compressed_pubkey CHAR(66) NOT NULL,
    child_compressed_pubkey CHAR(66) NOT NULL,
    issuer_session_pubkey CHAR(66) NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    verification_sha256 CHAR(64) UNIQUE,
    CONSTRAINT ck_cmlc_schema CHECK (
        proposal_schema = 'hodlxxi.canonical_multi_outpoint_admission_proposal.v2'
    ),
    CONSTRAINT ck_cmlc_challenge_sha CHECK (challenge_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_cmlc_proposal_sha CHECK (proposal_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_cmlc_nonce CHECK (nonce_hex ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_cmlc_sponsor CHECK (sponsor_compressed_pubkey ~ '^(02|03)[0-9a-f]{64}$'),
    CONSTRAINT ck_cmlc_child CHECK (child_compressed_pubkey ~ '^(02|03)[0-9a-f]{64}$'),
    CONSTRAINT ck_cmlc_keys CHECK (
        issuer_session_pubkey = sponsor_compressed_pubkey
        AND sponsor_compressed_pubkey <> child_compressed_pubkey
    ),
    CONSTRAINT ck_cmlc_window CHECK (
        issued_at < expires_at AND expires_at <= issued_at + INTERVAL '300 seconds'
    ),
    CONSTRAINT ck_cmlc_consumption_pair CHECK (
        (consumed_at IS NULL) = (verification_sha256 IS NULL)
    ),
    CONSTRAINT ck_cmlc_consumed_window CHECK (
        consumed_at IS NULL OR (consumed_at >= issued_at AND consumed_at < expires_at)
    ),
    CONSTRAINT ck_cmlc_verification CHECK (
        verification_sha256 IS NULL OR verification_sha256 ~ '^[0-9a-f]{64}$'
    )
);

-- Challenge details are immutable. Only a single NULL -> consumed change is allowed.
CREATE FUNCTION public.guard_canonical_multileg_consent_challenge_v2()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'multileg consent challenge deletion forbidden';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF ROW(
            NEW.challenge_sha256, NEW.proposal_schema, NEW.proposal_sha256,
            NEW.nonce_hex, NEW.sponsor_compressed_pubkey, NEW.child_compressed_pubkey,
            NEW.issuer_session_pubkey, NEW.issued_at, NEW.expires_at
        ) IS DISTINCT FROM ROW(
            OLD.challenge_sha256, OLD.proposal_schema, OLD.proposal_sha256,
            OLD.nonce_hex, OLD.sponsor_compressed_pubkey, OLD.child_compressed_pubkey,
            OLD.issuer_session_pubkey, OLD.issued_at, OLD.expires_at
        ) OR OLD.consumed_at IS NOT NULL OR OLD.verification_sha256 IS NOT NULL
        OR NEW.consumed_at IS NULL OR NEW.verification_sha256 IS NULL THEN
            RAISE EXCEPTION 'multileg consent challenge immutable or already consumed';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_guard_canonical_multileg_consent_v2
BEFORE UPDATE OR DELETE ON public.canonical_multileg_consent_challenges_v2
FOR EACH ROW EXECUTE FUNCTION public.guard_canonical_multileg_consent_challenge_v2();

COMMENT ON TABLE public.canonical_multileg_consent_challenges_v2 IS
    'Dormant signed multileg proposal nonce ledger. Consumption is not an admission, Full or durable effective edge.';
