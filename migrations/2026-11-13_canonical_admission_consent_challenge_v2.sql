-- Proposed Canon V2 challenge issuance/one-time consumption only.
-- ADDITIVE / DORMANT. Do not apply on production without explicit approval.
-- A successful consumption is NOT an admission or Full entitlement.
-- PostgreSQL 16+; create in a controlled migration transaction.
CREATE TABLE public.canonical_admission_consent_challenges_v2 (
    challenge_sha256 CHAR(64) PRIMARY KEY,
    proposal_sha256 CHAR(64) NOT NULL,
    nonce_hex CHAR(64) NOT NULL UNIQUE,
    sponsor_compressed_pubkey CHAR(66) NOT NULL,
    child_compressed_pubkey CHAR(66) NOT NULL,
    issuer_session_pubkey CHAR(66) NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    verification_sha256 CHAR(64) UNIQUE,
    CONSTRAINT ck_cac_v2_challenge_sha CHECK (challenge_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_cac_v2_proposal_sha CHECK (proposal_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_cac_v2_nonce CHECK (nonce_hex ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_cac_v2_sponsor CHECK (
        sponsor_compressed_pubkey ~ '^(02|03)[0-9a-f]{64}$'
    ),
    CONSTRAINT ck_cac_v2_child CHECK (
        child_compressed_pubkey ~ '^(02|03)[0-9a-f]{64}$'
    ),
    CONSTRAINT ck_cac_v2_issuer CHECK (
        issuer_session_pubkey = sponsor_compressed_pubkey
    ),
    CONSTRAINT ck_cac_v2_different_keys CHECK (
        sponsor_compressed_pubkey <> child_compressed_pubkey
    ),
    CONSTRAINT ck_cac_v2_valid_window CHECK (
        expires_at > issued_at AND expires_at <= issued_at + INTERVAL '300 seconds'
    ),
    CONSTRAINT ck_cac_v2_consumption_pair CHECK (
        (consumed_at IS NULL) = (verification_sha256 IS NULL)
    ),
    CONSTRAINT ck_cac_v2_consumption_timestamp CHECK (
        consumed_at IS NULL OR (consumed_at >= issued_at AND consumed_at < expires_at)
    ),
    CONSTRAINT ck_cac_v2_verification CHECK (
        verification_sha256 IS NULL OR verification_sha256 ~ '^[0-9a-f]{64}$'
    )
);

-- The sole permitted UPDATE is monotonic NULL -> consumed once.
-- Prevent a compromised writer from rewriting a challenge/receipt or erasing history.
CREATE FUNCTION public.guard_canonical_admission_consent_challenge_v2()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'canonical admission challenge deletion forbidden';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF ROW(
            NEW.challenge_sha256,
            NEW.proposal_sha256,
            NEW.nonce_hex,
            NEW.sponsor_compressed_pubkey,
            NEW.child_compressed_pubkey,
            NEW.issuer_session_pubkey,
            NEW.issued_at,
            NEW.expires_at
        ) IS DISTINCT FROM ROW(
            OLD.challenge_sha256,
            OLD.proposal_sha256,
            OLD.nonce_hex,
            OLD.sponsor_compressed_pubkey,
            OLD.child_compressed_pubkey,
            OLD.issuer_session_pubkey,
            OLD.issued_at,
            OLD.expires_at
        ) OR OLD.consumed_at IS NOT NULL OR OLD.verification_sha256 IS NOT NULL
        OR NEW.consumed_at IS NULL OR NEW.verification_sha256 IS NULL THEN
            RAISE EXCEPTION 'canonical admission challenge immutable/consumed';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_guard_canonical_admission_consent_challenge_v2
BEFORE UPDATE OR DELETE ON public.canonical_admission_consent_challenges_v2
FOR EACH ROW EXECUTE FUNCTION public.guard_canonical_admission_consent_challenge_v2();

COMMENT ON TABLE public.canonical_admission_consent_challenges_v2 IS
    'Dormant proof of issuance and consumed nonce; never a Full grant or effective admission.';

-- No model, endpoint, systemd, cron, or runtime integration in this migration.
-- No GRANT statements; access must be separately authorized.
