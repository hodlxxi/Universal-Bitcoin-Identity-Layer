-- Source-only registered-device sessions. Separate from enrollment and OAuth.
-- No runtime grants or feature enablement are implicit in this migration.
CREATE TABLE public.social_registered_device_challenges_v1 (
    challenge_id varchar(64) PRIMARY KEY CHECK (challenge_id ~ '^[0-9a-f]{64}$'),
    subject varchar(64) NOT NULL CHECK (subject ~ '^[0-9a-f]{64}$'),
    device_id varchar(64) NOT NULL CHECK (device_id ~ '^[0-9a-f]{64}$'),
    challenge_wire text NOT NULL CHECK (octet_length(challenge_wire) BETWEEN 1 AND 4096),
    issued_at bigint NOT NULL CHECK (issued_at >= 0),
    expires_at bigint NOT NULL CHECK (expires_at > issued_at AND expires_at - issued_at <= 60000)
);
CREATE INDEX social_registered_device_challenges_v1_device
    ON public.social_registered_device_challenges_v1 (subject, device_id, issued_at DESC);
CREATE TABLE public.social_registered_device_sessions_v1 (
    session_id varchar(64) PRIMARY KEY CHECK (session_id ~ '^[0-9a-f]{64}$'),
    challenge_id varchar(64) NOT NULL UNIQUE REFERENCES public.social_registered_device_challenges_v1(challenge_id),
    credential_digest varchar(64) NOT NULL UNIQUE CHECK (credential_digest ~ '^[0-9a-f]{64}$'),
    issued_at bigint NOT NULL CHECK (issued_at >= 0),
    expires_at bigint NOT NULL CHECK (expires_at > issued_at AND expires_at - issued_at <= 300000)
);
CREATE TABLE public.social_registered_device_revocations_v1 (
    session_id varchar(64) PRIMARY KEY REFERENCES public.social_registered_device_sessions_v1(session_id),
    revoked_at bigint NOT NULL CHECK (revoked_at >= 0)
);
CREATE FUNCTION public.deny_social_registered_device_history_mutation_v1()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
    RAISE EXCEPTION 'registered device history is immutable';
END;
$$;
CREATE TRIGGER registered_challenge_immutable_v1 BEFORE UPDATE OR DELETE ON public.social_registered_device_challenges_v1
    FOR EACH ROW EXECUTE FUNCTION public.deny_social_registered_device_history_mutation_v1();
CREATE TRIGGER registered_challenge_no_truncate_v1 BEFORE TRUNCATE ON public.social_registered_device_challenges_v1
    FOR EACH STATEMENT EXECUTE FUNCTION public.deny_social_registered_device_history_mutation_v1();
CREATE TRIGGER registered_session_immutable_v1 BEFORE UPDATE OR DELETE ON public.social_registered_device_sessions_v1
    FOR EACH ROW EXECUTE FUNCTION public.deny_social_registered_device_history_mutation_v1();
CREATE TRIGGER registered_session_no_truncate_v1 BEFORE TRUNCATE ON public.social_registered_device_sessions_v1
    FOR EACH STATEMENT EXECUTE FUNCTION public.deny_social_registered_device_history_mutation_v1();
CREATE TRIGGER registered_revocation_immutable_v1 BEFORE UPDATE OR DELETE ON public.social_registered_device_revocations_v1
    FOR EACH ROW EXECUTE FUNCTION public.deny_social_registered_device_history_mutation_v1();
CREATE TRIGGER registered_revocation_no_truncate_v1 BEFORE TRUNCATE ON public.social_registered_device_revocations_v1
    FOR EACH STATEMENT EXECUTE FUNCTION public.deny_social_registered_device_history_mutation_v1();
REVOKE ALL ON public.social_registered_device_challenges_v1, public.social_registered_device_sessions_v1,
    public.social_registered_device_revocations_v1 FROM PUBLIC;
REVOKE ALL ON FUNCTION public.deny_social_registered_device_history_mutation_v1() FROM PUBLIC;
