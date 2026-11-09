-- Dormant additive migration following 2026-09-13_social_session_issuance_v1.sql.
-- This repository uses dated SQL files, not an Alembic revision graph.
-- Apply the whole file in one explicitly owned transaction. No backfill,
-- runtime registration, database clock, identity foreign key or live activation.
-- Once used, retain evidence; dropping history is not operational rollback.
CREATE TABLE social_device_admission_challenges (
    challenge_id VARCHAR(64) PRIMARY KEY,
    context_wire TEXT NOT NULL,
    challenge_wire TEXT NOT NULL,
    routing_request_wire TEXT,
    state VARCHAR(11) NOT NULL,
    CONSTRAINT ck_social_challenge_id CHECK (challenge_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_social_challenge_state
        CHECK (state IN ('issued','consumed','expired','invalidated','cancelled')),
    CONSTRAINT ck_social_challenge_context_wire CHECK (
        octet_length(context_wire) BETWEEN 1 AND 4096 AND context_wire !~ '[^ -~]'),
    CONSTRAINT ck_social_challenge_wire CHECK (
        octet_length(challenge_wire) BETWEEN 1 AND 4096 AND challenge_wire !~ '[^ -~]'),
    CONSTRAINT ck_social_challenge_routing_wire CHECK (
        routing_request_wire IS NULL OR (octet_length(routing_request_wire) BETWEEN 1 AND 2048
        AND routing_request_wire !~ '[^ -~]')),
    CONSTRAINT ck_social_challenge_wire_id CHECK ((
        context_wire::json ->> 'challengeId' = challenge_id AND
        COALESCE(challenge_wire::json ->> 'challengeId',
                 challenge_wire::json ->> 'enrollmentChallengeId') = challenge_id) IS TRUE)
);

-- JSON casts above only check the indexed key. They never replace stored TEXT.
-- The adapter reparses every wire with the shared canonical contract on every
-- create/read. All remaining identities, attemptId and issuedAt/expiresAt are
-- derived, without loss, from exact wires. The primary key is the sole creation
-- arbiter: an existing ID always fails, even for identical bytes/attemptId.
CREATE FUNCTION guard_social_device_challenge_v1() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'issued' THEN
            RAISE EXCEPTION 'social device challenge storage unavailable';
        END IF;
        RETURN NEW;
    ELSIF TG_OP = 'UPDATE' THEN
        IF ROW(NEW.challenge_id, NEW.context_wire, NEW.challenge_wire, NEW.routing_request_wire)
           IS DISTINCT FROM
           ROW(OLD.challenge_id, OLD.context_wire, OLD.challenge_wire, OLD.routing_request_wire)
           OR OLD.state <> 'issued'
           OR NEW.state NOT IN ('expired','invalidated','cancelled') THEN
            RAISE EXCEPTION 'social device challenge storage unavailable';
        END IF;
        -- Only freeze non-consuming terminal schema transitions. No adapter
        -- transition API is supplied. 'consumed' is reserved vocabulary and
        -- denied until a future atomic consumer/receipt constraint is supplied.
        RETURN NEW;
    END IF;
    -- Neither deletion nor truncation may free an issued or terminal ID.
    RAISE EXCEPTION 'social device challenge storage unavailable';
END $$;
CREATE TRIGGER trg_social_challenge_guard
    BEFORE INSERT OR UPDATE OR DELETE ON social_device_admission_challenges
    FOR EACH ROW EXECUTE FUNCTION guard_social_device_challenge_v1();
CREATE TRIGGER trg_social_challenge_no_truncate
    BEFORE TRUNCATE ON social_device_admission_challenges
    FOR EACH STATEMENT EXECUTE FUNCTION guard_social_device_challenge_v1();
