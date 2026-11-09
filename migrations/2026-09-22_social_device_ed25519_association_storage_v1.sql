-- Dormant, additive Social Ed25519 association authority. Apply only in a
-- separately authorized transaction. No backfill or runtime activation.
CREATE TABLE social_device_ed25519_association_chains (
    subject VARCHAR(64) NOT NULL,
    device_id VARCHAR(64) NOT NULL,
    authority_epoch BIGINT NOT NULL,
    last_association_id VARCHAR(64),
    last_association_version BIGINT,
    current_association_id VARCHAR(64),
    state VARCHAR(7) NOT NULL,
    CONSTRAINT pk_social_ed25519_chain PRIMARY KEY (subject, device_id),
    CONSTRAINT ck_social_ed25519_chain_subject CHECK (subject ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_social_ed25519_chain_device CHECK (device_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_social_ed25519_chain_state CHECK (
        (state = 'empty' AND authority_epoch = 0 AND last_association_id IS NULL
         AND last_association_version IS NULL AND current_association_id IS NULL) OR
        (state = 'active' AND authority_epoch >= 1 AND last_association_id IS NOT NULL
         AND last_association_version >= 1 AND current_association_id = last_association_id) OR
        (state = 'revoked' AND authority_epoch >= 2 AND last_association_id IS NOT NULL
         AND last_association_version >= 1 AND current_association_id IS NULL)
    )
);

CREATE TABLE social_device_ed25519_association_events (
    subject VARCHAR(64) NOT NULL,
    device_id VARCHAR(64) NOT NULL,
    authority_epoch BIGINT NOT NULL,
    kind VARCHAR(10) NOT NULL,
    association_id VARCHAR(64) NOT NULL,
    association_version BIGINT NOT NULL,
    predecessor_association_id VARCHAR(64),
    ed25519_public_key VARCHAR(64),
    enrollment_challenge_id VARCHAR(64),
    event_wire TEXT NOT NULL,
    CONSTRAINT pk_social_ed25519_event PRIMARY KEY (subject, device_id, authority_epoch),
    CONSTRAINT fk_social_ed25519_event_chain FOREIGN KEY (subject, device_id)
        REFERENCES social_device_ed25519_association_chains (subject, device_id),
    CONSTRAINT ck_social_ed25519_event_subject CHECK (subject ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_social_ed25519_event_device CHECK (device_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_social_ed25519_event_id CHECK (association_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_social_ed25519_event_predecessor CHECK
        (predecessor_association_id IS NULL OR predecessor_association_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_social_ed25519_event_key CHECK
        (ed25519_public_key IS NULL OR ed25519_public_key ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_social_ed25519_event_challenge CHECK
        (enrollment_challenge_id IS NULL OR enrollment_challenge_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_social_ed25519_event_bounds CHECK
        (authority_epoch BETWEEN 1 AND 9007199254740991 AND
         association_version BETWEEN 1 AND 9007199254740991),
    CONSTRAINT ck_social_ed25519_event_kind CHECK (
        kind IN ('initial','rotate','invalidate','revoke','reenroll') AND
        ((kind IN ('initial','rotate','reenroll') AND ed25519_public_key IS NOT NULL
          AND enrollment_challenge_id IS NOT NULL) OR
         (kind IN ('invalidate','revoke') AND ed25519_public_key IS NULL
          AND enrollment_challenge_id IS NULL))
    )
);

CREATE UNIQUE INDEX uq_social_ed25519_creation_id
    ON social_device_ed25519_association_events (association_id)
    WHERE kind IN ('initial','rotate','reenroll');
CREATE UNIQUE INDEX uq_social_ed25519_creation_version
    ON social_device_ed25519_association_events (subject, device_id, association_version)
    WHERE kind IN ('initial','rotate','reenroll');
CREATE UNIQUE INDEX uq_social_ed25519_creation_predecessor
    ON social_device_ed25519_association_events (predecessor_association_id)
    WHERE kind IN ('rotate','reenroll');
CREATE UNIQUE INDEX uq_social_ed25519_creation_key
    ON social_device_ed25519_association_events (subject, device_id, ed25519_public_key)
    WHERE kind IN ('initial','rotate','reenroll');
CREATE UNIQUE INDEX uq_social_ed25519_creation_challenge
    ON social_device_ed25519_association_events (enrollment_challenge_id)
    WHERE kind IN ('initial','rotate','reenroll');

CREATE FUNCTION guard_social_ed25519_chain_v1() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        -- Raw SQL creation obeys the same absent-row lock as the adapter.
        PERFORM pg_advisory_xact_lock(hashtextextended(NEW.subject || ':' || NEW.device_id, 0));
        IF NEW.state <> 'empty' THEN
            RAISE EXCEPTION 'social device ed25519 association storage unavailable';
        END IF;
        RETURN NEW;
    ELSIF TG_OP = 'UPDATE' THEN
        -- Only the event trigger may advance the materialized current row.
        IF pg_trigger_depth() <> 2 OR
           ROW(NEW.subject, NEW.device_id) IS DISTINCT FROM ROW(OLD.subject, OLD.device_id) OR
           NEW.authority_epoch <> OLD.authority_epoch + 1 THEN
            RAISE EXCEPTION 'social device ed25519 association storage unavailable';
        END IF;
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'social device ed25519 association storage unavailable';
END $$;

CREATE FUNCTION assert_social_ed25519_chain_initialized_v1() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM social_device_ed25519_association_chains
        WHERE subject = NEW.subject AND device_id = NEW.device_id
          AND state <> 'empty' AND authority_epoch >= 1
    ) THEN
        RAISE EXCEPTION 'social device ed25519 association storage unavailable';
    END IF;
    RETURN NULL;
END $$;

CREATE FUNCTION guard_social_ed25519_event_v1() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    head social_device_ed25519_association_chains%ROWTYPE;
    creation social_device_ed25519_association_events%ROWTYPE;
    document jsonb;
    enrollment jsonb;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'social device ed25519 association storage unavailable';
    END IF;
    SELECT * INTO head FROM social_device_ed25519_association_chains
        WHERE subject = NEW.subject AND device_id = NEW.device_id FOR UPDATE;
    IF NOT FOUND OR NEW.authority_epoch <> head.authority_epoch + 1 THEN
        RAISE EXCEPTION 'social device ed25519 association storage unavailable';
    END IF;
    document := NEW.event_wire::jsonb;
    IF octet_length(NEW.event_wire) NOT BETWEEN 1 AND 4096 OR NEW.event_wire ~ '[^ -~]' OR
       document ->> 'schema' IS DISTINCT FROM 'hodlxxi.social_messaging_device_ed25519_association_event.v1' OR
       document ->> 'version' IS DISTINCT FROM '1' OR
       document ->> 'kind' IS DISTINCT FROM NEW.kind OR
       document ->> 'associationId' IS DISTINCT FROM NEW.association_id OR
       (document ->> 'associationVersion')::bigint IS DISTINCT FROM NEW.association_version OR
       (document ->> 'authorityEpoch')::bigint IS DISTINCT FROM NEW.authority_epoch OR
       document ->> 'predecessorAssociationId' IS DISTINCT FROM NEW.predecessor_association_id THEN
        RAISE EXCEPTION 'social device ed25519 association storage unavailable';
    END IF;
    IF NEW.kind IN ('initial','rotate','reenroll') THEN
        enrollment := (document ->> 'enrollmentWire')::jsonb;
        IF enrollment ->> 'subject' IS DISTINCT FROM NEW.subject OR
           enrollment ->> 'deviceId' IS DISTINCT FROM NEW.device_id OR
           enrollment ->> 'ed25519PublicKey' IS DISTINCT FROM NEW.ed25519_public_key OR
           enrollment ->> 'enrollmentChallengeId' IS DISTINCT FROM NEW.enrollment_challenge_id THEN
            RAISE EXCEPTION 'social device ed25519 association storage unavailable';
        END IF;
        IF NEW.kind = 'initial' THEN
            IF head.state <> 'empty' OR NEW.association_version <> 1 OR
               NEW.predecessor_association_id IS NOT NULL THEN
                RAISE EXCEPTION 'social device ed25519 association storage unavailable';
            END IF;
        ELSIF NEW.association_version <> head.last_association_version + 1 OR
              NEW.predecessor_association_id IS DISTINCT FROM head.last_association_id OR
              (NEW.kind = 'rotate' AND head.state <> 'active') OR
              (NEW.kind = 'reenroll' AND head.state <> 'revoked') THEN
            RAISE EXCEPTION 'social device ed25519 association storage unavailable';
        END IF;
    ELSE
        IF document -> 'enrollmentWire' <> 'null'::jsonb OR head.state <> 'active' OR
           NEW.association_id <> head.current_association_id OR
           NEW.association_version <> head.last_association_version THEN
            RAISE EXCEPTION 'social device ed25519 association storage unavailable';
        END IF;
        SELECT * INTO creation FROM social_device_ed25519_association_events
            WHERE subject = NEW.subject AND device_id = NEW.device_id
              AND association_id = NEW.association_id
              AND kind IN ('initial','rotate','reenroll');
        IF NOT FOUND OR NEW.predecessor_association_id IS DISTINCT FROM creation.predecessor_association_id THEN
            RAISE EXCEPTION 'social device ed25519 association storage unavailable';
        END IF;
    END IF;
    RETURN NEW;
END $$;

CREATE FUNCTION advance_social_ed25519_chain_v1() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.kind IN ('initial','rotate','reenroll') THEN
        UPDATE social_device_ed25519_association_chains SET
            authority_epoch = NEW.authority_epoch,
            last_association_id = NEW.association_id,
            last_association_version = NEW.association_version,
            current_association_id = NEW.association_id,
            state = 'active'
        WHERE subject = NEW.subject AND device_id = NEW.device_id;
    ELSIF NEW.kind = 'revoke' THEN
        UPDATE social_device_ed25519_association_chains SET
            authority_epoch = NEW.authority_epoch,
            current_association_id = NULL,
            state = 'revoked'
        WHERE subject = NEW.subject AND device_id = NEW.device_id;
    ELSE
        UPDATE social_device_ed25519_association_chains SET
            authority_epoch = NEW.authority_epoch
        WHERE subject = NEW.subject AND device_id = NEW.device_id;
    END IF;
    RETURN NULL;
END $$;

CREATE TRIGGER trg_social_ed25519_chain_guard BEFORE INSERT OR UPDATE OR DELETE
    ON social_device_ed25519_association_chains FOR EACH ROW
    EXECUTE FUNCTION guard_social_ed25519_chain_v1();
CREATE TRIGGER trg_social_ed25519_chain_truncate BEFORE TRUNCATE
    ON social_device_ed25519_association_chains FOR EACH STATEMENT
    EXECUTE FUNCTION guard_social_ed25519_chain_v1();
CREATE CONSTRAINT TRIGGER trg_social_ed25519_chain_initialized
    AFTER INSERT ON social_device_ed25519_association_chains
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    EXECUTE FUNCTION assert_social_ed25519_chain_initialized_v1();
CREATE TRIGGER trg_social_ed25519_event_guard BEFORE INSERT OR UPDATE OR DELETE
    ON social_device_ed25519_association_events FOR EACH ROW
    EXECUTE FUNCTION guard_social_ed25519_event_v1();
CREATE TRIGGER trg_social_ed25519_event_truncate BEFORE TRUNCATE
    ON social_device_ed25519_association_events FOR EACH STATEMENT
    EXECUTE FUNCTION guard_social_ed25519_event_v1();
CREATE TRIGGER trg_social_ed25519_event_advance AFTER INSERT
    ON social_device_ed25519_association_events FOR EACH ROW
    EXECUTE FUNCTION advance_social_ed25519_chain_v1();
