-- Dormant, empty-by-default signed alias-namespace lifecycle history.
-- Apply this whole file in one explicitly owned transaction after
-- 2026-09-24_social_messaging_active_alias_namespace_v1.sql. It provisions no
-- row, key, route, role, runtime wiring or database actor privilege.

LOCK TABLE social_messaging_active_alias_namespaces IN ACCESS EXCLUSIVE MODE;

-- The earlier registry had no authenticated writer or authorized seed. Refuse
-- to bless any pre-existing row by installing event guards around it.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM social_messaging_active_alias_namespaces) THEN
        RAISE EXCEPTION 'social messaging alias namespace lifecycle storage unavailable';
    END IF;
END $$;

CREATE TABLE social_messaging_active_alias_namespace_lifecycle_events (
    command_id VARCHAR(120) NOT NULL,
    action VARCHAR(9) NOT NULL,
    key_id VARCHAR(64) NOT NULL,
    nonce VARCHAR(43) NOT NULL,
    expected_version INTEGER,
    expected_commitment VARCHAR(112),
    successor_version INTEGER NOT NULL,
    successor_commitment VARCHAR(112) NOT NULL,
    issued_at_ms BIGINT NOT NULL,
    expires_at_ms BIGINT NOT NULL,
    command_wire TEXT NOT NULL,
    signature VARCHAR(86) NOT NULL,
    staged_top_level_transaction_id xid8 NOT NULL,
    CONSTRAINT pk_social_alias_lifecycle_event PRIMARY KEY (command_id),
    CONSTRAINT uq_social_alias_lifecycle_event_nonce UNIQUE (nonce),
    CONSTRAINT uq_social_alias_lifecycle_event_successor_version
        UNIQUE (successor_version),
    CONSTRAINT uq_social_alias_lifecycle_event_successor_commitment
        UNIQUE (successor_commitment),
    CONSTRAINT uq_social_alias_lifecycle_event_command_wire UNIQUE (command_wire),
    CONSTRAINT fk_social_alias_lifecycle_event_expected_version
        FOREIGN KEY (expected_version)
        REFERENCES social_messaging_active_alias_namespaces (alias_version)
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT fk_social_alias_lifecycle_event_successor_version
        FOREIGN KEY (successor_version)
        REFERENCES social_messaging_active_alias_namespaces (alias_version)
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT ck_social_alias_lifecycle_event_action
        CHECK (action IN ('provision', 'rotate')),
    CONSTRAINT ck_social_alias_lifecycle_event_successor_version
        CHECK (successor_version BETWEEN 1 AND 2147483647),
    CONSTRAINT ck_social_alias_lifecycle_event_interval CHECK (
        issued_at_ms BETWEEN 0 AND 9007199254740991
        AND expires_at_ms BETWEEN 0 AND 9007199254740991
        AND expires_at_ms > issued_at_ms
        AND expires_at_ms - issued_at_ms <= 86400000),
    CONSTRAINT ck_social_alias_lifecycle_event_command_id CHECK (
        command_id ~
        '^hodlxxi-social-active-alias-lifecycle-command-v1-sha256:[0-9a-f]{64}$'),
    CONSTRAINT ck_social_alias_lifecycle_event_key_id
        CHECK (key_id ~ '^[a-z0-9][a-z0-9._:-]{0,63}$'),
    CONSTRAINT ck_social_alias_lifecycle_event_nonce
        CHECK (nonce ~ '^[A-Za-z0-9_-]{43}$'),
    CONSTRAINT ck_social_alias_lifecycle_event_signature
        CHECK (signature ~ '^[A-Za-z0-9_-]{86}$'),
    CONSTRAINT ck_social_alias_lifecycle_event_successor_commitment CHECK (
        successor_commitment ~
        '^hodlxxi-social-active-alias-namespace-v1-sha256:[0-9a-f]{64}$'),
    CONSTRAINT ck_social_alias_lifecycle_event_command_wire CHECK (
        octet_length(command_wire) BETWEEN 1 AND 2048
        AND command_wire !~ '[^ -~]')
);

-- This function validates exact canonical field duplication and the command-ID
-- digest. Ed25519 authentication is deliberately outside SQL and is repeated
-- by the pinned transaction owner. These checks do not grant database roles.
CREATE FUNCTION guard_social_alias_namespace_lifecycle_event_v1()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    expected_commitment_json TEXT;
    expected_version_json TEXT;
    command_without_id TEXT;
    canonical_command TEXT;
    derived_command_id TEXT;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'social messaging alias namespace lifecycle storage unavailable';
    END IF;

    -- Commit classification is derived only from a PostgreSQL-stamped full
    -- top-level transaction ID. Discard any value supplied by an inserter.
    NEW.staged_top_level_transaction_id := pg_current_xact_id();

    IF NEW.action = 'provision' THEN
        IF NEW.expected_version IS NOT NULL
           OR NEW.expected_commitment IS NOT NULL
           OR NEW.successor_version <> 1 THEN
            RAISE EXCEPTION 'social messaging alias namespace lifecycle storage unavailable';
        END IF;
    ELSIF NEW.action = 'rotate' THEN
        IF NEW.expected_version IS NULL
           OR NEW.expected_commitment IS NULL
           OR NEW.expected_version < 1
           OR NEW.expected_version >= 2147483647
           OR NEW.successor_version <> NEW.expected_version + 1
           OR NEW.expected_commitment = NEW.successor_commitment
           OR NEW.expected_commitment !~
              '^hodlxxi-social-active-alias-namespace-v1-sha256:[0-9a-f]{64}$' THEN
            RAISE EXCEPTION 'social messaging alias namespace lifecycle storage unavailable';
        END IF;
    ELSE
        RAISE EXCEPTION 'social messaging alias namespace lifecycle storage unavailable';
    END IF;

    expected_commitment_json := CASE
        WHEN NEW.expected_commitment IS NULL THEN 'null'
        ELSE '"' || NEW.expected_commitment || '"'
    END;
    expected_version_json := CASE
        WHEN NEW.expected_version IS NULL THEN 'null'
        ELSE NEW.expected_version::TEXT
    END;

    command_without_id :=
        '{"action":"' || NEW.action ||
        '","algorithm":"Ed25519"' ||
        ',"audience":"hodlxxi.ubid.alias_namespace_lifecycle.v1"' ||
        ',"expectedCommitment":' || expected_commitment_json ||
        ',"expectedVersion":' || expected_version_json ||
        ',"expiresAtMs":' || NEW.expires_at_ms::TEXT ||
        ',"issuedAtMs":' || NEW.issued_at_ms::TEXT ||
        ',"keyId":"' || NEW.key_id ||
        '","nonce":"' || NEW.nonce ||
        '","schema":"hodlxxi.social_active_alias_namespace_lifecycle_command.v1"' ||
        ',"successorCommitment":"' || NEW.successor_commitment ||
        '","successorVersion":' || NEW.successor_version::TEXT ||
        ',"version":1}';

    derived_command_id :=
        'hodlxxi-social-active-alias-lifecycle-command-v1-sha256:' ||
        encode(
            sha256(
                convert_to(
                    'HODLXXI_SOCIAL_ACTIVE_ALIAS_LIFECYCLE_COMMAND_ID_V1',
                    'UTF8') ||
                decode('00', 'hex') ||
                convert_to(command_without_id, 'UTF8')),
            'hex');

    canonical_command :=
        '{"action":"' || NEW.action ||
        '","algorithm":"Ed25519"' ||
        ',"audience":"hodlxxi.ubid.alias_namespace_lifecycle.v1"' ||
        ',"commandId":"' || NEW.command_id ||
        '","expectedCommitment":' || expected_commitment_json ||
        ',"expectedVersion":' || expected_version_json ||
        ',"expiresAtMs":' || NEW.expires_at_ms::TEXT ||
        ',"issuedAtMs":' || NEW.issued_at_ms::TEXT ||
        ',"keyId":"' || NEW.key_id ||
        '","nonce":"' || NEW.nonce ||
        '","schema":"hodlxxi.social_active_alias_namespace_lifecycle_command.v1"' ||
        ',"successorCommitment":"' || NEW.successor_commitment ||
        '","successorVersion":' || NEW.successor_version::TEXT ||
        ',"version":1}';

    IF NEW.command_id <> derived_command_id
       OR NEW.command_wire <> canonical_command THEN
        RAISE EXCEPTION 'social messaging alias namespace lifecycle storage unavailable';
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER trg_social_alias_lifecycle_event_guard
    BEFORE INSERT OR UPDATE OR DELETE
    ON social_messaging_active_alias_namespace_lifecycle_events
    FOR EACH ROW
    EXECUTE FUNCTION guard_social_alias_namespace_lifecycle_event_v1();

CREATE FUNCTION deny_social_alias_namespace_lifecycle_event_truncate_v1()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'social messaging alias namespace lifecycle storage unavailable';
END $$;

CREATE TRIGGER trg_social_alias_lifecycle_event_no_truncate
    BEFORE TRUNCATE
    ON social_messaging_active_alias_namespace_lifecycle_events
    FOR EACH STATEMENT
    EXECUTE FUNCTION deny_social_alias_namespace_lifecycle_event_truncate_v1();

-- Final-state invariants establish one contiguous event-backed namespace
-- history. They are deferred so provision and rotation can stage their row and
-- event mutations in the caller transaction, but no proper subset can commit.
CREATE FUNCTION check_social_alias_namespace_lifecycle_invariant_v1()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    namespace_count BIGINT;
    event_count BIGINT;
    minimum_version INTEGER;
    maximum_version INTEGER;
    active_count BIGINT;
BEGIN
    SELECT count(*), min(alias_version), max(alias_version),
           count(*) FILTER (WHERE lifecycle_state = 'ACTIVE')
      INTO namespace_count, minimum_version, maximum_version, active_count
      FROM social_messaging_active_alias_namespaces;
    SELECT count(*) INTO event_count
      FROM social_messaging_active_alias_namespace_lifecycle_events;

    IF namespace_count = 0 AND event_count = 0 THEN
        RETURN NULL;
    END IF;
    IF namespace_count <> event_count
       OR minimum_version <> 1
       OR maximum_version::BIGINT <> namespace_count
       OR active_count <> 1 THEN
        RAISE EXCEPTION 'social messaging alias namespace lifecycle storage unavailable';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM social_messaging_active_alias_namespaces AS namespace_row
          LEFT JOIN social_messaging_active_alias_namespace_lifecycle_events AS event_row
            ON event_row.successor_version = namespace_row.alias_version
         WHERE event_row.command_id IS NULL
            OR event_row.successor_commitment <> namespace_row.secret_commitment
            OR namespace_row.lifecycle_state <>
               CASE WHEN namespace_row.alias_version = maximum_version
                    THEN 'ACTIVE' ELSE 'RETIRED' END
    ) THEN
        RAISE EXCEPTION 'social messaging alias namespace lifecycle storage unavailable';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM social_messaging_active_alias_namespace_lifecycle_events AS event_row
          LEFT JOIN social_messaging_active_alias_namespaces AS predecessor
            ON predecessor.alias_version = event_row.expected_version
         WHERE (
             event_row.successor_version = 1
             AND (
                 event_row.action <> 'provision'
                 OR event_row.expected_version IS NOT NULL
                 OR event_row.expected_commitment IS NOT NULL))
            OR (
             event_row.successor_version > 1
             AND (
                 event_row.action <> 'rotate'
                 OR event_row.expected_version <> event_row.successor_version - 1
                 OR predecessor.alias_version IS NULL
                 OR predecessor.secret_commitment <>
                    event_row.expected_commitment))
    ) THEN
        RAISE EXCEPTION 'social messaging alias namespace lifecycle storage unavailable';
    END IF;
    RETURN NULL;
END $$;

CREATE CONSTRAINT TRIGGER trg_social_alias_lifecycle_namespace_invariant
    AFTER INSERT OR UPDATE OR DELETE
    ON social_messaging_active_alias_namespaces
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW
    EXECUTE FUNCTION check_social_alias_namespace_lifecycle_invariant_v1();

CREATE CONSTRAINT TRIGGER trg_social_alias_lifecycle_event_invariant
    AFTER INSERT OR UPDATE OR DELETE
    ON social_messaging_active_alias_namespace_lifecycle_events
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW
    EXECUTE FUNCTION check_social_alias_namespace_lifecycle_invariant_v1();
