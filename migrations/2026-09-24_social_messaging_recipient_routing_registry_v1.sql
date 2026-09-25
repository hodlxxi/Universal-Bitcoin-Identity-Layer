-- Dormant additive confidential recipient-routing registry.
-- Apply the whole file in one explicitly owned transaction. It adds no
-- backfill, route, runtime wiring, ciphertext store, self-read authority,
-- request admission, receipt, challenge consumption, or deployment.
CREATE TABLE social_messaging_recipient_handle_owners (
    device_handle VARCHAR(24) PRIMARY KEY,
    viewer_subject VARCHAR(64) NOT NULL,
    recipient_subject VARCHAR(64) NOT NULL,
    alias_version INTEGER NOT NULL,
    device_id VARCHAR(64) NOT NULL,
    binding_id VARCHAR(64) NOT NULL,
    binding_version INTEGER NOT NULL,
    CONSTRAINT uq_social_routing_handle_owner_namespace UNIQUE
        (alias_version, viewer_subject, recipient_subject, device_id, binding_id, binding_version),
    CONSTRAINT ck_social_routing_handle_value
        CHECK (device_handle ~ '^d_[A-Za-z0-9_-]{21}[AQgw]$'),
    CONSTRAINT ck_social_routing_handle_viewer
        CHECK (viewer_subject ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_social_routing_handle_recipient
        CHECK (recipient_subject ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_social_routing_handle_pair
        CHECK (viewer_subject <> recipient_subject),
    CONSTRAINT ck_social_routing_handle_alias_version
        CHECK (alias_version BETWEEN 1 AND 2147483647),
    CONSTRAINT ck_social_routing_handle_device
        CHECK (device_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_social_routing_handle_binding
        CHECK (binding_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_social_routing_handle_binding_version
        CHECK (binding_version BETWEEN 1 AND 1024)
);

CREATE TABLE social_messaging_recipient_routing_snapshots (
    snapshot_id VARCHAR(71) PRIMARY KEY,
    viewer_subject VARCHAR(64) NOT NULL,
    recipient_subject VARCHAR(64) NOT NULL,
    alias_version INTEGER NOT NULL,
    issued_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    route_count SMALLINT NOT NULL,
    snapshot_wire TEXT NOT NULL,
    CONSTRAINT ck_social_routing_snapshot_id
        CHECK (snapshot_id ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT ck_social_routing_snapshot_viewer
        CHECK (viewer_subject ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_social_routing_snapshot_recipient
        CHECK (recipient_subject ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_social_routing_snapshot_pair
        CHECK (viewer_subject <> recipient_subject),
    CONSTRAINT ck_social_routing_snapshot_alias_version
        CHECK (alias_version BETWEEN 1 AND 2147483647),
    CONSTRAINT ck_social_routing_snapshot_issued_at
        CHECK (issued_at BETWEEN 0 AND 9007199254740991),
    CONSTRAINT ck_social_routing_snapshot_expires_at CHECK (
        expires_at BETWEEN 1 AND 9007199254740991 AND
        issued_at < expires_at AND expires_at - issued_at <= 300000),
    CONSTRAINT ck_social_routing_snapshot_route_count
        CHECK (route_count BETWEEN 1 AND 16),
    CONSTRAINT ck_social_routing_snapshot_wire CHECK (
        octet_length(snapshot_wire) BETWEEN 1 AND 16384 AND snapshot_wire !~ '[^ -~]')
);

CREATE TABLE social_messaging_recipient_routing_snapshot_routes (
    snapshot_id VARCHAR(71) NOT NULL,
    route_ordinal SMALLINT NOT NULL,
    device_handle VARCHAR(24) NOT NULL,
    device_id VARCHAR(64) NOT NULL,
    binding_id VARCHAR(64) NOT NULL,
    binding_version INTEGER NOT NULL,
    authorization_proof_id VARCHAR(111) NOT NULL,
    authorization_valid_from BIGINT NOT NULL,
    authorization_expires_at BIGINT NOT NULL,
    PRIMARY KEY (snapshot_id, route_ordinal),
    CONSTRAINT fk_social_routing_snapshot_route_snapshot FOREIGN KEY (snapshot_id)
        REFERENCES social_messaging_recipient_routing_snapshots(snapshot_id)
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT fk_social_routing_snapshot_route_handle FOREIGN KEY (device_handle)
        REFERENCES social_messaging_recipient_handle_owners(device_handle)
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT uq_social_routing_snapshot_route_handle UNIQUE (snapshot_id, device_handle),
    CONSTRAINT uq_social_routing_snapshot_route_device UNIQUE (snapshot_id, device_id),
    CONSTRAINT uq_social_routing_snapshot_route_binding UNIQUE (snapshot_id, binding_id),
    CONSTRAINT uq_social_routing_snapshot_route_proof UNIQUE (snapshot_id, authorization_proof_id),
    CONSTRAINT ck_social_routing_snapshot_route_ordinal
        CHECK (route_ordinal BETWEEN 1 AND 16),
    CONSTRAINT ck_social_routing_snapshot_route_handle
        CHECK (device_handle ~ '^d_[A-Za-z0-9_-]{21}[AQgw]$'),
    CONSTRAINT ck_social_routing_snapshot_route_device
        CHECK (device_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_social_routing_snapshot_route_binding
        CHECK (binding_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_social_routing_snapshot_route_binding_version
        CHECK (binding_version BETWEEN 1 AND 1024),
    CONSTRAINT ck_social_routing_snapshot_route_proof CHECK (
        authorization_proof_id ~
        '^hodlxxi-(mobile-)?binding-authorization-v1-sha256:[0-9a-f]{64}$'),
    CONSTRAINT ck_social_routing_snapshot_route_valid_from
        CHECK (authorization_valid_from BETWEEN 0 AND 9007199254740991),
    CONSTRAINT ck_social_routing_snapshot_route_expires_at CHECK (
        authorization_expires_at BETWEEN 1 AND 9007199254740991 AND
        authorization_valid_from < authorization_expires_at)
);

CREATE TABLE social_messaging_recipient_routing_decisions (
    message_id VARCHAR(45) PRIMARY KEY,
    envelope_digest VARCHAR(106) NOT NULL,
    snapshot_id VARCHAR(71) NOT NULL,
    viewer_subject VARCHAR(64) NOT NULL,
    recipient_subject VARCHAR(64) NOT NULL,
    expires_at BIGINT NOT NULL,
    route_count SMALLINT NOT NULL,
    decision_wire TEXT NOT NULL,
    CONSTRAINT fk_social_routing_decision_snapshot FOREIGN KEY (snapshot_id)
        REFERENCES social_messaging_recipient_routing_snapshots(snapshot_id)
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT ck_social_routing_decision_message
        CHECK (message_id ~ '^m_[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$'),
    CONSTRAINT ck_social_routing_decision_envelope CHECK (
        envelope_digest ~
        '^hodlxxi-social-message-envelope-v1-sha256:[0-9a-f]{64}$'),
    CONSTRAINT ck_social_routing_decision_snapshot
        CHECK (snapshot_id ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT ck_social_routing_decision_viewer
        CHECK (viewer_subject ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_social_routing_decision_recipient
        CHECK (recipient_subject ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_social_routing_decision_pair
        CHECK (viewer_subject <> recipient_subject),
    CONSTRAINT ck_social_routing_decision_expires_at
        CHECK (expires_at BETWEEN 1 AND 9007199254740991),
    CONSTRAINT ck_social_routing_decision_route_count
        CHECK (route_count BETWEEN 1 AND 16),
    CONSTRAINT ck_social_routing_decision_wire CHECK (
        octet_length(decision_wire) BETWEEN 1 AND 8192 AND decision_wire !~ '[^ -~]')
);

CREATE TABLE social_messaging_recipient_routing_decision_routes (
    message_id VARCHAR(45) NOT NULL,
    route_ordinal SMALLINT NOT NULL,
    device_handle VARCHAR(24) NOT NULL,
    device_id VARCHAR(64) NOT NULL,
    binding_id VARCHAR(64) NOT NULL,
    binding_version INTEGER NOT NULL,
    PRIMARY KEY (message_id, route_ordinal),
    CONSTRAINT fk_social_routing_decision_route_decision FOREIGN KEY (message_id)
        REFERENCES social_messaging_recipient_routing_decisions(message_id)
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT fk_social_routing_decision_route_handle FOREIGN KEY (device_handle)
        REFERENCES social_messaging_recipient_handle_owners(device_handle)
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT uq_social_routing_decision_route_handle UNIQUE (message_id, device_handle),
    CONSTRAINT uq_social_routing_decision_route_device UNIQUE (message_id, device_id),
    CONSTRAINT uq_social_routing_decision_route_binding UNIQUE (message_id, binding_id),
    CONSTRAINT ck_social_routing_decision_route_ordinal
        CHECK (route_ordinal BETWEEN 1 AND 16),
    CONSTRAINT ck_social_routing_decision_route_handle
        CHECK (device_handle ~ '^d_[A-Za-z0-9_-]{21}[AQgw]$'),
    CONSTRAINT ck_social_routing_decision_route_device
        CHECK (device_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_social_routing_decision_route_binding
        CHECK (binding_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_social_routing_decision_route_binding_version
        CHECK (binding_version BETWEEN 1 AND 1024)
);

-- Every retained row is immutable history. INSERT remains available only so
-- the adapter can publish a complete unit in the caller's transaction.
CREATE FUNCTION deny_social_routing_history_mutation_v1()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'recipient messaging routing unavailable';
END $$;

CREATE TRIGGER trg_social_routing_handle_guard
    BEFORE UPDATE OR DELETE ON social_messaging_recipient_handle_owners
    FOR EACH ROW EXECUTE FUNCTION deny_social_routing_history_mutation_v1();
CREATE TRIGGER trg_social_routing_handle_no_truncate
    BEFORE TRUNCATE ON social_messaging_recipient_handle_owners
    FOR EACH STATEMENT EXECUTE FUNCTION deny_social_routing_history_mutation_v1();
CREATE TRIGGER trg_social_routing_snapshot_guard
    BEFORE UPDATE OR DELETE ON social_messaging_recipient_routing_snapshots
    FOR EACH ROW EXECUTE FUNCTION deny_social_routing_history_mutation_v1();
CREATE TRIGGER trg_social_routing_snapshot_no_truncate
    BEFORE TRUNCATE ON social_messaging_recipient_routing_snapshots
    FOR EACH STATEMENT EXECUTE FUNCTION deny_social_routing_history_mutation_v1();
CREATE TRIGGER trg_social_routing_snapshot_route_guard
    BEFORE UPDATE OR DELETE ON social_messaging_recipient_routing_snapshot_routes
    FOR EACH ROW EXECUTE FUNCTION deny_social_routing_history_mutation_v1();
CREATE TRIGGER trg_social_routing_snapshot_route_no_truncate
    BEFORE TRUNCATE ON social_messaging_recipient_routing_snapshot_routes
    FOR EACH STATEMENT EXECUTE FUNCTION deny_social_routing_history_mutation_v1();
CREATE TRIGGER trg_social_routing_decision_guard
    BEFORE UPDATE OR DELETE ON social_messaging_recipient_routing_decisions
    FOR EACH ROW EXECUTE FUNCTION deny_social_routing_history_mutation_v1();
CREATE TRIGGER trg_social_routing_decision_no_truncate
    BEFORE TRUNCATE ON social_messaging_recipient_routing_decisions
    FOR EACH STATEMENT EXECUTE FUNCTION deny_social_routing_history_mutation_v1();
CREATE TRIGGER trg_social_routing_decision_route_guard
    BEFORE UPDATE OR DELETE ON social_messaging_recipient_routing_decision_routes
    FOR EACH ROW EXECUTE FUNCTION deny_social_routing_history_mutation_v1();
CREATE TRIGGER trg_social_routing_decision_route_no_truncate
    BEFORE TRUNCATE ON social_messaging_recipient_routing_decision_routes
    FOR EACH STATEMENT EXECUTE FUNCTION deny_social_routing_history_mutation_v1();

CREATE FUNCTION assert_social_routing_snapshot_v1(p_snapshot_id VARCHAR)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    snapshot_row RECORD;
    expected_routes JSONB;
BEGIN
    SELECT * INTO STRICT snapshot_row
      FROM social_messaging_recipient_routing_snapshots
     WHERE snapshot_id = p_snapshot_id;

    SELECT COALESCE(jsonb_agg(jsonb_build_object(
               'authorizationExpiresAt', route.authorization_expires_at,
               'authorizationProofId', route.authorization_proof_id,
               'authorizationValidFrom', route.authorization_valid_from,
               'bindingId', route.binding_id,
               'bindingVersion', route.binding_version,
               'deviceHandle', route.device_handle,
               'deviceId', route.device_id)
               ORDER BY route.route_ordinal), '[]'::jsonb)
      INTO expected_routes
      FROM social_messaging_recipient_routing_snapshot_routes AS route
     WHERE route.snapshot_id = p_snapshot_id;

    IF (SELECT count(*) FROM social_messaging_recipient_routing_snapshot_routes
         WHERE snapshot_id = p_snapshot_id) <> snapshot_row.route_count
       OR snapshot_row.snapshot_wire::jsonb IS DISTINCT FROM jsonb_build_object(
            'aliasVersion', snapshot_row.alias_version,
            'complete', true,
            'expiresAt', snapshot_row.expires_at,
            'issuedAt', snapshot_row.issued_at,
            'recipientPackageSnapshotId', snapshot_row.snapshot_id,
            'recipientSubject', snapshot_row.recipient_subject,
            'routes', expected_routes,
            'schema', 'hodlxxi.social_messaging_recipient_routing_snapshot.v1',
            'source', 'hodlxxi-ubid',
            'version', 1,
            'viewerSubject', snapshot_row.viewer_subject)
       OR EXISTS (
            SELECT 1
              FROM social_messaging_recipient_routing_snapshot_routes AS route
              LEFT JOIN social_messaging_recipient_handle_owners AS owner
                ON owner.device_handle = route.device_handle
             WHERE route.snapshot_id = p_snapshot_id
               AND (owner.device_handle IS NULL OR
                    ROW(owner.viewer_subject, owner.recipient_subject, owner.alias_version,
                        owner.device_id, owner.binding_id, owner.binding_version)
                    IS DISTINCT FROM
                    ROW(snapshot_row.viewer_subject, snapshot_row.recipient_subject,
                        snapshot_row.alias_version, route.device_id, route.binding_id,
                        route.binding_version))) THEN
        RAISE EXCEPTION 'recipient messaging routing unavailable';
    END IF;
END $$;

CREATE FUNCTION check_social_routing_snapshot_v1()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM assert_social_routing_snapshot_v1(NEW.snapshot_id);
    RETURN NULL;
END $$;

CREATE CONSTRAINT TRIGGER trg_social_routing_snapshot_atomic
    AFTER INSERT ON social_messaging_recipient_routing_snapshots
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    EXECUTE FUNCTION check_social_routing_snapshot_v1();
CREATE CONSTRAINT TRIGGER trg_social_routing_snapshot_route_atomic
    AFTER INSERT ON social_messaging_recipient_routing_snapshot_routes
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    EXECUTE FUNCTION check_social_routing_snapshot_v1();

CREATE FUNCTION check_social_routing_handle_owner_v1()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM social_messaging_recipient_routing_snapshot_routes AS route
          JOIN social_messaging_recipient_routing_snapshots AS snapshot
            ON snapshot.snapshot_id = route.snapshot_id
         WHERE route.device_handle = NEW.device_handle
           AND ROW(snapshot.viewer_subject, snapshot.recipient_subject, snapshot.alias_version,
                   route.device_id, route.binding_id, route.binding_version)
               = ROW(NEW.viewer_subject, NEW.recipient_subject, NEW.alias_version,
                     NEW.device_id, NEW.binding_id, NEW.binding_version)) THEN
        RAISE EXCEPTION 'recipient messaging routing unavailable';
    END IF;
    RETURN NULL;
END $$;

CREATE CONSTRAINT TRIGGER trg_social_routing_handle_atomic
    AFTER INSERT ON social_messaging_recipient_handle_owners
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    EXECUTE FUNCTION check_social_routing_handle_owner_v1();

CREATE FUNCTION assert_social_routing_decision_v1(p_message_id VARCHAR)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    decision_row RECORD;
    expected_routes JSONB;
BEGIN
    SELECT * INTO STRICT decision_row
      FROM social_messaging_recipient_routing_decisions
     WHERE message_id = p_message_id;

    SELECT COALESCE(jsonb_agg(jsonb_build_object(
               'bindingId', route.binding_id,
               'bindingVersion', route.binding_version,
               'deviceHandle', route.device_handle,
               'deviceId', route.device_id)
               ORDER BY route.route_ordinal), '[]'::jsonb)
      INTO expected_routes
      FROM social_messaging_recipient_routing_decision_routes AS route
     WHERE route.message_id = p_message_id;

    IF (SELECT count(*) FROM social_messaging_recipient_routing_decision_routes
         WHERE message_id = p_message_id) <> decision_row.route_count
       OR decision_row.decision_wire::jsonb IS DISTINCT FROM jsonb_build_object(
            'complete', true,
            'envelopeDigest', decision_row.envelope_digest,
            'expiresAt', decision_row.expires_at,
            'messageId', decision_row.message_id,
            'recipientPackageSnapshotId', decision_row.snapshot_id,
            'recipientSubject', decision_row.recipient_subject,
            'routes', expected_routes,
            'schema', 'hodlxxi.social_messaging_recipient_routing_decision.v1',
            'source', 'hodlxxi-ubid',
            'version', 1,
            'viewerSubject', decision_row.viewer_subject)
       OR NOT EXISTS (
            SELECT 1
              FROM social_messaging_recipient_routing_snapshots AS snapshot
             WHERE snapshot.snapshot_id = decision_row.snapshot_id
               AND snapshot.viewer_subject = decision_row.viewer_subject
               AND snapshot.recipient_subject = decision_row.recipient_subject
               AND snapshot.expires_at = decision_row.expires_at
               AND snapshot.route_count = decision_row.route_count)
       OR EXISTS (
            SELECT 1
              FROM social_messaging_recipient_routing_decision_routes AS route
              LEFT JOIN social_messaging_recipient_routing_snapshot_routes AS snapshot_route
                ON snapshot_route.snapshot_id = decision_row.snapshot_id
               AND snapshot_route.route_ordinal = route.route_ordinal
             WHERE route.message_id = p_message_id
               AND (snapshot_route.snapshot_id IS NULL OR
                    ROW(snapshot_route.device_handle, snapshot_route.device_id,
                        snapshot_route.binding_id, snapshot_route.binding_version)
                    IS DISTINCT FROM
                    ROW(route.device_handle, route.device_id,
                        route.binding_id, route.binding_version))) THEN
        RAISE EXCEPTION 'recipient messaging routing unavailable';
    END IF;
END $$;

CREATE FUNCTION check_social_routing_decision_v1()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM assert_social_routing_decision_v1(NEW.message_id);
    RETURN NULL;
END $$;

CREATE CONSTRAINT TRIGGER trg_social_routing_decision_atomic
    AFTER INSERT ON social_messaging_recipient_routing_decisions
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    EXECUTE FUNCTION check_social_routing_decision_v1();
CREATE CONSTRAINT TRIGGER trg_social_routing_decision_route_atomic
    AFTER INSERT ON social_messaging_recipient_routing_decision_routes
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    EXECUTE FUNCTION check_social_routing_decision_v1();
