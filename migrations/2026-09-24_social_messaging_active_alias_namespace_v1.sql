-- Dormant, empty-by-default alias-namespace reconciliation registry.
-- Apply the whole file in one explicitly owned transaction. It adds no
-- provisioning/rotation API, current-handle resolver, self-read authority,
-- request admission, route, runtime wiring, backfill, seed row or deployment.
CREATE TABLE social_messaging_active_alias_namespaces (
    alias_version INTEGER PRIMARY KEY,
    secret_commitment VARCHAR(112) NOT NULL,
    lifecycle_state VARCHAR(7) NOT NULL,
    CONSTRAINT uq_social_active_alias_namespace_commitment
        UNIQUE (secret_commitment),
    CONSTRAINT ck_social_active_alias_namespace_version
        CHECK (alias_version BETWEEN 1 AND 2147483647),
    CONSTRAINT ck_social_active_alias_namespace_commitment CHECK (
        secret_commitment ~
        '^hodlxxi-social-active-alias-namespace-v1-sha256:[0-9a-f]{64}$'),
    CONSTRAINT ck_social_active_alias_namespace_state
        CHECK (lifecycle_state IN ('ACTIVE', 'RETIRED'))
);

-- This enforces at most one ACTIVE row. The table is deliberately empty after
-- migration; the reader separately requires exactly one row under FOR UPDATE.
CREATE UNIQUE INDEX uq_social_active_alias_namespace_singleton
    ON social_messaging_active_alias_namespaces (lifecycle_state)
    WHERE lifecycle_state = 'ACTIVE';

-- Trusted lifecycle tooling remains a separate prerequisite. If such an owner
-- is later supplied, a generation can only be inserted ACTIVE and can only
-- transition once from ACTIVE to RETIRED without changing its identity.
CREATE FUNCTION guard_social_active_alias_namespace_v1()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.lifecycle_state <> 'ACTIVE' THEN
            RAISE EXCEPTION 'social messaging active alias namespace unavailable';
        END IF;
        RETURN NEW;
    END IF;

    IF TG_OP = 'UPDATE' THEN
        IF OLD.lifecycle_state <> 'ACTIVE'
           OR NEW.lifecycle_state <> 'RETIRED'
           OR NEW.alias_version IS DISTINCT FROM OLD.alias_version
           OR NEW.secret_commitment IS DISTINCT FROM OLD.secret_commitment THEN
            RAISE EXCEPTION 'social messaging active alias namespace unavailable';
        END IF;
        RETURN NEW;
    END IF;

    RAISE EXCEPTION 'social messaging active alias namespace unavailable';
END $$;

CREATE TRIGGER trg_social_active_alias_namespace_guard
    BEFORE INSERT OR UPDATE OR DELETE
    ON social_messaging_active_alias_namespaces
    FOR EACH ROW EXECUTE FUNCTION guard_social_active_alias_namespace_v1();

CREATE FUNCTION deny_social_active_alias_namespace_truncate_v1()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'social messaging active alias namespace unavailable';
END $$;

CREATE TRIGGER trg_social_active_alias_namespace_no_truncate
    BEFORE TRUNCATE ON social_messaging_active_alias_namespaces
    FOR EACH STATEMENT
    EXECUTE FUNCTION deny_social_active_alias_namespace_truncate_v1();
