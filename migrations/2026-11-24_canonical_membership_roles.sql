-- Apply as the database administrator in the same transaction as the Task 2B
-- schema changes. The two named group roles are provisioned before this stage.
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
DECLARE
    principal record;
BEGIN
    FOR principal IN
        SELECT * FROM pg_roles
        WHERE rolname IN ('hodlxxi', 'hodlxxi_canonical_owner', 'hodlxxi_canonical_publisher')
    LOOP
        IF principal.rolsuper OR principal.rolcreaterole OR principal.rolcreatedb
            OR principal.rolreplication OR principal.rolbypassrls
            OR (principal.rolname <> 'hodlxxi' AND principal.rolcanlogin)
        THEN
            RAISE EXCEPTION 'unsafe attributes on canonical role %', principal.rolname;
        END IF;
    END LOOP;
    IF (SELECT count(*) FROM pg_roles
        WHERE rolname IN ('hodlxxi', 'hodlxxi_canonical_owner', 'hodlxxi_canonical_publisher')) <> 3
        OR pg_has_role('hodlxxi', 'hodlxxi_canonical_owner', 'MEMBER')
        OR pg_has_role('hodlxxi', 'hodlxxi_canonical_publisher', 'MEMBER')
        OR pg_has_role('hodlxxi_canonical_publisher', 'hodlxxi_canonical_owner', 'MEMBER')
        OR pg_has_role('hodlxxi_canonical_publisher', 'hodlxxi', 'MEMBER')
    THEN
        RAISE EXCEPTION 'canonical roles are missing or have unsafe memberships';
    END IF;
END;
$$;

REVOKE CREATE ON SCHEMA public FROM PUBLIC, hodlxxi, hodlxxi_canonical_publisher;
GRANT USAGE ON SCHEMA public TO hodlxxi, hodlxxi_canonical_owner, hodlxxi_canonical_publisher;

-- Preserve the named legacy Social reader/row-lock grants. Reject mutations
-- for all callers, including those whose SELECT FOR UPDATE requires UPDATE.
DROP TRIGGER trg_caeov1_evidence_immutable ON public.current_entitlement_evidence;
CREATE TRIGGER trg_caeov1_evidence_immutable
    BEFORE UPDATE OR DELETE ON public.current_entitlement_evidence
    FOR EACH ROW EXECUTE FUNCTION public.reject_canonical_auto_import_mutation_v1();

-- The explicit object list leaves other owners and service ACLs in place.
ALTER TABLE public.canonical_admission_candidate_outpoints_v2 OWNER TO hodlxxi_canonical_owner;
ALTER TABLE public.canonical_admission_candidates_v2 OWNER TO hodlxxi_canonical_owner;
ALTER TABLE public.canonical_admission_consent_challenges_v2 OWNER TO hodlxxi_canonical_owner;
ALTER TABLE public.canonical_admission_edge_legs OWNER TO hodlxxi_canonical_owner;
ALTER TABLE public.canonical_admission_edges OWNER TO hodlxxi_canonical_owner;
ALTER TABLE public.canonical_authority_child_claims_v1 OWNER TO hodlxxi_canonical_owner;
ALTER TABLE public.canonical_auto_admission_revocations_v1 OWNER TO hodlxxi_canonical_owner;
ALTER TABLE public.canonical_auto_effective_edges_v1 OWNER TO hodlxxi_canonical_owner;
ALTER TABLE public.canonical_auto_effective_outpoints_v1 OWNER TO hodlxxi_canonical_owner;
ALTER TABLE public.canonical_auto_entitlement_observations_v1 OWNER TO hodlxxi_canonical_owner;
ALTER TABLE public.canonical_auto_import_intents_v1 OWNER TO hodlxxi_canonical_owner;
ALTER TABLE public.canonical_auto_import_pairs_v1 OWNER TO hodlxxi_canonical_owner;
ALTER TABLE public.canonical_auto_import_scripts_v1 OWNER TO hodlxxi_canonical_owner;
ALTER TABLE public.canonical_auto_refresh_progress_v1 OWNER TO hodlxxi_canonical_owner;
ALTER TABLE public.canonical_covenant_funding_outpoints OWNER TO hodlxxi_canonical_owner;
ALTER TABLE public.canonical_covenant_funding_sets OWNER TO hodlxxi_canonical_owner;
ALTER TABLE public.canonical_genesis_records OWNER TO hodlxxi_canonical_owner;
ALTER TABLE public.canonical_global_outpoint_claims_v2 OWNER TO hodlxxi_canonical_owner;
ALTER TABLE public.canonical_multileg_admission_candidates_v2 OWNER TO hodlxxi_canonical_owner;
ALTER TABLE public.canonical_multileg_candidate_expirations_v2 OWNER TO hodlxxi_canonical_owner;
ALTER TABLE public.canonical_multileg_candidate_outpoints_v2 OWNER TO hodlxxi_canonical_owner;
ALTER TABLE public.canonical_multileg_consent_browser_bindings_v2 OWNER TO hodlxxi_canonical_owner;
ALTER TABLE public.canonical_multileg_consent_challenges_v2 OWNER TO hodlxxi_canonical_owner;
ALTER TABLE public.canonical_multileg_effective_edges_v2 OWNER TO hodlxxi_canonical_owner;
ALTER TABLE public.canonical_multileg_live_child_claims_v2 OWNER TO hodlxxi_canonical_owner;
ALTER TABLE public.canonical_multileg_live_outpoint_claims_v2 OWNER TO hodlxxi_canonical_owner;
ALTER TABLE public.canonical_root_registration_bindings OWNER TO hodlxxi_canonical_owner;
ALTER TABLE public.current_entitlement_evidence OWNER TO hodlxxi_canonical_owner;
ALTER VIEW public.canonical_effective_authority_edges_v1 OWNER TO hodlxxi_canonical_owner;

-- Seal the finite trigger/function inventory. These bodies use qualified relations.
DO $$
DECLARE
    routine regprocedure;
BEGIN
    FOREACH routine IN ARRAY ARRAY[
        'public.claim_canonical_authority_child_v1()',
        'public.claim_canonical_multileg_child_v2()',
        'public.claim_canonical_multileg_outpoint_v2()',
        'public.claim_global_auto_outpoint_v1()',
        'public.claim_global_multileg_outpoint_v2()',
        'public.claim_global_strict_two_outpoint_v2()',
        'public.expire_canonical_multileg_candidate_v2(varchar)',
        'public.guard_canonical_admission_candidate_v2()',
        'public.guard_canonical_admission_consent_challenge_v2()',
        'public.guard_canonical_authority_child_v1()',
        'public.guard_canonical_multileg_browser_binding_v2()',
        'public.guard_canonical_multileg_candidate_expiry_v2()',
        'public.guard_canonical_multileg_candidate_immutable_v2()',
        'public.guard_canonical_multileg_consent_challenge_v2()',
        'public.guard_canonical_multileg_effective_edge_v2()',
        'public.guard_effective_multileg_claim_release_v2()',
        'public.guard_global_outpoint_claim_v2()',
        'public.reject_canonical_auto_import_mutation_v1()',
        'public.release_canonical_authority_child_v1()',
        'public.release_global_multileg_outpoint_v2()',
        'public.require_canonical_auto_observation_v1()',
        'public.validate_canonical_auto_effective_v1()',
        'public.validate_canonical_auto_observation_v1()',
        'public.validate_canonical_multileg_browser_binding_v2()',
        'public.validate_canonical_multileg_candidate_v2()',
        'public.validate_canonical_multileg_effective_edge_v2()',
        'public.validate_global_multileg_release_v2()'
    ]::regprocedure[] LOOP
        EXECUTE format('ALTER FUNCTION %s OWNER TO hodlxxi_canonical_owner', routine);
        EXECUTE format('ALTER FUNCTION %s SET search_path TO pg_catalog, pg_temp', routine);
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC, hodlxxi, hodlxxi_canonical_publisher', routine);
    END LOOP;
END;
$$;

REVOKE ALL ON TABLE
    public.canonical_admission_candidate_outpoints_v2,
    public.canonical_admission_candidates_v2,
    public.canonical_admission_consent_challenges_v2,
    public.canonical_admission_edge_legs,
    public.canonical_admission_edges,
    public.canonical_authority_child_claims_v1,
    public.canonical_auto_admission_revocations_v1,
    public.canonical_auto_effective_edges_v1,
    public.canonical_auto_effective_outpoints_v1,
    public.canonical_auto_entitlement_observations_v1,
    public.canonical_auto_import_intents_v1,
    public.canonical_auto_import_pairs_v1,
    public.canonical_auto_import_scripts_v1,
    public.canonical_auto_refresh_progress_v1,
    public.canonical_covenant_funding_outpoints,
    public.canonical_covenant_funding_sets,
    public.canonical_genesis_records,
    public.canonical_global_outpoint_claims_v2,
    public.canonical_multileg_admission_candidates_v2,
    public.canonical_multileg_candidate_expirations_v2,
    public.canonical_multileg_candidate_outpoints_v2,
    public.canonical_multileg_consent_browser_bindings_v2,
    public.canonical_multileg_consent_challenges_v2,
    public.canonical_multileg_effective_edges_v2,
    public.canonical_multileg_live_child_claims_v2,
    public.canonical_multileg_live_outpoint_claims_v2,
    public.canonical_root_registration_bindings,
    public.current_entitlement_evidence,
    public.canonical_effective_authority_edges_v1
    FROM PUBLIC, hodlxxi, hodlxxi_canonical_publisher;

-- Preserve browser lookup and the authenticated import journal.
GRANT SELECT ON public.current_entitlement_evidence, public.canonical_genesis_records,
    public.canonical_admission_edges, public.canonical_admission_edge_legs,
    public.canonical_root_registration_bindings, public.canonical_covenant_funding_sets,
    public.canonical_covenant_funding_outpoints
    TO hodlxxi, hodlxxi_canonical_publisher;
GRANT SELECT ON public.canonical_effective_authority_edges_v1,
    public.canonical_auto_effective_edges_v1, public.canonical_auto_entitlement_observations_v1,
    public.canonical_auto_admission_revocations_v1,
    public.canonical_auto_import_intents_v1, public.canonical_auto_import_scripts_v1,
    public.canonical_auto_import_pairs_v1
    TO hodlxxi, hodlxxi_canonical_publisher;
GRANT INSERT ON public.canonical_auto_import_intents_v1 TO hodlxxi;
GRANT INSERT ON public.canonical_auto_import_scripts_v1, public.canonical_auto_import_pairs_v1
    TO hodlxxi, hodlxxi_canonical_publisher;

-- Row locking needs UPDATE. Keep the existing full-row ACL shape on evidence
-- for Social's catalog attestation. The immutable trigger rejects every update.
GRANT UPDATE ON public.current_entitlement_evidence TO hodlxxi, hodlxxi_canonical_publisher;
GRANT SELECT, UPDATE (last_login) ON public.users TO hodlxxi_canonical_owner, hodlxxi_canonical_publisher;
GRANT SELECT, UPDATE (generation_id) ON public.oauth_browser_generations TO hodlxxi_canonical_owner;
GRANT UPDATE (pair_sha256) ON public.canonical_auto_effective_edges_v1 TO hodlxxi_canonical_publisher;
GRANT UPDATE (intent_id) ON public.canonical_auto_import_intents_v1 TO hodlxxi_canonical_publisher;

GRANT SELECT ON public.canonical_auto_effective_outpoints_v1,
    public.canonical_multileg_admission_candidates_v2, public.canonical_multileg_candidate_outpoints_v2,
    public.canonical_multileg_effective_edges_v2, public.canonical_auto_refresh_progress_v1
    TO hodlxxi_canonical_publisher;
GRANT INSERT ON public.current_entitlement_evidence,
    public.canonical_auto_effective_edges_v1, public.canonical_auto_effective_outpoints_v1,
    public.canonical_auto_entitlement_observations_v1
    TO hodlxxi_canonical_publisher;
GRANT UPDATE (child_depth, pair_sha256) ON public.canonical_auto_refresh_progress_v1
    TO hodlxxi_canonical_publisher;

-- Preserve the production Social authority readers when those roles exist.
DO $$
DECLARE
    reader name;
BEGIN
    FOR reader IN SELECT rolname FROM pg_roles
        WHERE rolname IN ('ubid_v2_prod_challenge', 'ubid_v2_prod_finalizer')
    LOOP
        EXECUTE format(
            'GRANT SELECT ON public.canonical_genesis_records,
             public.canonical_effective_authority_edges_v1, public.canonical_auto_effective_edges_v1,
             public.canonical_auto_entitlement_observations_v1, public.canonical_auto_admission_revocations_v1 TO %I',
            reader
        );
    END LOOP;
END;
$$;

-- The web role still owns legacy identity/OAuth tables. A cascaded drop on
-- one of those parents must not remove a constraint on protected history.
CREATE FUNCTION public.reject_runtime_canonical_cascade_drop_v1()
RETURNS event_trigger LANGUAGE plpgsql
SET search_path TO pg_catalog, pg_temp AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = current_user AND rolsuper)
        AND (pg_has_role(current_user, 'hodlxxi', 'MEMBER')
            OR pg_has_role(current_user, 'hodlxxi_canonical_publisher', 'MEMBER'))
        AND EXISTS (
            SELECT 1 FROM pg_event_trigger_dropped_objects() d
            WHERE d.address_names[1] = 'public'
                AND (left(d.address_names[2], 10) = 'canonical_'
                    OR d.address_names[2] = 'current_entitlement_evidence')
        )
    THEN
        RAISE EXCEPTION 'runtime DDL cannot remove canonical history dependencies' USING ERRCODE = '42501';
    END IF;
END;
$$;
ALTER FUNCTION public.reject_runtime_canonical_cascade_drop_v1() OWNER TO hodlxxi_canonical_owner;
REVOKE ALL ON FUNCTION public.reject_runtime_canonical_cascade_drop_v1()
    FROM PUBLIC, hodlxxi, hodlxxi_canonical_publisher;
CREATE EVENT TRIGGER task2b_protect_canonical_cascade_drop ON sql_drop
    EXECUTE FUNCTION public.reject_runtime_canonical_cascade_drop_v1();

-- Explicit grants above do not remove rights inherited from other roles.
-- Reject such a catalog rather than silently accepting a weaker boundary.
DO $$
DECLARE
    principal name;
    protected regclass;
    routine regprocedure;
    allowed_inserts text[];
BEGIN
    FOREACH principal IN ARRAY ARRAY['hodlxxi', 'hodlxxi_canonical_publisher']::name[] LOOP
        IF has_schema_privilege(principal, 'public', 'CREATE')
            OR has_database_privilege(principal, current_database(), 'CREATE')
        THEN
            RAISE EXCEPTION 'canonical runtime retains DDL privileges: %', principal;
        END IF;
        allowed_inserts := ARRAY['canonical_auto_import_scripts_v1', 'canonical_auto_import_pairs_v1'];
        IF principal = 'hodlxxi' THEN
            allowed_inserts := allowed_inserts || ARRAY['canonical_auto_import_intents_v1'];
        ELSE
            allowed_inserts := allowed_inserts || ARRAY[
                'current_entitlement_evidence', 'canonical_auto_effective_edges_v1',
                'canonical_auto_effective_outpoints_v1', 'canonical_auto_entitlement_observations_v1'
            ];
        END IF;
        FOR protected IN
            SELECT c.oid::regclass FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public'
                AND c.relkind IN ('r', 'v')
                AND c.relowner = 'hodlxxi_canonical_owner'::regrole
        LOOP
            IF has_table_privilege(principal, protected, 'DELETE, TRUNCATE, TRIGGER, REFERENCES')
                OR has_any_column_privilege(principal, protected, 'REFERENCES')
                OR (has_any_column_privilege(principal, protected, 'INSERT') IS DISTINCT FROM
                    (SELECT relname = ANY (allowed_inserts) FROM pg_class WHERE oid = protected))
                OR (has_any_column_privilege(principal, protected, 'UPDATE')
                    AND protected NOT IN (
                        'public.current_entitlement_evidence'::regclass,
                        'public.canonical_auto_effective_edges_v1'::regclass,
                        'public.canonical_auto_import_intents_v1'::regclass,
                        'public.canonical_auto_refresh_progress_v1'::regclass
                    ))
            THEN
                RAISE EXCEPTION 'unexpected inherited privileges on % for %', protected, principal;
            END IF;
        END LOOP;
        FOR routine IN
            SELECT p.oid::regprocedure FROM pg_proc p
            JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = 'public' AND p.proowner = 'hodlxxi_canonical_owner'::regrole
        LOOP
            IF has_function_privilege(principal, routine, 'EXECUTE') THEN
                RAISE EXCEPTION 'unexpected EXECUTE on % for %', routine, principal;
            END IF;
        END LOOP;
    END LOOP;
    IF has_any_column_privilege('hodlxxi', 'public.canonical_auto_refresh_progress_v1', 'UPDATE')
    THEN
        RAISE EXCEPTION 'web runtime can write canonical refresh progress';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_proc p
        CROSS JOIN LATERAL aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
        WHERE p.pronamespace = 'public'::regnamespace
            AND p.proowner = 'hodlxxi_canonical_owner'::regrole AND a.grantee <> p.proowner
    ) THEN
        RAISE EXCEPTION 'canonical routine has an unexpected EXECUTE grant';
    END IF;
END;
$$;
