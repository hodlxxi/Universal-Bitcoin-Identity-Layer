-- SOURCE ONLY. Apply separately as a trusted DDL owner in one transaction
-- after the legacy challenge and receipt/consumption schemas. No backfill.
-- Applying current_user owns the new objects; runtime must be a distinct login
-- with companion SELECT ONLY, no owner membership, schema CREATE or EXECUTE.
-- This source creates no role and does not apply/rewrite prior schemas.
DO $installation$
DECLARE parent_oid oid; parent_namespace oid; parent_owner oid; parent_index oid;
BEGIN
    parent_oid := pg_catalog.to_regclass('public.social_device_admission_challenges');
    IF parent_oid IS NULL OR
       pg_catalog.current_setting('server_version_num')::integer NOT BETWEEN 130000 AND 169999 THEN
        RAISE EXCEPTION 'social device challenge revision unavailable';
    END IF;
    -- Prevent concurrent structural replacement through producer attachment.
    LOCK TABLE public.social_device_admission_challenges IN SHARE ROW EXCLUSIVE MODE;
    SELECT c.relnamespace, c.relowner INTO parent_namespace, parent_owner
      FROM pg_catalog.pg_class c WHERE c.oid=parent_oid;
    SELECT k.conindid INTO parent_index FROM pg_catalog.pg_constraint k
      WHERE k.conrelid=parent_oid AND k.conname='social_device_admission_challenges_pkey';
    IF parent_oid IS NULL OR NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_class c WHERE c.oid = parent_oid
        AND c.relkind = 'r' AND c.relpersistence = 'p' AND c.relnatts = 5
        AND c.relam=2 AND c.reltablespace=0 AND c.relhasindex AND NOT c.relisshared
        AND c.relhastriggers AND c.relispopulated AND c.relreplident='d'
        AND c.relpartbound IS NULL AND c.relchecks = 6 AND c.reloftype = 0 AND c.reloptions IS NULL
        AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity
        AND NOT c.relispartition AND NOT c.relhassubclass AND NOT c.relhasrules
    ) OR NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_proc p
        JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
        JOIN pg_catalog.pg_language l ON l.oid=p.prolang
        WHERE n.nspname='public' AND p.proname='guard_social_device_challenge_v1'
        AND p.pronargs=0 AND p.prorettype='pg_catalog.trigger'::pg_catalog.regtype
        AND p.proowner=parent_owner
        AND l.lanname='plpgsql' AND NOT p.prosecdef
        AND p.prokind='f' AND NOT p.proleakproof AND NOT p.proisstrict
        AND NOT p.proretset AND p.provolatile='v' AND p.proparallel='u'
        AND p.procost=100 AND p.prorows=0 AND p.prosupport=0
        AND p.provariadic=0 AND p.pronargdefaults=0 AND p.proargtypes=''::pg_catalog.oidvector
        AND p.proallargtypes IS NULL AND p.proargmodes IS NULL AND p.proargnames IS NULL
        AND p.proargdefaults IS NULL AND p.protrftypes IS NULL
        AND p.probin IS NULL AND p.proconfig IS NULL
        AND (pg_catalog.to_jsonb(p)->>'prosqlbody') IS NULL
        AND p.prosrc = $legacy$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'issued' THEN
            RAISE EXCEPTION 'social device challenge storage unavailable';
        END IF;
        RETURN NEW;
    ELSIF TG_OP = 'UPDATE' THEN
        IF ROW(NEW.challenge_id, NEW.context_wire, NEW.challenge_wire,
               NEW.routing_request_wire) IS DISTINCT FROM
           ROW(OLD.challenge_id, OLD.context_wire, OLD.challenge_wire,
               OLD.routing_request_wire) OR
           OLD.state <> 'issued' THEN
            RAISE EXCEPTION 'social device challenge storage unavailable';
        END IF;
        IF NEW.state = 'consumed' THEN
            IF NEW.context_wire::jsonb ->> 'challengeKind' <> 'enrollment-v2' OR
               NEW.challenge_wire::jsonb ->> 'schema' <>
                   'hodlxxi.social_messaging_device_enrollment.v2' THEN
                RAISE EXCEPTION 'social device challenge storage unavailable';
            END IF;
        ELSIF NEW.state NOT IN ('expired','invalidated','cancelled') THEN
            RAISE EXCEPTION 'social device challenge storage unavailable';
        END IF;
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'social device challenge storage unavailable';
END $legacy$
        AND EXISTS (SELECT 1 FROM pg_catalog.pg_trigger t WHERE t.tgrelid=parent_oid
          AND t.tgfoid=p.oid AND t.tgname='trg_social_challenge_guard'
          AND t.tgtype=31 AND t.tgenabled='O' AND NOT t.tgisinternal
          AND t.tgqual IS NULL AND t.tgnargs=0 AND t.tgparentid=0
          AND t.tgattr=''::pg_catalog.int2vector AND t.tgargs=''::pg_catalog.bytea
          AND t.tgconstraint=0 AND t.tgconstrrelid=0 AND t.tgconstrindid=0
          AND NOT t.tgdeferrable AND NOT t.tginitdeferred
          AND t.tgoldtable IS NULL AND t.tgnewtable IS NULL)
        AND EXISTS (SELECT 1 FROM pg_catalog.pg_trigger t WHERE t.tgrelid=parent_oid
          AND t.tgfoid=p.oid AND t.tgname='trg_social_challenge_no_truncate'
          AND t.tgtype=34 AND t.tgenabled='O' AND NOT t.tgisinternal
          AND t.tgqual IS NULL AND t.tgnargs=0 AND t.tgparentid=0
          AND t.tgattr=''::pg_catalog.int2vector AND t.tgargs=''::pg_catalog.bytea
          AND t.tgconstraint=0 AND t.tgconstrrelid=0 AND t.tgconstrindid=0
          AND NOT t.tgdeferrable AND NOT t.tginitdeferred
          AND t.tgoldtable IS NULL AND t.tgnewtable IS NULL)
    ) THEN
        RAISE EXCEPTION 'social device challenge revision unavailable';
    END IF;

    IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_trigger t
          WHERE t.tgrelid=parent_oid AND NOT t.tgisinternal
            AND t.tgname<>'trg_social_enrollment_challenge_atomic') <> 2
      OR NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_class tc ON tc.oid=c.reltoastrelid
        JOIN pg_catalog.pg_namespace n ON n.oid=tc.relnamespace WHERE c.oid=parent_oid
          AND n.nspname='pg_toast' AND tc.relname='pg_toast_' || parent_oid::text
          AND tc.relowner=parent_owner AND tc.reltype=0 AND tc.reloftype=0
          AND tc.relam=2 AND tc.reltablespace=0 AND tc.relhasindex AND NOT tc.relisshared
          AND tc.relpersistence='p' AND tc.relkind='t' AND tc.relnatts=3 AND tc.relchecks=0
          AND NOT tc.relhasrules AND NOT tc.relhastriggers AND NOT tc.relhassubclass
          AND NOT tc.relrowsecurity AND NOT tc.relforcerowsecurity AND tc.relispopulated
          AND tc.relreplident='n' AND NOT tc.relispartition AND tc.reloptions IS NULL
          AND tc.relpartbound IS NULL
    ) THEN
        RAISE EXCEPTION 'social device challenge revision unavailable';
    END IF;
    -- Exact canonical source definitions, no normalization or expression adoption.
    -- Exact nested BETWEEN renderings observed on disposable PostgreSQL 16.
    -- SQL installation/execution must still pass the independent rehearsal.
    IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_attribute a
          WHERE a.attrelid=parent_oid AND a.attnum>0) <> 5 OR EXISTS (
        SELECT 1 FROM (VALUES
          (1,'challenge_id',1043,68,true,100,'x'),
          (2,'context_wire',25,-1,true,100,'x'),
          (3,'challenge_wire',25,-1,true,100,'x'),
          (4,'routing_request_wire',25,-1,false,100,'x'),
          (5,'state',1043,15,true,100,'x')
        ) e(num,name,typ,mod,required,coll,storage)
        LEFT JOIN pg_catalog.pg_attribute a ON a.attrelid=parent_oid AND a.attnum=e.num
        WHERE a.attname IS DISTINCT FROM e.name OR a.atttypid IS DISTINCT FROM e.typ::pg_catalog.oid
          OR a.atttypmod IS DISTINCT FROM e.mod OR a.attnotnull IS DISTINCT FROM e.required
          OR a.attcollation IS DISTINCT FROM e.coll::pg_catalog.oid OR a.attstorage::text IS DISTINCT FROM e.storage
          OR a.attisdropped OR a.atthasdef OR a.attgenerated<>'' OR a.attidentity<>''
          OR a.atthasmissing OR a.attmissingval IS NOT NULL OR NOT a.attislocal OR a.attinhcount<>0
          OR a.attoptions IS NOT NULL OR a.attfdwoptions IS NOT NULL
    ) OR (SELECT pg_catalog.count(*) FROM pg_catalog.pg_constraint k WHERE k.conrelid=parent_oid) <> 8
      OR EXISTS (
        SELECT 1 FROM (VALUES
          ('trg_social_enrollment_challenge_atomic','t','TRIGGER DEFERRABLE INITIALLY DEFERRED',NULL::pg_catalog.int2[]),
          ('social_device_admission_challenges_pkey','p','PRIMARY KEY (challenge_id)',ARRAY[1]::pg_catalog.int2[]),
          ('ck_social_challenge_id','c','CHECK (((challenge_id)::text ~ ''^[0-9a-f]{64}$''::text))',ARRAY[1]::pg_catalog.int2[]),
          ('ck_social_challenge_state','c','CHECK (((state)::text = ANY ((ARRAY[''issued''::character varying, ''consumed''::character varying, ''expired''::character varying, ''invalidated''::character varying, ''cancelled''::character varying])::text[])))',ARRAY[5]::pg_catalog.int2[]),
          ('ck_social_challenge_context_wire','c','CHECK ((((octet_length(context_wire) >= 1) AND (octet_length(context_wire) <= 4096)) AND (context_wire !~ ''[^ -~]''::text)))',ARRAY[2]::pg_catalog.int2[]),
          ('ck_social_challenge_wire','c','CHECK ((((octet_length(challenge_wire) >= 1) AND (octet_length(challenge_wire) <= 4096)) AND (challenge_wire !~ ''[^ -~]''::text)))',ARRAY[3]::pg_catalog.int2[]),
          ('ck_social_challenge_routing_wire','c','CHECK (((routing_request_wire IS NULL) OR (((octet_length(routing_request_wire) >= 1) AND (octet_length(routing_request_wire) <= 2048)) AND (routing_request_wire !~ ''[^ -~]''::text))))',ARRAY[4]::pg_catalog.int2[]),
          ('ck_social_challenge_wire_id','c','CHECK ((((((context_wire)::json ->> ''challengeId''::text) = (challenge_id)::text) AND (COALESCE(((challenge_wire)::json ->> ''challengeId''::text), ((challenge_wire)::json ->> ''enrollmentChallengeId''::text)) = (challenge_id)::text)) IS TRUE))',ARRAY[2,1,3]::pg_catalog.int2[])
        ) e(name,kind,definition,keys)
        LEFT JOIN pg_catalog.pg_constraint k ON k.conrelid=parent_oid AND k.conname=e.name
        WHERE k.oid IS NULL OR k.connamespace<>parent_namespace OR k.contype::text<>e.kind
          OR pg_catalog.pg_get_constraintdef(k.oid,false)<>e.definition
          OR k.conkey IS DISTINCT FROM e.keys OR k.contypid<>0
          OR k.conindid<>(CASE WHEN e.kind='p' THEN parent_index ELSE 0 END)
          OR k.conparentid<>0 OR k.confrelid<>0 OR k.confupdtype<>' '
          OR k.confdeltype<>' ' OR k.confmatchtype<>' '
          OR NOT k.convalidated OR k.condeferrable<>(e.kind='t') OR k.condeferred<>(e.kind='t')
          OR NOT k.conislocal OR k.coninhcount<>0 OR k.connoinherit<>(e.kind IN ('p','t'))
          OR k.confkey IS NOT NULL OR k.conpfeqop IS NOT NULL OR k.conppeqop IS NOT NULL
          OR k.conffeqop IS NOT NULL OR k.conexclop IS NOT NULL
          OR (pg_catalog.to_jsonb(k)->>'confdelsetcols') IS NOT NULL
          OR (e.kind='t' AND (
              (SELECT pg_catalog.count(*) FROM pg_catalog.pg_trigger t WHERE t.tgconstraint=k.oid)<>1
              OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger t
                  WHERE t.tgconstraint=k.oid AND t.tgrelid=parent_oid
                    AND t.tgname='trg_social_enrollment_challenge_atomic'
                    AND t.tgtype=17 AND NOT t.tgisinternal
                    AND t.tgdeferrable AND t.tginitdeferred)))
          OR (e.kind IN ('p','t') AND k.conbin IS NOT NULL) OR (e.kind='c' AND k.conbin IS NULL)
    ) OR (SELECT pg_catalog.count(*) FROM pg_catalog.pg_index i WHERE i.indrelid=parent_oid) <> 1
      OR NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid
        WHERE i.indexrelid=parent_index AND i.indrelid=parent_oid
          AND c.relnamespace=parent_namespace AND c.relowner=parent_owner
          AND c.relname='social_device_admission_challenges_pkey' AND c.relkind='i' AND c.relam=403
          AND i.indnatts=1 AND i.indnkeyatts=1 AND i.indisunique AND i.indisprimary
          AND NOT i.indisexclusion AND i.indimmediate AND NOT i.indisclustered
          AND i.indisvalid AND NOT i.indcheckxmin AND i.indisready AND i.indislive
          AND NOT i.indisreplident AND i.indkey='1'::pg_catalog.int2vector
          AND i.indcollation='100'::pg_catalog.oidvector AND i.indclass='3126'::pg_catalog.oidvector
          AND i.indoption='0'::pg_catalog.int2vector AND i.indexprs IS NULL AND i.indpred IS NULL
          AND COALESCE((pg_catalog.to_jsonb(i)->>'indnullsnotdistinct')::boolean,false)=false
    ) THEN
        RAISE EXCEPTION 'social device challenge revision unavailable';
    END IF;
END $installation$;

CREATE TABLE public.social_device_admission_challenge_revisions (
    challenge_id varchar(64) PRIMARY KEY,
    revision integer NOT NULL,
    CONSTRAINT ck_social_challenge_revision_id CHECK (challenge_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_social_challenge_revision_generation CHECK (revision = 1),
    CONSTRAINT fk_social_challenge_revision_parent FOREIGN KEY (challenge_id)
        REFERENCES public.social_device_admission_challenges (challenge_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
);
REVOKE ALL ON TABLE public.social_device_admission_challenge_revisions FROM PUBLIC;

CREATE FUNCTION public.issue_social_device_challenge_revision_v1()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog AS $producer$
BEGIN
    IF TG_OP <> 'INSERT' OR TG_LEVEL <> 'ROW' OR
       TG_TABLE_SCHEMA <> 'public' OR TG_TABLE_NAME <> 'social_device_admission_challenges' OR
       TG_RELID <> 'public.social_device_admission_challenges'::pg_catalog.regclass OR
       NEW.state <> 'issued' THEN
        RAISE EXCEPTION 'social device challenge revision unavailable';
    END IF;
    INSERT INTO public.social_device_admission_challenge_revisions (challenge_id, revision)
        VALUES (NEW.challenge_id, 1);
    RETURN NEW;
END
$producer$;
REVOKE ALL ON FUNCTION public.issue_social_device_challenge_revision_v1() FROM PUBLIC;
CREATE FUNCTION public.deny_social_device_challenge_revision_mutation_v1()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $immutable$
BEGIN
    RAISE EXCEPTION 'social device challenge revision unavailable';
END
$immutable$;
REVOKE ALL ON FUNCTION public.deny_social_device_challenge_revision_mutation_v1() FROM PUBLIC;

CREATE TRIGGER trg_social_challenge_revision_issue
AFTER INSERT ON public.social_device_admission_challenges
FOR EACH ROW EXECUTE FUNCTION public.issue_social_device_challenge_revision_v1();
CREATE TRIGGER trg_social_challenge_revision_immutable
BEFORE UPDATE OR DELETE ON public.social_device_admission_challenge_revisions
FOR EACH ROW EXECUTE FUNCTION public.deny_social_device_challenge_revision_mutation_v1();
CREATE TRIGGER trg_social_challenge_revision_no_truncate
BEFORE TRUNCATE ON public.social_device_admission_challenge_revisions
FOR EACH STATEMENT EXECUTE FUNCTION public.deny_social_device_challenge_revision_mutation_v1();
-- Runtime cannot manually/late/duplicate INSERT: never grant INSERT to it.
-- Producer failure aborts the parent INSERT in the same transaction.
