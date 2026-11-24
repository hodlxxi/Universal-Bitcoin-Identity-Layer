"""Pinned automatic-admission triggers for the shared V2 evidence table."""

from hashlib import sha256

EVIDENCE_TABLE = "current_entitlement_evidence"
REQUIRED_TRIGGER = "trg_caeov1_required"
_IMMUTABLE_TRIGGER = "trg_caeov1_evidence_immutable"

# Body digests are from the approved import journal and effective migration SQL.
_PROFILES = (
    (
        _IMMUTABLE_TRIGGER,
        "reject_canonical_auto_import_mutation_v1",
        27,
        False,
        "7fa856e8ca5c26f79faeb5ac1961d00b8bdbdf281e758905557b48ae1cfae354",
        f"CREATE TRIGGER {_IMMUTABLE_TRIGGER} BEFORE DELETE OR UPDATE ON " f"public.{EVIDENCE_TABLE} FOR EACH ROW ",
    ),
    (
        REQUIRED_TRIGGER,
        "require_canonical_auto_observation_v1",
        5,
        True,
        "1300fde92f2e8e107cd034045e4795681554dddc101f794d214da1f3826ef4ae",
        f"CREATE CONSTRAINT TRIGGER {REQUIRED_TRIGGER} AFTER INSERT ON "
        f"public.{EVIDENCE_TABLE} DEFERRABLE INITIALLY DEFERRED FOR EACH ROW ",
    ),
)

_TRIGGER_SQL = """
SELECT t.tgname AS trigger_name,t.oid::bigint AS trigger_oid,t.tgfoid::bigint AS function_oid,
       t.tgconstraint::bigint AS constraint_oid,t.tgtype AS trigger_kind,
       t.tgdeferrable AS deferred,t.tginitdeferred AS initially_deferred,t.tgqual::text AS predicate,
       pg_catalog.pg_get_triggerdef(t.oid,false) AS trigger_definition,
       p.proname AS function_name,p.prosrc AS body,p.proconfig AS config,
       c.relowner::bigint AS owner,
       (c.relname='current_entitlement_evidence' AND n.nspname='public' AND p.pronamespace=c.relnamespace
        AND t.tgenabled='O' AND t.tgparentid=0 AND t.tgconstrrelid=0 AND t.tgconstrindid=0
        AND t.tgnargs=0 AND t.tgattr::text='' AND pg_catalog.octet_length(t.tgargs)=0
        AND t.tgoldtable IS NULL AND t.tgnewtable IS NULL
        AND p.proowner=c.relowner AND p.prosecdef AND p.provolatile='v'
        AND p.prokind='f' AND l.lanname='plpgsql' AND p.pronargs=0 AND p.pronargdefaults=0
        AND p.prorettype='pg_catalog.trigger'::regtype AND NOT p.proretset
        AND NOT p.proleakproof AND NOT p.proisstrict AND p.proparallel='u'
        AND NOT pg_catalog.pg_has_role(current_user,p.proowner,'MEMBER')
        AND NOT pg_catalog.has_function_privilege(current_user,p.oid,'EXECUTE')
        AND NOT EXISTS (
            SELECT 1 FROM pg_catalog.aclexplode(
                COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))
            ) a WHERE a.grantee<>p.proowner
        )) AS protected,
       CASE WHEN t.tgconstraint=0 THEN k.oid IS NULL ELSE
          (k.conname=t.tgname AND k.connamespace=c.relnamespace AND k.contype='t'
           AND k.conrelid=c.oid AND k.convalidated AND k.condeferrable AND k.condeferred
           AND k.conislocal AND k.conparentid=0 AND k.conindid=0 AND k.confrelid=0
           AND pg_catalog.pg_get_constraintdef(k.oid,false)='TRIGGER DEFERRABLE INITIALLY DEFERRED')
       END AS constraint_bound
FROM pg_catalog.pg_trigger t
JOIN pg_catalog.pg_class c ON c.oid=t.tgrelid
JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
JOIN pg_catalog.pg_proc p ON p.oid=t.tgfoid
JOIN pg_catalog.pg_language l ON l.oid=p.prolang
LEFT JOIN pg_catalog.pg_constraint k ON k.oid=t.tgconstraint
WHERE t.tgrelid=:oid AND NOT t.tgisinternal
ORDER BY t.tgname
"""


def attest_automatic_evidence_triggers(sql, table_oid, owner_oid):
    """Require exactly the two installed triggers and their approved functions."""
    rows = sql(_TRIGGER_SQL, {"oid": table_oid}).mappings().all()
    if len(rows) != len(_PROFILES):
        raise ValueError("invalid automatic-admission evidence trigger profile")
    identities = []
    for row, profile in zip(rows, _PROFILES):
        trigger, function, kind, deferred, body_digest, declaration = profile
        definition = row["trigger_definition"]
        constraint = row["constraint_oid"]
        if (
            row["trigger_name"] != trigger
            or row["function_name"] != function
            or row["trigger_kind"] != kind
            or row["owner"] != owner_oid
            or row["protected"] is not True
            or row["constraint_bound"] is not True
            or row["deferred"] is not deferred
            or row["initially_deferred"] is not deferred
            or type(constraint) is not int
            or (constraint > 0 if deferred else constraint == 0) is not True
            or row["predicate"] is not None
            or definition
            not in (
                f"{declaration}EXECUTE FUNCTION {function}()",
                f"{declaration}EXECUTE FUNCTION public.{function}()",
            )
            or type(row["config"]) not in (list, tuple)
            or tuple(row["config"]) != ("search_path=pg_catalog, pg_temp",)
            or type(row["body"]) is not str
            or sha256(row["body"].encode("utf-8")).hexdigest() != body_digest
            or any(type(row[key]) is not int or row[key] <= 0 for key in ("trigger_oid", "function_oid"))
        ):
            raise ValueError("invalid automatic-admission evidence trigger definition")
        identities.append(
            (row["trigger_oid"], row["function_oid"], constraint, definition, row["predicate"], body_digest)
        )
    return tuple(identities), identities[1][2]
