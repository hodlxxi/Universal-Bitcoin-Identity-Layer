"""Dormant issuance provenance; no acceptance or current-authority grant.

Supported callers exclusively use SQLAlchemy transaction/savepoint APIs. Raw
transaction SQL, driver/cursor control, autocommit changes and concurrent or
reentrant Session use are outside this port. Savepoint continuity means the
original active SQLAlchemy objects, not backend savepoint authentication. The
private pg_current_xact_id marker authenticates top-level continuity only and
can allocate an XID even during read-only observation. It never supplies native
issuance provenance. Failure poisons this reader and requires caller rollback.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import NoReturn

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.services import social_device_challenge_store as legacy

TABLE = "social_device_admission_challenge_revisions"
RUNTIME_ENABLED = False
UNAVAILABLE_MESSAGE = "social device challenge revision unavailable"


class SocialDeviceChallengeRevisionStorageUnavailable(ValueError):
    """The sole non-sensitive failure, without retained diagnostic context."""

    def __init__(self) -> None:
        super().__init__(UNAVAILABLE_MESSAGE)


def _deny() -> NoReturn:
    raise SocialDeviceChallengeRevisionStorageUnavailable() from None


@dataclass(frozen=True, slots=True, repr=False)
class VerifiedIssuedDeviceChallengeRevisionV1:
    """Transaction-scoped immutable history, never a detached authority grant."""

    challenge: legacy.DeviceAdmissionChallengeV1
    challenge_revision: int


CATALOG_SQL = """
SELECT c.oid::bigint AS oid, c.relowner::bigint AS owner,
       c.reltype::bigint AS row_type, c.reltoastrelid::bigint AS toast_oid,
       pg_catalog.to_jsonb(c) AS relation, pg_catalog.to_jsonb(n) AS namespace,
       (SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
           'index', pg_catalog.to_jsonb(i), 'oid', ic.oid,
           'namespace', ic.relnamespace, 'owner', ic.relowner,
           'kind', ic.relkind, 'name', ic.relname, 'am', ic.relam) ORDER BY ic.oid)
          FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class ic ON ic.oid=i.indexrelid
          WHERE i.indrelid=c.oid) AS indexes,
       (SELECT pg_catalog.to_jsonb(tc) FROM pg_catalog.pg_class tc
          WHERE tc.oid=c.reltoastrelid) AS toast,
       (SELECT n.nspname FROM pg_catalog.pg_class tc JOIN pg_catalog.pg_namespace n
          ON n.oid=tc.relnamespace WHERE tc.oid=c.reltoastrelid) AS toast_schema,
       (SELECT pg_catalog.jsonb_agg(pg_catalog.to_jsonb(a) ORDER BY a.attnum)
          FROM pg_catalog.pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0) AS attributes,
       (SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
           'catalog', pg_catalog.to_jsonb(k),
           'definition', pg_catalog.pg_get_constraintdef(k.oid, false)) ORDER BY k.conname)
          FROM pg_catalog.pg_constraint k WHERE k.conrelid=c.oid) AS constraints,
       (SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
           'trigger', pg_catalog.to_jsonb(t), 'function', pg_catalog.to_jsonb(p),
           'language', l.lanname, 'namespace', n.nspname,
           'cost', pg_catalog.encode(pg_catalog.float4send(p.procost), 'hex'),
           'rows', pg_catalog.encode(pg_catalog.float4send(p.prorows), 'hex')) ORDER BY t.tgname)
          FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_proc p ON p.oid=t.tgfoid
          JOIN pg_catalog.pg_language l ON l.oid=p.prolang
          JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
          WHERE t.tgrelid=c.oid AND NOT t.tgisinternal
          AND t.tgname <> 'trg_social_enrollment_challenge_atomic') AS guards,
       (SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
          'oid', t.oid::bigint, 'constraint', t.tgconstraint::bigint,
          'parent', t.tgrelid::bigint, 'name', t.tgname,
          'type', t.tgtype, 'internal', t.tgisinternal,
          'deferrable', t.tgdeferrable, 'deferred', t.tginitdeferred))
        FROM pg_catalog.pg_trigger t WHERE
          ((t.tgrelid=c.oid AND t.tgname='trg_social_enrollment_challenge_atomic') OR
               t.tgconstraint IN (SELECT k.oid FROM pg_catalog.pg_constraint k
                  WHERE k.conrelid=c.oid AND k.contype='t'))) AS atomic_binding,
       pg_catalog.to_regclass('social_device_admission_challenges')::oid =
           pg_catalog.to_regclass('public.social_device_admission_challenges')::oid AS resolves_parent
FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname='public' AND c.relname IN
    ('social_device_admission_challenges', 'social_device_admission_challenge_revisions')
ORDER BY c.relname
"""

SECURITY_SQL = """
WITH actual_owners AS (
    SELECT c.relowner AS owner FROM pg_catalog.pg_class c
      WHERE c.oid IN (CAST(:parent AS pg_catalog.oid), CAST(:companion AS pg_catalog.oid))
         OR c.oid IN (SELECT p.reltoastrelid FROM pg_catalog.pg_class p
                      WHERE p.oid IN (CAST(:parent AS pg_catalog.oid), CAST(:companion AS pg_catalog.oid)))
    UNION SELECT p.proowner FROM pg_catalog.pg_proc p
      WHERE p.oid = ANY(CAST(:guard_oids AS pg_catalog.oid[]))
    UNION SELECT n.nspowner FROM pg_catalog.pg_namespace n WHERE n.nspname='public'
)
SELECT NOT EXISTS (SELECT 1 FROM actual_owners o
          WHERE o.owner=r.oid OR pg_catalog.pg_has_role(r.oid,o.owner,'MEMBER')) AS no_actual_ddl_authority,
       current_user = session_user AS direct_login,
       pg_catalog.to_jsonb(r) AS role,
       pg_catalog.current_setting('session_replication_role') = 'origin' AS origin,
       pg_catalog.has_schema_privilege(r.oid, 'public', 'USAGE') AS schema_usage,
       NOT EXISTS (SELECT 1 FROM pg_catalog.pg_namespace n
          WHERE n.nspname !~ '^pg_temp_' AND
          pg_catalog.has_schema_privilege(r.oid,n.oid,'CREATE')) AS no_schema_create,
       NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles o WHERE o.oid<>r.oid
          AND o.rolname<>'pg_read_all_settings'
          AND pg_catalog.pg_has_role(r.oid,o.oid,'MEMBER')) AS no_owner_membership,
       pg_catalog.has_table_privilege(r.oid,CAST(:companion AS pg_catalog.oid),'SELECT') AS companion_select,
       NOT EXISTS (SELECT 1 FROM pg_catalog.unnest(ARRAY['INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER']) p
          WHERE pg_catalog.has_table_privilege(r.oid,CAST(:companion AS pg_catalog.oid),p)) AS companion_read_only,
       NOT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a WHERE a.attrelid=CAST(:companion AS pg_catalog.oid)
          AND a.attnum>0 AND (pg_catalog.has_column_privilege(r.oid,a.attrelid,a.attnum,'INSERT')
            OR pg_catalog.has_column_privilege(r.oid,a.attrelid,a.attnum,'UPDATE')
            OR pg_catalog.has_column_privilege(r.oid,a.attrelid,a.attnum,'REFERENCES'))) AS no_column_write,
       pg_catalog.has_table_privilege(r.oid,CAST(:parent AS pg_catalog.oid),'SELECT') AND
          pg_catalog.has_table_privilege(r.oid,CAST(:parent AS pg_catalog.oid),'UPDATE') AS parent_lock_privilege,
       NOT EXISTS (SELECT 1 FROM pg_catalog.unnest(ARRAY['DELETE','TRUNCATE','TRIGGER']) p
          WHERE pg_catalog.has_table_privilege(r.oid,CAST(:parent AS pg_catalog.oid),p)) AS parent_no_bypass,
       NOT EXISTS (SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
          WHERE n.nspname='public' AND p.proname IN
          ('issue_social_device_challenge_revision_v1','deny_social_device_challenge_revision_mutation_v1')
          AND (pg_catalog.has_function_privilege(r.oid,p.oid,'EXECUTE') OR p.proowner=r.oid)) AS no_execute,
       r.oid <> CAST(:parent_owner AS pg_catalog.oid) AND r.oid <> CAST(:companion_owner AS pg_catalog.oid) AS distinct_owner
FROM pg_catalog.pg_roles r WHERE r.rolname=current_user
"""


PARENT_CHECKS = (
    ("ck_social_challenge_id", "CHECK (((challenge_id)::text ~ '^[0-9a-f]{64}$'::text))", [1]),
    (
        "ck_social_challenge_state",
        "CHECK (((state)::text = ANY ((ARRAY['issued'::character varying, 'consumed'::character varying, 'expired'::character varying, 'invalidated'::character varying, 'cancelled'::character varying])::text[])))",
        [5],
    ),
    (
        "ck_social_challenge_context_wire",
        "CHECK ((((octet_length(context_wire) >= 1) AND (octet_length(context_wire) <= 4096)) AND (context_wire !~ '[^ -~]'::text)))",
        [2],
    ),
    (
        "ck_social_challenge_wire",
        "CHECK ((((octet_length(challenge_wire) >= 1) AND (octet_length(challenge_wire) <= 4096)) AND (challenge_wire !~ '[^ -~]'::text)))",
        [3],
    ),
    (
        "ck_social_challenge_routing_wire",
        "CHECK (((routing_request_wire IS NULL) OR (((octet_length(routing_request_wire) >= 1) AND (octet_length(routing_request_wire) <= 2048)) AND (routing_request_wire !~ '[^ -~]'::text))))",
        [4],
    ),
    (
        "ck_social_challenge_wire_id",
        "CHECK ((((((context_wire)::json ->> 'challengeId'::text) = (challenge_id)::text) AND (COALESCE(((challenge_wire)::json ->> 'challengeId'::text), ((challenge_wire)::json ->> 'enrollmentChallengeId'::text)) = (challenge_id)::text)) IS TRUE))",
        [2, 1, 3],
    ),
)

COMPANION_CHECKS = (
    ("ck_social_challenge_revision_id", "CHECK (((challenge_id)::text ~ '^[0-9a-f]{64}$'::text))", [1]),
    ("ck_social_challenge_revision_generation", "CHECK ((revision = 1))", [2]),
)


_OID_FIELDS = {
    "relation": "oid relnamespace reltype reloftype relowner relam reltablespace reltoastrelid",
    "namespace": "oid nspowner",
    "attribute": "attrelid atttypid attcollation",
    "constraint": "oid connamespace conrelid contypid conindid conparentid confrelid",
    "index": "indexrelid indrelid",
    "index_relation": "oid namespace owner am",
    "function": "oid proowner pronamespace prolang prorettype provariadic",
    "trigger": "oid tgrelid tgparentid tgfoid tgconstrrelid tgconstrindid tgconstraint",
    "role": "oid",
}


def _native_oid(value):
    if type(value) is not str or re.fullmatch(r"0|[1-9][0-9]{0,9}", value) is None:
        _deny()
    result = int(value)
    if result > 4294967295:
        _deny()
    return result


def _native_catalog_object(record, kind):
    """Decode only catalog OID/vector fields; no recursive string coercion.

    Native OIDs are canonical unsigned decimal JSON strings. int2vector and
    oidvector are JSON arrays, including [] for empty vectors. SQL NULL remains
    None; bytea and pg_node_tree remain exact strings. Unknown fields survive
    for the closed definition validators to reject; no field is discarded here.
    """
    if type(record) is not dict:
        _deny()
    result = dict(record)
    vocabularies = {
        "relation": "oid relname relnamespace reltype reloftype relowner relam relfilenode reltablespace relpages reltuples relallvisible reltoastrelid relhasindex relisshared relpersistence relkind relnatts relchecks relhasrules relhastriggers relhassubclass relrowsecurity relforcerowsecurity relispopulated relreplident relispartition relrewrite relfrozenxid relminmxid relacl reloptions relpartbound",
        "namespace": "oid nspname nspowner nspacl",
        "attribute": "attrelid attname atttypid attstattarget attlen attnum attndims attcacheoff atttypmod attbyval attstorage attcompression attalign attnotnull atthasdef atthasmissing attidentity attgenerated attisdropped attislocal attinhcount attcollation attacl attoptions attfdwoptions attmissingval",
        "role": "oid rolname rolsuper rolinherit rolcreaterole rolcreatedb rolcanlogin rolreplication rolconnlimit rolpassword rolvaliduntil rolbypassrls rolconfig",
    }
    if kind in vocabularies and set(record) - set(vocabularies[kind].split()):
        _deny()
    boolean_fields = {
        "relation": "relhasindex relisshared relhasrules relhastriggers relhassubclass relrowsecurity relforcerowsecurity relispopulated relispartition",
        "attribute": "attbyval attnotnull atthasdef atthasmissing attisdropped attislocal",
        "constraint": "condeferrable condeferred convalidated conislocal connoinherit",
        "index": "indisunique indisprimary indisexclusion indimmediate indisclustered indisvalid indcheckxmin indisready indislive indisreplident indnullsnotdistinct",
        "function": "prosecdef proleakproof proisstrict proretset",
        "trigger": "tgisinternal tgdeferrable tginitdeferred",
        "role": "rolsuper rolinherit rolcreaterole rolcreatedb rolcanlogin rolreplication rolbypassrls",
    }
    integer_fields = {
        "relation": "relnatts relchecks",
        "attribute": "attnum atttypmod attinhcount",
        "constraint": "coninhcount",
        "index": "indnatts indnkeyatts",
        "function": "pronargs pronargdefaults",
        "trigger": "tgtype tgnargs",
    }
    for field in boolean_fields.get(kind, "").split():
        if field in result and type(result[field]) is not bool:
            _deny()
    for field in integer_fields.get(kind, "").split():
        if field in result and (type(result[field]) is not int or not -2147483648 <= result[field] <= 2147483647):
            _deny()
    for field in _OID_FIELDS[kind].split():
        result[field] = _native_oid(result[field])
    if kind == "function":
        # regproc uses symbolic output: only the native absent-support sentinel
        # is allowed. Named/nonzero support is outside this closed guard contract.
        if type(result.get("prosupport")) is not str or result["prosupport"] != "-":
            _deny()
        result["prosupport"] = 0
    positive_ids = {
        "relation": "oid relnamespace relowner",
        "namespace": "oid nspowner",
        "attribute": "attrelid atttypid",
        "constraint": "oid connamespace conrelid",
        "index": "indexrelid indrelid",
        "index_relation": "oid namespace owner am",
        "function": "oid proowner pronamespace prolang prorettype",
        "trigger": "oid tgrelid tgfoid",
        "role": "oid",
    }
    if any(result[field] == 0 for field in positive_ids[kind].split()):
        _deny()
    oid_arrays = {
        "constraint": ("conpfeqop", "conppeqop", "conffeqop", "conexclop"),
        "function": ("proallargtypes", "protrftypes"),
    }
    vectors = {
        "index": {"indkey": False, "indoption": False, "indcollation": True, "indclass": True},
        "function": {"proargtypes": True},
        "trigger": {"tgattr": False},
    }
    for field, is_oid in vectors.get(kind, {}).items():
        value = result[field]
        if type(value) is not list:
            _deny()
        if is_oid:
            value = [_native_oid(v) for v in value]
        elif any(type(v) is not int or not -32768 <= v <= 32767 for v in value):
            _deny()
        result[field] = " ".join(str(v) for v in value)
    for field in oid_arrays.get(kind, ()):
        value = result[field]
        if value is not None:
            if type(value) is not list:
                _deny()
            result[field] = [_native_oid(v) for v in value]
    if kind == "constraint":
        for field in ("conkey", "confkey", "confdelsetcols"):
            value = result.get(field)
            if value is not None and (
                type(value) is not list or any(type(v) is not int or not -32768 <= v <= 32767 for v in value)
            ):
                _deny()
    return result


def _native_catalog_rows(rows):
    result = []
    for original in rows:
        row = dict(original)
        if set(row) != {
            "oid",
            "owner",
            "row_type",
            "toast_oid",
            "relation",
            "namespace",
            "indexes",
            "toast",
            "toast_schema",
            "attributes",
            "constraints",
            "guards",
            "atomic_binding",
            "resolves_parent",
        }:
            _deny()
        for item in row["constraints"]:
            if type(item) is not dict or set(item) != {"catalog", "definition"}:
                _deny()
        for item in row["guards"]:
            if type(item) is not dict or set(item) != {"trigger", "function", "language", "namespace", "cost", "rows"}:
                _deny()
        for field in ("oid", "owner", "row_type", "toast_oid"):
            if type(row[field]) is not int or not 0 <= row[field] <= 4294967295:
                _deny()
        row["relation"] = _native_catalog_object(row["relation"], "relation")
        row["namespace"] = _native_catalog_object(row["namespace"], "namespace")
        if row["toast"] is not None:
            row["toast"] = _native_catalog_object(row["toast"], "relation")
        row["attributes"] = [_native_catalog_object(a, "attribute") for a in row["attributes"]]
        row["constraints"] = [
            dict(k, catalog=_native_catalog_object(k["catalog"], "constraint")) for k in row["constraints"]
        ]
        row["indexes"] = [
            dict(_native_catalog_object(i, "index_relation"), index=_native_catalog_object(i["index"], "index"))
            for i in row["indexes"]
        ]
        row["guards"] = [
            dict(
                g,
                function=_native_catalog_object(g["function"], "function"),
                trigger=_native_catalog_object(g["trigger"], "trigger"),
            )
            for g in row["guards"]
        ]
        result.append(row)
    return result


def _constraints(row, parent):
    """Closed PostgreSQL 13..16 constraint/index contract; native 16 renderings reviewed.

    connoinherit is type-specific: native PK/FK true, default CHECK false.
    conbin is never an accepted substitute for the exact expected deparsing;
    its stable bytes and all constraint/index identities are pinned on repeats.
    """
    pk_name = row["relation"]["relname"] + "_pkey"
    checks = PARENT_CHECKS if row is parent else COMPANION_CHECKS
    expected = {pk_name: ("p", "PRIMARY KEY (challenge_id)", [1])}
    expected.update({n: ("c", d, k) for n, d, k in checks})
    if row is parent:
        expected["trg_social_enrollment_challenge_atomic"] = ("t", "TRIGGER DEFERRABLE INITIALLY DEFERRED", None)
    if row is not parent:
        expected["fk_social_challenge_revision_parent"] = (
            "f",
            "FOREIGN KEY (challenge_id) REFERENCES social_device_admission_challenges(challenge_id) ON UPDATE RESTRICT ON DELETE RESTRICT",
            [1],
        )
    constraints = row["constraints"]
    if len(constraints) != len(expected) or {k["catalog"]["conname"] for k in constraints} != set(expected):
        _deny()
    indexes = row["indexes"]
    if len(indexes) != 1:
        _deny()
    index = indexes[0]
    i = dict(index["index"])
    index_oid = i.pop("indexrelid")
    # Added in 15; native non-NULLS-NOT-DISTINCT primary key must be false.
    if i.pop("indnullsnotdistinct", False) is not False:
        _deny()
    expected_index = {
        "indrelid": row["oid"],
        "indnatts": 1,
        "indnkeyatts": 1,
        "indisunique": True,
        "indisprimary": True,
        "indisexclusion": False,
        "indimmediate": True,
        "indisclustered": False,
        "indisvalid": True,
        "indcheckxmin": False,
        "indisready": True,
        "indislive": True,
        "indisreplident": False,
        "indkey": "1",
        "indcollation": "100",
        "indclass": "3126",
        "indoption": "0",
        "indexprs": None,
        "indpred": None,
    }
    if (
        type(index_oid) is not int
        or index_oid <= 0
        or i != expected_index
        or index
        != {
            "index": index["index"],
            "oid": index_oid,
            "namespace": row["namespace"]["oid"],
            "owner": row["owner"],
            "kind": "i",
            "name": pk_name,
            "am": 403,
        }
    ):
        _deny()
    parent_pk = next(k["catalog"] for k in parent["constraints"] if k["catalog"]["conname"] == legacy.TABLE + "_pkey")
    identities = [(index_oid, index["namespace"], index["owner"], index["name"], i)]
    for item in constraints:
        c = dict(item["catalog"])
        oid = c.pop("oid")
        conbin = c.pop("conbin")
        # Added in 15 for SET NULL/DEFAULT column lists; unsupported here.
        if c.pop("confdelsetcols", None) is not None:
            _deny()
        name = c["conname"]
        kind, definition, keys = expected[name]
        definitions = {definition}
        if kind == "f":
            definitions.add(definition.replace("REFERENCES social_", "REFERENCES public.social_"))
        if item["definition"] not in definitions or type(oid) is not int or oid <= 0:
            _deny()
        if (kind == "c" and (type(conbin) is not str or not conbin)) or (kind != "c" and conbin is not None):
            _deny()
        expected_catalog = {
            "conname": name,
            "connamespace": row["namespace"]["oid"],
            "contype": kind,
            "condeferrable": kind == "t",
            "condeferred": kind == "t",
            "convalidated": True,
            "conrelid": row["oid"],
            "contypid": 0,
            "conindid": index_oid if kind == "p" else parent_pk["conindid"] if kind == "f" else 0,
            "conparentid": 0,
            "confrelid": parent["oid"] if kind == "f" else 0,
            "confupdtype": "r" if kind == "f" else " ",
            "confdeltype": "r" if kind == "f" else " ",
            "confmatchtype": "s" if kind == "f" else " ",
            "conislocal": True,
            "coninhcount": 0,
            "connoinherit": kind in ("p", "f", "t"),
            "conkey": keys,
            "confkey": [1] if kind == "f" else None,
            "conpfeqop": [98] if kind == "f" else None,
            "conppeqop": [98] if kind == "f" else None,
            "conffeqop": [98] if kind == "f" else None,
            "conexclop": None,
        }
        if c != expected_catalog:
            _deny()
        identities.append((oid, c, item["definition"], conbin))
    # Authenticate only the known non-structural constraint's trigger binding.
    # Its predicate/function/effects remain outside issuance attestation.
    binding = row["atomic_binding"]
    if row is parent:
        atomic = next(k["catalog"] for k in constraints if k["catalog"]["contype"] == "t")
        if type(binding) is not list or len(binding) != 1:
            _deny()
        trigger = binding[0]
        trigger_oid = trigger.get("oid")
        if (
            type(trigger_oid) is not int
            or not 0 < trigger_oid <= 4294967295
            or trigger
            != {
                "oid": trigger_oid,
                "constraint": atomic["oid"],
                "parent": row["oid"],
                "name": "trg_social_enrollment_challenge_atomic",
                "type": 17,
                "internal": False,
                "deferrable": True,
                "deferred": True,
            }
            or any(type(trigger[k]) is not int for k in ("constraint", "parent", "type"))
        ):
            _deny()
        identities.append(("legacy_atomic_binding", trigger))
    elif binding is not None:
        _deny()
    return identities


def _function_definition(item, *, name, source, definer):
    """Authenticate all stable pg_proc fields, not just a body or trigger name.

    prosqlbody is absent in PostgreSQL 13; PL/pgSQL requires NULL where present.
    Floating fields use binary float4send, independent of text-output settings.
    OIDs, namespace, owners and ACL authority are checked separately.
    """
    p = dict(item["function"])
    identity = (p.pop("oid"), p.pop("proowner"), p.pop("pronamespace"), p.pop("prolang"))
    p.pop("proacl")
    p.pop("procost")
    p.pop("prorows")
    if p.pop("prosqlbody", None) is not None:
        _deny()
    expected = {
        "proname": name,
        "prokind": "f",
        "prosecdef": definer,
        "proleakproof": False,
        "proisstrict": False,
        "proretset": False,
        "provolatile": "v",
        "proparallel": "u",
        "pronargs": 0,
        "pronargdefaults": 0,
        "prorettype": 2279,
        "proargtypes": "",
        "proallargtypes": None,
        "proargmodes": None,
        "proargnames": None,
        "proargdefaults": None,
        "protrftypes": None,
        "prosrc": source,
        "probin": None,
        "proconfig": None if name == "guard_social_device_challenge_v1" else ["search_path=pg_catalog"],
        "provariadic": 0,
        "prosupport": 0,
    }
    if (
        p != expected
        or item["language"] != "plpgsql"
        or item["namespace"] != "public"
        or item["cost"] != "42c80000"
        or item["rows"] != "00000000"
    ):
        _deny()
    return identity


def _trigger_definition(item, *, name, kind, function_oid, relation_oid):
    t = dict(item["trigger"])
    identity = t.pop("oid")
    expected = {
        "tgrelid": relation_oid,
        "tgparentid": 0,
        "tgname": name,
        "tgfoid": function_oid,
        "tgtype": kind,
        "tgenabled": "O",
        "tgisinternal": False,
        "tgconstrrelid": 0,
        "tgconstrindid": 0,
        "tgconstraint": 0,
        "tgdeferrable": False,
        "tginitdeferred": False,
        "tgnargs": 0,
        "tgattr": "",
        "tgargs": "\\x",
        "tgqual": None,
        "tgoldtable": None,
        "tgnewtable": None,
    }
    if t != expected or type(identity) is not int or identity <= 0:
        _deny()
    return identity


class SqlAlchemyTransactionBoundIssuedChallengeRevisionReader:
    """Read native revision under the parent's state lock, in caller order.

    Caller transaction and savepoints must be managed exclusively through
    SQLAlchemy APIs. Direct transaction SQL and driver control, concurrent or
    reentrant use are unsupported. pg_current_xact_id proves top-level identity
    only; it deliberately cannot authenticate raw savepoint operations.
    The parent lock precedes the SELECT-only immutable companion. This reader
    takes no Full/OAuth/binding/association locks. Later orchestration must
    resample time after waits and before effects; observed_at cannot prove that.
    """

    def __init__(self, session: Session) -> None:
        self._session = session
        self._failed = False
        self._xid = None
        self._catalog_identity = None
        try:
            self._root = session.get_transaction()
            self._nested = session.get_nested_transaction()
            if (
                self._root is None
                or not self._root.is_active
                or not session.is_active
                or session.in_transaction() is not True
                or session.new
                or session.dirty
                or session.deleted
                or session.get_bind().dialect.name != "postgresql"
            ):
                _deny()
            self._connection = session.connection()
            self._connection_root = self._connection.get_transaction()
            self._connection_nested = self._connection.get_nested_transaction()
            self._physical = self._connection.connection.dbapi_connection
            self._objects()
            self._marker()
            if self._execute(text("SHOW transaction_isolation")).scalar_one() != "read committed":
                _deny()
            version = self._execute(text("SELECT pg_catalog.current_setting('server_version_num')")).scalar_one()
            if type(version) is not str or not version.isdecimal() or not 130000 <= int(version) < 170000:
                _deny()
            self._catalog()
            self._store = legacy.SqlAlchemyDeviceChallengeStore(session)
            self._store_identity()
            self._marker()
            return
        except Exception:
            self._failed = True
        _deny()

    def _objects(self):
        s, c = self._session, self._connection
        if (
            self._failed
            or not s.is_active
            or s.in_transaction() is not True
            or self._root is None
            or not self._root.is_active
            or s.get_transaction() is not self._root
            or s.get_nested_transaction() is not self._nested
            or (self._nested is not None and not self._nested.is_active)
            or s.new
            or s.dirty
            or s.deleted
            or s.get_bind().dialect.name != "postgresql"
            or s.connection() is not c
            or c.closed
            or c.invalidated
            or not c.in_transaction()
            or self._connection_root is None
            or not self._connection_root.is_active
            or c.get_transaction() is not self._connection_root
            or c.get_nested_transaction() is not self._connection_nested
            or (self._connection_nested is not None and not self._connection_nested.is_active)
            or c.connection.dbapi_connection is not self._physical
            or getattr(self._physical, "autocommit", None) is not False
        ):
            _deny()

    def _marker(self):
        self._objects()
        xid = self._connection.execute(text("SELECT pg_catalog.pg_current_xact_id()::text")).scalar_one()
        self._objects()
        if type(xid) is not str or re.fullmatch(r"[1-9][0-9]{0,19}", xid) is None or int(xid) > 2**64 - 1:
            _deny()
        if self._xid is None:
            self._xid = xid
        elif xid != self._xid:
            _deny()

    def _execute(self, statement, parameters=None):
        self._marker()
        result = self._connection.execute(statement, parameters or {})
        self._marker()
        return result

    def _store_identity(self):
        if (
            type(self._store) is not legacy.SqlAlchemyDeviceChallengeStore
            or self._store._session is not self._session
            or self._store._connection is not self._connection
            or self._store._transaction is not self._root
            or self._store._nested_transaction is not self._nested
            or self._store._database_transaction is not self._connection_root
            or self._store._database_nested_transaction is not self._connection_nested
            or self._store._failed
        ):
            _deny()

    def _catalog(self):
        rows = _native_catalog_rows(self._execute(text(CATALOG_SQL)).mappings().all())
        if len(rows) != 2:
            _deny()
        by_name = {r["relation"]["relname"]: r for r in rows}
        parent, companion = by_name[legacy.TABLE], by_name[TABLE]
        identities = []
        guard_owners = set()
        guard_oids = set()
        for row, column_types in (
            (
                parent,
                [
                    ("challenge_id", 1043, 68, True),
                    ("context_wire", 25, -1, True),
                    ("challenge_wire", 25, -1, True),
                    ("routing_request_wire", 25, -1, False),
                    ("state", 1043, 15, True),
                ],
            ),
            (companion, [("challenge_id", 1043, 68, True), ("revision", 23, -1, True)]),
        ):
            r = row["relation"]
            namespace = row["namespace"]
            if (
                namespace["nspname"] != "public"
                or r["oid"] != row["oid"]
                or r["relowner"] != row["owner"]
                or r["reltype"] != row["row_type"]
                or r["reltoastrelid"] != row["toast_oid"]
                or r["relnamespace"] != namespace["oid"]
            ):
                _deny()
            identities.append((namespace["oid"], namespace["nspname"], namespace["nspowner"]))
            if (
                row["resolves_parent"] is not True
                or r["relkind"] != "r"
                or r["relpersistence"] != "p"
                or r["relrowsecurity"]
                or r["relforcerowsecurity"]
                or r["relhasrules"]
                or r["relhassubclass"]
                or r["relispartition"]
                or r["reloftype"] != 0
                or r["reloptions"] is not None
                or r["relpartbound"] is not None
                or r["relnatts"] != len(column_types)
            ):
                _deny()
            stable_relation = {
                "relam": 2,
                "reltablespace": 0,
                "relhasindex": True,
                "relisshared": False,
                "relhastriggers": True,
                "relispopulated": True,
                "relreplident": "d",
                "relchecks": 6 if row is parent else 2,
            }
            if any(r[field] != value for field, value in stable_relation.items()):
                _deny()
            toast = row["toast"]
            if row is parent:
                expected_toast = {
                    "relname": f"pg_toast_{row['oid']}",
                    "relowner": row["owner"],
                    "reltype": 0,
                    "reloftype": 0,
                    "relam": 2,
                    "reltablespace": 0,
                    "relhasindex": True,
                    "relisshared": False,
                    "relpersistence": "p",
                    "relkind": "t",
                    "relnatts": 3,
                    "relchecks": 0,
                    "relhasrules": False,
                    "relhastriggers": False,
                    "relhassubclass": False,
                    "relrowsecurity": False,
                    "relforcerowsecurity": False,
                    "relispopulated": True,
                    "relreplident": "n",
                    "relispartition": False,
                    "reloptions": None,
                    "relpartbound": None,
                }
                if (
                    toast is None
                    or row["toast_schema"] != "pg_toast"
                    or any(toast[field] != value for field, value in expected_toast.items())
                ):
                    _deny()
                identities.append((toast["oid"], toast["relnamespace"], toast["relowner"]))
            elif toast is not None or row["toast_oid"] != 0:
                _deny()
            attrs = row["attributes"]
            if len(attrs) != len(column_types):
                _deny()
            for position, (a, (name, typ, mod, required)) in enumerate(zip(attrs, column_types), 1):
                if (
                    a["attrelid"] != row["oid"]
                    or a["attnum"] != position
                    or a["attislocal"] is not True
                    or a["attinhcount"] != 0
                    or a["attname"] != name
                    or a["atttypid"] != typ
                    or a["atttypmod"] != mod
                    or a["attnotnull"] is not required
                    or a["attisdropped"]
                    or a["atthasdef"]
                    or a["attgenerated"] != ""
                    or a["attidentity"] != ""
                    or a["atthasmissing"]
                    or a["attmissingval"] is not None
                    or a["attcollation"] != (0 if typ == 23 else 100)
                ):
                    _deny()
            identities.append((row["oid"], row["owner"], row["row_type"], row["toast_oid"]))
            identities.append(
                tuple(
                    (
                        a["attnum"],
                        a["attname"],
                        a["atttypid"],
                        a["atttypmod"],
                        a["attnotnull"],
                        a["attcollation"],
                        a["attstorage"],
                        a["attoptions"],
                        a["attfdwoptions"],
                    )
                    for a in attrs
                )
            )
        for row in rows:
            identities.extend(_constraints(row, parent))
        expected_guards = {
            "trg_social_challenge_guard": (parent, 31, "guard_social_device_challenge_v1", LEGACY_SOURCE, False),
            "trg_social_challenge_no_truncate": (parent, 34, "guard_social_device_challenge_v1", LEGACY_SOURCE, False),
            "trg_social_challenge_revision_issue": (
                parent,
                5,
                "issue_social_device_challenge_revision_v1",
                PRODUCER_SOURCE,
                True,
            ),
            "trg_social_challenge_revision_immutable": (
                companion,
                27,
                "deny_social_device_challenge_revision_mutation_v1",
                IMMUTABLE_SOURCE,
                False,
            ),
            "trg_social_challenge_revision_no_truncate": (
                companion,
                34,
                "deny_social_device_challenge_revision_mutation_v1",
                IMMUTABLE_SOURCE,
                False,
            ),
        }
        guards = [g for r in rows for g in r["guards"]]
        if len(guards) != len(expected_guards) or {g["trigger"]["tgname"] for g in guards} != set(expected_guards):
            _deny()
        for g in guards:
            name = g["trigger"]["tgname"]
            row, kind, fn, source, definer = expected_guards[name]
            function_identity = _function_definition(g, name=fn, source=source, definer=definer)
            guard_owners.add(function_identity[1])
            guard_oids.add(function_identity[0])
            if fn == "guard_social_device_challenge_v1" and function_identity[1] != parent["owner"]:
                _deny()
            if fn != "guard_social_device_challenge_v1" and function_identity[1] != companion["owner"]:
                _deny()
            trigger_oid = _trigger_definition(
                g, name=name, kind=kind, function_oid=function_identity[0], relation_oid=row["oid"]
            )
            identities.append((name, trigger_oid, function_identity))
        security = (
            self._execute(
                text(SECURITY_SQL),
                {
                    "parent": parent["oid"],
                    "companion": companion["oid"],
                    "parent_owner": parent["owner"],
                    "companion_owner": companion["owner"],
                    "guard_oids": sorted(guard_oids),
                },
            )
            .mappings()
            .one()
        )
        role = _native_catalog_object(security["role"], "role")
        actual_owners = guard_owners | {row["owner"] for row in rows} | {row["namespace"]["nspowner"] for row in rows}
        actual_owners.update(row["toast"]["relowner"] for row in rows if row["toast"] is not None)
        if role["oid"] in actual_owners or security.get("no_actual_ddl_authority") is not True:
            _deny()
        if (
            role["rolsuper"]
            or role["rolcreaterole"]
            or role["rolcreatedb"]
            or role["rolreplication"]
            or role["rolbypassrls"]
            or not role["rolcanlogin"]
            or not role["rolinherit"]
            or any(value is not True for key, value in security.items() if key != "role")
        ):
            _deny()
        identities.append((role["oid"], role["rolname"]))
        if self._catalog_identity is None:
            self._catalog_identity = identities
        elif identities != self._catalog_identity:
            _deny()

    def read_issued_with_revision_in_transaction(self, challenge_id, *, observed_at):
        """Lock/reparse parent then observe its immutable native companion.

        The same-transaction AFTER INSERT producer supplies generation 1; a
        missing companion never has a synthetic default. Parent state owns the
        lock; SELECT-only companion evidence cannot change during the observed
        generation. Results authorize neither consumption nor any effect.
        """
        try:
            key = legacy.contract._hex64(challenge_id)
            self._catalog()
            self._store_identity()
            self._marker()
            challenge = self._store.read_for_update(key)
            self._marker()
            self._store_identity()
            self._catalog()
            row = (
                self._execute(
                    text(
                        "SELECT challenge_id, revision FROM public.social_device_admission_challenge_revisions "
                        "WHERE challenge_id = :challenge_id"
                    ),
                    {"challenge_id": key},
                )
                .mappings()
                .one()
            )
            self._catalog()
            self._marker()
            if (
                set(row) != {"challenge_id", "revision"}
                or type(row["challenge_id"]) is not str
                or row["challenge_id"] != key
                or type(row["revision"]) is not int
                or row["revision"] != 1
                or challenge.context.challenge_id != key
                or challenge.context.challenge_kind != "enrollment-v2"
                or challenge.state != "issued"
                or challenge.inspect_deadline(now=observed_at).disposition != "current"
            ):
                _deny()
            return VerifiedIssuedDeviceChallengeRevisionV1(challenge, row["revision"])
        except Exception:
            self._failed = True
        _deny()


LEGACY_SOURCE = "\nBEGIN\n    IF TG_OP = 'INSERT' THEN\n        IF NEW.state <> 'issued' THEN\n            RAISE EXCEPTION 'social device challenge storage unavailable';\n        END IF;\n        RETURN NEW;\n    ELSIF TG_OP = 'UPDATE' THEN\n        IF ROW(NEW.challenge_id, NEW.context_wire, NEW.challenge_wire,\n               NEW.routing_request_wire) IS DISTINCT FROM\n           ROW(OLD.challenge_id, OLD.context_wire, OLD.challenge_wire,\n               OLD.routing_request_wire) OR\n           OLD.state <> 'issued' THEN\n            RAISE EXCEPTION 'social device challenge storage unavailable';\n        END IF;\n        IF NEW.state = 'consumed' THEN\n            IF NEW.context_wire::jsonb ->> 'challengeKind' <> 'enrollment-v2' OR\n               NEW.challenge_wire::jsonb ->> 'schema' <>\n                   'hodlxxi.social_messaging_device_enrollment.v2' THEN\n                RAISE EXCEPTION 'social device challenge storage unavailable';\n            END IF;\n        ELSIF NEW.state NOT IN ('expired','invalidated','cancelled') THEN\n            RAISE EXCEPTION 'social device challenge storage unavailable';\n        END IF;\n        RETURN NEW;\n    END IF;\n    RAISE EXCEPTION 'social device challenge storage unavailable';\nEND "
PRODUCER_SOURCE = "\nBEGIN\n    IF TG_OP <> 'INSERT' OR TG_LEVEL <> 'ROW' OR\n       TG_TABLE_SCHEMA <> 'public' OR TG_TABLE_NAME <> 'social_device_admission_challenges' OR\n       TG_RELID <> 'public.social_device_admission_challenges'::pg_catalog.regclass OR\n       NEW.state <> 'issued' THEN\n        RAISE EXCEPTION 'social device challenge revision unavailable';\n    END IF;\n    INSERT INTO public.social_device_admission_challenge_revisions (challenge_id, revision)\n        VALUES (NEW.challenge_id, 1);\n    RETURN NEW;\nEND\n"
IMMUTABLE_SOURCE = "\nBEGIN\n    RAISE EXCEPTION 'social device challenge revision unavailable';\nEND\n"
