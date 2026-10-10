"""Offline guarded doubles plus real legacy parsing and PostgreSQL compilation.

Catalog doubles test rejection paths; they do not prove PostgreSQL definitions,
function execution, role grants, transaction isolation or lock serialization.
"""

from copy import deepcopy
from dataclasses import FrozenInstanceError
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy.dialects import postgresql
from sqlalchemy.sql.selectable import Select

from app.services import social_device_challenge_revision_storage as storage
from app.services import social_device_challenge_store as legacy
from tests.unit.test_social_device_challenge_store import Result, Session, persisted

ROOT = Path(__file__).resolve().parents[2]
DENIED = storage.SocialDeviceChallengeRevisionStorageUnavailable
ERROR = "^social device challenge revision unavailable$"


def function(name, source, oid, owner, definer=False):
    return {
        "function": {
            "oid": oid,
            "proowner": owner,
            "pronamespace": 2200,
            "prolang": 13563,
            "proacl": None,
            "procost": 100,
            "prorows": 0,
            "prosqlbody": None,
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
        },
        "language": "plpgsql",
        "namespace": "public",
        "cost": "42c80000",
        "rows": "00000000",
    }


def guard(name, kind, relation, fn):
    item = deepcopy(fn)
    item["trigger"] = {
        "oid": 1000 + kind,
        "tgrelid": relation,
        "tgparentid": 0,
        "tgname": name,
        "tgfoid": fn["function"]["oid"],
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
    return item


def catalog_fixture():
    rows = []
    for oid, name, owner, columns in (
        (
            10,
            legacy.TABLE,
            20,
            [
                ("challenge_id", 1043, 68, True),
                ("context_wire", 25, -1, True),
                ("challenge_wire", 25, -1, True),
                ("routing_request_wire", 25, -1, False),
                ("state", 1043, 15, True),
            ],
        ),
        (11, storage.TABLE, 21, [("challenge_id", 1043, 68, True), ("revision", 23, -1, True)]),
    ):
        row = {
            "oid": oid,
            "owner": owner,
            "row_type": oid + 100,
            "toast_oid": 200 if oid == 10 else 0,
            "resolves_parent": True,
            "constraints": [],
            "guards": [],
            "toast": None,
            "toast_schema": "pg_toast" if oid == 10 else None,
        }
        row["relation"] = {
            "relname": name,
            "relkind": "r",
            "relpersistence": "p",
            "relrowsecurity": False,
            "relforcerowsecurity": False,
            "relhasrules": False,
            "relhassubclass": False,
            "relispartition": False,
            "reloftype": 0,
            "reloptions": None,
            "relpartbound": None,
            "relnatts": len(columns),
            "relam": 2,
            "reltablespace": 0,
            "relhasindex": True,
            "relisshared": False,
            "relhastriggers": True,
            "relispopulated": True,
            "relreplident": "d",
            "relchecks": 6 if oid == 10 else 2,
        }
        row["attributes"] = [
            {
                "attnum": i,
                "attname": n,
                "atttypid": t,
                "atttypmod": m,
                "attnotnull": null,
                "attisdropped": False,
                "atthasdef": False,
                "attgenerated": "",
                "attidentity": "",
                "atthasmissing": False,
                "attmissingval": None,
                "attcollation": 0 if t == 23 else 100,
                "attstorage": "p" if t == 23 else "x",
                "attoptions": None,
                "attfdwoptions": None,
            }
            for i, (n, t, m, null) in enumerate(columns, 1)
        ]
        if oid == 10:
            row["toast"] = {
                **row["relation"],
                "oid": 200,
                "relnamespace": 99,
                "relname": "pg_toast_10",
                "reltoastrelid": 0,
                "relowner": 20,
                "reltype": 0,
                "relkind": "t",
                "relnatts": 3,
                "relchecks": 0,
                "relhastriggers": False,
                "relreplident": "n",
            }
        rows.append(row)
    parent, companion = rows
    old = function("guard_social_device_challenge_v1", storage.LEGACY_SOURCE, 30, 20)
    producer = function("issue_social_device_challenge_revision_v1", storage.PRODUCER_SOURCE, 31, 21, True)
    immutable = function("deny_social_device_challenge_revision_mutation_v1", storage.IMMUTABLE_SOURCE, 32, 21)
    parent["guards"] = [
        guard("trg_social_challenge_guard", 31, 10, old),
        guard("trg_social_challenge_no_truncate", 34, 10, old),
        guard("trg_social_challenge_revision_issue", 5, 10, producer),
    ]
    companion["guards"] = [
        guard("trg_social_challenge_revision_immutable", 27, 11, immutable),
        guard("trg_social_challenge_revision_no_truncate", 34, 11, immutable),
    ]
    for i, (name, kind, definition, keys) in enumerate(
        (
            ("social_device_admission_challenge_revisions_pkey", "p", "PRIMARY KEY (challenge_id)", [1]),
            ("ck_social_challenge_revision_id", "c", "CHECK (((challenge_id)::text ~ '^[0-9a-f]{64}$'::text))", [1]),
            ("ck_social_challenge_revision_generation", "c", "CHECK ((revision = 1))", [2]),
            (
                "fk_social_challenge_revision_parent",
                "f",
                "FOREIGN KEY (challenge_id) REFERENCES public.social_device_admission_challenges(challenge_id) ON UPDATE RESTRICT ON DELETE RESTRICT",
                [1],
            ),
        )
    ):
        companion["constraints"].append(
            {
                "definition": definition,
                "catalog": {
                    "oid": 40 + i,
                    "conname": name,
                    "contype": kind,
                    "convalidated": True,
                    "condeferrable": False,
                    "condeferred": False,
                    "connoinherit": False,
                    "conkey": keys,
                    "confrelid": 10 if kind == "f" else 0,
                    "confkey": [1] if kind == "f" else None,
                    "confupdtype": "r",
                    "confdeltype": "r",
                    "confmatchtype": "s",
                    "conbin": definition if kind == "c" else None,
                },
            }
        )
    return rows


# Closed expected rendering of the unchanged canonical parent migration.
# Literal renderings independently transcribed from the disposable PostgreSQL 16 capture.
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


def constraint(oid, relation, name, kind, definition, keys, *, native=True):
    return {
        "definition": definition,
        "catalog": {
            "oid": oid,
            "conname": name,
            "connamespace": 2200,
            "contype": kind,
            "condeferrable": False,
            "condeferred": False,
            "convalidated": True,
            "conrelid": relation,
            "contypid": 0,
            "conindid": (310 if relation == 10 or kind == "f" else 311) if kind in ("p", "f") else 0,
            "conparentid": 0,
            "confrelid": 10 if kind == "f" else 0,
            "confupdtype": "r" if kind == "f" else " ",
            "confdeltype": "r" if kind == "f" else " ",
            "confmatchtype": "s" if kind == "f" else " ",
            "conislocal": True,
            "coninhcount": 0,
            "connoinherit": native and kind in ("p", "f"),
            "conkey": keys,
            "confkey": [1] if kind == "f" else None,
            "conpfeqop": [98] if kind == "f" else None,
            "conppeqop": [98] if kind == "f" else None,
            "conffeqop": [98] if kind == "f" else None,
            "conexclop": None,
            "conbin": definition if kind == "c" else None,
        },
    }


def pk_index(relation):
    return {
        "index": {
            "indexrelid": 300 + relation,
            "indrelid": relation,
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
        },
        "oid": 300 + relation,
        "namespace": 2200,
        "owner": 20 if relation == 10 else 21,
        "kind": "i",
        "name": (legacy.TABLE if relation == 10 else storage.TABLE) + "_pkey",
        "am": 403,
    }


def reviewed_catalog(*, native=True):
    rows = catalog_fixture()
    for row in rows:
        row["namespace"] = {"oid": 2200, "nspname": "public", "nspowner": 22}
        row["relation"].update(
            oid=row["oid"],
            relnamespace=2200,
            relowner=row["owner"],
            reltype=row["row_type"],
            reltoastrelid=row["toast_oid"],
        )
        for attr in row["attributes"]:
            attr.update(attrelid=row["oid"], attislocal=True, attinhcount=0)
        row["indexes"] = [pk_index(row["oid"])]
    rows[0]["constraints"] = [
        constraint(60, 10, legacy.TABLE + "_pkey", "p", "PRIMARY KEY (challenge_id)", [1], native=native),
        *[constraint(61 + i, 10, n, "c", d, k, native=native) for i, (n, d, k) in enumerate(PARENT_CHECKS)],
    ]
    rows[1]["constraints"] = [
        constraint(
            40 + i,
            11,
            item["catalog"]["conname"],
            item["catalog"]["contype"],
            item["definition"],
            item["catalog"]["conkey"],
            native=native,
        )
        for i, item in enumerate(rows[1]["constraints"])
    ]
    atomic = constraint(
        80, 10, "trg_social_enrollment_challenge_atomic", "t", "TRIGGER DEFERRABLE INITIALLY DEFERRED", None
    )
    atomic["catalog"].update(condeferrable=True, condeferred=True, connoinherit=True)
    rows[0]["constraints"].append(atomic)
    rows[0]["atomic_binding"] = [
        {
            "oid": 90,
            "constraint": 80,
            "parent": 10,
            "name": "trg_social_enrollment_challenge_atomic",
            "type": 17,
            "internal": False,
            "deferrable": True,
            "deferred": True,
        }
    ]
    rows[1]["atomic_binding"] = None
    return rows


# Native PostgreSQL JSON types, independently enumerated from the captured catalogs.
NATIVE_OIDS = {
    "relation": "oid relnamespace reltype reloftype relowner relam reltablespace reltoastrelid",
    "namespace": "oid nspowner",
    "attribute": "attrelid atttypid attcollation",
    "constraint": "oid connamespace conrelid contypid conindid conparentid confrelid",
    "index": "indexrelid indrelid",
    "function": "oid proowner pronamespace prolang prorettype provariadic",
    "trigger": "oid tgrelid tgparentid tgfoid tgconstrrelid tgconstrindid tgconstraint",
    "role": "oid",
}


def native_json(record, kind):
    result = deepcopy(record)
    if kind == "function" and type(result.get("prosupport")) is int and result["prosupport"] == 0:
        result["prosupport"] = "-"
    for field in NATIVE_OIDS[kind].split():
        if field in result and type(result[field]) is int:
            result[field] = str(result[field])
    vectors = {
        "index": {"indkey": False, "indoption": False, "indcollation": True, "indclass": True},
        "function": {"proargtypes": True},
        "trigger": {"tgattr": False},
    }
    for field, oid in vectors.get(kind, {}).items():
        if type(result[field]) is str:
            result[field] = [v if oid else int(v) for v in result[field].split()]
    if kind == "constraint":
        for field in ("conpfeqop", "conppeqop", "conffeqop", "conexclop"):
            if result[field] is not None:
                result[field] = [str(v) if type(v) is int else v for v in result[field]]
    return result


def native_catalog(rows):
    result = deepcopy(rows)
    for row in result:
        row["relation"] = native_json(row["relation"], "relation")
        row["namespace"] = native_json(row["namespace"], "namespace")
        if row["toast"] is not None:
            row["toast"] = native_json(row["toast"], "relation")
        row["attributes"] = [native_json(a, "attribute") for a in row["attributes"]]
        for item in row["constraints"]:
            item["catalog"] = native_json(item["catalog"], "constraint")
        for item in row["indexes"]:
            item["index"] = native_json(item["index"], "index")
            for field in ("oid", "namespace", "owner", "am"):
                if type(item[field]) is int:
                    item[field] = str(item[field])
        for item in row["guards"]:
            item["function"] = native_json(item["function"], "function")
            item["trigger"] = native_json(item["trigger"], "trigger")
    return result


class Rows(Result):
    def all(self):
        return self.value

    def one(self):
        if isinstance(self.value, list):
            if len(self.value) != 1:
                raise ValueError("confidential database detail")
            return self.value[0]
        return super().one()


class GuardedSession(Session):
    def __init__(self, row=None, *, nested=False):
        super().__init__(row if row is not None else persisted("enrollmentV2"))
        self.bound_connection.get_transaction = lambda: self.connection_root
        self.bound_connection.get_nested_transaction = lambda: self.connection_nested
        self.connection_root = SimpleNamespace(is_active=True)
        self.connection_nested = SimpleNamespace(is_active=True) if nested else None
        self.nested = SimpleNamespace(is_active=True) if nested else None
        self.catalog = reviewed_catalog()
        self.actual_memberships = set()
        self.xid = "123456789"
        self.companion = [{"challenge_id": self.row["challenge_id"], "revision": 1}]
        self.hook = lambda _: None
        self.security = {
            key: True
            for key in (
                "direct_login",
                "origin",
                "schema_usage",
                "no_schema_create",
                "no_owner_membership",
                "companion_select",
                "companion_read_only",
                "no_column_write",
                "parent_lock_privilege",
                "parent_no_bypass",
                "no_execute",
                "distinct_owner",
            )
        }
        self.security["role"] = {
            "oid": 50,
            "rolname": "synthetic_runtime",
            "rolsuper": False,
            "rolcreaterole": False,
            "rolcreatedb": False,
            "rolreplication": False,
            "rolbypassrls": False,
            "rolcanlogin": True,
            "rolinherit": True,
        }

    def execute(self, statement, parameters=None):
        sql = str(statement)
        self.statements.append(statement)
        self.hook(statement)
        if "pg_current_xact_id" in sql:
            return Result(self.xid)
        if "server_version_num" in sql:
            return Result("160004")
        if sql == "SHOW transaction_isolation":
            return Result(self.isolation)
        if sql == storage.CATALOG_SQL:
            return Rows(deepcopy(self.raw_catalog) if hasattr(self, "raw_catalog") else native_catalog(self.catalog))
        if sql == storage.SECURITY_SQL:
            result = deepcopy(self.security)
            if "AS no_actual_ddl_authority" in sql:
                owners = {row["owner"] for row in self.catalog}
                owners.update(row["namespace"]["nspowner"] for row in self.catalog)
                owners.update(g["function"]["proowner"] for row in self.catalog for g in row["guards"])
                owners.update(row["toast"]["relowner"] for row in self.catalog if row["toast"])
                result["no_actual_ddl_authority"] = not (owners & self.actual_memberships)
            result["role"] = native_json(result["role"], "role")
            return Rows(result)
        if "SELECT count(*) FROM pg_trigger" in sql:
            return Result(self.guards)
        if "FROM public.social_device_admission_challenge_revisions" in sql:
            assert parameters == {"challenge_id": self.row["challenge_id"]}
            assert "FOR UPDATE" not in sql
            return Rows(deepcopy(self.companion))
        assert isinstance(statement, Select)
        assert statement.get_execution_options()["autoflush"] is False
        return Rows(deepcopy(self.row))

    def begin(self):
        pytest.fail("reader began caller transaction")

    def commit(self):
        pytest.fail("reader committed caller transaction")

    def rollback(self):
        pytest.fail("reader rolled back caller transaction")

    def close(self):
        pytest.fail("reader closed caller session")


def read(reader, session, now=None):
    parsed = legacy.parse_stored_device_challenge_v1(session.row)
    return reader.read_issued_with_revision_in_transaction(
        session.row["challenge_id"], observed_at=parsed.issued_at if now is None else now
    )


def test_native_regproc_absence_complete_reader_boundary():
    session = GuardedSession()
    session.raw_catalog = native_catalog(reviewed_catalog())
    guards = [g for row in session.raw_catalog for g in row["guards"]]
    assert len(guards) == 5
    assert all(g["function"]["prosupport"] == "-" for g in guards)
    original = deepcopy(session.raw_catalog)
    reader = storage.SqlAlchemyTransactionBoundIssuedChallengeRevisionReader(session)
    reader._catalog()
    assert read(reader, session).challenge_revision == 1
    assert read(reader, session).challenge_revision == 1
    assert session.raw_catalog == original


@pytest.mark.parametrize("guard_index", range(5))
@pytest.mark.parametrize(
    "support",
    [
        "missing",
        "0",
        "1",
        "12345",
        "pg_catalog.fake_support",
        "fake_support",
        "",
        " -",
        "- ",
        "0.0",
        "01",
        0,
        1,
        True,
        False,
        None,
        0.0,
        [],
        {},
    ],
)
def test_native_regproc_other_representations_deny(guard_index, support):
    session = GuardedSession()
    session.raw_catalog = native_catalog(reviewed_catalog())
    guards = [g for row in session.raw_catalog for g in row["guards"]]
    function = guards[guard_index]["function"]
    if support == "missing":
        del function["prosupport"]
    else:
        function["prosupport"] = support
    with pytest.raises(DENIED, match=ERROR):
        storage.SqlAlchemyTransactionBoundIssuedChallengeRevisionReader(session)


def test_real_legacy_reparse_exact_native_revision_and_locked_statement():
    session = GuardedSession()
    reader = storage.SqlAlchemyTransactionBoundIssuedChallengeRevisionReader(session)
    result = read(reader, session)
    assert result.challenge == legacy.parse_stored_device_challenge_v1(session.row)
    assert result.challenge_revision == session.companion[0]["revision"] == 1
    statements = [s for s in session.statements if isinstance(s, Select)]
    compiled = statements[-1].compile(dialect=postgresql.dialect())
    assert "FOR UPDATE OF social_device_admission_challenges" in str(compiled)
    assert compiled.params == {"challenge_id_1": session.row["challenge_id"]}
    lock_index = next(i for i, s in enumerate(session.statements) if isinstance(s, Select))
    companion_index = next(
        i
        for i, s in enumerate(session.statements)
        if "FROM public.social_device_admission_challenge_revisions" in str(s)
    )
    assert lock_index < companion_index
    assert not any("advisory" in str(s) for s in session.statements)
    assert session.row["challenge_id"] not in repr(result)
    with pytest.raises(FrozenInstanceError):
        result.challenge_revision = 2
    with pytest.raises(FrozenInstanceError):
        result.challenge.state = "consumed"


@pytest.mark.parametrize("point", ["before", "parent", "companion", "catalog", "security"])
def test_backend_root_replaced_with_every_sqlalchemy_and_driver_object_unchanged(point):
    session = GuardedSession(nested=True)
    reader = storage.SqlAlchemyTransactionBoundIssuedChallengeRevisionReader(session)
    identities = (
        session.transaction,
        session.nested,
        session.bound_connection,
        session.connection_root,
        session.connection_nested,
        session.driver,
    )
    fired = []

    def change(statement):
        sql = str(statement)
        if not fired and (
            (point == "parent" and isinstance(statement, Select))
            or (point == "companion" and "FROM public.social_device_admission_challenge_revisions" in sql)
            or (point == "catalog" and sql == storage.CATALOG_SQL)
            or (point == "security" and sql == storage.SECURITY_SQL)
        ):
            fired.append(True)
            session.xid = "123456790"

    session.hook = change
    if point == "before":
        session.xid = "123456790"
    with pytest.raises(DENIED, match=ERROR) as failure:
        read(reader, session)
    assert failure.value.__cause__ is None and failure.value.__context__ is None
    assert reader._failed and session.transaction.is_active
    assert identities == (
        session.transaction,
        session.nested,
        session.bound_connection,
        session.connection_root,
        session.connection_nested,
        session.driver,
    )
    session.xid = "123456789"
    with pytest.raises(DENIED, match=ERROR):
        read(reader, session)


@pytest.mark.parametrize("revision", [True, False, 0, -1, 2, 1.0, "1", None, 9007199254740992])
def test_unsupported_stored_generation_denies(revision):
    session = GuardedSession()
    reader = storage.SqlAlchemyTransactionBoundIssuedChallengeRevisionReader(session)
    session.companion[0]["revision"] = revision
    with pytest.raises(DENIED, match=ERROR):
        read(reader, session)
    assert reader._failed


@pytest.mark.parametrize("change", ["missing", "duplicate", "wrong_id", "extra_field"])
def test_no_old_row_adoption_or_ambiguous_provenance(change):
    session = GuardedSession()
    reader = storage.SqlAlchemyTransactionBoundIssuedChallengeRevisionReader(session)
    if change == "missing":
        session.companion = []
    elif change == "duplicate":
        session.companion *= 2
    elif change == "wrong_id":
        session.companion[0]["challenge_id"] = "ff" * 32
    else:
        session.companion[0]["adopted"] = True
    with pytest.raises(DENIED, match=ERROR):
        read(reader, session)
    assert legacy.SqlAlchemyDeviceChallengeStore(session).read(session.row["challenge_id"]).state == "issued"


@pytest.mark.parametrize("state", ["consumed", "expired", "invalidated", "cancelled"])
def test_terminal_parent_is_history_only(state):
    session = GuardedSession()
    reader = storage.SqlAlchemyTransactionBoundIssuedChallengeRevisionReader(session)
    session.row["state"] = state
    with pytest.raises(DENIED, match=ERROR):
        read(reader, session)


@pytest.mark.parametrize("offset,success", [(-1, False), (0, True), (59999, True), (60000, False)])
def test_actual_enrollment_exclusive_millisecond_boundary(offset, success):
    session = GuardedSession()
    reader = storage.SqlAlchemyTransactionBoundIssuedChallengeRevisionReader(session)
    parsed = legacy.parse_stored_device_challenge_v1(session.row)
    # The canonical fixture's actual interval, not copied implementation arithmetic.
    assert parsed.expires_at - parsed.issued_at == 60000
    if success:
        assert read(reader, session, parsed.issued_at + offset).challenge == parsed
    else:
        with pytest.raises(DENIED, match=ERROR):
            read(reader, session, parsed.issued_at + offset)


@pytest.mark.parametrize("now", [True, 1.0, -1, 9007199254740992])
def test_invalid_observation_time(now):
    session = GuardedSession()
    reader = storage.SqlAlchemyTransactionBoundIssuedChallengeRevisionReader(session)
    with pytest.raises(DENIED, match=ERROR):
        read(reader, session, now)


@pytest.mark.parametrize("kind", ["ciphertextSubmit", "recipientSelfRead"])
def test_native_reader_is_enrollment_only(kind):
    session = GuardedSession(persisted(kind))
    reader = storage.SqlAlchemyTransactionBoundIssuedChallengeRevisionReader(session)
    with pytest.raises(DENIED, match=ERROR):
        read(reader, session)


@pytest.mark.parametrize(
    "change",
    [
        "session_root",
        "session_nested",
        "session_nested_inactive",
        "connection_root",
        "connection_nested",
        "connection_nested_inactive",
        "physical",
        "connection",
        "dirty",
        "autocommit",
    ],
)
def test_object_guards_and_caller_ownership(change):
    session = GuardedSession(nested=True)
    reader = storage.SqlAlchemyTransactionBoundIssuedChallengeRevisionReader(session)
    if change == "session_root":
        session.transaction = SimpleNamespace(is_active=True)
    elif change == "session_nested":
        session.nested = SimpleNamespace(is_active=True)
    elif change == "session_nested_inactive":
        session.nested.is_active = False
    elif change == "connection_root":
        session.connection_root = SimpleNamespace(is_active=True)
    elif change == "connection_nested":
        session.connection_nested = SimpleNamespace(is_active=True)
    elif change == "connection_nested_inactive":
        session.connection_nested.is_active = False
    elif change == "physical":
        session.bound_connection.connection.dbapi_connection = SimpleNamespace(autocommit=False)
    elif change == "connection":
        session.bound_connection = GuardedSession().bound_connection
    elif change == "dirty":
        session.dirty.add(object())
    else:
        session.driver.autocommit = True
    with pytest.raises(DENIED, match=ERROR):
        read(reader, session)
    assert reader._failed


@pytest.mark.parametrize("xid", [None, "0", "01", "-1", " 1", "1.0", 1, True, "18446744073709551616"])
def test_backend_marker_has_one_canonical_nonzero_xid8_encoding(xid):
    session = GuardedSession()
    session.xid = xid
    with pytest.raises(DENIED, match=ERROR):
        storage.SqlAlchemyTransactionBoundIssuedChallengeRevisionReader(session)


@pytest.mark.parametrize(
    "field,value",
    [
        ("prosrc", "BEGIN RETURN NEW; END"),
        ("prosecdef", False),
        ("proconfig", ["search_path=public"]),
        ("prosupport", 123),
        ("proparallel", "s"),
        ("procost", 99),
    ],
)
def test_modified_producer_definition_rejected(field, value):
    session = GuardedSession()
    if field == "procost":
        session.catalog[0]["guards"][2]["cost"] = "42c60000"
    else:
        session.catalog[0]["guards"][2]["function"][field] = value
    with pytest.raises(DENIED, match=ERROR):
        storage.SqlAlchemyTransactionBoundIssuedChallengeRevisionReader(session)


@pytest.mark.parametrize(
    "change", ["shadow", "disabled", "missing", "predicate", "swapped_oid", "wrong_fk", "row_security"]
)
def test_catalog_guards_initial_and_repeated(change):
    session = GuardedSession()
    reader = storage.SqlAlchemyTransactionBoundIssuedChallengeRevisionReader(session)
    if change == "shadow":
        session.catalog[0]["resolves_parent"] = False
    elif change == "disabled":
        session.catalog[0]["guards"][2]["trigger"]["tgenabled"] = "D"
    elif change == "missing":
        session.catalog[0]["guards"].pop()
    elif change == "predicate":
        session.catalog[0]["guards"][2]["trigger"]["tgqual"] = "false"
    elif change == "swapped_oid":
        session.catalog[0]["guards"][2]["trigger"]["oid"] += 1
    elif change == "wrong_fk":
        session.catalog[1]["constraints"][-1]["catalog"]["confrelid"] = 99
    else:
        session.catalog[1]["relation"]["relrowsecurity"] = True
    with pytest.raises(DENIED, match=ERROR):
        read(reader, session)


@pytest.mark.parametrize(
    "key",
    [
        "direct_login",
        "origin",
        "no_schema_create",
        "no_owner_membership",
        "companion_read_only",
        "no_column_write",
        "no_execute",
        "distinct_owner",
    ],
)
def test_runtime_security_boundary(key):
    session = GuardedSession()
    session.security[key] = False
    with pytest.raises(DENIED, match=ERROR):
        storage.SqlAlchemyTransactionBoundIssuedChallengeRevisionReader(session)


def test_cached_orm_cannot_override_reparsed_parent_and_failure_is_confidential():
    session = GuardedSession()
    reader = storage.SqlAlchemyTransactionBoundIssuedChallengeRevisionReader(session)
    observed_at = legacy.parse_stored_device_challenge_v1(session.row).issued_at
    session.identity_map = {session.row["challenge_id"]: SimpleNamespace(state="issued", revision=1)}
    session.row["challenge_wire"] += " "
    with pytest.raises(DENIED, match=ERROR) as failure:
        reader.read_issued_with_revision_in_transaction(session.row["challenge_id"], observed_at=observed_at)
    assert failure.value.__context__ is None and failure.value.__cause__ is None
    assert session.row["challenge_id"] not in str(failure.value)


def test_source_only_native_schema_and_real_legacy_source_pin():
    sql = (ROOT / "migrations/2026-10-09_social_device_challenge_revision_v1.sql").read_text()
    old = (ROOT / "migrations/2026-09-23_social_device_admission_receipt_consumption_v1.sql").read_text()
    assert (
        storage.LEGACY_SOURCE
        == old.split("CREATE OR REPLACE FUNCTION guard_social_device_challenge_v1()", 1)[1].split("$$", 2)[1]
    )
    assert storage.PRODUCER_SOURCE in sql and storage.IMMUTABLE_SOURCE in sql
    assert "AFTER INSERT ON public.social_device_admission_challenges" in sql
    assert "VALUES (NEW.challenge_id, 1)" in sql
    assert "SECURITY DEFINER" in sql and "SET search_path = pg_catalog" in sql
    assert "CREATE ROLE" not in sql and "ON CONFLICT" not in sql
    assert storage.TABLE not in legacy.Base.metadata.tables


@pytest.mark.parametrize("phase", ["initial", "repeat"])
@pytest.mark.parametrize(
    "change",
    [
        "weakened",
        "columns",
        "relation",
        "namespace",
        "unvalidated",
        "pk_index",
        "index_columns",
        "companion_binding",
        "legacy_owner",
        "schema_owner",
    ],
)
def test_review_initial_and_repeated_constraint_and_owner_denial(phase, change):
    session = GuardedSession()
    adapter = storage.SqlAlchemyTransactionBoundIssuedChallengeRevisionReader(session) if phase == "repeat" else None
    parent, companion = session.catalog
    c = parent["constraints"][1]["catalog"]
    if change == "weakened":
        parent["constraints"][1]["definition"] = "CHECK (((challenge_id)::text ~ '^[0-9a-f]+$'::text))"
        c["conbin"] = "weakened synthetic expression"
        assert (
            parent["relation"]["relchecks"] == sum(k["catalog"]["contype"] == "c" for k in parent["constraints"]) == 6
        )
        assert len(parent["constraints"]) == 8
    elif change == "columns":
        c["conkey"] = [5]
    elif change == "relation":
        c["conrelid"] = 99
    elif change == "namespace":
        c["connamespace"] = 99
    elif change == "unvalidated":
        c["convalidated"] = False
    elif change == "pk_index":
        parent["constraints"][0]["catalog"]["conindid"] = 311
    elif change == "index_columns":
        parent["indexes"][0]["index"]["indkey"] = "5"
    elif change == "companion_binding":
        companion["constraints"][1]["catalog"]["conkey"] = [2]
    elif change == "legacy_owner":
        for g in parent["guards"][:2]:
            g["function"]["proowner"] = 50
    else:
        for row in session.catalog:
            row["namespace"]["nspowner"] = 50
    with pytest.raises(DENIED, match=ERROR):
        if adapter is None:
            storage.SqlAlchemyTransactionBoundIssuedChallengeRevisionReader(session)
        else:
            read(adapter, session)
            pytest.fail("returned evidence after catalog tampering")
    if adapter is not None:
        assert adapter._failed and session.transaction.is_active
        with pytest.raises(DENIED, match=ERROR):
            read(adapter, session)


def test_review_native_pk_and_fk_inheritance_metadata_is_accepted():
    session = GuardedSession()
    session.catalog = reviewed_catalog(native=True)
    adapter = storage.SqlAlchemyTransactionBoundIssuedChallengeRevisionReader(session)
    assert read(adapter, session).challenge_revision == 1


@pytest.mark.parametrize("object_kind", ["parent", "companion", "toast", "functions", "schema"])
def test_review_actual_ddl_owner_membership_has_no_builtin_exception(object_kind):
    # Inspect the actual owner query, independently of effective grant booleans.
    sql = storage.SECURITY_SQL
    assert "AS no_actual_ddl_authority" in sql
    assert "nspowner" in sql and "proowner" in sql and "reltoastrelid" in sql
    owner_query = sql.split("actual_owners AS", 1)[1].split("AS no_actual_ddl_authority", 1)[0]
    assert "pg_read_all_settings" not in owner_query
    assert "pg_catalog.pg_has_role" in owner_query
    assert "o.owner=r.oid" in owner_query


def test_review_all_sql_helpers_are_schema_qualified():
    assert "FROM unnest(" not in storage.SECURITY_SQL
    assert "FROM pg_catalog.unnest(" in storage.SECURITY_SQL


@pytest.mark.parametrize("phase", ["initial", "repeat"])
@pytest.mark.parametrize("kind", ["parent", "companion", "toast", "legacy", "schema", "builtin_schema"])
def test_review_actual_owner_membership_denies_with_unchanged_grants(phase, kind):
    session = GuardedSession()
    adapter = storage.SqlAlchemyTransactionBoundIssuedChallengeRevisionReader(session) if phase == "repeat" else None
    if kind == "parent":
        owner = session.catalog[0]["owner"]
    elif kind == "companion":
        owner = session.catalog[1]["owner"]
    elif kind == "toast":
        owner = session.catalog[0]["toast"]["relowner"]
    elif kind == "legacy":
        owner = session.catalog[0]["guards"][0]["function"]["proowner"]
    elif kind == "builtin_schema":
        owner = 70  # synthetic pg_read_all_settings also owns the actual schema
        for row in session.catalog:
            row["namespace"]["nspowner"] = owner
    else:
        owner = session.catalog[0]["namespace"]["nspowner"]
    grants = deepcopy(session.security)
    session.actual_memberships.add(owner)
    with pytest.raises(DENIED, match=ERROR):
        if adapter is None:
            storage.SqlAlchemyTransactionBoundIssuedChallengeRevisionReader(session)
        else:
            read(adapter, session)
    assert session.security == grants  # CREATE remains revoked, same effective grants


@pytest.mark.parametrize("change", ["constraint", "pk_index"])
def test_review_replacement_object_identity_denies(change):
    session = GuardedSession()
    adapter = storage.SqlAlchemyTransactionBoundIssuedChallengeRevisionReader(session)
    if change == "constraint":
        session.catalog[0]["constraints"][1]["catalog"]["oid"] += 100
    else:
        session.catalog[0]["constraints"][0]["catalog"]["conindid"] += 100
        session.catalog[1]["constraints"][-1]["catalog"]["conindid"] += 100
        session.catalog[0]["indexes"][0]["oid"] += 100
        session.catalog[0]["indexes"][0]["index"]["indexrelid"] += 100
    with pytest.raises(DENIED, match=ERROR):
        read(adapter, session)


@pytest.mark.parametrize("boundary", ["parent", "companion"])
@pytest.mark.parametrize("change", ["parent_check", "legacy_owner", "owner_membership"])
def test_catalog_tampering_during_observation_denies_before_return(boundary, change):
    session = GuardedSession()
    adapter = storage.SqlAlchemyTransactionBoundIssuedChallengeRevisionReader(session)
    fired = []

    def tamper(statement):
        sql = str(statement)
        if fired or not (
            (boundary == "parent" and isinstance(statement, Select))
            or (boundary == "companion" and "FROM public.social_device_admission_challenge_revisions" in sql)
        ):
            return
        fired.append(True)
        if change == "parent_check":
            session.catalog[0]["constraints"][1]["definition"] = "CHECK (true)"
        elif change == "legacy_owner":
            for guard in session.catalog[0]["guards"][:2]:
                guard["function"]["proowner"] = 50
        else:
            session.actual_memberships.add(20)

    session.hook = tamper
    with pytest.raises(DENIED, match=ERROR):
        read(adapter, session)
    assert fired and adapter._failed and session.transaction.is_active


@pytest.mark.parametrize("relation,position", [(0, 0), (0, 1), (1, 0), (1, 1), (1, 3)])
@pytest.mark.parametrize(
    "field,value",
    [
        ("conislocal", False),
        ("coninhcount", 1),
        ("conparentid", 60),
        ("condeferrable", True),
        ("convalidated", False),
    ],
)
def test_each_constraint_kind_has_independent_native_flags(relation, position, field, value):
    session = GuardedSession()
    session.catalog[relation]["constraints"][position]["catalog"][field] = value
    with pytest.raises(DENIED, match=ERROR):
        storage.SqlAlchemyTransactionBoundIssuedChallengeRevisionReader(session)


@pytest.mark.parametrize("relation,position", [(0, 0), (0, 1), (1, 0), (1, 1), (1, 3)])
def test_noinherit_is_type_specific(relation, position):
    session = GuardedSession()
    c = session.catalog[relation]["constraints"][position]["catalog"]
    c["connoinherit"] = not c["connoinherit"]
    with pytest.raises(DENIED, match=ERROR):
        storage.SqlAlchemyTransactionBoundIssuedChallengeRevisionReader(session)


def test_unknown_native_constraint_fields_fail_closed():
    session = GuardedSession()
    session.catalog[0]["constraints"][1]["catalog"]["conenforced"] = True
    with pytest.raises(DENIED, match=ERROR):
        storage.SqlAlchemyTransactionBoundIssuedChallengeRevisionReader(session)


def test_installation_pins_same_closed_parent_contract_before_producer_attachment():
    sql = (ROOT / "migrations/2026-10-09_social_device_challenge_revision_v1.sql").read_text()
    installation = sql.split("END $installation$;", 1)[0]
    for name, definition, _ in PARENT_CHECKS:
        assert name in installation and definition.replace("'", "''") in installation
    assert "k.connamespace<>parent_namespace" in installation
    assert "k.conkey IS DISTINCT FROM e.keys" in installation
    assert "k.connoinherit<>(e.kind IN ('p','t'))" in installation
    assert "i.indexrelid=parent_index" in installation
    assert "LOCK TABLE public.social_device_admission_challenges" in installation


def test_postgresql_integration_source_is_syntax_only_in_this_task():
    import ast

    path = ROOT / "tests/integration/test_social_device_challenge_revision_storage_postgresql.py"
    ast.parse(path.read_text())  # No import, fixture invocation, SQL or database connection.


def test_native_parent_atomic_constraint_and_between_renderings_are_accepted():
    session = GuardedSession()
    reader = storage.SqlAlchemyTransactionBoundIssuedChallengeRevisionReader(session)
    assert read(reader, session).challenge_revision == 1


@pytest.mark.parametrize(
    "field,value",
    [
        ("contype", "c"),
        ("condeferrable", False),
        ("condeferred", False),
        ("conrelid", 11),
        ("connoinherit", False),
        ("conkey", [1]),
        ("confrelid", 11),
        ("conname", "unexpected_trigger"),
    ],
)
def test_native_atomic_constraint_malformed_binding_denies(field, value):
    session = GuardedSession()
    session.catalog[0]["constraints"][-1]["catalog"][field] = value
    with pytest.raises(DENIED, match=ERROR):
        storage.SqlAlchemyTransactionBoundIssuedChallengeRevisionReader(session)


@pytest.mark.parametrize(
    "kind,field,value",
    [
        ("relation", "oid", 10),
        ("relation", "relowner", "0"),
        ("function", "oid", "0"),
        ("namespace", "oid", "0"),
        ("relation", "relowner", "020"),
        ("relation", "reltype", "4294967296"),
        ("relation", "relam", True),
        ("namespace", "nspowner", "22.0"),
        ("toast", "relowner", " 20"),
        ("attribute", "atttypid", "+1043"),
        ("attribute", "attcollation", "1e2"),
        ("constraint", "conindid", 310),
        ("constraint", "conrelid", "010"),
        ("constraint", "conkey", [True]),
        ("constraint", "convalidated", 1),
        ("index", "indexrelid", 310),
        ("index", "indkey", "1"),
        ("index", "indcollation", [100]),
        ("index", "indclass", ["03126"]),
        ("index", "indoption", [False]),
        ("index_relation", "owner", "020"),
        ("function", "proowner", 20),
        ("function", "proargtypes", ""),
        ("function", "proargtypes", [0]),
        ("function", "prorettype", "02279"),
        ("trigger", "tgfoid", 30),
        ("trigger", "tgattr", ""),
        ("trigger", "tgargs", ""),
        ("trigger", "tgdeferrable", 0),
        ("relation", "unknown_catalog_field", 0),
    ],
)
def test_native_json_metadata_types_are_closed(kind, field, value):
    session = GuardedSession()
    session.raw_catalog = native_catalog(session.catalog)
    parent = session.raw_catalog[0]
    records = {
        "relation": parent["relation"],
        "namespace": parent["namespace"],
        "toast": parent["toast"],
        "attribute": parent["attributes"][0],
        "constraint": parent["constraints"][0]["catalog"],
        "index": parent["indexes"][0]["index"],
        "index_relation": parent["indexes"][0],
        "function": parent["guards"][0]["function"],
        "trigger": parent["guards"][0]["trigger"],
    }
    records[kind][field] = value
    with pytest.raises(DENIED, match=ERROR):
        storage.SqlAlchemyTransactionBoundIssuedChallengeRevisionReader(session)


@pytest.mark.parametrize(
    "field,value",
    [
        ("conindid", "311"),
        ("confrelid", "11"),
        ("confkey", [2]),
        ("conpfeqop", ["99"]),
        ("conppeqop", ["99"]),
        ("conffeqop", ["99"]),
        ("confdelsetcols", []),
        ("connoinherit", False),
    ],
)
def test_native_full_foreign_key_binding_denies(field, value):
    session = GuardedSession()
    session.raw_catalog = native_catalog(session.catalog)
    session.raw_catalog[1]["constraints"][-1]["catalog"][field] = value
    with pytest.raises(DENIED, match=ERROR):
        storage.SqlAlchemyTransactionBoundIssuedChallengeRevisionReader(session)


@pytest.mark.parametrize(
    "field,value",
    [
        ("constraint", 60),
        ("parent", 11),
        ("type", 5),
        ("deferrable", False),
        ("deferred", False),
        ("name", "unknown_atomic"),
        ("internal", True),
        ("oid", "90"),
    ],
)
def test_native_atomic_trigger_binding_is_exact(field, value):
    session = GuardedSession()
    session.catalog[0]["atomic_binding"][0][field] = value
    with pytest.raises(DENIED, match=ERROR):
        storage.SqlAlchemyTransactionBoundIssuedChallengeRevisionReader(session)


@pytest.mark.parametrize("owner", ["20", "21", "22", "020", 50, "4294967296", True])
def test_native_role_owner_comparison_and_encoding_denies(owner):
    session = GuardedSession()
    execute = session.execute

    def native_role(statement, parameters=None):
        result = execute(statement, parameters)
        if str(statement) == storage.SECURITY_SQL:
            result.value["role"]["oid"] = owner
        return result

    session.bound_connection.execute = native_role
    with pytest.raises(DENIED, match=ERROR):
        storage.SqlAlchemyTransactionBoundIssuedChallengeRevisionReader(session)


def test_native_optional_fields_and_empty_vectors_are_accepted():
    session = GuardedSession()
    session.raw_catalog = native_catalog(session.catalog)
    for row in session.raw_catalog:
        for item in row["constraints"]:
            item["catalog"]["confdelsetcols"] = None
        row["indexes"][0]["index"]["indnullsnotdistinct"] = False
        assert row["guards"][0]["function"]["proargtypes"] == []
        assert row["guards"][0]["trigger"]["tgattr"] == []
        assert row["guards"][0]["trigger"]["tgargs"] == "\\x"
    reader = storage.SqlAlchemyTransactionBoundIssuedChallengeRevisionReader(session)
    assert read(reader, session).challenge_revision == 1


@pytest.mark.parametrize(
    "change",
    ["duplicate_atomic", "missing_atomic", "extra_constraint", "atomic_identity", "binding_identity", "unknown_row"],
)
def test_native_atomic_inventory_and_repeated_identity_denies(change):
    session = GuardedSession()
    reader = storage.SqlAlchemyTransactionBoundIssuedChallengeRevisionReader(session)
    parent = session.catalog[0]
    if change == "duplicate_atomic":
        parent["atomic_binding"].append(deepcopy(parent["atomic_binding"][0]))
    elif change == "missing_atomic":
        parent["constraints"].pop()
    elif change == "extra_constraint":
        parent["constraints"].append(deepcopy(parent["constraints"][-1]))
    elif change == "atomic_identity":
        parent["constraints"][-1]["catalog"]["oid"] += 1
        parent["atomic_binding"][0]["constraint"] += 1
    elif change == "binding_identity":
        parent["atomic_binding"][0]["oid"] += 1
    else:
        parent["unknown_row_field"] = True
    with pytest.raises(DENIED, match=ERROR):
        read(reader, session)
    assert reader._failed


# Independent complete native observations; OIDs here are synthetic samples,
# never policy identifiers. Captured after pinned SQL in an empty prerequisite.
CAPTURED_NATIVE_CATALOG = [
    {
        "oid": 16482,
        "owner": 10,
        "row_type": 16484,
        "toast_oid": 0,
        "relation": {
            "oid": "16482",
            "relam": "2",
            "relacl": [
                "issued_challenge_revision_ddl=arwdDxt/issued_challenge_revision_ddl",
                "issued_challenge_revision_runtime=r/issued_challenge_revision_ddl",
            ],
            "relkind": "r",
            "relname": "social_device_admission_challenge_revisions",
            "reltype": "16484",
            "relnatts": 2,
            "relowner": "10",
            "relpages": 0,
            "relchecks": 2,
            "reloftype": "0",
            "reltuples": -1,
            "relminmxid": "1",
            "reloptions": None,
            "relrewrite": "0",
            "relfilenode": "16482",
            "relhasindex": True,
            "relhasrules": False,
            "relisshared": False,
            "relfrozenxid": "734",
            "relnamespace": "2200",
            "relpartbound": None,
            "relreplident": "d",
            "relallvisible": 0,
            "reltablespace": "0",
            "reltoastrelid": "0",
            "relhassubclass": False,
            "relhastriggers": True,
            "relispartition": False,
            "relispopulated": True,
            "relpersistence": "p",
            "relrowsecurity": False,
            "relforcerowsecurity": False,
        },
        "namespace": {
            "oid": "2200",
            "nspacl": [
                "issued_challenge_revision_ddl=UC/issued_challenge_revision_ddl",
                "issued_challenge_revision_runtime=U/issued_challenge_revision_ddl",
            ],
            "nspname": "public",
            "nspowner": "10",
        },
        "indexes": [
            {
                "am": "403",
                "oid": "16487",
                "kind": "i",
                "name": "social_device_admission_challenge_revisions_pkey",
                "index": {
                    "indkey": [1],
                    "indpred": None,
                    "indclass": ["3126"],
                    "indexprs": None,
                    "indnatts": 1,
                    "indrelid": "16482",
                    "indislive": True,
                    "indoption": [0],
                    "indexrelid": "16487",
                    "indisready": True,
                    "indisvalid": True,
                    "indisunique": True,
                    "indnkeyatts": 1,
                    "indcheckxmin": False,
                    "indcollation": ["100"],
                    "indimmediate": True,
                    "indisprimary": True,
                    "indisclustered": False,
                    "indisexclusion": False,
                    "indisreplident": False,
                    "indnullsnotdistinct": False,
                },
                "owner": "10",
                "namespace": "2200",
            }
        ],
        "toast": None,
        "toast_schema": None,
        "attributes": [
            {
                "attacl": None,
                "attlen": -1,
                "attnum": 1,
                "attname": "challenge_id",
                "attalign": "i",
                "attbyval": False,
                "attndims": 0,
                "attrelid": "16482",
                "atttypid": "1043",
                "atthasdef": False,
                "atttypmod": 68,
                "attislocal": True,
                "attnotnull": True,
                "attoptions": None,
                "attstorage": "x",
                "attcacheoff": -1,
                "attidentity": "",
                "attinhcount": 0,
                "attcollation": "100",
                "attgenerated": "",
                "attisdropped": False,
                "attfdwoptions": None,
                "atthasmissing": False,
                "attmissingval": None,
                "attstattarget": -1,
                "attcompression": "",
            },
            {
                "attacl": None,
                "attlen": 4,
                "attnum": 2,
                "attname": "revision",
                "attalign": "i",
                "attbyval": True,
                "attndims": 0,
                "attrelid": "16482",
                "atttypid": "23",
                "atthasdef": False,
                "atttypmod": -1,
                "attislocal": True,
                "attnotnull": True,
                "attoptions": None,
                "attstorage": "p",
                "attcacheoff": -1,
                "attidentity": "",
                "attinhcount": 0,
                "attcollation": "0",
                "attgenerated": "",
                "attisdropped": False,
                "attfdwoptions": None,
                "atthasmissing": False,
                "attmissingval": None,
                "attstattarget": -1,
                "attcompression": "",
            },
        ],
        "constraints": [
            {
                "catalog": {
                    "oid": "16486",
                    "conbin": "{OPEXPR :opno 96 :opfuncid 65 :opresulttype 16 :opretset false "
                    ":opcollid 0 :inputcollid 0 :args ({VAR :varno 1 :varattno 2 "
                    ":vartype 23 :vartypmod -1 :varcollid 0 :varnullingrels (b) "
                    ":varlevelsup 0 :varnosyn 1 :varattnosyn 2 :location 12634} {CONST "
                    ":consttype 23 :consttypmod -1 :constcollid 0 :constlen 4 "
                    ":constbyval true :constisnull false :location 12645 :constvalue 4 "
                    "[ 1 0 0 0 0 0 0 0 ]}) :location 12643}",
                    "conkey": [2],
                    "confkey": None,
                    "conname": "ck_social_challenge_revision_generation",
                    "contype": "c",
                    "conindid": "0",
                    "conrelid": "16482",
                    "contypid": "0",
                    "conexclop": None,
                    "conffeqop": None,
                    "confrelid": "0",
                    "conpfeqop": None,
                    "conppeqop": None,
                    "conislocal": True,
                    "condeferred": False,
                    "confdeltype": " ",
                    "confupdtype": " ",
                    "coninhcount": 0,
                    "conparentid": "0",
                    "connamespace": "2200",
                    "connoinherit": False,
                    "convalidated": True,
                    "condeferrable": False,
                    "confmatchtype": " ",
                    "confdelsetcols": None,
                },
                "definition": "CHECK ((revision = 1))",
            },
            {
                "catalog": {
                    "oid": "16485",
                    "conbin": "{OPEXPR :opno 641 :opfuncid 1254 :opresulttype 16 :opretset false "
                    ":opcollid 0 :inputcollid 100 :args ({RELABELTYPE :arg {VAR :varno "
                    "1 :varattno 1 :vartype 1043 :vartypmod 68 :varcollid 100 "
                    ":varnullingrels (b) :varlevelsup 0 :varnosyn 1 :varattnosyn 1 "
                    ":location 12538} :resulttype 25 :resulttypmod -1 :resultcollid 100 "
                    ":relabelformat 2 :location -1} {CONST :consttype 25 :consttypmod "
                    "-1 :constcollid 100 :constlen -1 :constbyval false :constisnull "
                    "false :location 12553 :constvalue 18 [ 72 0 0 0 94 91 48 45 57 97 "
                    "45 102 93 123 54 52 125 36 ]}) :location 12551}",
                    "conkey": [1],
                    "confkey": None,
                    "conname": "ck_social_challenge_revision_id",
                    "contype": "c",
                    "conindid": "0",
                    "conrelid": "16482",
                    "contypid": "0",
                    "conexclop": None,
                    "conffeqop": None,
                    "confrelid": "0",
                    "conpfeqop": None,
                    "conppeqop": None,
                    "conislocal": True,
                    "condeferred": False,
                    "confdeltype": " ",
                    "confupdtype": " ",
                    "coninhcount": 0,
                    "conparentid": "0",
                    "connamespace": "2200",
                    "connoinherit": False,
                    "convalidated": True,
                    "condeferrable": False,
                    "confmatchtype": " ",
                    "confdelsetcols": None,
                },
                "definition": "CHECK (((challenge_id)::text ~ '^[0-9a-f]{64}$'::text))",
            },
            {
                "catalog": {
                    "oid": "16489",
                    "conbin": None,
                    "conkey": [1],
                    "confkey": [1],
                    "conname": "fk_social_challenge_revision_parent",
                    "contype": "f",
                    "conindid": "16398",
                    "conrelid": "16482",
                    "contypid": "0",
                    "conexclop": None,
                    "conffeqop": ["98"],
                    "confrelid": "16387",
                    "conpfeqop": ["98"],
                    "conppeqop": ["98"],
                    "conislocal": True,
                    "condeferred": False,
                    "confdeltype": "r",
                    "confupdtype": "r",
                    "coninhcount": 0,
                    "conparentid": "0",
                    "connamespace": "2200",
                    "connoinherit": True,
                    "convalidated": True,
                    "condeferrable": False,
                    "confmatchtype": "s",
                    "confdelsetcols": None,
                },
                "definition": "FOREIGN KEY (challenge_id) REFERENCES "
                "social_device_admission_challenges(challenge_id) ON UPDATE RESTRICT ON "
                "DELETE RESTRICT",
            },
            {
                "catalog": {
                    "oid": "16488",
                    "conbin": None,
                    "conkey": [1],
                    "confkey": None,
                    "conname": "social_device_admission_challenge_revisions_pkey",
                    "contype": "p",
                    "conindid": "16487",
                    "conrelid": "16482",
                    "contypid": "0",
                    "conexclop": None,
                    "conffeqop": None,
                    "confrelid": "0",
                    "conpfeqop": None,
                    "conppeqop": None,
                    "conislocal": True,
                    "condeferred": False,
                    "confdeltype": " ",
                    "confupdtype": " ",
                    "coninhcount": 0,
                    "conparentid": "0",
                    "connamespace": "2200",
                    "connoinherit": True,
                    "convalidated": True,
                    "condeferrable": False,
                    "confmatchtype": " ",
                    "confdelsetcols": None,
                },
                "definition": "PRIMARY KEY (challenge_id)",
            },
        ],
        "guards": [
            {
                "cost": "42c80000",
                "rows": "00000000",
                "trigger": {
                    "oid": "16497",
                    "tgargs": "\\x",
                    "tgattr": [],
                    "tgfoid": "16495",
                    "tgname": "trg_social_challenge_revision_immutable",
                    "tgqual": None,
                    "tgtype": 27,
                    "tgnargs": 0,
                    "tgrelid": "16482",
                    "tgenabled": "O",
                    "tgnewtable": None,
                    "tgoldtable": None,
                    "tgparentid": "0",
                    "tgconstraint": "0",
                    "tgdeferrable": False,
                    "tgisinternal": False,
                    "tgconstrindid": "0",
                    "tgconstrrelid": "0",
                    "tginitdeferred": False,
                },
                "function": {
                    "oid": "16495",
                    "proacl": ["issued_challenge_revision_ddl=X/issued_challenge_revision_ddl"],
                    "probin": None,
                    "prosrc": "\n"
                    "BEGIN\n"
                    "    RAISE EXCEPTION 'social device challenge revision unavailable';\n"
                    "END\n",
                    "procost": 100,
                    "prokind": "f",
                    "prolang": "13614",
                    "proname": "deny_social_device_challenge_revision_mutation_v1",
                    "prorows": 0,
                    "pronargs": 0,
                    "proowner": "10",
                    "proconfig": ["search_path=pg_catalog"],
                    "proretset": False,
                    "prosecdef": False,
                    "prorettype": "2279",
                    "prosqlbody": None,
                    "prosupport": "-",
                    "proargmodes": None,
                    "proargnames": None,
                    "proargtypes": [],
                    "proisstrict": False,
                    "proparallel": "u",
                    "protrftypes": None,
                    "provariadic": "0",
                    "provolatile": "v",
                    "proleakproof": False,
                    "pronamespace": "2200",
                    "proallargtypes": None,
                    "proargdefaults": None,
                    "pronargdefaults": 0,
                },
                "language": "plpgsql",
                "namespace": "public",
            },
            {
                "cost": "42c80000",
                "rows": "00000000",
                "trigger": {
                    "oid": "16498",
                    "tgargs": "\\x",
                    "tgattr": [],
                    "tgfoid": "16495",
                    "tgname": "trg_social_challenge_revision_no_truncate",
                    "tgqual": None,
                    "tgtype": 34,
                    "tgnargs": 0,
                    "tgrelid": "16482",
                    "tgenabled": "O",
                    "tgnewtable": None,
                    "tgoldtable": None,
                    "tgparentid": "0",
                    "tgconstraint": "0",
                    "tgdeferrable": False,
                    "tgisinternal": False,
                    "tgconstrindid": "0",
                    "tgconstrrelid": "0",
                    "tginitdeferred": False,
                },
                "function": {
                    "oid": "16495",
                    "proacl": ["issued_challenge_revision_ddl=X/issued_challenge_revision_ddl"],
                    "probin": None,
                    "prosrc": "\n"
                    "BEGIN\n"
                    "    RAISE EXCEPTION 'social device challenge revision unavailable';\n"
                    "END\n",
                    "procost": 100,
                    "prokind": "f",
                    "prolang": "13614",
                    "proname": "deny_social_device_challenge_revision_mutation_v1",
                    "prorows": 0,
                    "pronargs": 0,
                    "proowner": "10",
                    "proconfig": ["search_path=pg_catalog"],
                    "proretset": False,
                    "prosecdef": False,
                    "prorettype": "2279",
                    "prosqlbody": None,
                    "prosupport": "-",
                    "proargmodes": None,
                    "proargnames": None,
                    "proargtypes": [],
                    "proisstrict": False,
                    "proparallel": "u",
                    "protrftypes": None,
                    "provariadic": "0",
                    "provolatile": "v",
                    "proleakproof": False,
                    "pronamespace": "2200",
                    "proallargtypes": None,
                    "proargdefaults": None,
                    "pronargdefaults": 0,
                },
                "language": "plpgsql",
                "namespace": "public",
            },
        ],
        "atomic_binding": None,
        "resolves_parent": True,
    },
    {
        "oid": 16387,
        "owner": 10,
        "row_type": 16389,
        "toast_oid": 16396,
        "relation": {
            "oid": "16387",
            "relam": "2",
            "relacl": [
                "issued_challenge_revision_ddl=arwdDxt/issued_challenge_revision_ddl",
                "issued_challenge_revision_runtime=arw/issued_challenge_revision_ddl",
            ],
            "relkind": "r",
            "relname": "social_device_admission_challenges",
            "reltype": "16389",
            "relnatts": 5,
            "relowner": "10",
            "relpages": 0,
            "relchecks": 6,
            "reloftype": "0",
            "reltuples": -1,
            "relminmxid": "1",
            "reloptions": None,
            "relrewrite": "0",
            "relfilenode": "16387",
            "relhasindex": True,
            "relhasrules": False,
            "relisshared": False,
            "relfrozenxid": "733",
            "relnamespace": "2200",
            "relpartbound": None,
            "relreplident": "d",
            "relallvisible": 0,
            "reltablespace": "0",
            "reltoastrelid": "16396",
            "relhassubclass": False,
            "relhastriggers": True,
            "relispartition": False,
            "relispopulated": True,
            "relpersistence": "p",
            "relrowsecurity": False,
            "relforcerowsecurity": False,
        },
        "namespace": {
            "oid": "2200",
            "nspacl": [
                "issued_challenge_revision_ddl=UC/issued_challenge_revision_ddl",
                "issued_challenge_revision_runtime=U/issued_challenge_revision_ddl",
            ],
            "nspname": "public",
            "nspowner": "10",
        },
        "indexes": [
            {
                "am": "403",
                "oid": "16398",
                "kind": "i",
                "name": "social_device_admission_challenges_pkey",
                "index": {
                    "indkey": [1],
                    "indpred": None,
                    "indclass": ["3126"],
                    "indexprs": None,
                    "indnatts": 1,
                    "indrelid": "16387",
                    "indislive": True,
                    "indoption": [0],
                    "indexrelid": "16398",
                    "indisready": True,
                    "indisvalid": True,
                    "indisunique": True,
                    "indnkeyatts": 1,
                    "indcheckxmin": False,
                    "indcollation": ["100"],
                    "indimmediate": True,
                    "indisprimary": True,
                    "indisclustered": False,
                    "indisexclusion": False,
                    "indisreplident": False,
                    "indnullsnotdistinct": False,
                },
                "owner": "10",
                "namespace": "2200",
            }
        ],
        "toast": {
            "oid": "16396",
            "relam": "2",
            "relacl": None,
            "relkind": "t",
            "relname": "pg_toast_16387",
            "reltype": "0",
            "relnatts": 3,
            "relowner": "10",
            "relpages": 0,
            "relchecks": 0,
            "reloftype": "0",
            "reltuples": -1,
            "relminmxid": "1",
            "reloptions": None,
            "relrewrite": "0",
            "relfilenode": "16396",
            "relhasindex": True,
            "relhasrules": False,
            "relisshared": False,
            "relfrozenxid": "733",
            "relnamespace": "99",
            "relpartbound": None,
            "relreplident": "n",
            "relallvisible": 0,
            "reltablespace": "0",
            "reltoastrelid": "0",
            "relhassubclass": False,
            "relhastriggers": False,
            "relispartition": False,
            "relispopulated": True,
            "relpersistence": "p",
            "relrowsecurity": False,
            "relforcerowsecurity": False,
        },
        "toast_schema": "pg_toast",
        "attributes": [
            {
                "attacl": None,
                "attlen": -1,
                "attnum": 1,
                "attname": "challenge_id",
                "attalign": "i",
                "attbyval": False,
                "attndims": 0,
                "attrelid": "16387",
                "atttypid": "1043",
                "atthasdef": False,
                "atttypmod": 68,
                "attislocal": True,
                "attnotnull": True,
                "attoptions": None,
                "attstorage": "x",
                "attcacheoff": -1,
                "attidentity": "",
                "attinhcount": 0,
                "attcollation": "100",
                "attgenerated": "",
                "attisdropped": False,
                "attfdwoptions": None,
                "atthasmissing": False,
                "attmissingval": None,
                "attstattarget": -1,
                "attcompression": "",
            },
            {
                "attacl": None,
                "attlen": -1,
                "attnum": 2,
                "attname": "context_wire",
                "attalign": "i",
                "attbyval": False,
                "attndims": 0,
                "attrelid": "16387",
                "atttypid": "25",
                "atthasdef": False,
                "atttypmod": -1,
                "attislocal": True,
                "attnotnull": True,
                "attoptions": None,
                "attstorage": "x",
                "attcacheoff": -1,
                "attidentity": "",
                "attinhcount": 0,
                "attcollation": "100",
                "attgenerated": "",
                "attisdropped": False,
                "attfdwoptions": None,
                "atthasmissing": False,
                "attmissingval": None,
                "attstattarget": -1,
                "attcompression": "",
            },
            {
                "attacl": None,
                "attlen": -1,
                "attnum": 3,
                "attname": "challenge_wire",
                "attalign": "i",
                "attbyval": False,
                "attndims": 0,
                "attrelid": "16387",
                "atttypid": "25",
                "atthasdef": False,
                "atttypmod": -1,
                "attislocal": True,
                "attnotnull": True,
                "attoptions": None,
                "attstorage": "x",
                "attcacheoff": -1,
                "attidentity": "",
                "attinhcount": 0,
                "attcollation": "100",
                "attgenerated": "",
                "attisdropped": False,
                "attfdwoptions": None,
                "atthasmissing": False,
                "attmissingval": None,
                "attstattarget": -1,
                "attcompression": "",
            },
            {
                "attacl": None,
                "attlen": -1,
                "attnum": 4,
                "attname": "routing_request_wire",
                "attalign": "i",
                "attbyval": False,
                "attndims": 0,
                "attrelid": "16387",
                "atttypid": "25",
                "atthasdef": False,
                "atttypmod": -1,
                "attislocal": True,
                "attnotnull": False,
                "attoptions": None,
                "attstorage": "x",
                "attcacheoff": -1,
                "attidentity": "",
                "attinhcount": 0,
                "attcollation": "100",
                "attgenerated": "",
                "attisdropped": False,
                "attfdwoptions": None,
                "atthasmissing": False,
                "attmissingval": None,
                "attstattarget": -1,
                "attcompression": "",
            },
            {
                "attacl": None,
                "attlen": -1,
                "attnum": 5,
                "attname": "state",
                "attalign": "i",
                "attbyval": False,
                "attndims": 0,
                "attrelid": "16387",
                "atttypid": "1043",
                "atthasdef": False,
                "atttypmod": 15,
                "attislocal": True,
                "attnotnull": True,
                "attoptions": None,
                "attstorage": "x",
                "attcacheoff": -1,
                "attidentity": "",
                "attinhcount": 0,
                "attcollation": "100",
                "attgenerated": "",
                "attisdropped": False,
                "attfdwoptions": None,
                "atthasmissing": False,
                "attmissingval": None,
                "attstattarget": -1,
                "attcompression": "",
            },
        ],
        "constraints": [
            {
                "catalog": {
                    "oid": "16392",
                    "conbin": "{BOOLEXPR :boolop and :args ({BOOLEXPR :boolop and :args ({OPEXPR "
                    ":opno 525 :opfuncid 150 :opresulttype 16 :opretset false :opcollid "
                    "0 :inputcollid 0 :args ({FUNCEXPR :funcid 1374 :funcresulttype 23 "
                    ":funcretset false :funcvariadic false :funcformat 0 :funccollid 0 "
                    ":inputcollid 100 :args ({VAR :varno 1 :varattno 2 :vartype 25 "
                    ":vartypmod -1 :varcollid 100 :varnullingrels (b) :varlevelsup 0 "
                    ":varnosyn 1 :varattnosyn 2 :location 890}) :location 877} {CONST "
                    ":consttype 23 :consttypmod -1 :constcollid 0 :constlen 4 "
                    ":constbyval true :constisnull false :location 912 :constvalue 4 [ "
                    "1 0 0 0 0 0 0 0 ]}) :location 904} {OPEXPR :opno 523 :opfuncid 149 "
                    ":opresulttype 16 :opretset false :opcollid 0 :inputcollid 0 :args "
                    "({FUNCEXPR :funcid 1374 :funcresulttype 23 :funcretset false "
                    ":funcvariadic false :funcformat 0 :funccollid 0 :inputcollid 100 "
                    ":args ({VAR :varno 1 :varattno 2 :vartype 25 :vartypmod -1 "
                    ":varcollid 100 :varnullingrels (b) :varlevelsup 0 :varnosyn 1 "
                    ":varattnosyn 2 :location 890}) :location 877} {CONST :consttype 23 "
                    ":consttypmod -1 :constcollid 0 :constlen 4 :constbyval true "
                    ":constisnull false :location 918 :constvalue 4 [ 0 16 0 0 0 0 0 0 "
                    "]}) :location 904}) :location 904} {OPEXPR :opno 642 :opfuncid "
                    "1256 :opresulttype 16 :opretset false :opcollid 0 :inputcollid 100 "
                    ":args ({VAR :varno 1 :varattno 2 :vartype 25 :vartypmod -1 "
                    ":varcollid 100 :varnullingrels (b) :varlevelsup 0 :varnosyn 1 "
                    ":varattnosyn 2 :location 927} {CONST :consttype 25 :consttypmod -1 "
                    ":constcollid 100 :constlen -1 :constbyval false :constisnull false "
                    ":location 943 :constvalue 10 [ 40 0 0 0 91 94 32 45 126 93 ]}) "
                    ":location 940}) :location 923}",
                    "conkey": [2],
                    "confkey": None,
                    "conname": "ck_social_challenge_context_wire",
                    "contype": "c",
                    "conindid": "0",
                    "conrelid": "16387",
                    "contypid": "0",
                    "conexclop": None,
                    "conffeqop": None,
                    "confrelid": "0",
                    "conpfeqop": None,
                    "conppeqop": None,
                    "conislocal": True,
                    "condeferred": False,
                    "confdeltype": " ",
                    "confupdtype": " ",
                    "coninhcount": 0,
                    "conparentid": "0",
                    "connamespace": "2200",
                    "connoinherit": False,
                    "convalidated": True,
                    "condeferrable": False,
                    "confmatchtype": " ",
                    "confdelsetcols": None,
                },
                "definition": "CHECK ((((octet_length(context_wire) >= 1) AND (octet_length(context_wire) "
                "<= 4096)) AND (context_wire !~ '[^ -~]'::text)))",
            },
            {
                "catalog": {
                    "oid": "16390",
                    "conbin": "{OPEXPR :opno 641 :opfuncid 1254 :opresulttype 16 :opretset false "
                    ":opcollid 0 :inputcollid 100 :args ({RELABELTYPE :arg {VAR :varno "
                    "1 :varattno 1 :vartype 1043 :vartypmod 68 :varcollid 100 "
                    ":varnullingrels (b) :varlevelsup 0 :varnosyn 1 :varattnosyn 1 "
                    ":location 654} :resulttype 25 :resulttypmod -1 :resultcollid 100 "
                    ":relabelformat 2 :location -1} {CONST :consttype 25 :consttypmod "
                    "-1 :constcollid 100 :constlen -1 :constbyval false :constisnull "
                    "false :location 669 :constvalue 18 [ 72 0 0 0 94 91 48 45 57 97 45 "
                    "102 93 123 54 52 125 36 ]}) :location 667}",
                    "conkey": [1],
                    "confkey": None,
                    "conname": "ck_social_challenge_id",
                    "contype": "c",
                    "conindid": "0",
                    "conrelid": "16387",
                    "contypid": "0",
                    "conexclop": None,
                    "conffeqop": None,
                    "confrelid": "0",
                    "conpfeqop": None,
                    "conppeqop": None,
                    "conislocal": True,
                    "condeferred": False,
                    "confdeltype": " ",
                    "confupdtype": " ",
                    "coninhcount": 0,
                    "conparentid": "0",
                    "connamespace": "2200",
                    "connoinherit": False,
                    "convalidated": True,
                    "condeferrable": False,
                    "confmatchtype": " ",
                    "confdelsetcols": None,
                },
                "definition": "CHECK (((challenge_id)::text ~ '^[0-9a-f]{64}$'::text))",
            },
            {
                "catalog": {
                    "oid": "16394",
                    "conbin": "{BOOLEXPR :boolop or :args ({NULLTEST :arg {VAR :varno 1 :varattno "
                    "4 :vartype 25 :vartypmod -1 :varcollid 100 :varnullingrels (b) "
                    ":varlevelsup 0 :varnosyn 1 :varattnosyn 4 :location 1155} "
                    ":nulltesttype 0 :argisrow false :location 1176} {BOOLEXPR :boolop "
                    "and :args ({BOOLEXPR :boolop and :args ({OPEXPR :opno 525 "
                    ":opfuncid 150 :opresulttype 16 :opretset false :opcollid 0 "
                    ":inputcollid 0 :args ({FUNCEXPR :funcid 1374 :funcresulttype 23 "
                    ":funcretset false :funcvariadic false :funcformat 0 :funccollid 0 "
                    ":inputcollid 100 :args ({VAR :varno 1 :varattno 4 :vartype 25 "
                    ":vartypmod -1 :varcollid 100 :varnullingrels (b) :varlevelsup 0 "
                    ":varnosyn 1 :varattnosyn 4 :location 1201}) :location 1188} {CONST "
                    ":consttype 23 :consttypmod -1 :constcollid 0 :constlen 4 "
                    ":constbyval true :constisnull false :location 1231 :constvalue 4 [ "
                    "1 0 0 0 0 0 0 0 ]}) :location 1223} {OPEXPR :opno 523 :opfuncid "
                    "149 :opresulttype 16 :opretset false :opcollid 0 :inputcollid 0 "
                    ":args ({FUNCEXPR :funcid 1374 :funcresulttype 23 :funcretset false "
                    ":funcvariadic false :funcformat 0 :funccollid 0 :inputcollid 100 "
                    ":args ({VAR :varno 1 :varattno 4 :vartype 25 :vartypmod -1 "
                    ":varcollid 100 :varnullingrels (b) :varlevelsup 0 :varnosyn 1 "
                    ":varattnosyn 4 :location 1201}) :location 1188} {CONST :consttype "
                    "23 :consttypmod -1 :constcollid 0 :constlen 4 :constbyval true "
                    ":constisnull false :location 1237 :constvalue 4 [ 0 8 0 0 0 0 0 0 "
                    "]}) :location 1223}) :location 1223} {OPEXPR :opno 642 :opfuncid "
                    "1256 :opresulttype 16 :opretset false :opcollid 0 :inputcollid 100 "
                    ":args ({VAR :varno 1 :varattno 4 :vartype 25 :vartypmod -1 "
                    ":varcollid 100 :varnullingrels (b) :varlevelsup 0 :varnosyn 1 "
                    ":varattnosyn 4 :location 1254} {CONST :consttype 25 :consttypmod "
                    "-1 :constcollid 100 :constlen -1 :constbyval false :constisnull "
                    "false :location 1278 :constvalue 10 [ 40 0 0 0 91 94 32 45 126 93 "
                    "]}) :location 1275}) :location 1250}) :location 1184}",
                    "conkey": [4],
                    "confkey": None,
                    "conname": "ck_social_challenge_routing_wire",
                    "contype": "c",
                    "conindid": "0",
                    "conrelid": "16387",
                    "contypid": "0",
                    "conexclop": None,
                    "conffeqop": None,
                    "confrelid": "0",
                    "conpfeqop": None,
                    "conppeqop": None,
                    "conislocal": True,
                    "condeferred": False,
                    "confdeltype": " ",
                    "confupdtype": " ",
                    "coninhcount": 0,
                    "conparentid": "0",
                    "connamespace": "2200",
                    "connoinherit": False,
                    "convalidated": True,
                    "condeferrable": False,
                    "confmatchtype": " ",
                    "confdelsetcols": None,
                },
                "definition": "CHECK (((routing_request_wire IS NULL) OR "
                "(((octet_length(routing_request_wire) >= 1) AND "
                "(octet_length(routing_request_wire) <= 2048)) AND (routing_request_wire !~ "
                "'[^ -~]'::text))))",
            },
            {
                "catalog": {
                    "oid": "16391",
                    "conbin": "{SCALARARRAYOPEXPR :opno 98 :opfuncid 67 :hashfuncid 0 :negfuncid "
                    "0 :useOr true :inputcollid 100 :args ({RELABELTYPE :arg {VAR "
                    ":varno 1 :varattno 5 :vartype 1043 :vartypmod 15 :varcollid 100 "
                    ":varnullingrels (b) :varlevelsup 0 :varnosyn 1 :varattnosyn 5 "
                    ":location 744} :resulttype 25 :resulttypmod -1 :resultcollid 100 "
                    ":relabelformat 2 :location -1} {ARRAYCOERCEEXPR :arg {ARRAYEXPR "
                    ":array_typeid 1015 :array_collid 100 :element_typeid 1043 "
                    ":elements ({CONST :consttype 1043 :consttypmod -1 :constcollid 100 "
                    ":constlen -1 :constbyval false :constisnull false :location 754 "
                    ":constvalue 10 [ 40 0 0 0 105 115 115 117 101 100 ]} {CONST "
                    ":consttype 1043 :consttypmod -1 :constcollid 100 :constlen -1 "
                    ":constbyval false :constisnull false :location 763 :constvalue 12 "
                    "[ 48 0 0 0 99 111 110 115 117 109 101 100 ]} {CONST :consttype "
                    "1043 :consttypmod -1 :constcollid 100 :constlen -1 :constbyval "
                    "false :constisnull false :location 774 :constvalue 11 [ 44 0 0 0 "
                    "101 120 112 105 114 101 100 ]} {CONST :consttype 1043 :consttypmod "
                    "-1 :constcollid 100 :constlen -1 :constbyval false :constisnull "
                    "false :location 784 :constvalue 15 [ 60 0 0 0 105 110 118 97 108 "
                    "105 100 97 116 101 100 ]} {CONST :consttype 1043 :consttypmod -1 "
                    ":constcollid 100 :constlen -1 :constbyval false :constisnull false "
                    ":location 798 :constvalue 13 [ 52 0 0 0 99 97 110 99 101 108 108 "
                    "101 100 ]}) :multidims false :location -1} :elemexpr {RELABELTYPE "
                    ":arg {CASETESTEXPR :typeId 1043 :typeMod -1 :collation 0} "
                    ":resulttype 25 :resulttypmod -1 :resultcollid 100 :relabelformat 2 "
                    ":location -1} :resulttype 1009 :resulttypmod -1 :resultcollid 100 "
                    ":coerceformat 2 :location -1}) :location 750}",
                    "conkey": [5],
                    "confkey": None,
                    "conname": "ck_social_challenge_state",
                    "contype": "c",
                    "conindid": "0",
                    "conrelid": "16387",
                    "contypid": "0",
                    "conexclop": None,
                    "conffeqop": None,
                    "confrelid": "0",
                    "conpfeqop": None,
                    "conppeqop": None,
                    "conislocal": True,
                    "condeferred": False,
                    "confdeltype": " ",
                    "confupdtype": " ",
                    "coninhcount": 0,
                    "conparentid": "0",
                    "connamespace": "2200",
                    "connoinherit": False,
                    "convalidated": True,
                    "condeferrable": False,
                    "confmatchtype": " ",
                    "confdelsetcols": None,
                },
                "definition": "CHECK (((state)::text = ANY ((ARRAY['issued'::character varying, "
                "'consumed'::character varying, 'expired'::character varying, "
                "'invalidated'::character varying, 'cancelled'::character "
                "varying])::text[])))",
            },
            {
                "catalog": {
                    "oid": "16393",
                    "conbin": "{BOOLEXPR :boolop and :args ({BOOLEXPR :boolop and :args ({OPEXPR "
                    ":opno 525 :opfuncid 150 :opresulttype 16 :opretset false :opcollid "
                    "0 :inputcollid 0 :args ({FUNCEXPR :funcid 1374 :funcresulttype 23 "
                    ":funcretset false :funcvariadic false :funcformat 0 :funccollid 0 "
                    ":inputcollid 100 :args ({VAR :varno 1 :varattno 3 :vartype 25 "
                    ":vartypmod -1 :varcollid 100 :varnullingrels (b) :varlevelsup 0 "
                    ":varnosyn 1 :varattnosyn 3 :location 1023}) :location 1010} {CONST "
                    ":consttype 23 :consttypmod -1 :constcollid 0 :constlen 4 "
                    ":constbyval true :constisnull false :location 1047 :constvalue 4 [ "
                    "1 0 0 0 0 0 0 0 ]}) :location 1039} {OPEXPR :opno 523 :opfuncid "
                    "149 :opresulttype 16 :opretset false :opcollid 0 :inputcollid 0 "
                    ":args ({FUNCEXPR :funcid 1374 :funcresulttype 23 :funcretset false "
                    ":funcvariadic false :funcformat 0 :funccollid 0 :inputcollid 100 "
                    ":args ({VAR :varno 1 :varattno 3 :vartype 25 :vartypmod -1 "
                    ":varcollid 100 :varnullingrels (b) :varlevelsup 0 :varnosyn 1 "
                    ":varattnosyn 3 :location 1023}) :location 1010} {CONST :consttype "
                    "23 :consttypmod -1 :constcollid 0 :constlen 4 :constbyval true "
                    ":constisnull false :location 1053 :constvalue 4 [ 0 16 0 0 0 0 0 0 "
                    "]}) :location 1039}) :location 1039} {OPEXPR :opno 642 :opfuncid "
                    "1256 :opresulttype 16 :opretset false :opcollid 0 :inputcollid 100 "
                    ":args ({VAR :varno 1 :varattno 3 :vartype 25 :vartypmod -1 "
                    ":varcollid 100 :varnullingrels (b) :varlevelsup 0 :varnosyn 1 "
                    ":varattnosyn 3 :location 1062} {CONST :consttype 25 :consttypmod "
                    "-1 :constcollid 100 :constlen -1 :constbyval false :constisnull "
                    "false :location 1080 :constvalue 10 [ 40 0 0 0 91 94 32 45 126 93 "
                    "]}) :location 1077}) :location 1058}",
                    "conkey": [3],
                    "confkey": None,
                    "conname": "ck_social_challenge_wire",
                    "contype": "c",
                    "conindid": "0",
                    "conrelid": "16387",
                    "contypid": "0",
                    "conexclop": None,
                    "conffeqop": None,
                    "confrelid": "0",
                    "conpfeqop": None,
                    "conppeqop": None,
                    "conislocal": True,
                    "condeferred": False,
                    "confdeltype": " ",
                    "confupdtype": " ",
                    "coninhcount": 0,
                    "conparentid": "0",
                    "connamespace": "2200",
                    "connoinherit": False,
                    "convalidated": True,
                    "condeferrable": False,
                    "confmatchtype": " ",
                    "confdelsetcols": None,
                },
                "definition": "CHECK ((((octet_length(challenge_wire) >= 1) AND "
                "(octet_length(challenge_wire) <= 4096)) AND (challenge_wire !~ '[^ "
                "-~]'::text)))",
            },
            {
                "catalog": {
                    "oid": "16395",
                    "conbin": "{BOOLEANTEST :arg {BOOLEXPR :boolop and :args ({OPEXPR :opno 98 "
                    ":opfuncid 67 :opresulttype 16 :opretset false :opcollid 0 "
                    ":inputcollid 100 :args ({OPEXPR :opno 3963 :opfuncid 3948 "
                    ":opresulttype 25 :opretset false :opcollid 100 :inputcollid 100 "
                    ":args ({COERCEVIAIO :arg {VAR :varno 1 :varattno 2 :vartype 25 "
                    ":vartypmod -1 :varcollid 100 :varnullingrels (b) :varlevelsup 0 "
                    ":varnosyn 1 :varattnosyn 2 :location 1350} :resulttype 114 "
                    ":resultcollid 0 :coerceformat 1 :location 1362} {CONST :consttype "
                    "25 :consttypmod -1 :constcollid 100 :constlen -1 :constbyval false "
                    ":constisnull false :location 1373 :constvalue 15 [ 60 0 0 0 99 104 "
                    "97 108 108 101 110 103 101 73 100 ]}) :location 1369} {RELABELTYPE "
                    ":arg {VAR :varno 1 :varattno 1 :vartype 1043 :vartypmod 68 "
                    ":varcollid 100 :varnullingrels (b) :varlevelsup 0 :varnosyn 1 "
                    ":varattnosyn 1 :location 1389} :resulttype 25 :resulttypmod -1 "
                    ":resultcollid 100 :relabelformat 2 :location -1}) :location 1387} "
                    "{OPEXPR :opno 98 :opfuncid 67 :opresulttype 16 :opretset false "
                    ":opcollid 0 :inputcollid 100 :args ({COALESCEEXPR :coalescetype 25 "
                    ":coalescecollid 100 :args ({OPEXPR :opno 3963 :opfuncid 3948 "
                    ":opresulttype 25 :opretset false :opcollid 100 :inputcollid 100 "
                    ":args ({COERCEVIAIO :arg {VAR :varno 1 :varattno 3 :vartype 25 "
                    ":vartypmod -1 :varcollid 100 :varnullingrels (b) :varlevelsup 0 "
                    ":varnosyn 1 :varattnosyn 3 :location 1423} :resulttype 114 "
                    ":resultcollid 0 :coerceformat 1 :location 1437} {CONST :consttype "
                    "25 :consttypmod -1 :constcollid 100 :constlen -1 :constbyval false "
                    ":constisnull false :location 1448 :constvalue 15 [ 60 0 0 0 99 104 "
                    "97 108 108 101 110 103 101 73 100 ]}) :location 1444} {OPEXPR "
                    ":opno 3963 :opfuncid 3948 :opresulttype 25 :opretset false "
                    ":opcollid 100 :inputcollid 100 :args ({COERCEVIAIO :arg {VAR "
                    ":varno 1 :varattno 3 :vartype 25 :vartypmod -1 :varcollid 100 "
                    ":varnullingrels (b) :varlevelsup 0 :varnosyn 1 :varattnosyn 3 "
                    ":location 1480} :resulttype 114 :resultcollid 0 :coerceformat 1 "
                    ":location 1494} {CONST :consttype 25 :consttypmod -1 :constcollid "
                    "100 :constlen -1 :constbyval false :constisnull false :location "
                    "1505 :constvalue 25 [ 100 0 0 0 101 110 114 111 108 108 109 101 "
                    "110 116 67 104 97 108 108 101 110 103 101 73 100 ]}) :location "
                    "1501}) :location 1414} {RELABELTYPE :arg {VAR :varno 1 :varattno 1 "
                    ":vartype 1043 :vartypmod 68 :varcollid 100 :varnullingrels (b) "
                    ":varlevelsup 0 :varnosyn 1 :varattnosyn 1 :location 1532} "
                    ":resulttype 25 :resulttypmod -1 :resultcollid 100 :relabelformat 2 "
                    ":location -1}) :location 1530}) :location 1402} :booltesttype 0 "
                    ":location 1546}",
                    "conkey": [2, 1, 3],
                    "confkey": None,
                    "conname": "ck_social_challenge_wire_id",
                    "contype": "c",
                    "conindid": "0",
                    "conrelid": "16387",
                    "contypid": "0",
                    "conexclop": None,
                    "conffeqop": None,
                    "confrelid": "0",
                    "conpfeqop": None,
                    "conppeqop": None,
                    "conislocal": True,
                    "condeferred": False,
                    "confdeltype": " ",
                    "confupdtype": " ",
                    "coninhcount": 0,
                    "conparentid": "0",
                    "connamespace": "2200",
                    "connoinherit": False,
                    "convalidated": True,
                    "condeferrable": False,
                    "confmatchtype": " ",
                    "confdelsetcols": None,
                },
                "definition": "CHECK ((((((context_wire)::json ->> 'challengeId'::text) = "
                "(challenge_id)::text) AND (COALESCE(((challenge_wire)::json ->> "
                "'challengeId'::text), ((challenge_wire)::json ->> "
                "'enrollmentChallengeId'::text)) = (challenge_id)::text)) IS TRUE))",
            },
            {
                "catalog": {
                    "oid": "16399",
                    "conbin": None,
                    "conkey": [1],
                    "confkey": None,
                    "conname": "social_device_admission_challenges_pkey",
                    "contype": "p",
                    "conindid": "16398",
                    "conrelid": "16387",
                    "contypid": "0",
                    "conexclop": None,
                    "conffeqop": None,
                    "confrelid": "0",
                    "conpfeqop": None,
                    "conppeqop": None,
                    "conislocal": True,
                    "condeferred": False,
                    "confdeltype": " ",
                    "confupdtype": " ",
                    "coninhcount": 0,
                    "conparentid": "0",
                    "connamespace": "2200",
                    "connoinherit": True,
                    "convalidated": True,
                    "condeferrable": False,
                    "confmatchtype": " ",
                    "confdelsetcols": None,
                },
                "definition": "PRIMARY KEY (challenge_id)",
            },
            {
                "catalog": {
                    "oid": "16479",
                    "conbin": None,
                    "conkey": None,
                    "confkey": None,
                    "conname": "trg_social_enrollment_challenge_atomic",
                    "contype": "t",
                    "conindid": "0",
                    "conrelid": "16387",
                    "contypid": "0",
                    "conexclop": None,
                    "conffeqop": None,
                    "confrelid": "0",
                    "conpfeqop": None,
                    "conppeqop": None,
                    "conislocal": True,
                    "condeferred": True,
                    "confdeltype": " ",
                    "confupdtype": " ",
                    "coninhcount": 0,
                    "conparentid": "0",
                    "connamespace": "2200",
                    "connoinherit": True,
                    "convalidated": True,
                    "condeferrable": True,
                    "confmatchtype": " ",
                    "confdelsetcols": None,
                },
                "definition": "TRIGGER DEFERRABLE INITIALLY DEFERRED",
            },
        ],
        "guards": [
            {
                "cost": "42c80000",
                "rows": "00000000",
                "trigger": {
                    "oid": "16401",
                    "tgargs": "\\x",
                    "tgattr": [],
                    "tgfoid": "16400",
                    "tgname": "trg_social_challenge_guard",
                    "tgqual": None,
                    "tgtype": 31,
                    "tgnargs": 0,
                    "tgrelid": "16387",
                    "tgenabled": "O",
                    "tgnewtable": None,
                    "tgoldtable": None,
                    "tgparentid": "0",
                    "tgconstraint": "0",
                    "tgdeferrable": False,
                    "tgisinternal": False,
                    "tgconstrindid": "0",
                    "tgconstrrelid": "0",
                    "tginitdeferred": False,
                },
                "function": {
                    "oid": "16400",
                    "proacl": None,
                    "probin": None,
                    "prosrc": "\n"
                    "BEGIN\n"
                    "    IF TG_OP = 'INSERT' THEN\n"
                    "        IF NEW.state <> 'issued' THEN\n"
                    "            RAISE EXCEPTION 'social device challenge storage "
                    "unavailable';\n"
                    "        END IF;\n"
                    "        RETURN NEW;\n"
                    "    ELSIF TG_OP = 'UPDATE' THEN\n"
                    "        IF ROW(NEW.challenge_id, NEW.context_wire, "
                    "NEW.challenge_wire,\n"
                    "               NEW.routing_request_wire) IS DISTINCT FROM\n"
                    "           ROW(OLD.challenge_id, OLD.context_wire, "
                    "OLD.challenge_wire,\n"
                    "               OLD.routing_request_wire) OR\n"
                    "           OLD.state <> 'issued' THEN\n"
                    "            RAISE EXCEPTION 'social device challenge storage "
                    "unavailable';\n"
                    "        END IF;\n"
                    "        IF NEW.state = 'consumed' THEN\n"
                    "            IF NEW.context_wire::jsonb ->> 'challengeKind' <> "
                    "'enrollment-v2' OR\n"
                    "               NEW.challenge_wire::jsonb ->> 'schema' <>\n"
                    "                   'hodlxxi.social_messaging_device_enrollment.v2' "
                    "THEN\n"
                    "                RAISE EXCEPTION 'social device challenge storage "
                    "unavailable';\n"
                    "            END IF;\n"
                    "        ELSIF NEW.state NOT IN ('expired','invalidated','cancelled') "
                    "THEN\n"
                    "            RAISE EXCEPTION 'social device challenge storage "
                    "unavailable';\n"
                    "        END IF;\n"
                    "        RETURN NEW;\n"
                    "    END IF;\n"
                    "    RAISE EXCEPTION 'social device challenge storage unavailable';\n"
                    "END ",
                    "procost": 100,
                    "prokind": "f",
                    "prolang": "13614",
                    "proname": "guard_social_device_challenge_v1",
                    "prorows": 0,
                    "pronargs": 0,
                    "proowner": "10",
                    "proconfig": None,
                    "proretset": False,
                    "prosecdef": False,
                    "prorettype": "2279",
                    "prosqlbody": None,
                    "prosupport": "-",
                    "proargmodes": None,
                    "proargnames": None,
                    "proargtypes": [],
                    "proisstrict": False,
                    "proparallel": "u",
                    "protrftypes": None,
                    "provariadic": "0",
                    "provolatile": "v",
                    "proleakproof": False,
                    "pronamespace": "2200",
                    "proallargtypes": None,
                    "proargdefaults": None,
                    "pronargdefaults": 0,
                },
                "language": "plpgsql",
                "namespace": "public",
            },
            {
                "cost": "42c80000",
                "rows": "00000000",
                "trigger": {
                    "oid": "16402",
                    "tgargs": "\\x",
                    "tgattr": [],
                    "tgfoid": "16400",
                    "tgname": "trg_social_challenge_no_truncate",
                    "tgqual": None,
                    "tgtype": 34,
                    "tgnargs": 0,
                    "tgrelid": "16387",
                    "tgenabled": "O",
                    "tgnewtable": None,
                    "tgoldtable": None,
                    "tgparentid": "0",
                    "tgconstraint": "0",
                    "tgdeferrable": False,
                    "tgisinternal": False,
                    "tgconstrindid": "0",
                    "tgconstrrelid": "0",
                    "tginitdeferred": False,
                },
                "function": {
                    "oid": "16400",
                    "proacl": None,
                    "probin": None,
                    "prosrc": "\n"
                    "BEGIN\n"
                    "    IF TG_OP = 'INSERT' THEN\n"
                    "        IF NEW.state <> 'issued' THEN\n"
                    "            RAISE EXCEPTION 'social device challenge storage "
                    "unavailable';\n"
                    "        END IF;\n"
                    "        RETURN NEW;\n"
                    "    ELSIF TG_OP = 'UPDATE' THEN\n"
                    "        IF ROW(NEW.challenge_id, NEW.context_wire, "
                    "NEW.challenge_wire,\n"
                    "               NEW.routing_request_wire) IS DISTINCT FROM\n"
                    "           ROW(OLD.challenge_id, OLD.context_wire, "
                    "OLD.challenge_wire,\n"
                    "               OLD.routing_request_wire) OR\n"
                    "           OLD.state <> 'issued' THEN\n"
                    "            RAISE EXCEPTION 'social device challenge storage "
                    "unavailable';\n"
                    "        END IF;\n"
                    "        IF NEW.state = 'consumed' THEN\n"
                    "            IF NEW.context_wire::jsonb ->> 'challengeKind' <> "
                    "'enrollment-v2' OR\n"
                    "               NEW.challenge_wire::jsonb ->> 'schema' <>\n"
                    "                   'hodlxxi.social_messaging_device_enrollment.v2' "
                    "THEN\n"
                    "                RAISE EXCEPTION 'social device challenge storage "
                    "unavailable';\n"
                    "            END IF;\n"
                    "        ELSIF NEW.state NOT IN ('expired','invalidated','cancelled') "
                    "THEN\n"
                    "            RAISE EXCEPTION 'social device challenge storage "
                    "unavailable';\n"
                    "        END IF;\n"
                    "        RETURN NEW;\n"
                    "    END IF;\n"
                    "    RAISE EXCEPTION 'social device challenge storage unavailable';\n"
                    "END ",
                    "procost": 100,
                    "prokind": "f",
                    "prolang": "13614",
                    "proname": "guard_social_device_challenge_v1",
                    "prorows": 0,
                    "pronargs": 0,
                    "proowner": "10",
                    "proconfig": None,
                    "proretset": False,
                    "prosecdef": False,
                    "prorettype": "2279",
                    "prosqlbody": None,
                    "prosupport": "-",
                    "proargmodes": None,
                    "proargnames": None,
                    "proargtypes": [],
                    "proisstrict": False,
                    "proparallel": "u",
                    "protrftypes": None,
                    "provariadic": "0",
                    "provolatile": "v",
                    "proleakproof": False,
                    "pronamespace": "2200",
                    "proallargtypes": None,
                    "proargdefaults": None,
                    "pronargdefaults": 0,
                },
                "language": "plpgsql",
                "namespace": "public",
            },
            {
                "cost": "42c80000",
                "rows": "00000000",
                "trigger": {
                    "oid": "16496",
                    "tgargs": "\\x",
                    "tgattr": [],
                    "tgfoid": "16494",
                    "tgname": "trg_social_challenge_revision_issue",
                    "tgqual": None,
                    "tgtype": 5,
                    "tgnargs": 0,
                    "tgrelid": "16387",
                    "tgenabled": "O",
                    "tgnewtable": None,
                    "tgoldtable": None,
                    "tgparentid": "0",
                    "tgconstraint": "0",
                    "tgdeferrable": False,
                    "tgisinternal": False,
                    "tgconstrindid": "0",
                    "tgconstrrelid": "0",
                    "tginitdeferred": False,
                },
                "function": {
                    "oid": "16494",
                    "proacl": ["issued_challenge_revision_ddl=X/issued_challenge_revision_ddl"],
                    "probin": None,
                    "prosrc": "\n"
                    "BEGIN\n"
                    "    IF TG_OP <> 'INSERT' OR TG_LEVEL <> 'ROW' OR\n"
                    "       TG_TABLE_SCHEMA <> 'public' OR TG_TABLE_NAME <> "
                    "'social_device_admission_challenges' OR\n"
                    "       TG_RELID <> "
                    "'public.social_device_admission_challenges'::pg_catalog.regclass OR\n"
                    "       NEW.state <> 'issued' THEN\n"
                    "        RAISE EXCEPTION 'social device challenge revision "
                    "unavailable';\n"
                    "    END IF;\n"
                    "    INSERT INTO public.social_device_admission_challenge_revisions "
                    "(challenge_id, revision)\n"
                    "        VALUES (NEW.challenge_id, 1);\n"
                    "    RETURN NEW;\n"
                    "END\n",
                    "procost": 100,
                    "prokind": "f",
                    "prolang": "13614",
                    "proname": "issue_social_device_challenge_revision_v1",
                    "prorows": 0,
                    "pronargs": 0,
                    "proowner": "10",
                    "proconfig": ["search_path=pg_catalog"],
                    "proretset": False,
                    "prosecdef": True,
                    "prorettype": "2279",
                    "prosqlbody": None,
                    "prosupport": "-",
                    "proargmodes": None,
                    "proargnames": None,
                    "proargtypes": [],
                    "proisstrict": False,
                    "proparallel": "u",
                    "protrftypes": None,
                    "provariadic": "0",
                    "provolatile": "v",
                    "proleakproof": False,
                    "pronamespace": "2200",
                    "proallargtypes": None,
                    "proargdefaults": None,
                    "pronargdefaults": 0,
                },
                "language": "plpgsql",
                "namespace": "public",
            },
        ],
        "atomic_binding": [
            {
                "oid": 16478,
                "name": "trg_social_enrollment_challenge_atomic",
                "type": 17,
                "parent": 16387,
                "deferred": True,
                "internal": False,
                "constraint": 16479,
                "deferrable": True,
            }
        ],
        "resolves_parent": True,
    },
]
CAPTURED_NATIVE_SECURITY = {
    "no_actual_ddl_authority": True,
    "direct_login": True,
    "role": {
        "oid": "16384",
        "rolname": "issued_challenge_revision_runtime",
        "rolsuper": False,
        "rolconfig": None,
        "rolinherit": True,
        "rolcanlogin": True,
        "rolcreatedb": False,
        "rolpassword": "********",
        "rolbypassrls": False,
        "rolconnlimit": -1,
        "rolcreaterole": False,
        "rolvaliduntil": None,
        "rolreplication": False,
    },
    "origin": True,
    "schema_usage": True,
    "no_schema_create": True,
    "no_owner_membership": True,
    "companion_select": True,
    "companion_read_only": True,
    "no_column_write": True,
    "parent_lock_privilege": True,
    "parent_no_bypass": True,
    "no_execute": True,
    "distinct_owner": True,
}


class CapturedNativeSession(GuardedSession):
    def __init__(self):
        super().__init__()
        self.raw_catalog = deepcopy(CAPTURED_NATIVE_CATALOG)

    def execute(self, statement, parameters=None):
        if str(statement) == storage.SECURITY_SQL:
            return Rows(deepcopy(CAPTURED_NATIVE_SECURITY))
        return super().execute(statement, parameters)


def test_complete_independent_native_capture_constructor_and_repeated_reader():
    session = CapturedNativeSession()
    owners = {r["owner"] for r in session.raw_catalog}
    assert int(CAPTURED_NATIVE_SECURITY["role"]["oid"]) not in owners
    assert all(v is True for k, v in CAPTURED_NATIVE_SECURITY.items() if k != "role")
    reader = storage.SqlAlchemyTransactionBoundIssuedChallengeRevisionReader(session)
    reader._catalog()
    assert read(reader, session).challenge_revision == 1
    assert read(reader, session).challenge_revision == 1


@pytest.mark.parametrize("support", ["0", "1", "pg_catalog.fake_support", None, True, " -"])
def test_independent_native_capture_support_change_poisons_reader(support):
    session = CapturedNativeSession()
    reader = storage.SqlAlchemyTransactionBoundIssuedChallengeRevisionReader(session)
    session.raw_catalog[0]["guards"][0]["function"]["prosupport"] = support
    with pytest.raises(DENIED, match=ERROR) as failure:
        read(reader, session)
    assert failure.value.__cause__ is None and failure.value.__context__ is None
    assert reader._failed and session.transaction.is_active
    session.raw_catalog = deepcopy(CAPTURED_NATIVE_CATALOG)
    with pytest.raises(DENIED, match=ERROR):
        read(reader, session)
