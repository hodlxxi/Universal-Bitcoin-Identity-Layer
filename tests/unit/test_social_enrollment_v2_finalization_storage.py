"""Source/catalog synchronization and the real accepted-history boundary."""

import re
from copy import deepcopy
from pathlib import Path

import pytest

from app.services import social_enrollment_v2_finalization_storage as storage
from app.services.social_enrollment_v2_finalization_contract import FinalizationDenied
from tests.unit.test_social_device_challenge_revision_storage import function, native_json
from tests.unit.test_social_enrollment_v2_finalization import FinalSession, final_graph
from tests.unit.test_social_enrollment_v2_finalization_authority import prepare

ROOT = Path(__file__).parents[2]


@pytest.mark.parametrize(
    "name",
    (
        "social_enrollment_v2_native_associations",
        "social_enrollment_v2_native_effects",
        "social_enrollment_v2_native_consumptions",
        "social_enrollment_v2_native_decisions",
    ),
)
@pytest.mark.parametrize(
    "surface",
    (
        "rewrite",
        "index_options",
        "index_acl",
        "index_unknown",
        "toast_column",
        "toast_index_order",
        "toast_index_options",
        "toast_relation",
        "table_public",
        "table_third_party",
        "column_public",
    ),
)
def test_native_tables_complete_index_toast_definitions(name, surface):
    connection = CompleteCatalogConnection()
    storage.attest_native_schema(connection)
    relation = connection.relations[name]
    oid = relation["oid"]
    toast = relation["reltoastrelid"]
    index = connection.catalog[oid]["to_jsonb(i)"][0]
    if surface == "rewrite":
        relation["relrewrite"] = "777"
    elif surface == "index_options":
        index["relation"]["reloptions"] = ["fillfactor=90"]
    elif surface == "index_acl":
        index["relation"]["relacl"] = ["=r/owner"]
    elif surface == "index_unknown":
        index["relation"]["unknown_native_field"] = 1
    elif surface == "toast_column":
        connection.catalog[toast]["to_jsonb(a)"][0]["attribute"]["attnotnull"] = True
    elif surface == "toast_index_order":
        connection.catalog[toast]["to_jsonb(i)"][0]["index"]["indkey"] = [2, 1]
    elif surface == "toast_index_options":
        connection.catalog[toast]["to_jsonb(i)"][0]["relation"]["reloptions"] = ["fillfactor=90"]
    elif surface == "toast_relation":
        connection.catalog[toast]["to_jsonb(c) AS relation,n.nspname"][0]["relation"]["relrewrite"] = "777"
    elif surface in ("table_public", "table_third_party"):
        connection.catalog[oid]["aclexplode"].append(
            (202, 0 if surface == "table_public" else 707, "SELECT", False, 203)
        )
    else:
        connection.catalog[oid]["column_acl"] = [1]
    assert connection.relations[name]["oid"] == oid
    with pytest.raises(FinalizationDenied):
        storage.attest_native_schema(connection)


def catalog_function(name):
    body, names, returns, config = storage.NATIVE_FUNCTIONS[name]
    row = function(name, body, 101, 202, True)
    p = row["function"]
    p.update(
        proargnames=names,
        pronargs=len(names or ()),
        proargtypes=" ".join("25" for _ in names or ()),
        prorettype=2279 if returns == "trigger" else 2278,
        proconfig=[config],
        prosqlbody=None,
    )
    p = native_json(p, "function")
    p["prosupport"] = "-"
    row["function"] = p
    row.update(executable=name == storage.WRITE_FUNCTION, owns=False)
    return row


@pytest.mark.parametrize("name", storage.NATIVE_FUNCTIONS)
def test_complete_native_function_catalog_and_source_body(name):
    row = catalog_function(name)
    assert storage._attest_function(row, name) == (101, 202, 2200, 13563)
    source = (ROOT / "migrations/2026-10-12_social_enrollment_v2_finalization_v1.sql").read_text()
    match = re.search(r"FUNCTION public\." + name + r"\(.*?AS \$\$(.*?)\$\$;", source, re.S)
    assert match and match.group(1) == storage.NATIVE_FUNCTIONS[name][0]


@pytest.mark.parametrize(
    "field,value",
    [
        ("prosrc", "BEGIN RETURN; END"),
        ("proparallel", "s"),
        ("proleakproof", True),
        ("proisstrict", True),
        ("proconfig", ["search_path=public"]),
        ("prosqlbody", "altered"),
        ("proargdefaults", "altered"),
        ("unclassified", "unknown"),
    ],
)
def test_same_oid_complete_catalog_definition_changes_deny(field, value):
    row = catalog_function(storage.WRITE_FUNCTION)
    row["function"][field] = value
    with pytest.raises(FinalizationDenied):
        storage._attest_function(row, storage.WRITE_FUNCTION)


def test_original_v1_deferred_branch_is_preserved_exactly():
    old = (ROOT / "migrations/2026-09-23_social_device_admission_receipt_consumption_v1.sql").read_text()
    body = re.search(r"FUNCTION assert_social_enrollment_atomic_v1\(\).*?AS \$\$(.*?)\$\$;", old, re.S).group(1)
    combined = storage.NATIVE_FUNCTIONS["assert_social_enrollment_atomic_v1"][0]
    suffix = "    SELECT * INTO challenge FROM social_device_admission_challenges"
    assert combined[combined.index(suffix) :] == body[body.index(suffix) :]
    assert "pg_current_xact_id" in combined and "xmin" not in combined


def test_raw_authentic_accepted_cas_row_does_not_supply_native_effects(final_graph):
    g = final_graph
    with FinalSession(g) as s, s.begin():
        owner = g.finalizer(s)
        candidate = prepare(g, owner)
        record = owner.authority.resolve(candidate)
        from app.services import social_messaging_mobile_pre_enrollment_v2 as v2

        p = v2.parse_preaccepted_enrollment_verification_input_v2(g.input_wire)
        owner.authority.storage.finalize_accepted(
            g.reservation.reservation_id,
            finalization_observation_wire=record.canonical_plan.observation.wire,
            expected_input_wire=g.input_wire,
            expected_context_wire=p.context.wire,
            evidence_compact_jws=g.reservation.evidence_compact_jws,
            evidence_config=g.config.evidence_config,
            statement_compact_jws=g.statement,
            statement_config=g.final_config.statement_config,
            decided_at=record.canonical_plan.observation.observed_at,
        )
    # This SQLite row can pass the ORIGINAL authentic accepted reparser. The
    # native seam still rejects missing actual effects; native SQL rejects its
    # commit as well, to be checked by the separately opt-in integration draft.
    with FinalSession(g) as s, s.begin():
        with pytest.raises(FinalizationDenied):
            g.finalizer(s).finalize(**g.arguments())
    assert g.calls == ["cas"]


@pytest.mark.parametrize(
    "column", ["event_wire", "effect_wire", "receipt_wire", "birth_xid", "evidence_pin", "statement_pin"]
)
def test_altered_retained_native_bytes_or_birth_denies_recovery(final_graph, column):
    g = final_graph
    with FinalSession(g) as s, s.begin():
        g.finalizer(s).finalize(**g.arguments())
    with g.engine.begin() as c:
        c.exec_driver_sql(f"UPDATE social_enrollment_v2_native_effects SET {column}='altered'")
    g.calls.clear()
    with FinalSession(g) as s, s.begin():
        with pytest.raises(FinalizationDenied):
            g.finalizer(s).finalize(**g.arguments())
    assert not g.calls


# These doubles replace unrelated guards, never the shared definition validator.
# Native-shape rows are supplied independently of the validator's expectations.
class CatalogResult:
    def __init__(self, rows):
        self.rows = rows

    def mappings(self):
        return self

    def all(self):
        return self.rows

    def one(self):
        assert len(self.rows) == 1
        return self.rows[0]

    def scalar_one(self):
        return self.one()


def shared_relation(name, oid, *, columns=7, checks=3):
    return dict(
        oid=oid,
        relname=name,
        relnamespace=2200,
        reltype=oid + 10000,
        reloftype=0,
        relowner=202,
        relam=2,
        relfilenode=str(oid),
        reltablespace=0,
        relpages=0,
        reltuples=-1.0,
        relallvisible=0,
        reltoastrelid=oid + 20000,
        relhasindex=True,
        relisshared=False,
        relpersistence="p",
        relkind="r",
        relnatts=columns,
        relchecks=checks,
        relhasrules=False,
        relhastriggers=True,
        relhassubclass=False,
        relrowsecurity=False,
        relforcerowsecurity=False,
        relispopulated=True,
        relreplident="d",
        relispartition=False,
        relrewrite="0",
        relfrozenxid="1",
        relminmxid="1",
        relacl=None,
        reloptions=None,
        relpartbound=None,
    )


class SharedCatalogConnection:
    def __init__(self):
        self.relations = {n: shared_relation(n, 100 + i) for i, n in enumerate(storage.VISIBLE_AUTHORITIES)}
        self.catalog = {}
        self.queries = []

    def execute(self, statement, parameters=None):
        sql, params = str(statement), parameters or {}
        if "/* UBID_FRESH_FINALIZATION_CATALOG */" in sql:
            return _simulate_fresh_catalog_batch(self, sql, params)
        self.queries.append((sql, params))
        if sql == storage.PG16_TYPES_SQL:
            return CatalogResult(deepcopy(getattr(self, "system_types", SOURCE_PG16_TYPES)))
        if "AS opclass" in sql:
            return CatalogResult(deepcopy([getattr(self, "system_opclasses", SOURCE_PG16_OPCLASSES)[params["oid"]]]))
        if "AS operator" in sql:
            return CatalogResult(deepcopy([getattr(self, "system_operators", SOURCE_PG16_OPERATORS)[params["oid"]]]))
        if "AS collation" in sql:
            return CatalogResult(deepcopy([getattr(self, "system_collation", SOURCE_PG16_COLLATION)]))
        if sql == "SELECT pg_catalog.current_schemas(true)":
            return CatalogResult([["pg_catalog", "public"]])
        if "current_user=session_user" in sql:
            return CatalogResult([(True, 2200, 202)])
        if "m.admin_option,m.inherit_option,m.set_option" in sql:
            return CatalogResult([(999, 203, 202, False, True, True)])
        from app.services import social_device_challenge_revision_storage as revision

        if sql == revision.CATALOG_SQL:
            return CatalogResult(deepcopy(self.revision_catalog))
        if sql == storage.AUTHORITY_EFFECTIVE_ACL_SQL:
            name = next(n for n, r in self.relations.items() if r["oid"] == params["oid"])
            order = (
                "SELECT",
                "INSERT",
                "UPDATE",
                "DELETE",
                "TRUNCATE",
                "REFERENCES",
                "TRIGGER",
                "SELECT",
                "INSERT",
                "UPDATE",
                "REFERENCES",
            )
            return CatalogResult(
                [getattr(self, "effective_acls", {}).get(name, tuple(p in SOURCE_AUTHORITY_ACLS[name] for p in order))]
            )
        if "attacl IS NOT NULL" in sql:
            return CatalogResult(self.catalog[params["oid"]].get("column_acl", [0]))
        if sql == storage.FUNCTION_SQL:
            # The transport now retains missing ordinal cells. Render the
            # actual projection even when this fixture stubs function validation.
            return CatalogResult([deepcopy(self.functions[params["name"]])])
        if sql == storage.VISIBILITY_SQL:
            return CatalogResult(
                [
                    dict(relname=n, relation=native_json(r, "relation"), resolves=True, owns=False, standalone=True)
                    for n, r in self.relations.items()
                    if n in params["names"]
                ]
            )
        for marker, rows in self.catalog.get(params.get("oid"), {}).items():
            if marker in sql:
                if params.get("positions") and "to_jsonb(a)" in sql:
                    rows = [r for r in rows if r["attribute"]["attnum"] in params["positions"]]
                if params.get("name") and "to_jsonb(k)" in sql:
                    rows = [r for r in rows if r["constraint"]["conname"] == params["name"]]
                if params.get("name") and "to_jsonb(i)" in sql:
                    rows = [r for r in rows if r["relation"]["relname"] == params["name"]]
                if "to_jsonb(i)" in sql and "AS predicate" not in sql:
                    rows = [{k: v for k, v in r.items() if k != "predicate"} for r in rows]
                if "to_jsonb(t)" in sql and "AS definition" not in sql:
                    rows = [dict(trigger=r["trigger"]) for r in rows]
                elif "to_jsonb(t)" in sql and "constraint_name" not in sql:
                    rows = [dict(trigger=r["trigger"], definition=r["definition"]) for r in rows]
                return CatalogResult(deepcopy(rows))
        raise AssertionError(sql)


@pytest.fixture
def shared_catalog_perimeter(monkeypatch):
    from app.services import social_session_issuance_v2_storage as issuance

    monkeypatch.setattr(
        issuance, "_runtime_role_identity", lambda p: (203, True, True, 1, ("pg_read_all_settings",), (999,))
    )
    connection = SharedCatalogConnection()
    connection.functions = source_functions()
    monkeypatch.setattr(
        storage,
        "_attest_function",
        lambda row, name: (int(connection.functions[name]["function"]["oid"]), 202, 2200, 13563),
    )
    for name in ("_attest_native_table", "_attest_shared_triggers", "_attest_internal_triggers"):
        monkeypatch.setattr(storage, name, lambda *args: [])
    monkeypatch.setattr(storage, "_attest_history_privileges", lambda *args: ())
    return connection


@pytest.mark.parametrize("replacement", ["column", "constraint", "partial_index"])
def test_same_oid_shared_replacements_deny_before_mutation(shared_catalog_perimeter, replacement):
    c = shared_catalog_perimeter
    # The complete fixture is filled from pinned migration source below. The old
    # attestor ignores every one of these catalog queries, including corrupt rows.
    populate_shared_catalog(c)
    oid = c.relations["social_device_ed25519_association_events"]["oid"]
    if replacement == "column":
        c.catalog[oid]["to_jsonb(a)"][0]["attribute"]["attnotnull"] = False
    elif replacement == "constraint":
        c.catalog[oid]["to_jsonb(k)"][2]["definition"] = "CHECK (true)"
    else:
        c.catalog[oid]["to_jsonb(i)"][1]["predicate"] = "true"
    with pytest.raises(FinalizationDenied):
        storage.attest_native_schema(c)


# Independent pinned migration fixture definitions, never installed expectations.
# Fixed PG16 normal forms transcribed from the two pinned legacy migrations.
CHAIN = "social_device_ed25519_association_chains"
EVENT = "social_device_ed25519_association_events"
LEGACY_RECEIPT = "social_device_enrollment_admission_receipts"
SHARED_COLUMNS = {
    CHAIN: (
        ("subject", 1043, 68, True),
        ("device_id", 1043, 68, True),
        ("authority_epoch", 20, -1, True),
        ("last_association_id", 1043, 68, False),
        ("last_association_version", 20, -1, False),
        ("current_association_id", 1043, 68, False),
        ("state", 1043, 11, True),
    ),
    EVENT: (
        ("subject", 1043, 68, True),
        ("device_id", 1043, 68, True),
        ("authority_epoch", 20, -1, True),
        ("kind", 1043, 14, True),
        ("association_id", 1043, 68, True),
        ("association_version", 20, -1, True),
        ("predecessor_association_id", 1043, 68, False),
        ("ed25519_public_key", 1043, 68, False),
        ("enrollment_challenge_id", 1043, 68, False),
        ("event_wire", 25, -1, True),
    ),
    LEGACY_RECEIPT: (
        ("receipt_id", 1043, 68, True),
        ("challenge_id", 1043, 68, True),
        ("operation", 1043, 23, True),
        ("decided_at", 20, -1, True),
        ("effect_id", 1043, 68, True),
        ("effect_digest", 1043, 68, True),
        ("proposed_association_id", 1043, 68, True),
        ("authority_wire", 25, -1, True),
        ("receipt_wire", 25, -1, True),
    ),
}


def _hex_check(column):
    return f"CHECK ((({column})::text ~ '^[0-9a-f]{{64}}$'::text))"


def _kinds(values):
    return "((kind)::text = ANY ((ARRAY[" + ", ".join(f"'{v}'::character varying" for v in values) + "])::text[]))"


CREATION_PREDICATE = _kinds(("initial", "rotate", "reenroll"))
PREDECESSOR_PREDICATE = _kinds(("rotate", "reenroll"))
SHARED_CHECKS = {
    CHAIN: (
        ("ck_social_ed25519_chain_subject", _hex_check("subject"), [1]),
        ("ck_social_ed25519_chain_device", _hex_check("device_id"), [2]),
        (
            "ck_social_ed25519_chain_state",
            "CHECK (((((state)::text = 'empty'::text) AND (authority_epoch = 0) AND (last_association_id IS NULL) AND (last_association_version IS NULL) AND (current_association_id IS NULL)) OR (((state)::text = 'active'::text) AND (authority_epoch >= 1) AND (last_association_id IS NOT NULL) AND (last_association_version >= 1) AND ((current_association_id)::text = (last_association_id)::text)) OR (((state)::text = 'revoked'::text) AND (authority_epoch >= 2) AND (last_association_id IS NOT NULL) AND (last_association_version >= 1) AND (current_association_id IS NULL))))",
            [7, 3, 4, 5, 6],
        ),
    ),
    EVENT: (
        ("ck_social_ed25519_event_subject", _hex_check("subject"), [1]),
        ("ck_social_ed25519_event_device", _hex_check("device_id"), [2]),
        ("ck_social_ed25519_event_id", _hex_check("association_id"), [5]),
        (
            "ck_social_ed25519_event_predecessor",
            "CHECK (((predecessor_association_id IS NULL) OR ((predecessor_association_id)::text ~ '^[0-9a-f]{64}$'::text)))",
            [7],
        ),
        (
            "ck_social_ed25519_event_key",
            "CHECK (((ed25519_public_key IS NULL) OR ((ed25519_public_key)::text ~ '^[0-9a-f]{64}$'::text)))",
            [8],
        ),
        (
            "ck_social_ed25519_event_challenge",
            "CHECK (((enrollment_challenge_id IS NULL) OR ((enrollment_challenge_id)::text ~ '^[0-9a-f]{64}$'::text)))",
            [9],
        ),
        (
            "ck_social_ed25519_event_bounds",
            "CHECK ((((authority_epoch >= 1) AND (authority_epoch <= '9007199254740991'::bigint)) AND ((association_version >= 1) AND (association_version <= '9007199254740991'::bigint))))",
            [3, 6],
        ),
        (
            "ck_social_ed25519_event_kind",
            "CHECK (("
            + _kinds(("initial", "rotate", "invalidate", "revoke", "reenroll"))
            + " AND (("
            + CREATION_PREDICATE
            + " AND (ed25519_public_key IS NOT NULL) AND (enrollment_challenge_id IS NOT NULL)) OR ("
            + _kinds(("invalidate", "revoke"))
            + " AND (ed25519_public_key IS NULL) AND (enrollment_challenge_id IS NULL)))))",
            [4, 8, 9],
        ),
    ),
    LEGACY_RECEIPT: (
        ("ck_social_enrollment_receipt_id", _hex_check("receipt_id"), [1]),
        ("ck_social_enrollment_receipt_challenge", _hex_check("challenge_id"), [2]),
        ("ck_social_enrollment_receipt_effect_id", _hex_check("effect_id"), [5]),
        ("ck_social_enrollment_receipt_effect_digest", _hex_check("effect_digest"), [6]),
        ("ck_social_enrollment_receipt_association", _hex_check("proposed_association_id"), [7]),
        ("ck_social_enrollment_receipt_operation", "CHECK (((operation)::text = 'enrollment-activate'::text))", [3]),
        (
            "ck_social_enrollment_receipt_decided_at",
            "CHECK (((decided_at >= 0) AND (decided_at <= '9007199254740991'::bigint)))",
            [4],
        ),
        (
            "ck_social_enrollment_receipt_authority_wire",
            "CHECK ((((octet_length(authority_wire) >= 1) AND (octet_length(authority_wire) <= 8192)) AND (authority_wire !~ '[^ -~]'::text)))",
            [8],
        ),
        (
            "ck_social_enrollment_receipt_wire",
            "CHECK ((((octet_length(receipt_wire) >= 1) AND (octet_length(receipt_wire) <= 2048)) AND (receipt_wire !~ '[^ -~]'::text)))",
            [9],
        ),
    ),
}
SHARED_KEYS = {
    CHAIN: {
        "pk_social_ed25519_chain": ("p", [1, 2], None, None),
        "trg_social_ed25519_chain_initialized": ("t", None, None, None),
    },
    EVENT: {
        "pk_social_ed25519_event": ("p", [1, 2, 3], None, None),
        "fk_social_ed25519_event_chain": ("f", [1, 2], CHAIN, [1, 2]),
        "trg_social_enrollment_event_atomic": ("t", None, None, None),
    },
    LEGACY_RECEIPT: {
        LEGACY_RECEIPT + "_pkey": ("p", [1], None, None),
        "uq_social_enrollment_receipt_challenge": ("u", [2], None, None),
        "uq_social_enrollment_receipt_effect": ("u", [5], None, None),
        "fk_social_enrollment_receipt_challenge": ("f", [2], "social_device_admission_challenges", [1]),
        "trg_social_enrollment_receipt_atomic": ("t", None, None, None),
    },
}
SHARED_PARTIAL_INDEXES = {
    "uq_social_ed25519_creation_id": ([5], CREATION_PREDICATE),
    "uq_social_ed25519_creation_version": ([1, 2, 6], CREATION_PREDICATE),
    "uq_social_ed25519_creation_predecessor": ([7], PREDECESSOR_PREDICATE),
    "uq_social_ed25519_creation_key": ([1, 2, 8], CREATION_PREDICATE),
    "uq_social_ed25519_creation_challenge": ([9], CREATION_PREDICATE),
}


# Ancillary CAS relation definitions absent from the original function/trigger guard.
# Its native API/canonical rules remain solely in the original guard.
SHARED_COLUMNS["social_preaccepted_enrollment_v2_atomic_acceptances"] = (
    ("reservation_id", 1043, 68, True),
    ("reservation_revision", 20, -1, True),
    ("request_id", 1043, 68, True),
    ("operation_id", 1043, 68, True),
    ("subject", 1043, 68, True),
    ("device_id", 1043, 68, True),
    ("acceptance_id", 1043, 68, True),
    ("challenge_id", 1043, 68, True),
    ("challenge_revision", 20, -1, True),
    ("association_id", 1043, 68, True),
    ("input_digest", 1043, 135, True),
    ("input_payload_digest", 1043, 150, True),
    ("evidence_token_id", 1043, 68, True),
    ("evidence_digest", 1043, 143, True),
    ("evidence_payload_digest", 1043, 142, True),
    ("state", 1043, 13, True),
    ("created_at", 20, -1, True),
    ("expires_at", 20, -1, True),
    ("decided_at", 20, -1, False),
    ("statement_digest", 1043, 150, False),
    ("effect_id", 1043, 68, False),
    ("effect_digest", 1043, 133, False),
    ("receipt_id", 1043, 68, False),
    ("finalization_request_digest", 1043, 147, False),
    ("reservation_wire", 25, -1, True),
    ("input_wire", 25, -1, True),
    ("evidence_compact_jws", 25, -1, True),
    ("statement_compact_jws", 25, -1, False),
    ("finalization_observation_wire", 25, -1, False),
    ("effect_wire", 25, -1, False),
    ("receipt_wire", 25, -1, False),
)
SHARED_CHECKS["social_preaccepted_enrollment_v2_atomic_acceptances"] = (
    ("ck_social_preaccepted_v2_reservation_id", "CHECK (((reservation_id)::text ~ '^[0-9a-f]{64}$'::text))", [1]),
    ("ck_social_preaccepted_v2_request_id", "CHECK (((request_id)::text ~ '^[0-9a-f]{64}$'::text))", [3]),
    ("ck_social_preaccepted_v2_operation_id", "CHECK (((operation_id)::text ~ '^[0-9a-f]{64}$'::text))", [4]),
    ("ck_social_preaccepted_v2_subject", "CHECK (((subject)::text ~ '^[0-9a-f]{64}$'::text))", [5]),
    ("ck_social_preaccepted_v2_device_id", "CHECK (((device_id)::text ~ '^[0-9a-f]{64}$'::text))", [6]),
    ("ck_social_preaccepted_v2_acceptance_id", "CHECK (((acceptance_id)::text ~ '^[0-9a-f]{64}$'::text))", [7]),
    ("ck_social_preaccepted_v2_challenge_id", "CHECK (((challenge_id)::text ~ '^[0-9a-f]{64}$'::text))", [8]),
    ("ck_social_preaccepted_v2_association_id", "CHECK (((association_id)::text ~ '^[0-9a-f]{64}$'::text))", [10]),
    ("ck_social_preaccepted_v2_token_id", "CHECK (((evidence_token_id)::text ~ '^[0-9a-f]{64}$'::text))", [13]),
    ("ck_social_preaccepted_v2_revision", "CHECK ((reservation_revision = 1))", [2]),
    (
        "ck_social_preaccepted_v2_challenge_revision",
        "CHECK (((challenge_revision >= 1) AND (challenge_revision <= '9007199254740991'::bigint)))",
        [9],
    ),
    (
        "ck_social_preaccepted_v2_state",
        "CHECK (((state)::text = ANY ((ARRAY['pending'::character varying, 'accepted'::character varying, 'rejected'::character varying, 'expired'::character varying, 'cancelled'::character varying])::text[])))",
        [16],
    ),
    (
        "ck_social_preaccepted_v2_times",
        "CHECK ((((created_at >= 0) AND (created_at <= '9007199254740991'::bigint)) AND ((expires_at >= 1) AND (expires_at <= '9007199254740991'::bigint)) AND (created_at < expires_at) AND ((decided_at IS NULL) OR ((decided_at >= 0) AND (decided_at <= '9007199254740991'::bigint)))))",
        [17, 18, 19],
    ),
    (
        "ck_social_preaccepted_v2_reservation_wire",
        "CHECK ((((octet_length(reservation_wire) >= 1) AND (octet_length(reservation_wire) <= 8192)) AND (reservation_wire !~ '[^ -~]'::text)))",
        [25],
    ),
    (
        "ck_social_preaccepted_v2_input_wire",
        "CHECK ((((octet_length(input_wire) >= 1) AND (octet_length(input_wire) <= 24576)) AND (input_wire !~ '[^ -~]'::text)))",
        [26],
    ),
    (
        "ck_social_preaccepted_v2_evidence_wire",
        "CHECK ((((octet_length(evidence_compact_jws) >= 1) AND (octet_length(evidence_compact_jws) <= 16384)) AND (evidence_compact_jws !~ '[^ -~]'::text)))",
        [27],
    ),
    (
        "ck_social_preaccepted_v2_statement_wire",
        "CHECK (((statement_compact_jws IS NULL) OR (((octet_length(statement_compact_jws) >= 1) AND (octet_length(statement_compact_jws) <= 4096)) AND (statement_compact_jws !~ '[^ -~]'::text))))",
        [28],
    ),
    (
        "ck_social_preaccepted_v2_observation_wire",
        "CHECK (((finalization_observation_wire IS NULL) OR (((octet_length(finalization_observation_wire) >= 1) AND (octet_length(finalization_observation_wire) <= 16384)) AND (finalization_observation_wire !~ '[^ -~]'::text))))",
        [29],
    ),
    (
        "ck_social_preaccepted_v2_effect_wire",
        "CHECK (((effect_wire IS NULL) OR (((octet_length(effect_wire) >= 1) AND (octet_length(effect_wire) <= 8192)) AND (effect_wire !~ '[^ -~]'::text))))",
        [30],
    ),
    (
        "ck_social_preaccepted_v2_receipt_wire",
        "CHECK (((receipt_wire IS NULL) OR (((octet_length(receipt_wire) >= 1) AND (octet_length(receipt_wire) <= 8192)) AND (receipt_wire !~ '[^ -~]'::text))))",
        [31],
    ),
)
SHARED_KEYS["social_preaccepted_enrollment_v2_atomic_acceptances"] = {
    "social_preaccepted_enrollment_v2_atomic_acceptances_pkey": ("p", [1], None, None),
    "uq_social_preaccepted_v2_acceptance_request": ("u", [3], None, None),
    "uq_social_preaccepted_v2_acceptance_operation": ("u", [4], None, None),
    "uq_social_preaccepted_v2_acceptance_device": ("u", [6], None, None),
    "uq_social_preaccepted_v2_acceptance_acceptance": ("u", [7], None, None),
    "uq_social_preaccepted_v2_acceptance_challenge": ("u", [8], None, None),
    "uq_social_preaccepted_v2_acceptance_association": ("u", [10], None, None),
    "uq_social_preaccepted_v2_acceptance_input": ("u", [11], None, None),
    "uq_social_preaccepted_v2_acceptance_evidence_token": ("u", [13], None, None),
    "uq_social_preaccepted_v2_acceptance_evidence": ("u", [14], None, None),
    "uq_social_preaccepted_v2_acceptance_effect": ("u", [21], None, None),
    "uq_social_preaccepted_v2_acceptance_receipt": ("u", [23], None, None),
}


def fixture_attributes(r, columns):
    result = []
    for pos, (name, typ, mod, required) in enumerate(columns, 1):
        scalar = typ in (20, 23, 26)
        a = dict(
            attrelid=r["oid"],
            attname=name,
            atttypid=typ,
            attstattarget=-1,
            attlen=8 if typ == 20 else 4 if scalar else -1,
            attnum=pos,
            attndims=0,
            attcacheoff=-1,
            atttypmod=mod,
            attbyval=scalar,
            attstorage="p" if scalar or typ == 17 else "x",
            attcompression="",
            attalign="d" if typ == 20 else "i",
            attnotnull=required,
            atthasdef=False,
            atthasmissing=False,
            attidentity="",
            attgenerated="",
            attisdropped=False,
            attislocal=True,
            attinhcount=0,
            attcollation=100 if typ in (25, 1043) else 0,
            attacl=None,
            attoptions=None,
            attfdwoptions=None,
            attmissingval=None,
        )
        result.append(dict(attribute=native_json(a, "attribute")))
    return result


def fixture_index(r, name, columns, keys, kind, predicate, oid):
    ir = shared_relation(name, oid, columns=len(keys), checks=0)
    ir.update(
        relowner=r["relowner"],
        relnamespace=r["relnamespace"],
        reltype=0,
        reltoastrelid=0,
        relkind="i",
        relam=403,
        relhasindex=False,
        relhastriggers=False,
        relreplident="n",
    )
    types = [columns[k - 1][1] for k in keys]
    i = dict(
        indexrelid=oid,
        indrelid=r["oid"],
        indnatts=len(keys),
        indnkeyatts=len(keys),
        indisunique=kind != "n",
        indnullsnotdistinct=False,
        indisprimary=kind == "p" or r["relkind"] == "t",
        indisexclusion=False,
        indimmediate=True,
        indisclustered=False,
        indisvalid=True,
        indcheckxmin=False,
        indisready=True,
        indislive=True,
        indisreplident=False,
        indkey=" ".join(map(str, keys)),
        indcollation=" ".join("100" if t in (25, 1043) else "0" for t in types),
        indclass=" ".join(
            str({20: 3124, 23: 1978, 26: 1981, 25: 3126, 1043: 3126, 16: 10003, 1114: 3128, 1184: 3127}[t])
            for t in types
        ),
        indoption=" ".join("0" for _ in keys),
        indexprs=None,
        indpred="{PINNED PG16 EXPRESSION}" if predicate else None,
    )
    schema = "pg_toast" if r["relkind"] == "t" else "public"
    definition = (
        f"CREATE {'UNIQUE ' if kind != 'n' else ''}INDEX {name} ON {schema}.{r['relname']} USING btree ("
        + ", ".join(columns[k - 1][0] for k in keys)
        + ")"
    )
    if predicate:
        definition += " WHERE " + predicate
    return dict(
        index=native_json(i, "index"), relation=native_json(ir, "relation"), definition=definition, predicate=predicate
    )


def populate_shared_catalog(connection):
    from tests.unit.test_social_device_challenge_revision_storage import native_catalog, reviewed_catalog

    original = reviewed_catalog()
    for row in original:
        r = shared_relation(
            row["relation"]["relname"],
            row["oid"],
            columns=row["relation"]["relnatts"],
            checks=row["relation"]["relchecks"],
        )
        r.update(relowner=row["owner"], reltype=row["row_type"], reltoastrelid=row["toast_oid"])
        connection.relations[r["relname"]] = r
        columns = [(a["attname"], a["atttypid"], a["atttypmod"], a["attnotnull"]) for a in row["attributes"]]
        connection.catalog[r["oid"]] = {"to_jsonb(a)": fixture_attributes(r, columns), "pg_attrdef": [0]}
    connection.revision_catalog = native_catalog(original)
    index_ids = {}
    pk_ids = {}
    next_oid = 500
    for name, columns in SHARED_COLUMNS.items():
        r = connection.relations[name]
        r.update(relnatts=len(columns), relchecks=len(SHARED_CHECKS[name]))
        if name == CHAIN:
            r["reltoastrelid"] = 0
        entries = {
            "to_jsonb(a)": fixture_attributes(r, columns),
            "pg_attrdef": [0],
            "to_jsonb(i)": [],
            "to_jsonb(k)": [],
        }
        connection.catalog[r["oid"]] = entries
        owner_privs = ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")
        runtime_privs = ("SELECT",) if name == EVENT else ("SELECT", "UPDATE")
        if name == "social_preaccepted_enrollment_v2_atomic_acceptances":
            runtime_privs += ("INSERT",)
        entries["aclexplode"] = [(202, 202, p, False, 203) for p in owner_privs] + [
            (202, 203, p, False, 203) for p in runtime_privs
        ]
        specs = {n: (kind, keys, None) for n, (kind, keys, _, _) in SHARED_KEYS[name].items() if kind in ("p", "u")}
        if name == EVENT:
            specs.update({n: ("u", keys, pred) for n, (keys, pred) in SHARED_PARTIAL_INDEXES.items()})
        for n, (kind, keys, pred) in specs.items():
            next_oid += 1
            index_ids[n] = next_oid
            entries["to_jsonb(i)"].append(fixture_index(r, n, columns, keys, kind, pred, next_oid))
        t = shared_relation(f"pg_toast_{r['oid']}", r["reltoastrelid"], columns=3, checks=0)
        t.update(relnamespace=99, reltype=0, reltoastrelid=0, relkind="t", relhastriggers=False, relreplident="n")
        tc = (("chunk_id", 26, -1, False), ("chunk_seq", 23, -1, False), ("chunk_data", 17, -1, False))
        connection.catalog[t["oid"]] = {
            "to_jsonb(c) AS relation,n.nspname": [dict(relation=native_json(t, "relation"), nspname="pg_toast")],
            "to_jsonb(a)": fixture_attributes(t, tc),
            "pg_attrdef": [0],
            "to_jsonb(i)": [fixture_index(t, t["relname"] + "_index", tc, [1, 2], "u", None, next_oid + 100)],
            "count(*) FROM pg_catalog.pg_constraint": [0],
        }
    index_ids["social_device_admission_challenges_pkey"] = 310
    for name, columns in SHARED_COLUMNS.items():
        r = connection.relations[name]
        specs = dict(SHARED_KEYS[name])
        checks = {n: (d, k) for n, d, k in SHARED_CHECKS[name]}
        specs.update({n: ("c", k, None, None) for n, (d, k) in checks.items()})
        for n, (kind, keys, parent, parent_keys) in specs.items():
            next_oid += 1
            backing = (
                index_ids[n]
                if kind in ("p", "u")
                else (
                    index_ids[
                        "pk_social_ed25519_chain" if parent == CHAIN else "social_device_admission_challenges_pkey"
                    ]
                    if parent
                    else 0
                )
            )
            target = connection.relations[parent]["oid"] if parent else 0
            deferred = kind == "t" or n == "fk_social_enrollment_receipt_challenge"
            ops = [98 for _ in parent_keys] if parent else None
            c = dict(
                oid=next_oid,
                conname=n,
                connamespace=2200,
                contype=kind,
                condeferrable=deferred,
                condeferred=deferred,
                convalidated=True,
                conrelid=r["oid"],
                contypid=0,
                conindid=backing,
                conparentid=0,
                confrelid=target,
                confupdtype="a" if parent else " ",
                confdeltype="a" if parent else " ",
                confmatchtype="s" if parent else " ",
                conislocal=True,
                coninhcount=0,
                connoinherit=kind != "c",
                conkey=keys,
                confkey=parent_keys,
                conpfeqop=ops,
                conppeqop=ops,
                conffeqop=ops,
                confdelsetcols=None,
                conexclop=None,
                conbin="{PINNED PG16 CHECK}" if kind == "c" else None,
            )
            if kind == "c":
                definition = checks[n][0]
            elif kind == "t":
                definition = "TRIGGER DEFERRABLE INITIALLY DEFERRED"
            else:
                names = ", ".join(columns[k - 1][0] for k in keys)
                if parent:
                    target_cols = SHARED_COLUMNS.get(parent, (("challenge_id", 1043, 68, True),))
                    definition = (
                        f"FOREIGN KEY ({names}) REFERENCES {parent}("
                        + ", ".join(target_cols[k - 1][0] for k in parent_keys)
                        + ")"
                    )
                    if deferred:
                        definition += " DEFERRABLE INITIALLY DEFERRED"
                else:
                    definition = ("PRIMARY KEY" if kind == "p" else "UNIQUE") + f" ({names})"
            connection.catalog[r["oid"]]["to_jsonb(k)"].append(
                dict(constraint=native_json(c, "constraint"), definition=definition)
            )
            if kind == "p":
                pk_ids[r["oid"]] = (next_oid, backing)
    pk_ids[connection.relations["social_device_admission_challenges"]["oid"]] = (60, 310)
    for oid, pk in pk_ids.items():
        connection.catalog.setdefault(oid, {})["SELECT oid::bigint,conindid::bigint"] = [pk]
    populate_dependency_catalog(connection)


def test_shared_complete_pinned_catalog_positive_and_fresh(shared_catalog_perimeter):
    c = shared_catalog_perimeter
    populate_shared_catalog(c)
    first = storage.attest_native_schema(c)
    first_queries = len(c.queries)
    assert storage.attest_native_schema(c) == first
    assert len(c.queries) == 2 * first_queries


@pytest.mark.parametrize(
    "field,value",
    [
        ("attname", "replacement"),
        ("atttypid", "25"),
        ("atttypmod", 69),
        ("attndims", 1),
        ("attcollation", "0"),
        ("attnotnull", False),
        ("atthasdef", True),
        ("attgenerated", "s"),
        ("attidentity", "a"),
        ("attisdropped", True),
        ("attislocal", False),
        ("attinhcount", 1),
        ("atthasmissing", True),
        ("attmissingval", ["x"]),
        ("attcompression", "p"),
        ("attoptions", ["n_distinct=1"]),
        ("attacl", ["extra"]),
        ("attstorage", "p"),
        ("attstattarget", "-1"),
        ("attlen", True),
        ("attnum", "1"),
        ("attrelid", "001"),
        ("unclassified", False),
    ],
)
def test_shared_column_complete_stable_fields_deny(shared_catalog_perimeter, field, value):
    c = shared_catalog_perimeter
    populate_shared_catalog(c)
    oid = c.relations[EVENT]["oid"]
    c.catalog[oid]["to_jsonb(a)"][0]["attribute"][field] = value
    with pytest.raises(FinalizationDenied):
        storage.attest_native_schema(c)


@pytest.mark.parametrize("kind", ["attribute", "constraint", "index"])
@pytest.mark.parametrize("change", ["missing", "extra", "duplicate", "unknown_field", "missing_field"])
def test_shared_catalog_closed_rows(shared_catalog_perimeter, kind, change):
    c = shared_catalog_perimeter
    populate_shared_catalog(c)
    marker = {"attribute": "to_jsonb(a)", "constraint": "to_jsonb(k)", "index": "to_jsonb(i)"}[kind]
    rows = c.catalog[c.relations[EVENT]["oid"]][marker]
    if change == "missing":
        rows.pop()
    elif change == "extra":
        rows.append(deepcopy(rows[0]))
    elif change == "duplicate":
        rows[-1] = deepcopy(rows[0])
    elif change == "unknown_field":
        rows[0]["unexpected"] = 0
    else:
        rows[0][kind].pop(next(iter(rows[0][kind])))
    with pytest.raises(FinalizationDenied):
        storage.attest_native_schema(c)


@pytest.mark.parametrize(
    "field,value",
    [
        ("indrelid", "9999"),
        ("indkey", [1]),
        ("indkey", [2, 1, 6]),
        ("indclass", ["1978"]),
        ("indoption", [1]),
        ("indcollation", ["0"]),
        ("indnatts", 2),
        ("indnkeyatts", 0),
        ("indisunique", False),
        ("indisprimary", True),
        ("indisexclusion", True),
        ("indimmediate", False),
        ("indisvalid", False),
        ("indisready", False),
        ("indislive", False),
        ("indcheckxmin", True),
        ("indnullsnotdistinct", True),
        ("indisreplident", True),
        ("indexprs", "{REPLACED}"),
        ("indpred", None),
        ("unexpected", None),
    ],
)
def test_shared_partial_index_all_definition_flags_deny(shared_catalog_perimeter, field, value):
    c = shared_catalog_perimeter
    populate_shared_catalog(c)
    row = c.catalog[c.relations[EVENT]["oid"]]["to_jsonb(i)"][1]
    row["index"][field] = value
    with pytest.raises(FinalizationDenied):
        storage.attest_native_schema(c)


@pytest.mark.parametrize(
    "name,keys,kinds",
    [
        ("uq_social_ed25519_creation_id", [5], ("initial", "rotate", "reenroll")),
        ("uq_social_ed25519_creation_version", [1, 2, 6], ("initial", "rotate", "reenroll")),
        ("uq_social_ed25519_creation_predecessor", [7], ("rotate", "reenroll")),
        ("uq_social_ed25519_creation_key", [1, 2, 8], ("initial", "rotate", "reenroll")),
        ("uq_social_ed25519_creation_challenge", [9], ("initial", "rotate", "reenroll")),
    ],
)
def test_all_five_partial_indexes_fixed_predicates(shared_catalog_perimeter, name, keys, kinds):
    c = shared_catalog_perimeter
    populate_shared_catalog(c)
    row = next(r for r in c.catalog[c.relations[EVENT]["oid"]]["to_jsonb(i)"] if r["relation"]["relname"] == name)
    assert row["index"]["indkey"] == keys
    assert row["predicate"] == _kinds(kinds)
    row["predicate"] = _kinds(kinds[:-1])
    with pytest.raises(FinalizationDenied):
        storage.attest_native_schema(c)


@pytest.mark.parametrize(
    "field,value",
    [
        ("confrelid", "9999"),
        ("conindid", "9999"),
        ("conkey", [2, 1]),
        ("confkey", [2, 1]),
        ("conpfeqop", ["98", "410"]),
        ("conppeqop", ["410", "98"]),
        ("conffeqop", ["410", "98"]),
        ("confupdtype", "c"),
        ("confdeltype", "c"),
        ("confmatchtype", "f"),
        ("condeferrable", True),
        ("condeferred", True),
        ("convalidated", False),
        ("conislocal", False),
        ("coninhcount", 1),
        ("conparentid", "99"),
        ("connoinherit", False),
        ("confdelsetcols", [1]),
        ("unexpected", 0),
    ],
)
def test_shared_fk_full_identity_actions_keys_deny(shared_catalog_perimeter, field, value):
    c = shared_catalog_perimeter
    populate_shared_catalog(c)
    row = next(r for r in c.catalog[c.relations[EVENT]["oid"]]["to_jsonb(k)"] if r["constraint"]["contype"] == "f")
    row["constraint"][field] = value
    with pytest.raises(FinalizationDenied):
        storage.attest_native_schema(c)


@pytest.mark.parametrize(
    "target", [CHAIN, EVENT, LEGACY_RECEIPT, "social_preaccepted_enrollment_v2_atomic_acceptances"]
)
@pytest.mark.parametrize("replacement", ["nullable", "check", "backing_index", "default", "extra_acl"])
def test_each_shared_relation_fresh_definition_deny(shared_catalog_perimeter, target, replacement):
    c = shared_catalog_perimeter
    populate_shared_catalog(c)
    storage.attest_native_schema(c)
    entries = c.catalog[c.relations[target]["oid"]]
    if replacement == "nullable":
        entries["to_jsonb(a)"][0]["attribute"]["attnotnull"] = False
    elif replacement == "check":
        next(r for r in entries["to_jsonb(k)"] if r["constraint"]["contype"] == "c")["definition"] = "CHECK (true)"
    elif replacement == "backing_index":
        entries["to_jsonb(k)"][0]["constraint"]["conindid"] = "99999"
    elif replacement == "default":
        entries["pg_attrdef"] = [1]
    else:
        entries["aclexplode"].append((202, 999, "SELECT", False, 203))
    with pytest.raises(FinalizationDenied):
        storage.attest_native_schema(c)


@pytest.mark.parametrize(
    "field,value",
    [
        ("reloptions", ["fillfactor=90"]),
        ("relam", "999"),
        ("relreplident", "f"),
        ("relrewrite", "999"),
        ("relchecks", 99),
        ("relnatts", 99),
        ("unclassified", 0),
    ],
)
def test_shared_relation_stable_definition_deny(shared_catalog_perimeter, field, value):
    c = shared_catalog_perimeter
    populate_shared_catalog(c)
    c.relations[EVENT][field] = value
    with pytest.raises(FinalizationDenied):
        storage.attest_native_schema(c)


@pytest.mark.parametrize(
    "field,value",
    [
        ("relfilenode", "999"),
        ("relpages", 99),
        ("reltuples", 99.5),
        ("relallvisible", 9),
        ("relfrozenxid", "999"),
        ("relminmxid", "999"),
    ],
)
def test_shared_physical_state_is_not_definition(shared_catalog_perimeter, field, value):
    c = shared_catalog_perimeter
    populate_shared_catalog(c)
    first = storage.attest_native_schema(c)
    c.relations[EVENT][field] = value
    assert storage.attest_native_schema(c) == first


def test_index_cluster_selection_is_maintenance(shared_catalog_perimeter):
    c = shared_catalog_perimeter
    populate_shared_catalog(c)
    first = storage.attest_native_schema(c)
    c.catalog[c.relations[EVENT]["oid"]]["to_jsonb(i)"][1]["index"]["indisclustered"] = True
    assert storage.attest_native_schema(c) == first


def test_wrong_referenced_primary_index_deny(shared_catalog_perimeter):
    c = shared_catalog_perimeter
    populate_shared_catalog(c)
    c.catalog[c.relations[CHAIN]["oid"]]["SELECT oid::bigint,conindid::bigint"] = [(700, 999)]
    with pytest.raises(FinalizationDenied):
        storage.attest_native_schema(c)


def test_shared_toast_columns_and_indexes_are_closed(shared_catalog_perimeter):
    c = shared_catalog_perimeter
    populate_shared_catalog(c)
    oid = c.relations[EVENT]["reltoastrelid"]
    c.catalog[oid]["to_jsonb(a)"][2]["attribute"]["attstorage"] = "x"
    with pytest.raises(FinalizationDenied):
        storage.attest_native_schema(c)


def test_referenced_challenge_index_rechecked_against_real_original_validator(shared_catalog_perimeter):
    c = shared_catalog_perimeter
    populate_shared_catalog(c)
    oid = c.relations["social_device_admission_challenges"]["oid"]
    # Same target table and valid-looking unique index; the real original
    # validator checked its pinned parent PK/index, not this replacement binding.
    c.catalog[oid]["SELECT oid::bigint,conindid::bigint"] = [(60, 999)]
    with pytest.raises(FinalizationDenied):
        storage.attest_native_schema(c)


@pytest.mark.parametrize(
    "target", ["social_device_admission_challenges", "social_device_admission_challenge_revisions"]
)
def test_original_revision_validator_is_really_invoked(shared_catalog_perimeter, target):
    c = shared_catalog_perimeter
    populate_shared_catalog(c)
    row = next(r for r in c.revision_catalog if r["relation"]["relname"] == target)
    row["constraints"][0]["catalog"]["conindid"] = "999"
    with pytest.raises(FinalizationDenied):
        storage.attest_native_schema(c)


def test_writer_combined_catalog_path_same_connection_rechecks(shared_catalog_perimeter, monkeypatch):
    from types import SimpleNamespace

    from app.services import social_device_challenge_revision_storage as revision
    from app.services import social_session_issuance_v2_authority as issuance

    c = shared_catalog_perimeter
    populate_shared_catalog(c)
    calls = []
    guard = SimpleNamespace(connection=c)
    port = SimpleNamespace(guard=guard)
    authority = SimpleNamespace(guard=guard, port=port, _check=lambda: calls.append("authority"))

    class OriginalRevisionPort:
        def __init__(self, received):
            assert received is port and received.guard.connection is c
            calls.append("revision_constructor")

        def _catalog(self):
            calls.append("revision_catalog")

        def _marker(self):
            calls.append("revision_marker")

        def _store_identity(self):
            calls.append("revision_store_identity")

    def original_issuance(received):
        assert received is guard and received.connection is c
        calls.append("issuance")
        return ("original_issuance_identity",)

    monkeypatch.setattr(revision, "SqlAlchemyTransactionBoundIssuedChallengeRevisionReader", OriginalRevisionPort)
    monkeypatch.setattr(issuance, "attest", original_issuance)
    writer = object.__new__(storage.NativeV2Effects)
    writer.authority, writer.guard, writer.failed, writer._identity = authority, guard, False, None
    storage._WRITERS[writer] = (authority, guard)
    writer.check()
    assert calls == ["authority", "revision_constructor", "issuance", "authority"]
    calls.clear()
    writer.check()
    assert calls == [
        "authority",
        "revision_catalog",
        "revision_marker",
        "revision_store_identity",
        "issuance",
        "authority",
    ]
    # Real new schema validators (including the original revision _constraints)
    # execute in both passes; no complete attestor replacement or authority facts.
    assert sum(sql == revision.CATALOG_SQL for sql, _ in c.queries) == 2
    c.catalog[c.relations[EVENT]["oid"]]["to_jsonb(a)"][0]["attribute"]["attnotnull"] = False
    with pytest.raises(FinalizationDenied):
        writer.check()
    assert not any("execute_social_enrollment_v2_native_effects(" in sql for sql, _ in c.queries)


def test_independent_fixture_columns_keys_and_index_source_synchronization():
    # The outer runner pins these sources. Verify independent expected fixtures
    # against their original CREATE clauses, never against fake installed rows.
    sources = {
        CHAIN: "2026-09-22_social_device_ed25519_association_storage_v1.sql",
        EVENT: "2026-09-22_social_device_ed25519_association_storage_v1.sql",
        LEGACY_RECEIPT: "2026-09-23_social_device_admission_receipt_consumption_v1.sql",
        "social_preaccepted_enrollment_v2_atomic_acceptances": "2026-10-02_social_preaccepted_enrollment_v2_atomic_acceptance_storage_v1.sql",
    }
    for name, file in sources.items():
        sql = (ROOT / "migrations" / file).read_text()
        header = re.search(r'CREATE TABLE (?:"public"\.)?"?' + name + r'"? \((.*?)\n\);', sql, re.S)
        # Plain/unquoted and quoted public declarations are both fixed sources.
        if header is None:
            header = re.search(r'CREATE TABLE "public"\."' + name + r'" \((.*?)\n\);', sql, re.S)
        assert header is not None
        columns = []
        for column, typ, size, suffix in re.findall(
            r"^    (\w+) (VARCHAR|BIGINT|TEXT)(?:\((\d+)\))?([^,\n]*),", header[1], re.M
        ):
            columns.append(
                (
                    column,
                    {"VARCHAR": 1043, "BIGINT": 20, "TEXT": 25}[typ],
                    int(size) + 4 if size else -1,
                    "NOT NULL" in suffix or "PRIMARY KEY" in suffix,
                )
            )
        assert tuple(columns) == SHARED_COLUMNS[name] == storage.SHARED_COLUMNS[name]
        check_names = set(re.findall(r"CONSTRAINT (\w+)\s+CHECK", header[1]))
        assert check_names == {n for n, _, _ in SHARED_CHECKS[name]}
        assert SHARED_CHECKS[name] == storage.SHARED_CHECKS[name]
        assert SHARED_KEYS[name] == storage.SHARED_KEYS[name]
    sql = (ROOT / "migrations" / sources[EVENT]).read_text()
    indexes = re.findall(
        r"CREATE UNIQUE INDEX (\w+)\s+ON " + EVENT + r" \((.*?)\)\s+WHERE kind IN \((.*?)\);", sql, re.S
    )
    assert len(indexes) == 5
    for name, columns, kinds in indexes:
        keys = [
            next(i for i, c in enumerate(SHARED_COLUMNS[EVENT], 1) if c[0] == column.strip())
            for column in columns.split(",")
        ]
        values = tuple(v.strip().strip("'") for v in kinds.split(","))
        assert SHARED_PARTIAL_INDEXES[name] == (keys, _kinds(values)) == storage.SHARED_PARTIAL_INDEXES[name]


@pytest.mark.parametrize("value", [False, "0", None])
def test_default_catalog_count_native_type_is_exact(shared_catalog_perimeter, value):
    c = shared_catalog_perimeter
    populate_shared_catalog(c)
    c.catalog[c.relations[EVENT]["oid"]]["pg_attrdef"] = [value]
    with pytest.raises(FinalizationDenied):
        storage.attest_native_schema(c)


@pytest.mark.parametrize(
    "field,value", [("relfilenode", 99), ("relpages", "99"), ("reltuples", "99.0"), ("relfrozenxid", 99)]
)
def test_physical_exclusion_does_not_coerce_wrong_native_type(shared_catalog_perimeter, field, value):
    c = shared_catalog_perimeter
    populate_shared_catalog(c)
    c.relations[EVENT][field] = value
    with pytest.raises(FinalizationDenied):
        storage.attest_native_schema(c)


@pytest.mark.parametrize(
    "field,value",
    [
        ("indkey", [2, 1, 6]),
        ("indclass", ["3126", "3126", "1978"]),
        ("indoption", [0, 0, 2]),
        ("indcollation", ["100", "0", "0"]),
    ],
)
def test_multicolumn_partial_index_exact_order_and_classes(shared_catalog_perimeter, field, value):
    c = shared_catalog_perimeter
    populate_shared_catalog(c)
    row = next(
        r
        for r in c.catalog[c.relations[EVENT]["oid"]]["to_jsonb(i)"]
        if r["relation"]["relname"] == "uq_social_ed25519_creation_version"
    )
    row["index"][field] = value
    with pytest.raises(FinalizationDenied):
        storage.attest_native_schema(c)


def test_legacy_receipt_fk_cannot_lose_deferred_completeness(shared_catalog_perimeter):
    c = shared_catalog_perimeter
    populate_shared_catalog(c)
    row = next(
        r for r in c.catalog[c.relations[LEGACY_RECEIPT]["oid"]]["to_jsonb(k)"] if r["constraint"]["contype"] == "f"
    )
    row["constraint"].update(condeferrable=False, condeferred=False)
    with pytest.raises(FinalizationDenied):
        storage.attest_native_schema(c)


@pytest.mark.parametrize("column", ["predecessor_association_id", "ed25519_public_key", "enrollment_challenge_id"])
def test_original_nullable_event_columns_must_stay_nullable(shared_catalog_perimeter, column):
    c = shared_catalog_perimeter
    populate_shared_catalog(c)
    row = next(r for r in c.catalog[c.relations[EVENT]["oid"]]["to_jsonb(a)"] if r["attribute"]["attname"] == column)
    row["attribute"]["attnotnull"] = True
    with pytest.raises(FinalizationDenied):
        storage.attest_native_schema(c)


def test_returned_catalog_fingerprint_is_recursively_immutable(shared_catalog_perimeter):
    c = shared_catalog_perimeter
    populate_shared_catalog(c)
    fingerprint = storage.attest_native_schema(c)

    def assert_immutable(value):
        if type(value) is tuple:
            for child in value:
                assert_immutable(child)
        else:
            assert type(value) in (str, int, bool, type(None))

    assert_immutable(fingerprint)
    before = deepcopy(fingerprint)
    # Returned identities cannot alias the mutable fake catalog, either.
    c.revision_catalog[0]["constraints"][0]["catalog"]["conindid"] = "999"
    assert fingerprint == before
    with pytest.raises(FinalizationDenied):
        storage.attest_native_schema(c)


# The fixture derives columns from original models, constraints from the frozen
# original reader contract, and new-table keys from the preserved SQL migration.
# It never reads the added evaluator's expected profiles.
def dependency_source_columns():
    from sqlalchemy import JSON, BigInteger, Boolean, DateTime, Integer, String, Text

    from app.models import Base
    from app.services import (
        social_messaging_device_storage,
        social_messaging_mobile_authorization_storage,
        social_session_issuance,
    )
    from app.services.social_session_issuance_v2_storage import V2Base

    # Explicit bounded inventory: no recursive Base.metadata traversal.
    names = (
        "users",
        "current_entitlement_evidence",
        "oauth_tokens",
        "sessions",
        "oauth_clients",
        "oauth_session_generations",
        "oauth_browser_generations",
        "social_messaging_device_bindings",
        "social_session_issuers",
        "social_messaging_mobile_operations",
    )
    assert social_messaging_device_storage.SocialMessagingDeviceBindingRow.__table__ is Base.metadata.tables[names[7]]
    assert social_messaging_mobile_authorization_storage.MobileOperationRow.__table__ is Base.metadata.tables[names[9]]
    assert social_session_issuance.SocialSessionIssuer.__table__ is Base.metadata.tables[names[8]]
    tables = [Base.metadata.tables[name] for name in names] + list(V2Base.metadata.sorted_tables)
    result = {}
    for table in tables:
        columns = []
        for c in table.columns:
            assert c.server_default is None
            t = c.type
            if isinstance(t, Text):
                oid, mod = 25, -1
            elif isinstance(t, String):
                oid, mod = 1043, t.length + 4
            elif isinstance(t, Boolean):
                oid, mod = 16, -1
            elif isinstance(t, BigInteger):
                oid, mod = 20, -1
            elif isinstance(t, Integer):
                oid, mod = 23, -1
            elif isinstance(t, DateTime):
                oid, mod = (1184 if t.timezone else 1114), -1
            else:
                assert isinstance(t, JSON)
                oid, mod = 114, -1
            columns.append((c.name, oid, mod, not c.nullable))
        result[table.name] = tuple(columns)
    sql = (ROOT / "migrations/2026-09-13_social_messaging_mobile_authorization_v1.sql").read_text()
    assert "binding_id VARCHAR(64) PRIMARY KEY REFERENCES social_messaging_device_bindings(binding_id)" in sql
    assert (
        "request_id VARCHAR(64) NOT NULL UNIQUE REFERENCES social_messaging_device_authorization_requests(request_id)"
        in sql
    )
    result["social_messaging_device_authorization_binding_owners"] = (
        ("binding_id", 1043, 68, True),
        ("request_id", 1043, 68, True),
    )
    return result


def dependency_fixture_attributes(relation, columns):
    rows = fixture_attributes(relation, columns)
    for row, (_, typ, _, _) in zip(rows, columns):
        if typ == 16:
            row["attribute"].update(attlen=1, attbyval=True, attstorage="p", attalign="c")
        elif typ in (1114, 1184):
            row["attribute"].update(attlen=8, attbyval=True, attstorage="p", attalign="d")
    return rows


def fixture_toast(connection, relation):
    if relation["reltoastrelid"] == 0:
        return
    toast = shared_relation(f"pg_toast_{relation['oid']}", relation["reltoastrelid"], columns=3, checks=0)
    toast.update(
        relnamespace=99,
        reltype=0,
        reltoastrelid=0,
        relkind="t",
        relhastriggers=False,
        relreplident="n",
        relowner=relation["relowner"],
    )
    columns = (("chunk_id", 26, -1, False), ("chunk_seq", 23, -1, False), ("chunk_data", 17, -1, False))
    connection.catalog[toast["oid"]] = {
        "to_jsonb(c) AS relation,n.nspname": [dict(relation=native_json(toast, "relation"), nspname="pg_toast")],
        "to_jsonb(a)": fixture_attributes(toast, columns),
        "pg_attrdef": [0],
        "to_jsonb(i)": [
            fixture_index(toast, toast["relname"] + "_index", columns, [1, 2], "u", None, toast["oid"] + 1000)
        ],
        "count(*) FROM pg_catalog.pg_constraint": [0],
    }


def fixture_direct_acls(connection):
    # Explicit grants must appear in both native pg_class JSON and aclexplode;
    # a NULL ACL could not supply runtime SELECT under this role membership.
    codes = {
        "SELECT": "r",
        "INSERT": "a",
        "UPDATE": "w",
        "DELETE": "d",
        "TRUNCATE": "D",
        "REFERENCES": "x",
        "TRIGGER": "t",
    }
    for relation in connection.relations.values():
        grants = connection.catalog.get(relation["oid"], {}).get("aclexplode")
        if grants is None:
            continue
        grouped = {}
        for grantor, grantee, privilege, _, _ in grants:
            grouped.setdefault((grantor, grantee), []).append(codes[privilege])
        relation["relacl"] = [
            f"{'runtime' if grantee == 203 else 'owner' + str(grantee)}={''.join(privileges)}/owner{grantor}"
            for (grantor, grantee), privileges in grouped.items()
        ]


def fixture_key(relation, name, kind, keys, index, definition, *, parent=0, parent_keys=None, operators=None):
    catalog = dict(
        oid=index + 50000,
        conname=name,
        connamespace=relation["relnamespace"],
        contype=kind,
        condeferrable=kind == "t",
        condeferred=kind == "t",
        convalidated=True,
        conrelid=relation["oid"],
        contypid=0,
        conindid=index if kind in ("p", "u", "f") else 0,
        conparentid=0,
        confrelid=parent,
        confupdtype="a" if parent else " ",
        confdeltype="a" if parent else " ",
        confmatchtype="s" if parent else " ",
        conislocal=True,
        coninhcount=0,
        connoinherit=kind != "c",
        conkey=list(keys) if keys is not None else None,
        confkey=list(parent_keys) if parent_keys else None,
        conpfeqop=operators,
        conppeqop=operators,
        conffeqop=operators,
        confdelsetcols=None,
        conexclop=None,
        conbin="{SOURCE CHECK TREE; native rendering NOT_RUN}" if kind == "c" else None,
    )
    return dict(constraint=native_json(catalog, "constraint"), definition=definition)


def populate_dependency_catalog(connection):
    from app.services.social_session_issuance_v2_storage import CONSTRAINTS

    profiles = dependency_source_columns()
    keys = {}
    for name, columns in profiles.items():
        r = connection.relations[name]
        r["relnatts"] = len(columns)
        entries = {
            "to_jsonb(a)": dependency_fixture_attributes(r, columns),
            "pg_attrdef": [0],
            "to_jsonb(i)": [],
            "to_jsonb(k)": [],
        }
        connection.catalog[r["oid"]] = entries
        specs = CONSTRAINTS.get(name, ((name + "_pkey", "p", "PRIMARY KEY (" + columns[0][0] + ")", [1], None),))
        if name == "oauth_tokens":
            specs = (
                *specs,
                ("uq_oauth_token_generation_owner", "u", "UNIQUE (id, user_id, client_id)", [1, 6, 5], None),
            )
        for n, kind, definition, positions, _ in specs:
            if kind not in ("p", "u"):
                continue
            oid = 1000 + len(keys)
            keys[(name, tuple(columns[k - 1][0] for k in positions))] = oid
            entries["to_jsonb(i)"].append(fixture_index(r, n, columns, positions, kind, None, oid))
            entries["to_jsonb(k)"].append(fixture_key(r, n, kind, positions, oid, definition))
        if name.startswith("social_session_v2_"):
            r["relchecks"] = sum(c[1] == "c" for c in specs)
            if name == "social_session_v2_invalidations":
                r["reltoastrelid"] = 0
            fixture_toast(connection, r)
            readonly = name in (
                "social_session_v2_invalidations",
                "social_session_v2_binding_births",
                "social_session_v2_token_births",
            )
            entries["aclexplode"] = [
                (r["relowner"], r["relowner"], p, False, 203)
                for p in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")
            ]
            entries["aclexplode"] += [
                (r["relowner"], 203, p, False, 203) for p in (("SELECT",) if readonly else ("SELECT", "INSERT"))
            ]
    for name, specs in CONSTRAINTS.items():
        r = connection.relations[name]
        for n, kind, definition, positions, target in specs:
            if kind in ("p", "u"):
                continue
            parent, parent_keys, operators, index = (
                0,
                None,
                None,
                10000 + len(connection.catalog[r["oid"]]["to_jsonb(k)"]),
            )
            if target:
                parent_name, parent_names = target
                parent = connection.relations[parent_name]["oid"]
                parent_columns = profiles[parent_name]
                parent_keys = [next(i for i, c in enumerate(parent_columns, 1) if c[0] == key) for key in parent_names]
                operators = [98] * len(parent_keys)
                index = keys[(parent_name, tuple(parent_names))]
            entry = fixture_key(
                r, n, kind, positions, index, definition, parent=parent, parent_keys=parent_keys, operators=operators
            )
            entry["constraint"]["oid"] = str(60000 + r["oid"] * 100 + len(connection.catalog[r["oid"]]["to_jsonb(k)"]))
            connection.catalog[r["oid"]]["to_jsonb(k)"].append(entry)
        if name == "social_session_v2_offers":
            connection.catalog[r["oid"]]["to_jsonb(k)"].append(
                fixture_key(r, "v2_complete", "t", None, 15000, "TRIGGER DEFERRABLE INITIALLY DEFERRED")
            )
    for row in connection.revision_catalog:
        r = connection.relations[row["relation"]["relname"]]
        columns = tuple((a["attname"], int(a["atttypid"]), a["atttypmod"], a["attnotnull"]) for a in row["attributes"])
        idx = row["indexes"][0]
        connection.catalog[r["oid"]]["to_jsonb(i)"] = [
            fixture_index(r, r["relname"] + "_pkey", columns, [1], "p", None, int(idx["oid"]))
        ]
        privileges = ("SELECT", "UPDATE") if r["relname"] == "social_device_admission_challenges" else ("SELECT",)
        connection.catalog[r["oid"]]["aclexplode"] = [
            (r["relowner"], r["relowner"], p, False, 203)
            for p in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")
        ] + [(r["relowner"], 203, p, False, 203) for p in privileges]
        fixture_toast(connection, r)
    populate_v2_trigger_catalog(connection)
    populate_authority_catalog(connection)
    fixture_direct_acls(connection)


def populate_v2_trigger_catalog(connection):
    from app.services.social_session_issuance_v2_storage import CONSTRAINTS, trigger_definitions

    for name in CONSTRAINTS:
        r = connection.relations[name]
        rows = []
        for declaration in trigger_definitions(name):
            match = re.match(
                r"CREATE (CONSTRAINT )?TRIGGER (\w+) (.*?) ON public\.\w+ (.*?) EXECUTE FUNCTION (\w+)\(\)", declaration
            )
            constraint, n, timing, rest, fn = match.groups()
            kind = (2 if "BEFORE" in timing else 0) + (1 if "EACH ROW" in rest else 0)
            kind += sum(
                flag
                for word, flag in (("INSERT", 4), ("DELETE", 8), ("UPDATE", 16), ("TRUNCATE", 32))
                if word in timing
            )
            cons = (
                int(
                    next(
                        c["constraint"]["oid"]
                        for c in connection.catalog[r["oid"]]["to_jsonb(k)"]
                        if c["constraint"]["conname"] == n
                    )
                )
                if constraint
                else 0
            )
            trigger = fixture_trigger(
                r["oid"],
                500000 + len(rows) + r["oid"] * 100,
                n,
                connection.functions[fn]["function"]["oid"],
                kind,
                constraint=cons,
                deferred=bool(constraint),
            )
            rows.append(dict(trigger=native_json(trigger, "trigger"), definition=declaration))
        connection.catalog[r["oid"]]["to_jsonb(t)"] = rows


NATIVE_SOURCE = "migrations/2026-10-12_social_enrollment_v2_finalization_v1.sql"


def native_source_profiles():
    sql = (ROOT / NATIVE_SOURCE).read_text()
    result = {}
    for name, body in re.findall(r"CREATE TABLE public\.(\w+) \((.*?)\n\);", sql, re.S):
        columns, specs = [], []
        for line in body.splitlines():
            if not line.strip():
                continue
            match = re.match(r"\s*(\w+) (VARCHAR|BIGINT|TEXT)(?:\((\d+)\))?(.*)", line)
            if match:
                column, family, size, suffix = match.groups()
                typ, mod = (
                    (1043, int(size) + 4) if family == "VARCHAR" else (20, -1) if family == "BIGINT" else (25, -1)
                )
                columns.append((column, typ, mod, "PRIMARY KEY" in suffix or "NOT NULL" in suffix))
                if "PRIMARY KEY" in suffix:
                    specs.append((name + "_pkey", "p", (column,), None))
                if "UNIQUE" in suffix:
                    specs.append((name + "_" + column + "_key", "u", (column,), None))
                fk = re.search(r"CONSTRAINT (\w+) REFERENCES public\.(\w+)\((\w+)\)", suffix)
                if fk:
                    specs.append((fk[1], "f", (column,), (fk[2], (fk[3],))))
            else:
                fk = re.search(r"CONSTRAINT (\w+) FOREIGN KEY\(([^)]+)\) REFERENCES public\.(\w+)\(([^)]+)\)", line)
                assert fk, line
                specs.append(
                    (
                        fk[1],
                        "f",
                        tuple(c.strip() for c in fk[2].split(",")),
                        (fk[3], tuple(c.strip() for c in fk[4].split(","))),
                    )
                )
        result[name] = (tuple(columns), tuple(specs))
    assert len(result) == 4
    assert "CREATE CONSTRAINT TRIGGER v2_native_complete" in sql
    return result


def populate_native_catalog(connection):
    profiles = native_source_profiles()
    keys = {}
    # Every binding comes from an independent source-shaped parent catalog.
    for name in (CHAIN, EVENT, "social_device_admission_challenges"):
        r = connection.relations[name]
        if name == "social_device_admission_challenges":
            row = next(row for row in connection.revision_catalog if row["relation"]["relname"] == name)
            pk = next(k["catalog"] for k in row["constraints"] if k["catalog"]["contype"] == "p")
            keys[(name, ("challenge_id",))] = int(pk["conindid"])
        else:
            pk = next(
                k["constraint"]
                for k in connection.catalog[r["oid"]]["to_jsonb(k)"]
                if k["constraint"]["contype"] == "p"
            )
            keys[(name, ("subject", "device_id", "authority_epoch"))] = int(pk["conindid"])
        connection.catalog[r["oid"]]["SELECT conindid::bigint"] = [next(v for (n, _), v in keys.items() if n == name)]
    for name, (columns, specs) in profiles.items():
        r = connection.relations[name]
        r.update(relnatts=len(columns), relchecks=0)
        entries = {
            "to_jsonb(a)": fixture_attributes(r, columns),
            "pg_attrdef": [0],
            "to_jsonb(i)": [],
            "to_jsonb(k)": [],
        }
        connection.catalog[r["oid"]] = entries
        entries["aclexplode"] = [
            (202, 202, p, False, 203)
            for p in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")
        ] + [(202, 203, "SELECT", False, 203)]
        for n, kind, names, _ in specs:
            if kind not in ("p", "u"):
                continue
            positions = [next(i for i, c in enumerate(columns, 1) if c[0] == key) for key in names]
            idx = 3000 + len(keys)
            keys[(name, names)] = idx
            entries["to_jsonb(i)"].append(fixture_index(r, n, columns, positions, kind, None, idx))
            definition = ("PRIMARY KEY" if kind == "p" else "UNIQUE") + " (" + ", ".join(names) + ")"
            entries["to_jsonb(k)"].append(fixture_key(r, n, kind, positions, idx, definition))
            if kind == "p":
                entries["SELECT conindid::bigint"] = [idx]
        fixture_toast(connection, r)
    for name, (columns, specs) in profiles.items():
        r = connection.relations[name]
        for n, kind, names, target in specs:
            if kind != "f":
                continue
            parent, parent_names = target
            parent_columns = (
                profiles[parent][0]
                if parent in profiles
                else SHARED_COLUMNS.get(parent, (("challenge_id", 1043, 68, True),))
            )
            positions = [next(i for i, c in enumerate(columns, 1) if c[0] == key) for key in names]
            parent_positions = [next(i for i, c in enumerate(parent_columns, 1) if c[0] == key) for key in parent_names]
            operators = [410 if parent_columns[k - 1][1] == 20 else 98 for k in parent_positions]
            definition = (
                "FOREIGN KEY (" + ", ".join(names) + ") REFERENCES " + parent + "(" + ", ".join(parent_names) + ")"
            )
            entry = fixture_key(
                r,
                n,
                kind,
                positions,
                keys[(parent, parent_names)],
                definition,
                parent=connection.relations[parent]["oid"],
                parent_keys=parent_positions,
                operators=operators,
            )
            entry["constraint"]["oid"] = str(80000 + len(connection.catalog[r["oid"]]["to_jsonb(k)"]) + r["oid"] * 100)
            connection.catalog[r["oid"]]["to_jsonb(k)"].append(entry)
        complete = fixture_key(
            r, "v2_native_complete", "t", None, 40000 + r["oid"], "TRIGGER DEFERRABLE INITIALLY DEFERRED"
        )
        connection.catalog[r["oid"]]["to_jsonb(k)"].append(complete)


def source_functions():
    files = (
        "2026-09-04_social_messaging_device_bindings_v1.sql",
        "2026-09-10_social_messaging_device_binding_authorization_v1.sql",
        "2026-09-13_oauth_session_lifecycle_v1.sql",
        "2026-09-13_social_messaging_mobile_authorization_v1.sql",
        "2026-09-13_social_session_issuance_v1.sql",
        "2026-09-21_social_device_challenge_store_v1.sql",
        "2026-09-22_social_device_ed25519_association_storage_v1.sql",
        "2026-09-23_social_device_admission_receipt_consumption_v1.sql",
        "2026-10-02_social_preaccepted_enrollment_v2_atomic_acceptance_storage_v1.sql",
        "2026-10-09_social_device_challenge_revision_v1.sql",
        "2026-10-10_social_session_issuance_v2_provenance_v1.sql",
        "2026-10-12_social_enrollment_v2_finalization_v1.sql",
    )
    result = {}
    for file in files:
        sql = (ROOT / "migrations" / file).read_text()
        for match in re.finditer(
            r'CREATE(?: OR REPLACE)?\s+FUNCTION\s+(?:"?public"?\.)?"?(\w+)"?\s*\((.*?)\)\s*(RETURNS.*?)\bAS\s+(\$\w*\$)(.*?)\4',
            sql,
            re.S | re.I,
        ):
            name, args, header, _, body = match.groups()
            args = tuple(a.strip().split()[0] for a in args.split(",") if a.strip())
            row = function(name, body, 10000 + len(result), 202, "SECURITY DEFINER" in header)
            catalog = row["function"]
            setting = re.search(r"SET search_path\s*=\s*([a-z_, ]+)", header, re.I)
            config = "search_path=" + ", ".join(s.strip() for s in setting[1].strip().split(",")) if setting else None
            catalog.update(
                proargnames=list(args) if args else None,
                pronargs=len(args),
                proargtypes=" ".join("25" for _ in args),
                prorettype=2278 if re.match(r"RETURNS void", header, re.I) else 2279,
                proconfig=[config] if config else None,
                prosqlbody=None,
            )
            catalog = native_json(catalog, "function")
            catalog["prosupport"] = "-"
            row["function"] = catalog
            row.update(executable=name == "execute_social_enrollment_v2_native_effects", owns=False)
            result[name] = row
    for i, name in enumerate(sorted(result), 10000):
        result[name]["function"]["oid"] = str(i)
        result[name]["function"]["proacl"] = ["owner202=X/owner202"]
        if name == "execute_social_enrollment_v2_native_effects":
            result[name]["function"]["proacl"].append("runtime=X/owner202")
    return result


def fixture_trigger(
    table_oid,
    oid,
    name,
    function_oid,
    kind,
    *,
    constraint=0,
    deferred=False,
    predicate=None,
    internal=False,
    other=0,
    index=0,
):
    return dict(
        oid=oid,
        tgrelid=table_oid,
        tgparentid=0,
        tgname=name,
        tgfoid=int(function_oid),
        tgtype=kind,
        tgenabled="O",
        tgisinternal=internal,
        tgconstrrelid=other,
        tgconstrindid=index,
        tgconstraint=constraint,
        tgdeferrable=deferred,
        tginitdeferred=deferred,
        tgnargs=0,
        tgattr="",
        tgargs="\\x",
        tgqual=predicate,
        tgoldtable=None,
        tgnewtable=None,
    )


class CompleteCatalogConnection(SharedCatalogConnection):
    """Controlled native shapes; every actual attestor remains unpatched."""

    def __init__(self):
        super().__init__()
        self.functions = source_functions()
        populate_shared_catalog(self)
        populate_native_catalog(self)
        fixture_direct_acls(self)
        populate_trigger_catalog(self)

    def execute(self, statement, parameters=None):
        sql, params = str(statement), parameters or {}
        if "/* UBID_FRESH_FINALIZATION_CATALOG */" in sql:
            return _simulate_fresh_catalog_batch(self, sql, params)
        if "SELECT r.rolsuper,r.rolcreaterole" in sql:
            self.queries.append((sql, params))
            return CatalogResult(
                [(False, False, False, False, False, 1, ["pg_read_all_settings"], [999], 203, True, True, False)]
            )
        if sql == storage.FUNCTION_SQL:
            self.queries.append((sql, params))
            return CatalogResult([deepcopy(self.functions[params["name"]])])
        if sql == storage.AUTHORITY_EFFECTIVE_ACL_SQL:
            return super().execute(statement, parameters)
        if "SELECT has_table_privilege(current_user" in sql:
            self.queries.append((sql, params))
            return CatalogResult([(True, False, False)])
        if "has_table_privilege(current_user,:oid,'SELECT')" in sql and "has_any_column_privilege" in sql:
            self.queries.append((sql, params))
            name = next(n for n, r in self.relations.items() if r["oid"] == params["oid"])
            update = name != EVENT
            return CatalogResult([(True, False, update, False, False, False, update)])
        if "t.tgrelid=ANY" in sql and "t.tgisinternal" in sql:
            self.queries.append((sql, params))
            return CatalogResult(
                deepcopy(
                    [
                        r
                        for r in self.internal_triggers
                        if int(r["trigger"]["tgrelid"]) in params["oids"]
                        or int(r["trigger"]["tgconstraint"]) in params["constraints"]
                    ]
                )
            )
        if "WHERE k.conrelid=:child" in sql:
            self.queries.append((sql, params))
            rows = self.catalog[params["child"]].get("to_jsonb(k)", [])
            if not rows:
                original = next(row for row in self.revision_catalog if row["oid"] == params["child"])
                rows = [dict(constraint=k["catalog"]) for k in original["constraints"]]
            return CatalogResult(
                [
                    dict(constraint=deepcopy(r["constraint"]))
                    for r in rows
                    if r["constraint"]["conname"] == params["name"]
                ]
            )
        return super().execute(statement, parameters)


def populate_trigger_catalog(connection):
    # Original migrations own these trigger names and the two predicates.
    files = (
        "2026-09-21_social_device_challenge_store_v1.sql",
        "2026-09-22_social_device_ed25519_association_storage_v1.sql",
        "2026-09-23_social_device_admission_receipt_consumption_v1.sql",
        "2026-10-02_social_preaccepted_enrollment_v2_atomic_acceptance_storage_v1.sql",
        "2026-10-09_social_device_challenge_revision_v1.sql",
        "2026-10-12_social_enrollment_v2_finalization_v1.sql",
    )
    predicates = {
        "trg_social_enrollment_challenge_atomic": "((new.state)::text = 'consumed'::text)",
        "trg_social_enrollment_event_atomic": "((new.kind)::text = ANY ((ARRAY['initial'::character varying, 'rotate'::character varying, 'reenroll'::character varying])::text[]))",
    }
    for file in files:
        source = (ROOT / "migrations" / file).read_text()
        for match in re.finditer(
            r'^CREATE (CONSTRAINT )?TRIGGER "?(\w+)"?\s+(.*?)\s+ON (?:"?public"?\.)?"?(\w+)"?(.*?)EXECUTE FUNCTION (?:"?public"?\.)?"?(\w+)"?\(\);',
            source,
            re.S | re.M,
        ):
            constraint, name, timing, table, rest, fn = match.groups()
            if table not in connection.relations:
                continue
            r = connection.relations[table]
            kind = (2 if "BEFORE" in timing else 0) + (1 if "EACH ROW" in rest else 0)
            kind += sum(
                flag
                for word, flag in (("INSERT", 4), ("DELETE", 8), ("UPDATE", 16), ("TRUNCATE", 32))
                if word in timing
            )
            cons = 0
            if constraint:
                rows = connection.catalog[r["oid"]].get("to_jsonb(k)", [])
                if not rows:
                    original = next(row for row in connection.revision_catalog if row["oid"] == r["oid"])
                    rows = [dict(constraint=k["catalog"]) for k in original["constraints"]]
                cons = int(next(k["constraint"]["oid"] for k in rows if k["constraint"]["conname"] == name))
            predicate = predicates.get(name)
            trigger = fixture_trigger(
                r["oid"],
                400000 + len(connection.catalog[r["oid"]].get("to_jsonb(t)", [])) + r["oid"] * 100,
                name,
                connection.functions[fn]["function"]["oid"],
                kind,
                constraint=cons,
                deferred=bool(constraint),
                predicate="{NATIVE WHEN TREE}" if predicate else None,
            )
            definition = ""
            if predicate:
                definition = f"CREATE CONSTRAINT TRIGGER {name} AFTER " + ("UPDATE" if kind == 17 else "INSERT")
                definition += f" ON public.{table} DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN ({predicate}) EXECUTE FUNCTION {fn}()"
            connection.catalog[r["oid"]].setdefault("to_jsonb(t)", []).append(
                dict(
                    trigger=native_json(trigger, "trigger"),
                    definition=definition,
                    constraint_name=name if constraint else None,
                    proname=fn,
                    nspname="public",
                )
            )
    connection.internal_triggers = []
    for name, r in connection.relations.items():
        constraints = connection.catalog.get(r["oid"], {}).get("to_jsonb(k)", [])
        if name == "social_device_admission_challenge_revisions":
            row = next(row for row in connection.revision_catalog if row["oid"] == r["oid"])
            constraints = [dict(constraint=k["catalog"]) for k in row["constraints"]]
        for entry in constraints:
            c = entry["constraint"]
            if c["contype"] != "f":
                continue
            for table, other, kind, fn, child in (
                (int(c["conrelid"]), int(c["confrelid"]), 5, "RI_FKey_check_ins", True),
                (int(c["conrelid"]), int(c["confrelid"]), 17, "RI_FKey_check_upd", True),
                (
                    int(c["confrelid"]),
                    int(c["conrelid"]),
                    9,
                    "RI_FKey_restrict_del" if c["confdeltype"] == "r" else "RI_FKey_noaction_del",
                    False,
                ),
                (
                    int(c["confrelid"]),
                    int(c["conrelid"]),
                    17,
                    "RI_FKey_restrict_upd" if c["confupdtype"] == "r" else "RI_FKey_noaction_upd",
                    False,
                ),
            ):
                oid = 700000 + len(connection.internal_triggers)
                function_oid = 900000 + (
                    1
                    if fn == "RI_FKey_check_ins"
                    else (
                        2
                        if fn == "RI_FKey_check_upd"
                        else (
                            3
                            if fn == "RI_FKey_restrict_del"
                            else 4 if fn == "RI_FKey_restrict_upd" else 5 if fn == "RI_FKey_noaction_del" else 6
                        )
                    )
                )
                trigger = fixture_trigger(
                    table,
                    oid,
                    f"RI_ConstraintTrigger_{'c' if child else 'a'}_{oid}",
                    function_oid,
                    kind,
                    constraint=int(c["oid"]),
                    deferred=c["condeferrable"] and "restrict" not in fn,
                    internal=True,
                    other=other,
                    index=int(c["conindid"]),
                )
                connection.internal_triggers.append(
                    dict(
                        trigger=native_json(trigger, "trigger"),
                        function_oid=function_oid,
                        proname=fn,
                        prosrc=fn,
                        pronargs=0,
                        prorettype=2279,
                        nspname="pg_catalog",
                        canonical=True,
                        lanname="internal",
                    )
                )


def test_pg16_stock_toast_profile():
    # PG16's internal TOAST index is primary without a pg_constraint PK;
    # chunk attributes are nullable, and oid_ops is 1981 (1989 is its operator family).
    connection = CompleteCatalogConnection()
    relation = connection.relations["social_session_v2_offers"]
    entries = connection.catalog[relation["reltoastrelid"]]
    for row in entries["to_jsonb(a)"]:
        row["attribute"]["attnotnull"] = False
    index = entries["to_jsonb(i)"][0]["index"]
    index.update(indisprimary=True, indclass=["1981", "1978"])
    storage._attest_relation_definition(
        connection, relation, column_count=relation["relnatts"], checks=relation["relchecks"]
    )


def test_real_combined_attestor_dependency_definitions():
    connection = CompleteCatalogConnection()
    from app.services import social_session_issuance_v2_storage as original

    port = OriginalIssuanceCatalogPort(connection)
    original_pin = original.attest(port)
    assert original.attest(port) == original_pin
    assert len(port.calls) == 6
    first = storage.attest_native_schema(connection)
    first_queries = len(connection.queries)
    assert storage.attest_native_schema(connection) == first
    assert len(connection.queries) == 2 * first_queries
    oid = connection.relations["social_session_v2_parents"]["oid"]
    connection.catalog[oid]["to_jsonb(k)"][1]["constraint"]["confmatchtype"] = "f"
    # Pick a real FK even if the independent fixture changes row ordering.
    next(r["constraint"] for r in connection.catalog[oid]["to_jsonb(k)"] if r["constraint"]["contype"] == "f")[
        "confmatchtype"
    ] = "f"
    with pytest.raises(FinalizationDenied):
        storage.attest_native_schema(connection)
    assert not any("execute_social_enrollment_v2_native_effects(" in sql for sql, _ in connection.queries)
    # Exercise each newly closed section through the actual combined path. Every
    # fixture starts from independent model/migration/native-rendered profiles;
    # no guard or evaluator is replaced with a no-op.
    for surface in (
        "check",
        "unique",
        "fk",
        "nonunique",
        "partial",
        "acl",
        "inherited_acl",
        "trigger",
        "ri",
        "external_fk",
        "external_key",
        "relation",
        "toast",
        "system",
    ):
        fresh = CompleteCatalogConnection()
        storage.attest_native_schema(fresh)
        replace_authority_surface(fresh, surface)
        with pytest.raises(FinalizationDenied):
            storage.attest_native_schema(fresh)
        assert not any("execute_social_enrollment_v2_native_effects(" in sql for sql, _ in fresh.queries)


SOURCE_INVENTORY = (
    "users",
    "current_entitlement_evidence",
    "oauth_tokens",
    "sessions",
    "oauth_clients",
    "oauth_session_generations",
    "oauth_browser_generations",
    "social_messaging_device_bindings",
    "social_session_issuers",
    "social_messaging_mobile_operations",
    "social_messaging_device_authorization_binding_owners",
    "social_device_admission_challenges",
    "social_device_admission_challenge_revisions",
    "social_device_ed25519_association_chains",
    "social_device_ed25519_association_events",
    "social_device_enrollment_admission_receipts",
    "social_preaccepted_enrollment_v2_atomic_acceptances",
    "social_session_v2_offers",
    "social_session_v2_parents",
    "social_session_v2_acceptances",
    "social_session_v2_issuances",
    "social_session_v2_invalidations",
    "social_session_v2_binding_births",
    "social_session_v2_token_births",
    "social_enrollment_v2_native_associations",
    "social_enrollment_v2_native_effects",
    "social_enrollment_v2_native_consumptions",
    "social_enrollment_v2_native_decisions",
)


@pytest.mark.parametrize("name", SOURCE_INVENTORY)
def test_dependency_catalog_closed_inventory_matches_sources(name):
    from app.services.social_session_issuance_v2_storage import CONSTRAINTS
    from tests.unit.test_social_device_challenge_revision_storage import reviewed_catalog

    # Ordered model attributes plus independent full authority source profiles.
    profiles = dependency_source_columns()
    profiles.update(SHARED_COLUMNS)
    profiles.update({n: cols for n, (cols, _) in native_source_profiles().items()})
    for row in reviewed_catalog():
        profiles[row["relation"]["relname"]] = tuple(
            (a["attname"], a["atttypid"], a["atttypmod"], a["attnotnull"]) for a in row["attributes"]
        )
    assert set(profiles) == set(SOURCE_INVENTORY) == set(storage.VISIBLE_AUTHORITIES)
    assert storage._definition_columns(name) == profiles[name]
    if name.startswith("social_session_v2_"):
        frozen = tuple(
            (n, kind, definition, tuple(keys), target) for n, kind, definition, keys, target in CONSTRAINTS[name]
        )
        assert storage.V2_DEFINITION_PROFILES[name] == frozen
        migration = (ROOT / "migrations/2026-10-10_social_session_issuance_v2_provenance_v1.sql").read_text()
        assert all(n in migration for n, *_ in frozen)
    if name in SOURCE_AUTHORITY_CONSTRAINTS:
        assert storage.AUTHORITY_CONSTRAINTS[name] == SOURCE_AUTHORITY_CONSTRAINTS[name]
        assert storage.AUTHORITY_INDEXES[name] == SOURCE_AUTHORITY_INDEXES[name]
        assert storage.AUTHORITY_TRIGGERS[name] == SOURCE_AUTHORITY_TRIGGERS[name]
    with pytest.raises(TypeError):
        storage.DEPENDENCY_COLUMNS["invented"] = ()


@pytest.mark.parametrize("name", SOURCE_INVENTORY)
@pytest.mark.parametrize(
    "surface", ("missing", "extra", "duplicate", "type", "default", "orphan_default", "null", "acl", "unknown")
)
def test_dependency_catalog_same_oid_replacements_deny(name, surface):
    connection = CompleteCatalogConnection()
    storage.attest_native_schema(connection)
    oid = connection.relations[name]["oid"]
    rows = connection.catalog[oid]["to_jsonb(a)"]
    if surface == "missing":
        rows.pop()
    elif surface == "extra":
        rows.append(deepcopy(rows[-1]))
        rows[-1]["attribute"].update(attname="extra", attnum=len(rows))
    elif surface == "duplicate":
        rows.append(deepcopy(rows[0]))
    elif surface == "type":
        rows[0]["attribute"]["atttypid"] = "25"
    elif surface == "default":
        rows[0]["attribute"]["atthasdef"] = True
        connection.catalog[oid]["pg_attrdef"] = [1]
    elif surface == "orphan_default":
        connection.catalog[oid]["pg_attrdef"] = [1]
    elif surface == "null":
        rows[0]["attribute"]["attnotnull"] = False
    elif surface == "acl":
        rows[0]["attribute"]["attacl"] = ["=r/owner"]
    else:
        rows[0]["attribute"]["unknown_native_field"] = 1
    assert connection.relations[name]["oid"] == oid
    with pytest.raises(FinalizationDenied):
        storage.attest_native_schema(connection)


@pytest.mark.parametrize(
    "name",
    (
        "social_session_v2_parents",
        "social_session_v2_acceptances",
        "social_session_v2_issuances",
        "social_session_v2_invalidations",
        "social_session_v2_binding_births",
    ),
)
@pytest.mark.parametrize(
    "field,value",
    (
        ("confupdtype", "c"),
        ("confdeltype", "c"),
        ("confmatchtype", "f"),
        ("confrelid", "777"),
        ("conindid", "777"),
        ("conpfeqop", ["777"]),
        ("conppeqop", ["777"]),
        ("conffeqop", ["777"]),
        ("confkey", [99]),
        ("conparentid", "777"),
        ("unknown_native_field", True),
    ),
)
def test_issuance_dependency_full_fk_fields_deny(name, field, value):
    connection = CompleteCatalogConnection()
    storage.attest_native_schema(connection)
    rows = connection.catalog[connection.relations[name]["oid"]]["to_jsonb(k)"]
    next(r["constraint"] for r in rows if r["constraint"]["contype"] == "f")[field] = value
    with pytest.raises(FinalizationDenied):
        storage.attest_native_schema(connection)


@pytest.mark.parametrize(
    "name",
    tuple(
        "social_session_v2_" + n
        for n in ("offers", "parents", "acceptances", "issuances", "invalidations", "binding_births", "token_births")
    ),
)
@pytest.mark.parametrize(
    "surface",
    (
        "order",
        "opclass",
        "predicate",
        "standalone",
        "relation",
        "constraint_definition",
        "trigger_constraint",
        "trigger_unknown",
        "internal_binding",
        "public",
        "third_party",
    ),
)
def test_issuance_dependency_complete_definitions_deny(name, surface):
    connection = CompleteCatalogConnection()
    storage.attest_native_schema(connection)
    oid = connection.relations[name]["oid"]
    entries = connection.catalog[oid]
    index = entries["to_jsonb(i)"][0]
    if surface == "order":
        index["index"]["indkey"] = [99]
    elif surface == "opclass":
        index["index"]["indclass"] = ["1978"]
    elif surface == "predicate":
        index["index"]["indpred"] = "{replacement}"
        index["predicate"] = "true"
    elif surface == "standalone":
        entries["to_jsonb(i)"].append(deepcopy(index))
        entries["to_jsonb(i)"][-1]["relation"]["relname"] = "unexpected_standalone"
    elif surface == "relation":
        connection.relations[name]["relreplident"] = "f"
    elif surface == "constraint_definition":
        entries["to_jsonb(k)"][0]["definition"] = "PRIMARY KEY (replacement)"
    elif surface == "trigger_constraint":
        entries["to_jsonb(t)"][0]["trigger"]["tgconstraint"] = "777"
    elif surface == "trigger_unknown":
        entries["to_jsonb(t)"][0]["trigger"]["unknown_native_field"] = True
    elif surface == "internal_binding":
        if name == "social_session_v2_token_births":
            # This source table has no FK: an extra internal binding must deny.
            row = deepcopy(connection.internal_triggers[0])
            row["trigger"]["tgrelid"] = str(oid)
            connection.internal_triggers.append(row)
        else:
            row = next(r for r in connection.internal_triggers if int(r["trigger"]["tgrelid"]) == oid)
        row["trigger"]["tgconstrindid"] = "777"
    else:
        entries["aclexplode"].append((202, 0 if surface == "public" else 707, "SELECT", False, 203))
    with pytest.raises(FinalizationDenied):
        storage.attest_native_schema(connection)


def test_combined_catalog_observations_are_immutable_and_physical_only_is_excluded():
    connection = CompleteCatalogConnection()
    first = storage.attest_native_schema(connection)
    frozen = repr(first)
    for r in connection.relations.values():
        r.update(relfilenode="777", relpages=8, reltuples=99.5, relallvisible=3, relfrozenxid="777", relminmxid="888")
    for entries in connection.catalog.values():
        for row in entries.get("to_jsonb(i)", ()):
            row["index"]["indisclustered"] = True
    # Original revision _constraints retains its existing CLUSTER behavior;
    # its independently queried synthetic original catalog stays unchanged.
    assert storage.attest_native_schema(connection) == first
    connection.catalog[connection.relations["users"]["oid"]]["to_jsonb(a)"][0]["attribute"]["attnotnull"] = False
    assert repr(first) == frozen
    with pytest.raises(FinalizationDenied):
        storage.attest_native_schema(connection)
    assert all(type(value) not in (dict, list, set) for value in first)


def test_synthetic_user_not_null_profile_is_rejected():
    # Core model + pinned migrations leave users.is_active nullable. The older
    # isolated V1 helper invented NOT NULL and is not a full source profile.
    connection = CompleteCatalogConnection()
    storage.attest_native_schema(connection)
    oid = connection.relations["users"]["oid"]
    connection.catalog[oid]["to_jsonb(a)"][-1]["attribute"]["attnotnull"] = True
    with pytest.raises(FinalizationDenied):
        storage.attest_native_schema(connection)


class OriginalIssuanceCatalogPort:
    """Native-shape observation adapter for the real grouped catalog attestor."""

    poisoned = False

    def __init__(self, connection):
        self.connection = connection
        self.calls = []

    def _check_objects(self):
        assert not self.poisoned
        return (self.connection,)

    def check(self):
        self._check_objects()

    def answer(self, tag, values):
        from app.services.social_device_challenge_revision_storage import _native_catalog_object

        c = self.connection
        name = values.get("name")
        if tag == "role":
            return [(False, False, False, False, False, 1, ["pg_read_all_settings"], [999], 203, True, True, False)]
        if tag == "schema":
            return [(2200, 202, True)]
        if tag in ("function", "legacy_function"):
            f = _native_catalog_object(c.functions[name]["function"], "function")
            row = (
                f["oid"],
                f["proowner"],
                f["prosrc"],
                f["prosecdef"],
                f["proconfig"],
                f["provolatile"],
                f["prorettype"] == 2279,
                f["pronargs"],
                f["prokind"],
                "plpgsql",
                False,
            )
            return [row + (False,)] if tag == "function" else [row]
        if tag == "target":
            return [(c.relations[values["target"].removeprefix("public.")]["oid"],)]
        if tag == "legacy_table":
            r = c.relations[name]
            return [(r["oid"], r["relowner"], True, False)]
        if tag == "table":
            r = c.relations[name]
            allowed = name not in (
                "social_session_v2_invalidations",
                "social_session_v2_binding_births",
                "social_session_v2_token_births",
            )
            return [
                (
                    r["oid"],
                    r["relowner"],
                    r["reltype"],
                    r["reltoastrelid"],
                    "r",
                    False,
                    False,
                    False,
                    True,
                    allowed,
                    False,
                    False,
                    False,
                    False,
                )
            ]
        if tag == "toast":
            return [(False,)] if values["oid"] else []
        if tag == "column_privileges":
            return [(False,)]
        if tag == "index":
            row = next(
                row
                for entries in c.catalog.values()
                for row in entries.get("to_jsonb(i)", ())
                if int(row["index"]["indexrelid"]) == values["oid"]
            )
            i = row["index"]
            return [
                (
                    i["indisvalid"],
                    i["indisready"],
                    i["indislive"],
                    i["indisunique"],
                    i["indexprs"],
                    i["indpred"],
                    "btree",
                )
            ]
        entries = c.catalog[values["oid"]]
        if tag == "columns":
            rows = []
            for row in entries["to_jsonb(a)"]:
                a = _native_catalog_object(row["attribute"], "attribute")
                typ = (
                    "bigint"
                    if a["atttypid"] == 20
                    else "text" if a["atttypid"] == 25 else f"character varying({a['atttypmod'] - 4})"
                )
                rows.append((a["attname"], typ, a["attnotnull"]))
            return rows
        if tag == "constraints":
            rows = []
            for row in entries["to_jsonb(k)"]:
                k = _native_catalog_object(row["constraint"], "constraint")
                rows.append(
                    (
                        k["oid"],
                        k["conname"],
                        k["contype"],
                        row["definition"],
                        k["conkey"],
                        k["convalidated"],
                        k["condeferrable"],
                        k["condeferred"],
                        k["conislocal"],
                        k["coninhcount"],
                        k["conparentid"],
                        k["confrelid"],
                        k["conindid"],
                        k["conbin"],
                    )
                )
            return rows
        assert tag == "triggers"
        rows = []
        for row in entries.get("to_jsonb(t)", ()):
            t = _native_catalog_object(row["trigger"], "trigger")
            fn = next(n for n, f in c.functions.items() if int(f["function"]["oid"]) == t["tgfoid"])
            rows.append(
                (
                    t["oid"],
                    t["tgfoid"],
                    t["tgname"],
                    fn,
                    t["tgtype"],
                    t["tgdeferrable"],
                    t["tginitdeferred"],
                    t["tgenabled"],
                    t["tgnargs"],
                    t["tgattr"],
                    t["tgqual"],
                    b"",
                    t["tgoldtable"],
                    t["tgnewtable"],
                    t["tgparentid"],
                    "public",
                )
            )
        return rows

    def sql(self, sql, values=None):
        import json

        from app.services.social_session_issuance_v2_storage import _CATALOG_SELECTS

        self.calls.append(sql)
        assert sql.startswith("WITH ") and "SELECT pg_catalog.json_build_array(" in sql
        markers = re.findall(r"/\* UBID_CATALOG_FAMILIES ([a-z0-9_=,;]+) \*/", sql)
        assert len(markers) == 1
        values = values or {}
        observed = {}
        for group in markers[0].split(";"):
            tag, indexes = group.split("=")
            assert tag in _CATALOG_SELECTS
            width = _CATALOG_SELECTS[tag][2]
            for encoded in indexes.split(","):
                index = int(encoded)
                assert index not in observed
                prefix = "catalog_" + str(index) + "_"
                bound = {name.removeprefix(prefix): value for name, value in values.items() if name.startswith(prefix)}
                rows = []
                for answer in self.answer(tag, bound):
                    assert len(answer) == width
                    rows.append(
                        {
                            "f" + str(i + 1): "\\x" + value.hex() if type(value) is bytes else value
                            for i, value in enumerate(answer)
                        }
                    )
                observed[index] = rows
        assert observed and sorted(observed) == list(range(len(observed)))
        # Native row_to_json preserves explicit bigint OIDs as JSON numbers.
        # Re-encode solely to emulate driver-owned JSON arrays/objects; never
        # reuse an observed answer across attestations or read selector arrays
        # in place of each independently bound ordinal selector.
        return CatalogResult([json.loads(json.dumps([observed[i] for i in range(len(observed))]))])


# Independent PG16 rendering of core models plus the pinned migrations.
# No ephemeral relation/role/function/index OIDs are fixture expectations.
SOURCE_AUTHORITY_CONSTRAINTS = {
    "users": (("users_pkey", "p", "PRIMARY KEY (id)", (1,), None, " ", " ", False, False),),
    "current_entitlement_evidence": (
        (
            "ck_current_entitlement_contract_version",
            "c",
            "CHECK (((contract_version)::text = " "'hodlxxi.current_entitlement_evidence.v1'::text))",
            (2,),
            None,
            " ",
            " ",
            False,
            False,
        ),
        (
            "ck_current_entitlement_created_order",
            "c",
            "CHECK ((observed_at <= created_at))",
            (9, 12),
            None,
            " ",
            " ",
            False,
            False,
        ),
        (
            "ck_current_entitlement_evidence_id_canonical",
            "c",
            "CHECK (((evidence_id)::text ~ " "'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'::text))",
            (1,),
            None,
            " ",
            " ",
            False,
            False,
        ),
        (
            "ck_current_entitlement_evidence_id_length",
            "c",
            "CHECK ((length((evidence_id)::text) = 36))",
            (1,),
            None,
            " ",
            " ",
            False,
            False,
        ),
        (
            "ck_current_entitlement_hash_canonical",
            "c",
            "CHECK (((source_evidence_sha256)::text ~ '^[0-9a-f]{64}$'::text))",
            (8,),
            None,
            " ",
            " ",
            False,
            False,
        ),
        (
            "ck_current_entitlement_hash_length",
            "c",
            "CHECK ((length((source_evidence_sha256)::text) = 64))",
            (8,),
            None,
            " ",
            " ",
            False,
            False,
        ),
        (
            "ck_current_entitlement_identity_class",
            "c",
            "CHECK (((identity_class)::text = ANY ((ARRAY['limited'::character varying, "
            "'full'::character varying])::text[])))",
            (4,),
            None,
            " ",
            " ",
            False,
            False,
        ),
        (
            "ck_current_entitlement_identity_relation",
            "c",
            "CHECK (((((identity_class)::text = 'full'::text) AND "
            "(current_full_relation_satisfied = true)) OR (((identity_class)::text = "
            "'limited'::text) AND (current_full_relation_satisfied = false))))",
            (4, 5),
            None,
            " ",
            " ",
            False,
            False,
        ),
        (
            "ck_current_entitlement_revoked_order",
            "c",
            "CHECK (((revoked_at IS NULL) OR ((revoked_at >= observed_at) AND " "(revoked_at <= created_at))))",
            (11, 9, 12),
            None,
            " ",
            " ",
            False,
            False,
        ),
        (
            "ck_current_entitlement_source_canonical",
            "c",
            "CHECK (((evidence_source)::text = btrim((evidence_source)::text)))",
            (6,),
            None,
            " ",
            " ",
            False,
            False,
        ),
        (
            "ck_current_entitlement_source_length",
            "c",
            "CHECK (((length((evidence_source)::text) >= 1) AND " "(length((evidence_source)::text) <= 128)))",
            (6,),
            None,
            " ",
            " ",
            False,
            False,
        ),
        (
            "ck_current_entitlement_subject_canonical",
            "c",
            "CHECK (((subject_pubkey)::text ~ '^[0-9a-f]{64}$'::text))",
            (3,),
            None,
            " ",
            " ",
            False,
            False,
        ),
        (
            "ck_current_entitlement_subject_length",
            "c",
            "CHECK ((length((subject_pubkey)::text) = 64))",
            (3,),
            None,
            " ",
            " ",
            False,
            False,
        ),
        (
            "ck_current_entitlement_validity_duration",
            "c",
            "CHECK ((valid_until <= (observed_at + '00:15:00'::interval)))",
            (10, 9),
            None,
            " ",
            " ",
            False,
            False,
        ),
        (
            "ck_current_entitlement_validity_order",
            "c",
            "CHECK ((observed_at < valid_until))",
            (9, 10),
            None,
            " ",
            " ",
            False,
            False,
        ),
        (
            "ck_current_entitlement_version_canonical",
            "c",
            "CHECK (((evidence_version)::text = btrim((evidence_version)::text)))",
            (7,),
            None,
            " ",
            " ",
            False,
            False,
        ),
        (
            "ck_current_entitlement_version_length",
            "c",
            "CHECK (((length((evidence_version)::text) >= 1) AND " "(length((evidence_version)::text) <= 64)))",
            (7,),
            None,
            " ",
            " ",
            False,
            False,
        ),
        ("current_entitlement_evidence_pkey", "p", "PRIMARY KEY (evidence_id)", (1,), None, " ", " ", False, False),
    ),
    "oauth_tokens": (
        (
            "oauth_tokens_client_id_fkey",
            "f",
            "FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id)",
            (5,),
            ("oauth_clients", ("client_id",)),
            "a",
            "a",
            False,
            False,
        ),
        ("oauth_tokens_pkey", "p", "PRIMARY KEY (id)", (1,), None, " ", " ", False, False),
        (
            "oauth_tokens_user_id_fkey",
            "f",
            "FOREIGN KEY (user_id) REFERENCES users(id)",
            (6,),
            ("users", ("id",)),
            "a",
            "a",
            False,
            False,
        ),
        (
            "uq_oauth_token_generation_owner",
            "u",
            "UNIQUE (id, user_id, client_id)",
            (1, 6, 5),
            None,
            " ",
            " ",
            False,
            False,
        ),
    ),
    "sessions": (
        ("sessions_pkey", "p", "PRIMARY KEY (session_id)", (1,), None, " ", " ", False, False),
        (
            "sessions_user_id_fkey",
            "f",
            "FOREIGN KEY (user_id) REFERENCES users(id)",
            (2,),
            ("users", ("id",)),
            "a",
            "a",
            False,
            False,
        ),
        ("uq_session_generation_owner", "u", "UNIQUE (session_id, user_id)", (1, 2), None, " ", " ", False, False),
    ),
    "oauth_clients": (("oauth_clients_pkey", "p", "PRIMARY KEY (client_id)", (1,), None, " ", " ", False, False),),
    "oauth_session_generations": (
        (
            "fk_oauth_generation_browser_owner",
            "f",
            "FOREIGN KEY (browser_generation_id, user_id, client_id, subject) REFERENCES "
            "oauth_browser_generations(generation_id, user_id, client_id, subject)",
            (2, 4, 5, 6),
            ("oauth_browser_generations", ("generation_id", "user_id", "client_id", "subject")),
            "a",
            "a",
            False,
            False,
        ),
        (
            "fk_oauth_generation_session_owner",
            "f",
            "FOREIGN KEY (session_id, user_id) REFERENCES sessions(session_id, user_id)",
            (3, 4),
            ("sessions", ("session_id", "user_id")),
            "a",
            "a",
            False,
            False,
        ),
        (
            "fk_oauth_generation_token_owner",
            "f",
            "FOREIGN KEY (token_id, user_id, client_id) REFERENCES oauth_tokens(id, " "user_id, client_id)",
            (1, 4, 5),
            ("oauth_tokens", ("id", "user_id", "client_id")),
            "a",
            "a",
            False,
            False,
        ),
        ("oauth_session_generations_pkey", "p", "PRIMARY KEY (token_id)", (1,), None, " ", " ", False, False),
        ("oauth_session_generations_session_id_key", "u", "UNIQUE (session_id)", (3,), None, " ", " ", False, False),
        (
            "oauth_session_generations_subject_check",
            "c",
            "CHECK (((subject)::text ~ '^[0-9a-f]{64}$'::text))",
            (6,),
            None,
            " ",
            " ",
            False,
            False,
        ),
    ),
    "oauth_browser_generations": (
        (
            "ck_browser_generation_lifetime",
            "c",
            "CHECK ((created_at < expires_at))",
            (6, 7),
            None,
            " ",
            " ",
            False,
            False,
        ),
        (
            "oauth_browser_generations_client_id_fkey",
            "f",
            "FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id)",
            (3,),
            ("oauth_clients", ("client_id",)),
            "a",
            "a",
            False,
            False,
        ),
        (
            "oauth_browser_generations_generation_id_check",
            "c",
            "CHECK (((generation_id)::text ~ '^[0-9a-f]{64}$'::text))",
            (1,),
            None,
            " ",
            " ",
            False,
            False,
        ),
        ("oauth_browser_generations_pkey", "p", "PRIMARY KEY (generation_id)", (1,), None, " ", " ", False, False),
        (
            "oauth_browser_generations_proof_id_check",
            "c",
            "CHECK (((proof_id)::text ~ '^[0-9a-f]{64}$'::text))",
            (5,),
            None,
            " ",
            " ",
            False,
            False,
        ),
        ("oauth_browser_generations_proof_id_key", "u", "UNIQUE (proof_id)", (5,), None, " ", " ", False, False),
        (
            "oauth_browser_generations_subject_check",
            "c",
            "CHECK (((subject)::text ~ '^[0-9a-f]{64}$'::text))",
            (4,),
            None,
            " ",
            " ",
            False,
            False,
        ),
        (
            "oauth_browser_generations_user_id_fkey",
            "f",
            "FOREIGN KEY (user_id) REFERENCES users(id)",
            (2,),
            ("users", ("id",)),
            "a",
            "a",
            False,
            False,
        ),
        (
            "uq_browser_generation_owner",
            "u",
            "UNIQUE (generation_id, user_id, client_id, subject)",
            (1, 2, 3, 4),
            None,
            " ",
            " ",
            False,
            False,
        ),
    ),
    "social_messaging_device_bindings": (
        (
            "ck_social_messaging_device_active_state",
            "c",
            "CHECK ((((active = true) AND ((operation)::text = ANY "
            "((ARRAY['register'::character varying, 'rotate'::character "
            "varying])::text[])) AND (retired_at IS NULL)) OR ((active = false) AND "
            "(retired_at IS NOT NULL))))",
            (13, 10, 14),
            None,
            " ",
            " ",
            False,
            False,
        ),
        (
            "ck_social_messaging_device_algorithm",
            "c",
            "CHECK (((algorithm)::text = 'x25519-v1'::text))",
            (5,),
            None,
            " ",
            " ",
            False,
            False,
        ),
        (
            "ck_social_messaging_device_binding_id",
            "c",
            "CHECK (((binding_id)::text ~ '^[0-9a-f]{64}$'::text))",
            (1,),
            None,
            " ",
            " ",
            False,
            False,
        ),
        (
            "ck_social_messaging_device_device_id",
            "c",
            "CHECK (((device_id)::text ~ '^[0-9a-f]{64}$'::text))",
            (4,),
            None,
            " ",
            " ",
            False,
            False,
        ),
        (
            "ck_social_messaging_device_operation",
            "c",
            "CHECK (((operation)::text = ANY ((ARRAY['register'::character varying, "
            "'rotate'::character varying, 'revoke'::character varying])::text[])))",
            (10,),
            None,
            " ",
            " ",
            False,
            False,
        ),
        (
            "ck_social_messaging_device_prior",
            "c",
            "CHECK (((((operation)::text = 'register'::text) AND (prior_binding_id "
            "IS NULL) AND (binding_version = 1)) OR (((operation)::text = ANY "
            "((ARRAY['rotate'::character varying, 'revoke'::character "
            "varying])::text[])) AND (prior_binding_id IS NOT NULL) AND "
            "(binding_version >= 2))))",
            (10, 11, 7),
            None,
            " ",
            " ",
            False,
            False,
        ),
        (
            "ck_social_messaging_device_public_key",
            "c",
            "CHECK (((public_key)::text ~ '^[0-9a-f]{64}$'::text))",
            (6,),
            None,
            " ",
            " ",
            False,
            False,
        ),
        (
            "ck_social_messaging_device_request_id",
            "c",
            "CHECK (((request_id)::text ~ '^[0-9a-f]{64}$'::text))",
            (12,),
            None,
            " ",
            " ",
            False,
            False,
        ),
        (
            "ck_social_messaging_device_schema",
            "c",
            "CHECK (((record_schema)::text = " "'hodlxxi.social_messaging_device_binding_record.v1'::text))",
            (2,),
            None,
            " ",
            " ",
            False,
            False,
        ),
        (
            "ck_social_messaging_device_subject",
            "c",
            "CHECK (((subject_pubkey)::text ~ '^[0-9a-f]{64}$'::text))",
            (3,),
            None,
            " ",
            " ",
            False,
            False,
        ),
        (
            "ck_social_messaging_device_validity",
            "c",
            "CHECK ((valid_from < expires_at))",
            (8, 9),
            None,
            " ",
            " ",
            False,
            False,
        ),
        (
            "ck_social_messaging_device_version",
            "c",
            "CHECK (((binding_version >= 1) AND (binding_version <= 1024)))",
            (7,),
            None,
            " ",
            " ",
            False,
            False,
        ),
        (
            "fk_social_messaging_device_prior",
            "f",
            "FOREIGN KEY (prior_binding_id) REFERENCES " "social_messaging_device_bindings(binding_id)",
            (11,),
            ("social_messaging_device_bindings", ("binding_id",)),
            "a",
            "a",
            False,
            False,
        ),
        ("social_messaging_device_bindings_pkey", "p", "PRIMARY KEY (binding_id)", (1,), None, " ", " ", False, False),
        (
            "uq_social_messaging_device_authorization_identity",
            "u",
            "UNIQUE (binding_id, subject_pubkey, device_id, public_key, "
            "binding_version, operation, valid_from, expires_at)",
            (1, 3, 4, 6, 7, 10, 8, 9),
            None,
            " ",
            " ",
            False,
            False,
        ),
        (
            "uq_social_messaging_device_subject_device_version",
            "u",
            "UNIQUE (subject_pubkey, device_id, binding_version)",
            (3, 4, 7),
            None,
            " ",
            " ",
            False,
            False,
        ),
        (
            "uq_social_messaging_device_subject_request",
            "u",
            "UNIQUE (subject_pubkey, request_id)",
            (3, 12),
            None,
            " ",
            " ",
            False,
            False,
        ),
    ),
    "social_session_issuers": (
        (
            "social_session_issuers_backend_id_check",
            "c",
            "CHECK ((length((backend_id)::text) > 0))",
            (2,),
            None,
            " ",
            " ",
            False,
            False,
        ),
        (
            "social_session_issuers_client_id_backend_id_service_princip_key",
            "u",
            "UNIQUE (client_id, backend_id, service_principal)",
            (1, 2, 3),
            None,
            " ",
            " ",
            False,
            False,
        ),
        (
            "social_session_issuers_client_id_fkey",
            "f",
            "FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id)",
            (1,),
            ("oauth_clients", ("client_id",)),
            "a",
            "a",
            False,
            False,
        ),
        ("social_session_issuers_pkey", "p", "PRIMARY KEY (client_id)", (1,), None, " ", " ", False, False),
        (
            "social_session_issuers_service_principal_check",
            "c",
            "CHECK ((length((service_principal)::text) > 0))",
            (3,),
            None,
            " ",
            " ",
            False,
            False,
        ),
    ),
    "social_messaging_mobile_operations": (
        (
            "social_messaging_mobile_opera_operation_id_request_id_autho_key",
            "u",
            "UNIQUE (operation_id, request_id, authorization_digest)",
            (1, 10, 11),
            None,
            " ",
            " ",
            False,
            False,
        ),
        (
            "social_messaging_mobile_operations_authorization_digest_key",
            "u",
            "UNIQUE (authorization_digest)",
            (11,),
            None,
            " ",
            " ",
            False,
            False,
        ),
        (
            "social_messaging_mobile_operations_check",
            "c",
            "CHECK (((created_at < expires_at) AND (expires_at <= (created_at + " "300))))",
            (6, 7),
            None,
            " ",
            " ",
            False,
            False,
        ),
        (
            "social_messaging_mobile_operations_check1",
            "c",
            "CHECK (((((method)::text = 'legacy_challenge_v1'::text) AND "
            "((operation_id)::text ~ "
            "'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'::text) "
            "AND (revision IS NULL) AND (secret_commitment IS NULL) AND (source "
            "IS NOT NULL) AND ((status)::text <> ALL ((ARRAY['created'::character "
            "varying, 'awaiting-approval'::character varying, "
            "'approval-claimed'::character varying])::text[]))) OR "
            "(((method)::text = 'qr_desktop_v1'::text) AND ((operation_id)::text "
            "~ '^[0-9a-f]{64}$'::text) AND ((revision)::text ~ "
            "'^[0-9a-f]{64}$'::text) AND (revision IS NOT NULL) AND "
            "((secret_commitment)::text ~ '^[0-9a-f]{64}$'::text) AND "
            "(secret_commitment IS NOT NULL) AND ((status)::text <> "
            "'reserved'::text))))",
            (2, 1, 8, 9, 12, 13),
            None,
            " ",
            " ",
            False,
            False,
        ),
        (
            "social_messaging_mobile_operations_check2",
            "c",
            "CHECK ((((source IS NULL) AND (request_id IS NULL) AND "
            "(authorization_digest IS NULL) AND ((status)::text = ANY "
            "((ARRAY['created'::character varying, 'expired'::character varying, "
            "'cancelled'::character varying, 'abandoned'::character varying, "
            "'rejected'::character varying])::text[]))) OR ((source IS NOT NULL) "
            "AND ((octet_length(source) >= 1) AND (octet_length(source) <= "
            "16384)) AND (request_id IS NOT NULL) AND ((request_id)::text ~ "
            "'^[0-9a-f]{64}$'::text) AND (authorization_digest IS NOT NULL) AND "
            "((authorization_digest)::text ~ '^[0-9a-f]{64}$'::text) AND "
            "((status)::text <> 'created'::text))))",
            (12, 10, 11, 13),
            None,
            " ",
            " ",
            False,
            False,
        ),
        (
            "social_messaging_mobile_operations_context_id_check",
            "c",
            "CHECK (((context_id)::text ~ '^[0-9a-f]{64}$'::text))",
            (4,),
            None,
            " ",
            " ",
            False,
            False,
        ),
        (
            "social_messaging_mobile_operations_created_at_check",
            "c",
            "CHECK ((created_at >= 0))",
            (6,),
            None,
            " ",
            " ",
            False,
            False,
        ),
        (
            "social_messaging_mobile_operations_method_check",
            "c",
            "CHECK (((method)::text = ANY "
            "((ARRAY['legacy_challenge_v1'::character varying, "
            "'qr_desktop_v1'::character varying])::text[])))",
            (2,),
            None,
            " ",
            " ",
            False,
            False,
        ),
        (
            "social_messaging_mobile_operations_pkey",
            "p",
            "PRIMARY KEY (operation_id)",
            (1,),
            None,
            " ",
            " ",
            False,
            False,
        ),
        (
            "social_messaging_mobile_operations_request_id_fkey",
            "f",
            "FOREIGN KEY (request_id) REFERENCES " "social_messaging_device_authorization_requests(request_id)",
            (10,),
            ("social_messaging_device_authorization_requests", ("request_id",)),
            "a",
            "a",
            False,
            False,
        ),
        (
            "social_messaging_mobile_operations_request_id_key",
            "u",
            "UNIQUE (request_id)",
            (10,),
            None,
            " ",
            " ",
            False,
            False,
        ),
        (
            "social_messaging_mobile_operations_session_commitment_check",
            "c",
            "CHECK (((session_commitment)::text ~ '^[0-9a-f]{64}$'::text))",
            (5,),
            None,
            " ",
            " ",
            False,
            False,
        ),
        (
            "social_messaging_mobile_operations_status_check",
            "c",
            "CHECK (((status)::text = ANY ((ARRAY['created'::character varying, "
            "'reserved'::character varying, 'awaiting-approval'::character "
            "varying, 'approval-claimed'::character varying, "
            "'accepted'::character varying, 'expired'::character varying, "
            "'cancelled'::character varying, 'abandoned'::character varying, "
            "'rejected'::character varying])::text[])))",
            (13,),
            None,
            " ",
            " ",
            False,
            False,
        ),
        (
            "social_messaging_mobile_operations_subject_check",
            "c",
            "CHECK (((subject)::text ~ '^[0-9a-f]{64}$'::text))",
            (3,),
            None,
            " ",
            " ",
            False,
            False,
        ),
        (
            "trg_social_mobile_operation_receipt",
            "t",
            "TRIGGER DEFERRABLE INITIALLY DEFERRED",
            None,
            None,
            " ",
            " ",
            True,
            True,
        ),
    ),
    "social_messaging_device_authorization_binding_owners": (
        (
            "social_messaging_device_authorization_binding_o_binding_id_fkey",
            "f",
            "FOREIGN KEY (binding_id) REFERENCES "
            "social_messaging_device_bindings(binding_id) ON "
            "DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED",
            (1,),
            ("social_messaging_device_bindings", ("binding_id",)),
            "a",
            "r",
            True,
            True,
        ),
        (
            "social_messaging_device_authorization_binding_o_request_id_fkey",
            "f",
            "FOREIGN KEY (request_id) REFERENCES "
            "social_messaging_device_authorization_requests(request_id) "
            "DEFERRABLE INITIALLY DEFERRED",
            (2,),
            ("social_messaging_device_authorization_requests", ("request_id",)),
            "a",
            "a",
            True,
            True,
        ),
        (
            "social_messaging_device_authorization_binding_ow_request_id_key",
            "u",
            "UNIQUE (request_id)",
            (2,),
            None,
            " ",
            " ",
            False,
            False,
        ),
        (
            "social_messaging_device_authorization_binding_owners_pkey",
            "p",
            "PRIMARY KEY (binding_id)",
            (1,),
            None,
            " ",
            " ",
            False,
            False,
        ),
    ),
}

SOURCE_AUTHORITY_INDEXES = {
    "users": (
        ("idx_user_created", "n", (3,), None),
        ("idx_user_pubkey", "n", (2,), None),
        ("ix_users_pubkey", "u", (2,), None),
        ("users_pkey", "p", (1,), None),
    ),
    "current_entitlement_evidence": (
        ("current_entitlement_evidence_pkey", "p", (1,), None),
        ("idx_current_entitlement_revoked_at", "n", (11,), None),
        ("idx_current_entitlement_subject", "n", (3,), None),
        ("idx_current_entitlement_subject_created", "n", (3, 12), None),
        ("idx_current_entitlement_subject_observed", "n", (3, 9), None),
        ("idx_current_entitlement_valid_until", "n", (10,), None),
    ),
    "oauth_tokens": (
        ("idx_token_access", "n", (2,), None),
        ("idx_token_expires", "n", (9,), None),
        ("idx_token_refresh", "n", (3,), None),
        ("idx_token_user", "n", (6,), None),
        ("ix_oauth_tokens_access_token", "u", (2,), None),
        ("ix_oauth_tokens_refresh_token", "u", (3,), None),
        ("oauth_tokens_pkey", "p", (1,), None),
        ("uq_oauth_token_generation_owner", "u", (1, 6, 5), None),
    ),
    "sessions": (
        ("idx_session_active", "n", (10, 5), None),
        ("idx_session_expires", "n", (5,), None),
        ("idx_session_user", "n", (2,), None),
        ("sessions_pkey", "p", (1,), None),
        ("uq_session_generation_owner", "u", (1, 2), None),
    ),
    "oauth_clients": (
        ("idx_client_created", "n", (9,), None),
        ("idx_client_name", "n", (3,), None),
        ("oauth_clients_pkey", "p", (1,), None),
    ),
    "oauth_session_generations": (
        ("idx_oauth_generation_browser", "n", (2,), None),
        ("idx_oauth_generation_owner", "n", (4, 5), None),
        ("oauth_session_generations_pkey", "p", (1,), None),
        ("oauth_session_generations_session_id_key", "u", (3,), None),
    ),
    "oauth_browser_generations": (
        ("idx_browser_generation_owner", "n", (2, 3), None),
        ("oauth_browser_generations_pkey", "p", (1,), None),
        ("oauth_browser_generations_proof_id_key", "u", (5,), None),
        ("uq_browser_generation_current", "u", (2, 3), "(is_active IS TRUE)"),
        ("uq_browser_generation_owner", "u", (1, 2, 3, 4), None),
    ),
    "social_messaging_device_bindings": (
        ("idx_social_messaging_device_current_subject", "n", (3, 13, 4), None),
        ("idx_social_messaging_device_expires_at", "n", (9,), None),
        ("social_messaging_device_bindings_pkey", "p", (1,), None),
        ("uq_social_messaging_device_active_device", "u", (3, 4), "(active = true)"),
        ("uq_social_messaging_device_active_public_key", "u", (6,), "(active = true)"),
        ("uq_social_messaging_device_authorization_identity", "u", (1, 3, 4, 6, 7, 10, 8, 9), None),
        (
            "uq_social_messaging_device_historical_public_key",
            "u",
            (6,),
            "((operation)::text = ANY ((ARRAY['register'::character varying, "
            "'rotate'::character varying])::text[]))",
        ),
        ("uq_social_messaging_device_subject_device_version", "u", (3, 4, 7), None),
        ("uq_social_messaging_device_subject_request", "u", (3, 12), None),
    ),
    "social_session_issuers": (
        ("social_session_issuers_client_id_backend_id_service_princip_key", "u", (1, 2, 3), None),
        ("social_session_issuers_pkey", "p", (1,), None),
    ),
    "social_messaging_mobile_operations": (
        ("idx_social_mobile_expiry", "n", (13, 7), None),
        ("social_messaging_mobile_opera_operation_id_request_id_autho_key", "u", (1, 10, 11), None),
        ("social_messaging_mobile_operations_authorization_digest_key", "u", (11,), None),
        ("social_messaging_mobile_operations_pkey", "p", (1,), None),
        ("social_messaging_mobile_operations_request_id_key", "u", (10,), None),
    ),
    "social_messaging_device_authorization_binding_owners": (
        ("social_messaging_device_authorization_binding_ow_request_id_key", "u", (2,), None),
        ("social_messaging_device_authorization_binding_owners_pkey", "p", (1,), None),
    ),
}

SOURCE_AUTHORITY_TRIGGERS = {
    "users": (
        (
            "trg_oauth_user_session_invalidation",
            "oauth_owner_session_invalidation_v1",
            19,
            None,
            "CREATE TRIGGER trg_oauth_user_session_invalidation BEFORE UPDATE ON public.users FOR EACH ROW "
            "EXECUTE FUNCTION oauth_owner_session_invalidation_v1()",
        ),
        (
            "v2_invalidate",
            "social_session_v2_invalidate",
            27,
            None,
            "CREATE TRIGGER v2_invalidate BEFORE DELETE OR UPDATE ON public.users FOR EACH ROW EXECUTE "
            "FUNCTION social_session_v2_invalidate()",
        ),
    ),
    "current_entitlement_evidence": (),
    "oauth_tokens": (
        (
            "trg_oauth_token_session_invalidation",
            "oauth_token_session_invalidation_v1",
            19,
            None,
            "CREATE TRIGGER trg_oauth_token_session_invalidation BEFORE UPDATE ON public.oauth_tokens "
            "FOR EACH ROW EXECUTE FUNCTION oauth_token_session_invalidation_v1()",
        ),
        (
            "trg_social_session_token_guard",
            "social_session_token_guard_v1",
            19,
            None,
            "CREATE TRIGGER trg_social_session_token_guard BEFORE UPDATE ON public.oauth_tokens FOR "
            "EACH ROW EXECUTE FUNCTION social_session_token_guard_v1()",
        ),
        (
            "v2_birth",
            "social_session_v2_birth",
            5,
            None,
            "CREATE TRIGGER v2_birth AFTER INSERT ON public.oauth_tokens FOR EACH ROW EXECUTE FUNCTION "
            "social_session_v2_birth()",
        ),
        (
            "v2_invalidate",
            "social_session_v2_invalidate",
            27,
            None,
            "CREATE TRIGGER v2_invalidate BEFORE DELETE OR UPDATE ON public.oauth_tokens FOR EACH ROW "
            "EXECUTE FUNCTION social_session_v2_invalidate()",
        ),
    ),
    "sessions": (
        (
            "trg_oauth_mapped_session_guard",
            "oauth_mapped_session_guard_v1",
            19,
            None,
            "CREATE TRIGGER trg_oauth_mapped_session_guard BEFORE UPDATE ON public.sessions FOR EACH ROW "
            "EXECUTE FUNCTION oauth_mapped_session_guard_v1()",
        ),
        (
            "trg_social_session_parent_invalidation",
            "social_session_parent_invalidation_v1",
            19,
            None,
            "CREATE TRIGGER trg_social_session_parent_invalidation BEFORE UPDATE ON public.sessions FOR "
            "EACH ROW EXECUTE FUNCTION social_session_parent_invalidation_v1()",
        ),
        (
            "v2_invalidate",
            "social_session_v2_invalidate",
            27,
            None,
            "CREATE TRIGGER v2_invalidate BEFORE DELETE OR UPDATE ON public.sessions FOR EACH ROW EXECUTE "
            "FUNCTION social_session_v2_invalidate()",
        ),
    ),
    "oauth_clients": (
        (
            "trg_oauth_client_session_invalidation",
            "oauth_owner_session_invalidation_v1",
            19,
            None,
            "CREATE TRIGGER trg_oauth_client_session_invalidation BEFORE UPDATE ON "
            "public.oauth_clients FOR EACH ROW EXECUTE FUNCTION oauth_owner_session_invalidation_v1()",
        ),
        (
            "trg_social_session_client_invalidation",
            "social_session_client_invalidation_v1",
            19,
            None,
            "CREATE TRIGGER trg_social_session_client_invalidation BEFORE UPDATE ON "
            "public.oauth_clients FOR EACH ROW EXECUTE FUNCTION "
            "social_session_client_invalidation_v1()",
        ),
        (
            "v2_invalidate",
            "social_session_v2_invalidate",
            27,
            None,
            "CREATE TRIGGER v2_invalidate BEFORE DELETE OR UPDATE ON public.oauth_clients FOR EACH ROW "
            "EXECUTE FUNCTION social_session_v2_invalidate()",
        ),
    ),
    "oauth_session_generations": (
        (
            "trg_oauth_generation_guard",
            "oauth_session_generation_guard_v1",
            31,
            None,
            "CREATE TRIGGER trg_oauth_generation_guard BEFORE INSERT OR DELETE OR UPDATE "
            "ON public.oauth_session_generations FOR EACH ROW EXECUTE FUNCTION "
            "oauth_session_generation_guard_v1()",
        ),
    ),
    "oauth_browser_generations": (
        (
            "trg_oauth_browser_generation_guard",
            "oauth_browser_generation_guard_v1",
            31,
            None,
            "CREATE TRIGGER trg_oauth_browser_generation_guard BEFORE INSERT OR DELETE OR "
            "UPDATE ON public.oauth_browser_generations FOR EACH ROW EXECUTE FUNCTION "
            "oauth_browser_generation_guard_v1()",
        ),
        (
            "v2_invalidate",
            "social_session_v2_invalidate",
            27,
            None,
            "CREATE TRIGGER v2_invalidate BEFORE DELETE OR UPDATE ON "
            "public.oauth_browser_generations FOR EACH ROW EXECUTE FUNCTION "
            "social_session_v2_invalidate()",
        ),
    ),
    "social_messaging_device_bindings": (
        (
            "trg_social_session_binding_invalidation",
            "social_session_binding_invalidation_v1",
            19,
            None,
            "CREATE TRIGGER trg_social_session_binding_invalidation BEFORE UPDATE "
            "ON public.social_messaging_device_bindings FOR EACH ROW EXECUTE "
            "FUNCTION social_session_binding_invalidation_v1()",
        ),
        (
            "v2_birth",
            "social_session_v2_birth",
            5,
            None,
            "CREATE TRIGGER v2_birth AFTER INSERT ON "
            "public.social_messaging_device_bindings FOR EACH ROW EXECUTE FUNCTION "
            "social_session_v2_birth()",
        ),
        (
            "v2_invalidate",
            "social_session_v2_invalidate",
            27,
            None,
            "CREATE TRIGGER v2_invalidate BEFORE DELETE OR UPDATE ON "
            "public.social_messaging_device_bindings FOR EACH ROW EXECUTE FUNCTION "
            "social_session_v2_invalidate()",
        ),
    ),
    "social_session_issuers": (
        (
            "trg_social_session_issuer_guard",
            "social_session_issuer_guard_v1",
            31,
            None,
            "CREATE TRIGGER trg_social_session_issuer_guard BEFORE INSERT OR DELETE OR UPDATE "
            "ON public.social_session_issuers FOR EACH ROW EXECUTE FUNCTION "
            "social_session_issuer_guard_v1()",
        ),
        (
            "v2_invalidate",
            "social_session_v2_invalidate",
            27,
            None,
            "CREATE TRIGGER v2_invalidate BEFORE DELETE OR UPDATE ON "
            "public.social_session_issuers FOR EACH ROW EXECUTE FUNCTION "
            "social_session_v2_invalidate()",
        ),
    ),
    "social_messaging_mobile_operations": (
        (
            "trg_social_mobile_operation_guard",
            "guard_social_mobile_operation_v1",
            31,
            None,
            "CREATE TRIGGER trg_social_mobile_operation_guard BEFORE INSERT OR "
            "DELETE OR UPDATE ON public.social_messaging_mobile_operations FOR "
            "EACH ROW EXECUTE FUNCTION guard_social_mobile_operation_v1()",
        ),
        (
            "trg_social_mobile_operation_receipt",
            "validate_social_mobile_acceptance_v1",
            21,
            "trg_social_mobile_operation_receipt",
            "CREATE CONSTRAINT TRIGGER trg_social_mobile_operation_receipt AFTER "
            "INSERT OR UPDATE ON public.social_messaging_mobile_operations "
            "DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION "
            "validate_social_mobile_acceptance_v1()",
        ),
    ),
    "social_messaging_device_authorization_binding_owners": (
        (
            "trg_social_binding_owner_immutable",
            "reject_social_device_authorization_mutation_v1",
            27,
            None,
            "CREATE TRIGGER trg_social_binding_owner_immutable "
            "BEFORE DELETE OR UPDATE ON "
            "public.social_messaging_device_authorization_binding_owners "
            "FOR EACH ROW EXECUTE FUNCTION "
            "reject_social_device_authorization_mutation_v1()",
        ),
    ),
}

SOURCE_EXTERNAL_FKS = {
    "oauth_codes": (
        (
            "oauth_codes_client_id_fkey",
            "f",
            "FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id)",
            (2,),
            ("oauth_clients", ("client_id",)),
            "a",
            "a",
            False,
            False,
        ),
        (
            "oauth_codes_user_id_fkey",
            "f",
            "FOREIGN KEY (user_id) REFERENCES users(id)",
            (3,),
            ("users", ("id",)),
            "a",
            "a",
            False,
            False,
        ),
    ),
    "oauth_session_code_bindings": (
        (
            "oauth_session_code_bindings_browser_generation_id_fkey",
            "f",
            "FOREIGN KEY (browser_generation_id) REFERENCES " "oauth_browser_generations(generation_id)",
            (2,),
            ("oauth_browser_generations", ("generation_id",)),
            "a",
            "a",
            False,
            False,
        ),
    ),
    "social_messaging_device_binding_authorization_evidence": (
        (
            "fk_social_device_authorization_evidence_binding",
            "f",
            "FOREIGN KEY (binding_id, subject_pubkey, "
            "device_id, public_key, binding_version, "
            "binding_operation, binding_valid_from, "
            "binding_expires_at) REFERENCES "
            "social_messaging_device_bindings(binding_id, "
            "subject_pubkey, device_id, public_key, "
            "binding_version, operation, valid_from, "
            "expires_at) ON DELETE RESTRICT DEFERRABLE "
            "INITIALLY DEFERRED",
            (1, 7, 8, 9, 10, 11, 12, 13),
            (
                "social_messaging_device_bindings",
                (
                    "binding_id",
                    "subject_pubkey",
                    "device_id",
                    "public_key",
                    "binding_version",
                    "operation",
                    "valid_from",
                    "expires_at",
                ),
            ),
            "a",
            "r",
            True,
            True,
        ),
    ),
    "social_messaging_mobile_acceptances": (
        (
            "social_messaging_mobile_accep_operation_id_request_id_auth_fkey",
            "f",
            "FOREIGN KEY (operation_id, request_id, authorization_digest) "
            "REFERENCES social_messaging_mobile_operations(operation_id, "
            "request_id, authorization_digest) ON DELETE RESTRICT DEFERRABLE "
            "INITIALLY DEFERRED",
            (1, 2, 3),
            ("social_messaging_mobile_operations", ("operation_id", "request_id", "authorization_digest")),
            "a",
            "r",
            True,
            True,
        ),
        (
            "social_messaging_mobile_acceptances_binding_id_fkey",
            "f",
            "FOREIGN KEY (binding_id) REFERENCES " "social_messaging_device_bindings(binding_id) ON DELETE RESTRICT",
            (4,),
            ("social_messaging_device_bindings", ("binding_id",)),
            "a",
            "r",
            False,
            False,
        ),
    ),
    "social_session_issuances": (
        (
            "social_session_issuances_binding_id_fkey",
            "f",
            "FOREIGN KEY (binding_id) REFERENCES " "social_messaging_device_bindings(binding_id)",
            (10,),
            ("social_messaging_device_bindings", ("binding_id",)),
            "a",
            "a",
            False,
            False,
        ),
        (
            "social_session_issuances_client_id_backend_id_service_prin_fkey",
            "f",
            "FOREIGN KEY (client_id, backend_id, service_principal) REFERENCES "
            "social_session_issuers(client_id, backend_id, service_principal)",
            (5, 6, 7),
            ("social_session_issuers", ("client_id", "backend_id", "service_principal")),
            "a",
            "a",
            False,
            False,
        ),
        (
            "social_session_issuances_token_id_user_id_client_id_fkey",
            "f",
            "FOREIGN KEY (token_id, user_id, client_id) REFERENCES oauth_tokens(id, " "user_id, client_id)",
            (3, 8, 5),
            ("oauth_tokens", ("id", "user_id", "client_id")),
            "a",
            "a",
            False,
            False,
        ),
    ),
    "social_session_pairing_parents": (
        (
            "social_session_pairing_parents_client_id_fkey",
            "f",
            "FOREIGN KEY (client_id) REFERENCES social_session_issuers(client_id)",
            (3,),
            ("social_session_issuers", ("client_id",)),
            "a",
            "a",
            False,
            False,
        ),
        (
            "social_session_pairing_parents_operation_id_fkey",
            "f",
            "FOREIGN KEY (operation_id) REFERENCES " "social_messaging_mobile_operations(operation_id)",
            (1,),
            ("social_messaging_mobile_operations", ("operation_id",)),
            "a",
            "a",
            False,
            False,
        ),
        (
            "social_session_pairing_parents_parent_token_id_fkey",
            "f",
            "FOREIGN KEY (parent_token_id) REFERENCES " "oauth_session_generations(token_id)",
            (2,),
            ("oauth_session_generations", ("token_id",)),
            "a",
            "a",
            False,
            False,
        ),
    ),
}

SOURCE_EXTERNAL_COLUMNS = {
    "oauth_session_code_bindings": ((2, "browser_generation_id", 1043, 68, True),),
    "social_messaging_device_binding_authorization_evidence": (
        (1, "binding_id", 1043, 68, True),
        (7, "subject_pubkey", 1043, 68, True),
        (8, "device_id", 1043, 68, True),
        (9, "public_key", 1043, 68, True),
        (10, "binding_version", 20, -1, True),
        (11, "binding_operation", 1043, 12, True),
        (12, "binding_valid_from", 1184, -1, True),
        (13, "binding_expires_at", 1184, -1, True),
    ),
    "social_session_issuances": (
        (3, "token_id", 1043, 40, True),
        (5, "client_id", 1043, 259, True),
        (6, "backend_id", 1043, 259, True),
        (7, "service_principal", 1043, 259, True),
        (8, "user_id", 1043, 40, True),
        (10, "binding_id", 1043, 68, True),
    ),
    "social_messaging_device_authorization_requests": ((1, "request_id", 1043, 68, True),),
    "social_messaging_mobile_acceptances": (
        (1, "operation_id", 1043, 68, True),
        (2, "request_id", 1043, 68, True),
        (3, "authorization_digest", 1043, 68, True),
        (4, "binding_id", 1043, 68, True),
    ),
    "social_session_pairing_parents": (
        (1, "operation_id", 1043, 68, True),
        (2, "parent_token_id", 1043, 40, True),
        (3, "client_id", 1043, 259, True),
    ),
    "oauth_codes": ((2, "client_id", 1043, 259, True), (3, "user_id", 1043, 40, True)),
}

SOURCE_AUTHORITY_ACLS = {
    "users": ("SELECT", "UPDATE"),
    "current_entitlement_evidence": ("SELECT", "UPDATE"),
    "oauth_tokens": ("INSERT", "SELECT", "UPDATE"),
    "sessions": ("SELECT", "UPDATE"),
    "oauth_clients": ("SELECT", "UPDATE"),
    "oauth_session_generations": ("SELECT",),
    "oauth_browser_generations": ("SELECT", "UPDATE"),
    "social_messaging_device_bindings": ("INSERT", "SELECT", "UPDATE"),
    "social_session_issuers": ("SELECT", "UPDATE"),
    "social_messaging_mobile_operations": ("SELECT",),
    "social_messaging_device_authorization_binding_owners": ("SELECT",),
}

SOURCE_NO_TOAST = (
    "current_entitlement_evidence",
    "oauth_browser_generations",
    "social_messaging_device_bindings",
    "social_messaging_device_authorization_binding_owners",
)


def populate_authority_catalog(connection):
    columns = dependency_source_columns()
    for i, (n, profile) in enumerate(sorted(SOURCE_EXTERNAL_COLUMNS.items())):
        r = shared_relation(n, 5000 + i, columns=max(c[0] for c in profile))
        connection.relations[n] = r
        positions = tuple(c[0] for c in profile)
        rows = dependency_fixture_attributes(r, tuple(c[1:] for c in profile))
        for row, position in zip(rows, positions):
            row["attribute"]["attnum"] = position
        connection.catalog[r["oid"]] = {"to_jsonb(a)": rows, "to_jsonb(k)": [], "to_jsonb(i)": []}
    request = "social_messaging_device_authorization_requests"
    r = connection.relations[request]
    request_columns = (("request_id", 1043, 68, True),)
    connection.catalog[r["oid"]]["to_jsonb(i)"] = [
        fixture_index(r, request + "_pkey", request_columns, [1], "p", None, 20000)
    ]
    connection.catalog[r["oid"]]["to_jsonb(k)"] = [
        fixture_key(r, request + "_pkey", "p", [1], 20000, "PRIMARY KEY (request_id)")
    ]
    columns[request] = request_columns
    for name, specs in SOURCE_AUTHORITY_INDEXES.items():
        r = connection.relations[name]
        r.update(
            relchecks=sum(p[1] == "c" for p in SOURCE_AUTHORITY_CONSTRAINTS[name]),
            relhastriggers=bool(SOURCE_AUTHORITY_TRIGGERS[name]),
        )
        if name in SOURCE_NO_TOAST:
            r["reltoastrelid"] = 0
        entries = connection.catalog[r["oid"]]
        entries["to_jsonb(k)"] = []
        entries["to_jsonb(i)"] = [
            fixture_index(r, n, columns[name], keys, kind, pred, 21000 + r["oid"] * 100 + i)
            for i, (n, kind, keys, pred) in enumerate(specs)
        ]
        entries["aclexplode"] = [
            (r["relowner"], r["relowner"], p, False, 203)
            for p in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")
        ]
        entries["aclexplode"] += [(r["relowner"], 203, p, False, 203) for p in SOURCE_AUTHORITY_ACLS[name]]
        fixture_toast(connection, r)
    for name, specs in {**SOURCE_AUTHORITY_CONSTRAINTS, **SOURCE_EXTERNAL_FKS}.items():
        r = connection.relations[name]
        for n, kind, definition, keys, target, update, delete, deferrable, deferred in specs:
            index, parent, parent_keys, operators = 0, 0, None, None
            if kind in ("p", "u"):
                index = int(
                    next(
                        i["index"]["indexrelid"]
                        for i in connection.catalog[r["oid"]]["to_jsonb(i)"]
                        if i["relation"]["relname"] == n
                    )
                )
            if target:
                pn, pnames = target
                pr = connection.relations[pn]
                parent = pr["oid"]
                parent_keys = [next(i for i, c in enumerate(columns[pn], 1) if c[0] == key) for key in pnames]
                operators = [{1043: 98, 20: 410, 1184: 1320}[columns[pn][k - 1][1]] for k in parent_keys]
                # Parent key was constructed in the separate independent index inventory.
                matches = [
                    i
                    for i in connection.catalog[parent]["to_jsonb(i)"]
                    if i["index"]["indisunique"] and i["index"]["indkey"] == parent_keys and i["predicate"] is None
                ]
                assert len(matches) == 1, (pn, pnames)
                index = int(matches[0]["index"]["indexrelid"])
            entry = fixture_key(
                r, n, kind, keys, index, definition, parent=parent, parent_keys=parent_keys, operators=operators
            )
            entry["constraint"].update(
                oid=str(3000000 + r["oid"] * 100 + len(connection.catalog[r["oid"]]["to_jsonb(k)"])),
                confupdtype=update,
                confdeltype=delete,
                condeferrable=deferrable,
                condeferred=deferred,
            )
            connection.catalog[r["oid"]]["to_jsonb(k)"].append(entry)
    from app.services.social_session_issuance_v2_storage import CONSTRAINTS

    for name, specs in CONSTRAINTS.items():
        for n, kind, _, _, target in specs:
            if kind != "f":
                continue
            pn, pnames = target
            parent_keys = [next(i for i, c in enumerate(columns[pn], 1) if c[0] == key) for key in pnames]
            index = next(
                i["index"]["indexrelid"]
                for i in connection.catalog[connection.relations[pn]["oid"]]["to_jsonb(i)"]
                if i["index"]["indkey"] == parent_keys and i["index"]["indisunique"]
            )
            c = next(
                c["constraint"]
                for c in connection.catalog[connection.relations[name]["oid"]]["to_jsonb(k)"]
                if c["constraint"]["conname"] == n
            )
            c["conindid"] = index
    for name, profiles in SOURCE_AUTHORITY_TRIGGERS.items():
        r = connection.relations[name]
        rows = []
        for n, fn, kind, constraint, definition in profiles:
            cons = (
                int(
                    next(
                        c["constraint"]["oid"]
                        for c in connection.catalog[r["oid"]]["to_jsonb(k)"]
                        if c["constraint"]["conname"] == constraint
                    )
                )
                if constraint
                else 0
            )
            t = fixture_trigger(
                r["oid"],
                4000000 + r["oid"] * 100 + len(rows),
                n,
                connection.functions[fn]["function"]["oid"],
                kind,
                constraint=cons,
                deferred=bool(constraint),
            )
            rows.append(
                dict(
                    trigger=native_json(t, "trigger"),
                    definition=definition,
                    proname=fn,
                    nspname="public",
                    constraint_name=constraint,
                )
            )
        connection.catalog[r["oid"]]["to_jsonb(t)"] = rows


SOURCE_PG16_OPCLASSES = {
    1978: {
        "opclass": {
            "oid": "1978",
            "opcname": "int4_ops",
            "opcowner": "202",
            "opcfamily": "1976",
            "opcintype": "23",
            "opcmethod": "403",
            "opcdefault": True,
            "opckeytype": "0",
            "opcnamespace": "11",
        },
        "nspname": "pg_catalog",
        "amname": "btree",
        "owner": 202,
    },
    1981: {
        "opclass": {
            "oid": "1981",
            "opcname": "oid_ops",
            "opcowner": "202",
            "opcfamily": "1989",
            "opcintype": "26",
            "opcmethod": "403",
            "opcdefault": True,
            "opckeytype": "0",
            "opcnamespace": "11",
        },
        "nspname": "pg_catalog",
        "amname": "btree",
        "owner": 202,
    },
    3124: {
        "opclass": {
            "oid": "3124",
            "opcname": "int8_ops",
            "opcowner": "202",
            "opcfamily": "1976",
            "opcintype": "20",
            "opcmethod": "403",
            "opcdefault": True,
            "opckeytype": "0",
            "opcnamespace": "11",
        },
        "nspname": "pg_catalog",
        "amname": "btree",
        "owner": 202,
    },
    3126: {
        "opclass": {
            "oid": "3126",
            "opcname": "text_ops",
            "opcowner": "202",
            "opcfamily": "1994",
            "opcintype": "25",
            "opcmethod": "403",
            "opcdefault": True,
            "opckeytype": "0",
            "opcnamespace": "11",
        },
        "nspname": "pg_catalog",
        "amname": "btree",
        "owner": 202,
    },
    3127: {
        "opclass": {
            "oid": "3127",
            "opcname": "timestamptz_ops",
            "opcowner": "202",
            "opcfamily": "434",
            "opcintype": "1184",
            "opcmethod": "403",
            "opcdefault": True,
            "opckeytype": "0",
            "opcnamespace": "11",
        },
        "nspname": "pg_catalog",
        "amname": "btree",
        "owner": 202,
    },
    3128: {
        "opclass": {
            "oid": "3128",
            "opcname": "timestamp_ops",
            "opcowner": "202",
            "opcfamily": "434",
            "opcintype": "1114",
            "opcmethod": "403",
            "opcdefault": True,
            "opckeytype": "0",
            "opcnamespace": "11",
        },
        "nspname": "pg_catalog",
        "amname": "btree",
        "owner": 202,
    },
    10003: {
        "opclass": {
            "oid": "10003",
            "opcname": "bool_ops",
            "opcowner": "202",
            "opcfamily": "424",
            "opcintype": "16",
            "opcmethod": "403",
            "opcdefault": True,
            "opckeytype": "0",
            "opcnamespace": "11",
        },
        "nspname": "pg_catalog",
        "amname": "btree",
        "owner": 202,
    },
}


SOURCE_PG16_OPERATORS = {
    98: {
        "operator": {
            "oid": "98",
            "oprcom": "98",
            "oprcode": "texteq",
            "oprjoin": "eqjoinsel",
            "oprkind": "b",
            "oprleft": "25",
            "oprname": "=",
            "oprrest": "eqsel",
            "oprowner": "202",
            "oprright": "25",
            "oprnegate": "531",
            "oprresult": "16",
            "oprcanhash": True,
            "oprcanmerge": True,
            "oprnamespace": "11",
        },
        "nspname": "pg_catalog",
        "owner": 202,
        "prosrc": "texteq",
        "lanname": "internal",
        "pronargs": 2,
        "prorettype": 16,
        "canonical": True,
    },
    410: {
        "operator": {
            "oid": "410",
            "oprcom": "410",
            "oprcode": "int8eq",
            "oprjoin": "eqjoinsel",
            "oprkind": "b",
            "oprleft": "20",
            "oprname": "=",
            "oprrest": "eqsel",
            "oprowner": "202",
            "oprright": "20",
            "oprnegate": "411",
            "oprresult": "16",
            "oprcanhash": True,
            "oprcanmerge": True,
            "oprnamespace": "11",
        },
        "nspname": "pg_catalog",
        "owner": 202,
        "prosrc": "int8eq",
        "lanname": "internal",
        "pronargs": 2,
        "prorettype": 16,
        "canonical": True,
    },
    1320: {
        "operator": {
            "oid": "1320",
            "oprcom": "1320",
            "oprcode": "timestamptz_eq",
            "oprjoin": "eqjoinsel",
            "oprkind": "b",
            "oprleft": "1184",
            "oprname": "=",
            "oprrest": "eqsel",
            "oprowner": "202",
            "oprright": "1184",
            "oprnegate": "1321",
            "oprresult": "16",
            "oprcanhash": True,
            "oprcanmerge": True,
            "oprnamespace": "11",
        },
        "nspname": "pg_catalog",
        "owner": 202,
        "prosrc": "timestamp_eq",
        "lanname": "internal",
        "pronargs": 2,
        "prorettype": 16,
        "canonical": True,
    },
}


SOURCE_PG16_COLLATION = {
    "collation": {
        "oid": "100",
        "collname": "default",
        "collctype": None,
        "collowner": "202",
        "collcollate": None,
        "collversion": None,
        "collencoding": -1,
        "collicurules": None,
        "collprovider": "d",
        "colliculocale": None,
        "collnamespace": "11",
        "collisdeterministic": True,
    },
    "nspname": "pg_catalog",
    "owner": 202,
}

SOURCE_PG16_TYPES = (
    (16, "bool", 1, True, "c", "p", "B", 0, "pg_catalog", "b", 0, 0, 0, True),
    (17, "bytea", -1, False, "i", "x", "U", 0, "pg_catalog", "b", 0, 0, 0, True),
    (20, "int8", 8, True, "d", "p", "N", 0, "pg_catalog", "b", 0, 0, 0, True),
    (23, "int4", 4, True, "i", "p", "N", 0, "pg_catalog", "b", 0, 0, 0, True),
    (25, "text", -1, False, "i", "x", "S", 100, "pg_catalog", "b", 0, 0, 0, True),
    (26, "oid", 4, True, "i", "p", "N", 0, "pg_catalog", "b", 0, 0, 0, True),
    (114, "json", -1, False, "i", "x", "U", 0, "pg_catalog", "b", 0, 0, 0, True),
    (1043, "varchar", -1, False, "i", "x", "S", 100, "pg_catalog", "b", 0, 0, 0, True),
    (1114, "timestamp", 8, True, "d", "p", "D", 0, "pg_catalog", "b", 0, 0, 0, True),
    (1184, "timestamptz", 8, True, "d", "p", "D", 0, "pg_catalog", "b", 0, 0, 0, True),
)


def replace_authority_surface(c, surface):
    def entries(name):
        return c.catalog[c.relations[name]["oid"]]

    if surface in ("check", "unique", "fk"):
        name = "social_messaging_device_bindings"
        kind = {"check": "c", "unique": "u", "fk": "f"}[surface]
        row = next(r for r in entries(name)["to_jsonb(k)"] if r["constraint"]["contype"] == kind)
        if surface == "fk":
            row["constraint"]["conpfeqop"] = ["96"]
        else:
            row["definition"] += " replacement"
    elif surface in ("nonunique", "partial"):
        row = (
            next(i for i in entries("social_messaging_device_bindings")["to_jsonb(i)"] if i["predicate"] is not None)
            if surface == "partial"
            else next(i for i in entries("users")["to_jsonb(i)"] if not i["index"]["indisunique"])
        )
        row["predicate"] = "true" if surface == "partial" else None
        row["index"]["indclass"] = ["1978"]
    elif surface == "acl":
        entries("users")["aclexplode"].append((202, 0, "SELECT", False, 203))
    elif surface == "inherited_acl":
        c.effective_acls = {"users": (True, True, True, False, False, False, False, True, True, True, False)}
    elif surface == "trigger":
        entries("users")["to_jsonb(t)"][0]["trigger"]["tgfoid"] = "777"
    elif surface == "ri":
        oid = c.relations["social_messaging_device_bindings"]["oid"]
        row = next(r for r in c.internal_triggers if int(r["trigger"]["tgrelid"]) == oid)
        row["trigger"]["tgconstrindid"] = "777"
    elif surface == "external_fk":
        row = entries("oauth_codes")["to_jsonb(k)"][0]
        row["constraint"]["confrelid"] = "777"
    elif surface == "external_key":
        entries("social_messaging_device_authorization_requests")["to_jsonb(i)"][0]["index"]["indisvalid"] = False
    elif surface == "relation":
        c.relations["users"]["relhastriggers"] = False
    elif surface == "toast":
        toast = c.relations["users"]["reltoastrelid"]
        c.catalog[toast]["to_jsonb(a)"][0]["attribute"]["attnotnull"] = True
    elif surface == "system":
        c.system_opclasses = deepcopy(SOURCE_PG16_OPCLASSES)
        c.system_opclasses[1981]["opclass"]["opcname"] = "replacement"
    else:
        raise AssertionError(surface)


@pytest.mark.parametrize("name", tuple(SOURCE_AUTHORITY_CONSTRAINTS))
@pytest.mark.parametrize("surface", ("constraint", "index", "acl", "trigger"))
def test_authority_same_oid_definition_replacements_deny(name, surface):
    c = CompleteCatalogConnection()
    storage.attest_native_schema(c)
    oid = c.relations[name]["oid"]
    rows = c.catalog[oid]
    if surface == "constraint":
        rows["to_jsonb(k)"][0]["constraint"]["convalidated"] = False
    elif surface == "index":
        rows["to_jsonb(i)"][0]["index"]["indisready"] = False
    elif surface == "acl":
        rows["aclexplode"].append((202, 707, "SELECT", False, 203))
    elif rows["to_jsonb(t)"]:
        rows["to_jsonb(t)"][0]["trigger"]["tgenabled"] = "D"
    else:
        # The source's zero user trigger inventory must also be closed.
        row = deepcopy(c.catalog[c.relations["users"]["oid"]]["to_jsonb(t)"][0])
        row["trigger"]["tgrelid"] = str(oid)
        rows["to_jsonb(t)"].append(row)
    assert c.relations[name]["oid"] == oid
    with pytest.raises(FinalizationDenied):
        storage.attest_native_schema(c)


@pytest.mark.parametrize(
    "name,profile",
    tuple(
        (n, p) for n, ps in {**SOURCE_AUTHORITY_CONSTRAINTS, **SOURCE_EXTERNAL_FKS}.items() for p in ps if p[1] == "f"
    ),
)
def test_each_new_authority_fk_and_ri_binding_is_closed(name, profile):
    c = CompleteCatalogConnection()
    storage.attest_native_schema(c)
    oid = c.relations[name]["oid"]
    row = next(r for r in c.catalog[oid]["to_jsonb(k)"] if r["constraint"]["conname"] == profile[0])
    saved = deepcopy(row)
    row["constraint"]["confmatchtype"] = "f"
    with pytest.raises(FinalizationDenied):
        storage.attest_native_schema(c)
    row.clear()
    row.update(saved)
    target = int(row["constraint"]["confrelid"])
    trigger = next(
        r
        for r in c.internal_triggers
        if r["trigger"]["tgconstraint"] == row["constraint"]["oid"] and int(r["trigger"]["tgrelid"]) == target
    )
    trigger["trigger"]["tgdeferrable"] = not trigger["trigger"]["tgdeferrable"]
    with pytest.raises(FinalizationDenied):
        storage.attest_native_schema(c)


@pytest.mark.parametrize("surface", ("nullable", "primary", "oid_opclass"))
def test_fabricated_pre_pg16_toast_shape_denies(surface):
    c = CompleteCatalogConnection()
    storage.attest_native_schema(c)
    t = c.catalog[c.relations["users"]["reltoastrelid"]]
    if surface == "nullable":
        t["to_jsonb(a)"][0]["attribute"]["attnotnull"] = True
    elif surface == "primary":
        t["to_jsonb(i)"][0]["index"]["indisprimary"] = False
    else:
        t["to_jsonb(i)"][0]["index"]["indclass"] = ["1989", "1978"]
    with pytest.raises(FinalizationDenied):
        storage.attest_native_schema(c)


@pytest.mark.parametrize("surface", ("type", "opclass", "operator", "collation", "ri_function"))
def test_system_catalog_canonical_definitions_are_closed(surface):
    c = CompleteCatalogConnection()
    storage.attest_native_schema(c)
    if surface == "type":
        c.system_types = list(SOURCE_PG16_TYPES)
        c.system_types[0] = (True, *c.system_types[0][1:])
    elif surface == "opclass":
        c.system_opclasses = deepcopy(SOURCE_PG16_OPCLASSES)
        c.system_opclasses[1981]["opclass"]["unknown"] = None
    elif surface == "operator":
        c.system_operators = deepcopy(SOURCE_PG16_OPERATORS)
        c.system_operators[98]["operator"]["oprcode"] = "replacement"
    elif surface == "collation":
        c.system_collation = deepcopy(SOURCE_PG16_COLLATION)
        c.system_collation["collation"]["collisdeterministic"] = 1
    else:
        c.internal_triggers[0]["canonical"] = False
    with pytest.raises(FinalizationDenied):
        storage.attest_native_schema(c)


def test_pg16_native_timestamp_sql_name_and_c_symbol():
    connection = CompleteCatalogConnection()
    connection.system_operators = deepcopy(SOURCE_PG16_OPERATORS)
    # Native PG16: the canonical SQL function uses this distinct C symbol.
    connection.system_operators[1320]["prosrc"] = "timestamp_eq"
    assert connection.system_operators[1320]["operator"]["oprcode"] == "timestamptz_eq"
    assert connection.system_operators[1320]["canonical"] is True
    storage.attest_native_schema(connection)


@pytest.mark.parametrize(
    ("surface", "value"),
    (
        ("prosrc", "timestamptz_eq"),
        ("prosrc", "replacement"),
        ("oprcode", "timestamp_eq"),
        ("canonical", False),
    ),
)
def test_pg16_timestamp_function_symbol_or_identity_replacement_denies(surface, value):
    connection = CompleteCatalogConnection()
    connection.system_operators = deepcopy(SOURCE_PG16_OPERATORS)
    row = connection.system_operators[1320]
    if surface == "oprcode":
        row["operator"]["oprcode"] = value
    else:
        row[surface] = value
    with pytest.raises(FinalizationDenied):
        storage.attest_native_schema(connection)


def _cas_adapter_projection_fields():
    import ast

    source = ROOT / "app/services/social_preaccepted_enrollment_v2_atomic_acceptance_storage.py"
    queries = [
        node.value
        for node in ast.walk(ast.parse(source.read_text()))
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and "installed_trigger.tgfoid::bigint AS trigger_function_oid" in node.value
    ]
    assert len(queries) == 1
    select = queries[0].partition(" FROM pg_catalog.pg_class AS relation ")[0]
    return frozenset(re.findall(r"\bAS ([a-z_]+)\b", select))


def _cas_adapter_native_projection(connection):
    # Carrier keys come from the actual unchanged adapter query, independently
    # of the finalization declaration. Original V1 fields remain caller-checked.
    fields = _cas_adapter_projection_fields()
    names = (storage.durable.GUARD_TRIGGER, storage.durable.NO_TRUNCATE_TRIGGER, storage.DECISION_TRIGGER)
    decision_oid = int(connection.functions[storage.DECISION_FUNCTION]["function"]["oid"])
    rows = []
    for index, name in enumerate(names):
        row = dict.fromkeys(fields)
        row.update(
            function_cost="42c80000",
            function_rows="00000000",
            trigger_name=name,
            trigger_oid=9000 + index,
            trigger_function_oid=decision_oid,
            trigger_type=17,
            trigger_enabled="O",
            trigger_argument_count=0,
            trigger_arguments_hex="",
            trigger_attributes="",
            trigger_internal=False,
            trigger_constraint_oid=0,
            trigger_constraint_relation_oid=0,
            trigger_constraint_index_oid=0,
            trigger_deferrable=False,
            trigger_initially_deferred=False,
            trigger_qualification=None,
            trigger_old_table=None,
            trigger_new_table=None,
            trigger_parent_oid=0,
        )
        rows.append(row)
    return rows


def test_cas_catalog_fields_match_unchanged_adapter_query():
    fields = _cas_adapter_projection_fields()
    assert len(fields) == 93
    assert {"function_cost", "function_rows"} <= fields
    assert storage.CAS_CATALOG_FIELDS == fields


def test_cas_profile_accepts_complete_actual_query_projection():
    connection = CompleteCatalogConnection()
    rows = _cas_adapter_native_projection(connection)
    identity = storage.validate_cas_profile(connection, rows)
    assert identity[0] == rows[2]["trigger_oid"]
    assert identity[2] == storage.attest_native_schema(connection)


@pytest.mark.parametrize("surface", ("missing_cost", "missing_rows", "unknown_field"))
def test_cas_profile_denies_missing_or_unenumerated_query_fields(surface):
    connection = CompleteCatalogConnection()
    rows = _cas_adapter_native_projection(connection)
    if surface == "unknown_field":
        rows[0]["unexpected_catalog_column"] = None
    else:
        del rows[0]["function_cost" if surface == "missing_cost" else "function_rows"]
    with pytest.raises(FinalizationDenied):
        storage.validate_cas_profile(connection, rows)


def _simulate_fresh_catalog_batch(connection, sql, parameters):
    import hashlib

    grouped_query = getattr(storage, "_fresh_grouped_catalog_query", lambda descriptor: None)
    matches = [
        (source, descriptor)
        for source, descriptor in {
            **storage._FRESH_CATALOG_SELECTS,
            **{source: family[0] for source, family in storage._completion_named_selects.items()},
        }.items()
        if (grouped_query(descriptor) or descriptor[2]) in sql
        and "/* UBID_FRESH_SELECTOR_" + hashlib.sha256(source.encode()).hexdigest() + " */" in sql
    ]
    assert len(matches) == 1
    source, (kind, columns, _) = matches[0]
    assert set(parameters) == {"fresh_catalog_selectors"}
    selectors = parameters["fresh_catalog_selectors"]
    result = []
    before = len(connection.queries)
    for selector in sorted(selectors):
        try:
            transport_source = source
            if source in storage._completion_named_selects:
                if storage._completion_named_selects[source][1] == "child":
                    entries = connection.catalog.get(selector, {}).get("to_jsonb(k)", [])
                    if not entries:
                        original = next((row for row in connection.revision_catalog if row["oid"] == selector), None)
                        entries = (
                            [{"constraint": item["catalog"]} for item in original["constraints"]] if original else []
                        )
                    raw = [
                        {"constraint": deepcopy(row["constraint"])}
                        for row in entries
                        if row["constraint"]["contype"] == "f"
                    ]
                else:
                    transport_source = next(
                        original
                        for original, desc in storage._FRESH_CATALOG_SELECTS.items()
                        if desc == storage._completion_named_selects[source][0]
                    )
                    raw = connection.execute(storage.text(transport_source), {kind: selector}).all()
            else:
                raw = connection.execute(storage.text(transport_source), {kind: selector}).all()
        except (AssertionError, KeyError, StopIteration):
            # The earlier lazy double does not render unused selectors. Empty
            # rows cannot satisfy a required cardinality/profile validator.
            raw = []
        values = []
        for row in raw:
            if isinstance(row, dict):
                if columns == ("trigger", "definition", "constraint_name", "proname", "nspname") and set(row) == {
                    "trigger",
                    "definition",
                }:
                    # Native-table fixtures render the two-cell trigger query.
                    # Render this wider SQL's real joins from their catalog OIDs;
                    # a partially supplied wider row keeps its missing cells.
                    trigger = row["trigger"]
                    function_row = next(
                        f for f in connection.functions.values() if f["function"]["oid"] == trigger["tgfoid"]
                    )
                    constraint_name = next(
                        (
                            r["constraint"]["conname"]
                            for entries in connection.catalog.values()
                            for r in entries.get("to_jsonb(k)", [])
                            if r["constraint"]["oid"] == trigger["tgconstraint"]
                        ),
                        None,
                    )
                    row = dict(
                        row,
                        constraint_name=constraint_name,
                        proname=function_row["function"]["proname"],
                        nspname=function_row["namespace"],
                    )
                # Preserve unexpected mapping cells in the simulated ordinal
                # carrier. The actual _FreshCatalogRows closed-shape validator
                # must reject them; the double must never discard them.
                ordinal = {"f" + str(i): deepcopy(row[column]) for i, column in enumerate(columns, 1) if column in row}
                extras = tuple(value for key, value in row.items() if key not in columns)
                ordinal.update({"f" + str(i): deepcopy(value) for i, value in enumerate(extras, len(columns) + 1)})
                values.append(ordinal)
                continue
            elif not isinstance(row, (list, tuple)):
                row = (row,)
            values.append({"f" + str(i): deepcopy(value) for i, value in enumerate(row, 1)})
        result.append((selector, values))
    del connection.queries[before:]
    connection.queries.append((sql, deepcopy(parameters)))
    fault = getattr(connection, "fresh_catalog_fault", None)
    if fault == "duplicate":
        result[-1] = result[0]
    elif fault == "missing":
        result.pop()
    elif fault == "unknown":
        result[0] = ("unlisted", result[0][1])
    elif fault == "selector_bool":
        result[0] = (True, result[0][1])
    elif fault in ("row_missing", "row_extra", "rows_scalar"):
        nonempty = next(i for i, row in enumerate(result) if row[1])
        if fault == "row_missing":
            del result[nonempty][1][0]["f1"]
        elif fault == "row_extra":
            result[nonempty][1][0]["unexpected"] = None
        else:
            result[nonempty] = (result[nonempty][0], None)
    return CatalogResult(result)


class BatchCatalogConnection(CompleteCatalogConnection):
    def execute(self, statement, parameters=None):
        if "/* UBID_FRESH_FINALIZATION_CATALOG */" in str(statement):
            return _simulate_fresh_catalog_batch(self, str(statement), parameters or {})
        return super().execute(statement, parameters)


def test_fresh_catalog_transport_reduces_round_trips():
    connection = BatchCatalogConnection()
    storage.attest_native_schema(connection)
    # The former per-relation implementation exceeds 400 individual SELECTs.
    assert len(connection.queries) <= 192


def test_fresh_catalog_transport_keeps_complete_original_identity():
    original = storage._attest_native_schema(CompleteCatalogConnection())
    connection = BatchCatalogConnection()
    assert storage.attest_native_schema(connection) == original
    assert any("UBID_FRESH_FINALIZATION_CATALOG" in sql for sql, _ in connection.queries)
    assert not any("execute_social_enrollment_v2_native_effects(" in sql for sql, _ in connection.queries)


@pytest.mark.parametrize(
    "fault", ("duplicate", "missing", "unknown", "selector_bool", "row_missing", "row_extra", "rows_scalar")
)
def test_fresh_catalog_transport_denies_malformed_result(fault):
    connection = BatchCatalogConnection()
    connection.fresh_catalog_fault = fault
    with pytest.raises(FinalizationDenied):
        storage.attest_native_schema(connection)


def test_fresh_catalog_transport_never_reuses_across_attestations():
    connection = BatchCatalogConnection()
    storage.attest_native_schema(connection)
    oid = connection.relations[storage.EFFECT_TABLE]["oid"]
    connection.catalog[oid]["to_jsonb(a)"][0]["attribute"]["attnotnull"] = False
    with pytest.raises(FinalizationDenied):
        storage.attest_native_schema(connection)


def test_fresh_catalog_transport_repeated_selector_is_a_live_read():
    connection = BatchCatalogConnection()
    observation = storage._FreshCatalogObservation(connection)
    parameters = {"name": storage.WRITE_FUNCTION}
    first = observation.execute(storage.text(storage.FUNCTION_SQL), parameters).mappings().all()
    connection.functions[storage.WRITE_FUNCTION]["function"]["prosecdef"] = False
    second = observation.execute(storage.text(storage.FUNCTION_SQL), parameters).mappings().all()
    assert first[0]["function"]["prosecdef"] is True
    assert second[0]["function"]["prosecdef"] is False
    assert connection.queries[-1][0] == storage.FUNCTION_SQL
    with pytest.raises(FinalizationDenied):
        storage._attest_function(second[0], storage.WRITE_FUNCTION)


def test_fresh_catalog_rows_do_not_alias_mutable_results():
    rows = [{"f1": {"nested": [None, False, 7, "8"]}}]
    result = storage._FreshCatalogRows(rows, ("value",))
    rows[0]["f1"]["nested"].append("before")
    result.mappings().all()[0]["value"]["nested"].append("after")
    result.all()[0][0]["nested"].append("tuple")
    assert result.scalar_one() == {"nested": [None, False, 7, "8"]}


@pytest.mark.parametrize("surface", ("root", "savepoint", "physical", "closed", "invalidated"))
def test_fresh_catalog_transport_object_continuity(surface):
    class Physical:
        dbapi_connection = object()

    class Connection(BatchCatalogConnection):
        closed = False
        invalidated = False
        connection = Physical()
        root = object()
        nested = None

        def get_transaction(self):
            return self.root

        def get_nested_transaction(self):
            return self.nested

    connection = Connection()
    observation = storage._FreshCatalogObservation(connection)
    if surface == "root":
        connection.root = object()
    elif surface == "savepoint":
        connection.nested = object()
    elif surface == "physical":
        connection.connection.dbapi_connection = object()
    else:
        setattr(connection, surface, True)
    with pytest.raises(FinalizationDenied):
        observation.execute(storage.text(storage.FUNCTION_SQL), {"name": storage.WRITE_FUNCTION})
    assert not connection.queries


def _equivalent_fresh_catalog_queries():
    grouped = {}
    for query, descriptor in storage._FRESH_CATALOG_SELECTS.items():
        grouped.setdefault(descriptor[2], []).append(query)
    duplicates = [queries for queries in grouped.values() if len(queries) > 1]
    assert len(duplicates) == 1 and len(duplicates[0]) == 2
    assert duplicates[0][0] != duplicates[0][1]
    return duplicates[0]


def test_fresh_catalog_equivalent_sql_templates_have_unambiguous_source_labels():
    queries = _equivalent_fresh_catalog_queries()
    connection = BatchCatalogConnection()
    observation = storage._FreshCatalogObservation(connection)
    oid = connection.relations[EVENT]["oid"]
    observation._oids = (oid,)
    rows = [observation.execute(storage.text(query), {"oid": oid}).mappings().all() for query in queries]
    assert rows[0] == rows[1] and rows[0]
    batches = [sql for sql, _ in connection.queries if "UBID_FRESH_FINALIZATION_CATALOG" in sql]
    assert len(batches) == 2 and batches[0] != batches[1]


def test_fresh_catalog_driver_rejects_wrong_source_label():
    import hashlib

    query = _equivalent_fresh_catalog_queries()[0]
    connection = BatchCatalogConnection()
    observation = storage._FreshCatalogObservation(connection)
    oid = connection.relations[EVENT]["oid"]
    observation._oids = (oid,)
    observation.execute(storage.text(query), {"oid": oid})
    emitted = connection.queries[-1][0]
    label = hashlib.sha256(query.encode()).hexdigest()
    assert label in emitted
    malformed = emitted.replace(label, "0" * 64)
    before = len(connection.queries)
    with pytest.raises(AssertionError):
        _simulate_fresh_catalog_batch(connection, malformed, {"fresh_catalog_selectors": [oid]})
    assert len(connection.queries) == before


def test_fresh_performance_textclause_identification_does_not_compile(monkeypatch):
    from sqlalchemy.sql.elements import TextClause

    class Connection:
        def execute(self, statement, parameters):
            assert statement is query
            assert parameters == {"different": 7}
            return sentinel

    def compiled(*args, **kwargs):
        pytest.fail("TextClause identification compiled SQL")

    query = storage.text("SELECT :different")
    sentinel = object()
    monkeypatch.setattr(TextClause, "__str__", compiled)
    observation = storage._FreshCatalogObservation(Connection())
    assert observation.execute(query, {"different": 7}) is sentinel


def test_fresh_performance_carrier_has_no_json_round_trips(monkeypatch):
    def encoded(*args, **kwargs):
        pytest.fail("validated carrier performed JSON encoding/decoding")

    monkeypatch.setattr(storage, "_wire", encoded)
    monkeypatch.setattr(storage.json, "loads", encoded)
    result = storage._FreshCatalogRows([{"f1": {"values": [False, 0, "0", None]}}], ("value",))
    mapped = result.mappings()
    assert mapped.one() == {"value": {"values": [False, 0, "0", None]}}
    assert result.scalar_one() == {"values": [False, 0, "0", None]}
    assert mapped._values is result._values


def test_fresh_performance_grouped_scans_remove_selector_lateral_loop():
    connection = BatchCatalogConnection()
    storage.attest_native_schema(connection)
    batches = [sql for sql, _ in connection.queries if "UBID_FRESH_FINALIZATION_CATALOG" in sql]
    grouped = [sql for sql in batches if "WITH captured AS MATERIALIZED" in sql]
    assert len(grouped) >= 10
    assert all("CROSS JOIN LATERAL (SELECT COALESCE" not in sql for sql in grouped)
    assert all("GROUP BY catalog_rows.catalog_selector" in sql for sql in grouped)
    assert all("LEFT JOIN captured" in sql and "'[]'::jsonb" in sql for sql in grouped)


def test_fresh_performance_known_family_does_not_compile_and_consumes_once(monkeypatch):
    from sqlalchemy.sql.elements import TextClause

    source = next(sql for sql, descriptor in storage._FRESH_CATALOG_SELECTS.items() if descriptor[1] == ("attribute",))
    queries = []

    class Connection:
        def execute(self, statement, parameters):
            queries.append((statement.text, deepcopy(parameters)))
            if "UBID_FRESH_FINALIZATION_CATALOG" in statement.text:
                assert parameters == {"fresh_catalog_selectors": [7, 8]}
                return CatalogResult([(7, [{"f1": {"value": "7"}}]), (8, [])])
            assert statement.text == source and parameters == {"oid": 7}
            return CatalogResult([{"attribute": {"value": "changed"}}])

    def compiled(*args, **kwargs):
        pytest.fail("fixed SQL family identification invoked a compiler")

    monkeypatch.setattr(TextClause, "__str__", compiled)
    observation = storage._FreshCatalogObservation(Connection())
    observation._oids = (7, 8)
    assert observation.execute(storage.text(source), {"oid": 7}).mappings().one() == {"attribute": {"value": "7"}}
    assert observation.execute(storage.text(source), {"oid": 8}).all() == []
    assert len(queries) == 1
    assert observation.execute(storage.text(source), {"oid": 7}).mappings().one() == {"attribute": {"value": "changed"}}
    assert len(queries) == 2


@pytest.mark.parametrize("variant", ("custom", "subclass", "parameters", "sql", "selector"))
def test_fresh_performance_different_statements_remain_live(variant):
    from sqlalchemy.sql.elements import TextClause

    source = storage.FUNCTION_SQL
    parameters = {"name": storage.WRITE_FUNCTION}

    class Custom:
        text = source

        def __str__(self):
            pytest.fail("fallback statement was stringified")

    class Subclass(TextClause):
        pass

    query = storage.text(source)
    if variant == "custom":
        query = Custom()
    elif variant == "subclass":
        query = Subclass(source)
    elif variant == "parameters":
        parameters["extra"] = 0
    elif variant == "sql":
        query = storage.text(source + " ")
    else:
        parameters["name"] = "unlisted"
    sentinel = object()
    calls = []

    class Connection:
        def execute(self, statement, params):
            assert statement is query and params is parameters
            calls.append(statement)
            return sentinel

    observation = storage._FreshCatalogObservation(Connection())
    assert observation.execute(query, parameters) is sentinel
    assert observation.execute(query, parameters) is sentinel
    assert calls == [query, query]


def test_fresh_performance_grouped_sql_keeps_projection_and_aggregate_order():
    grouped_count = 0
    for descriptor in storage._FRESH_CATALOG_SELECTS.values():
        grouped = storage._fresh_grouped_catalog_query(descriptor)
        if grouped is None:
            continue
        grouped_count += 1
        query = descriptor[2]
        projection = query.split(" FROM (SELECT ", 1)[1].split(" FROM pg_catalog.", 1)[0]
        assert projection in grouped
        aggregate = query.split("SELECT COALESCE(", 1)[1].split(",'[]'::json)", 1)[0]
        assert aggregate in grouped
        assert grouped.count("=ANY(CAST(:fresh_catalog_selectors AS oid[]))") == 1
        assert "=selected.catalog_selector" not in grouped.split(") AS catalog_rows GROUP BY", 1)[0]
        assert grouped.endswith("ORDER BY selected.catalog_selector")
    assert grouped_count == 11
    for source, descriptor in storage._FRESH_CATALOG_SELECTS.items():
        if "SELECT count(*)" in source:
            assert storage._fresh_grouped_catalog_query(descriptor) is None


def test_fresh_performance_carrier_exact_types_order_and_independent_views():
    shared = {"values": [False, 0, "0", None, [], {}, 1.5]}
    columns = ["value"]
    rows = [{"f1": shared}, {"f1": shared}]
    result = storage._FreshCatalogRows(rows, columns)
    mapped = result.mappings()
    columns[0] = "changed"
    shared["values"].append("input")
    first = mapped.all()
    first[0]["value"]["values"][4].append("output")
    first[0]["value"]["values"][5]["new"] = True
    assert first[1]["value"]["values"] == [False, 0, "0", None, [], {}, 1.5]
    expected = {"values": [False, 0, "0", None, [], {}, 1.5]}
    assert result.all() == [(expected,), (expected,)]
    assert mapped.all() == [{"value": expected}, {"value": expected}]
    cells = result.all()[0][0]["values"]
    assert [type(cell) for cell in cells] == [bool, int, str, type(None), list, dict, float]
    assert mapped._values is result._values
    with pytest.raises(TypeError):
        result._values[0][0][0] = ("changed", ())


@pytest.mark.parametrize("rows", (None, {}, [None], [{"f1": 0, "f2": None}], [{}], [{"f01": 0}]))
def test_fresh_performance_carrier_closed_ordinal_shape(rows):
    with pytest.raises(FinalizationDenied):
        storage._FreshCatalogRows(rows, ("value",))


@pytest.mark.parametrize("rows", ([], [{"f1": None}, {"f1": None}]))
def test_fresh_performance_carrier_cardinality_denies(rows):
    result = storage._FreshCatalogRows(rows, ("value",))
    with pytest.raises(FinalizationDenied):
        result.one()
    with pytest.raises(FinalizationDenied):
        result.scalar_one()


def test_fresh_performance_carrier_duplicate_labels_and_scalar_shape_deny():
    result = storage._FreshCatalogRows([{"f1": False, "f2": 0}], ("?column?", "?column?"))
    row = result.one()
    assert row[0] is False and type(row[1]) is int and row[1] == 0
    with pytest.raises(FinalizationDenied):
        result.mappings()
    with pytest.raises(FinalizationDenied):
        result.scalar_one()
    mapped = storage._FreshCatalogRows([{"f1": None}], ("value",)).mappings()
    with pytest.raises(FinalizationDenied):
        mapped.scalar_one()


def test_fresh_performance_named_parent_reads_are_live_at_each_checkpoint():
    connection = CompleteCatalogConnection()
    observation = storage._FreshCatalogObservation(connection)
    first = storage._attest_dependency_parent_key(observation, connection.relations, "users", ("id",))
    assert first[0] > 0
    before = len(connection.queries)
    assert storage._attest_dependency_parent_key(observation, connection.relations, "users", ("id",)) == first
    assert len(connection.queries) > before
    row = connection.catalog[connection.relations["users"]["oid"]]["to_jsonb(k)"][0]
    row["definition"] = "PRIMARY KEY (changed)"
    before = len(connection.queries)
    with pytest.raises(FinalizationDenied):
        storage._attest_dependency_parent_key(observation, connection.relations, "users", ("id",))
    assert len(connection.queries) > before
    assert not any("UBID_FRESH_FINALIZATION_CATALOG" in sql for sql, _ in connection.queries)


@pytest.mark.parametrize(
    "field,value", (("attnotnull", 0), ("attnum", False), ("atttypid", 23), ("attacl", []), ("attmissingval", []))
)
def test_fresh_performance_complete_native_type_denials_equal_original(field, value):
    connection = BatchCatalogConnection()
    storage.attest_native_schema(connection)
    oid = connection.relations[storage.EFFECT_TABLE]["oid"]
    connection.catalog[oid]["to_jsonb(a)"][0]["attribute"][field] = value
    with pytest.raises(FinalizationDenied):
        storage._attest_native_schema(connection)
    with pytest.raises(FinalizationDenied):
        storage.attest_native_schema(connection)


def test_fresh_performance_simulator_keeps_missing_joined_projection_cell():
    source, descriptor = next(
        (source, descriptor)
        for source, descriptor in storage._FRESH_CATALOG_SELECTS.items()
        if descriptor[1] == ("trigger", "definition", "constraint_name", "proname", "nspname")
    )

    class Connection:
        queries = []

        def execute(self, statement, parameters):
            if "UBID_FRESH_FINALIZATION_CATALOG" in statement.text:
                return _simulate_fresh_catalog_batch(self, statement.text, parameters)
            assert statement.text == source
            return CatalogResult([dict(trigger={}, definition=None, constraint_name=None, proname="f")])

    observation = storage._FreshCatalogObservation(Connection())
    observation._oids = (7,)
    with pytest.raises(FinalizationDenied):
        observation.execute(storage.text(source), {"oid": 7})


def test_fresh_performance_scalar_subclasses_have_no_mutable_alias():
    class String(str):
        def __str__(self):
            pytest.fail("custom string conversion ran")

    class Integer(int):
        def __int__(self):
            pytest.fail("custom integer conversion ran")

    class Float(float):
        def __float__(self):
            pytest.fail("custom float conversion ran")

    key, string, integer, floating = String("key"), String("7"), Integer(7), Float(7.5)
    for value in (key, string, integer, floating):
        value.mutable = []
    result = storage._FreshCatalogRows([{"f1": {key: [string, integer, floating]}}], ("value",))
    cells = result.scalar_one()["key"]
    assert [type(value) for value in cells] == [str, int, float]
    assert cells == ["7", 7, 7.5]
    assert type(next(iter(result.scalar_one()))) is str
    assert all(not hasattr(value, "mutable") for value in cells)


def test_fresh_scalar_container_paths_match_reference_without_scalar_recursion():
    import cProfile
    import json

    native = {"cells": [None, False, True, 0, 7, "7", 1.5] * 128, "nested": {"empty": []}}
    expected = json.loads(json.dumps(native))
    profiler = cProfile.Profile()
    frozen = profiler.runcall(storage._fresh_freeze, native)
    result = profiler.runcall(storage._fresh_thaw, frozen)
    assert result == expected
    assert [type(cell) for cell in result["cells"][:7]] == [type(None), bool, bool, int, int, str, float]
    native["cells"].append("input mutation")
    result["nested"]["empty"].append("output mutation")
    assert storage._fresh_thaw(frozen) == expected
    calls = {entry.code: entry.callcount for entry in profiler.getstats()}
    # Four containers are visited. Native scalar children require no recursive
    # Python calls; their exact types and immutable ownership still hold.
    assert calls[storage._fresh_freeze.__code__] == 4
    assert calls[storage._fresh_thaw.__code__] == 4


def test_fresh_json_ordinal_encoding_preserves_fixed_full_projections():
    import hashlib
    import json

    assert len(storage._FRESH_CATALOG_SELECTS) == 19
    connection = CompleteCatalogConnection()
    for source, descriptor in storage._FRESH_CATALOG_SELECTS.items():
        kind, columns, query = descriptor
        assert query.count("pg_catalog.row_to_json(ROW(") == 1
        assert query.count("pg_catalog.json_agg(catalog_rows.row_values") == 1
        assert "pg_catalog.to_jsonb(ROW(" not in query
        assert "jsonb_agg" not in query
        assert ",'[]'::json)" in query
        # Only the ordinal envelope changes. Every native JSONB record retains
        # its complete projection, including fields unused by a consumer.
        assert re.findall(r"pg_catalog\.to_jsonb\([akictp]\)", query) == re.findall(
            r"pg_catalog\.to_jsonb\([akictp]\)", source
        )
        selectors = tuple(connection.catalog) if kind == "oid" else tuple(connection.functions)
        sql = storage._fresh_grouped_catalog_query(descriptor) or query
        if sql != query:
            assert "COALESCE(captured.catalog_rows,'[]'::jsonb::json) FROM pg_catalog.unnest" in sql
        sql += " /* UBID_FRESH_SELECTOR_" + hashlib.sha256(source.encode()).hexdigest() + " */"
        observed = _simulate_fresh_catalog_batch(connection, sql, {"fresh_catalog_selectors": selectors}).all()
        for _, rows in observed:
            # Compare decoded reference JSONB (canonical object key order) with
            # JSON's insertion order, then exercise the real ordinal decoder.
            old = json.loads(json.dumps(rows, sort_keys=True, ensure_ascii=True))
            new = json.loads(json.dumps(rows, sort_keys=False, ensure_ascii=False))
            assert old == new
            before = storage._FreshCatalogRows(old, columns).all()
            after = storage._FreshCatalogRows(new, columns).all()
            assert before == after
            assert all(len(row) == len(columns) for row in after)
            assert [tuple(type(cell) for cell in row) for row in before] == [
                tuple(type(cell) for cell in row) for row in after
            ]
    assert storage._FreshCatalogRows(json.loads('[{"f1":0}]'), ("count",)).scalar_one() == 0
    assert type(storage._FreshCatalogRows(json.loads('[{"f1":0}]'), ("count",)).scalar_one()) is int
    assert storage._FreshCatalogRows(json.loads("[]"), ("attribute",)).all() == []
    assert storage._FreshCatalogRows(json.loads('[{"f1":null}]'), ("predicate",)).scalar_one() is None


def test_fresh_json_decoded_complete_reference_identity_and_owned_views():
    import json

    class DecodedConnection(BatchCatalogConnection):
        def execute(self, statement, parameters=None):
            result = super().execute(statement, parameters)
            if "UBID_FRESH_FINALIZATION_CATALOG" in statement.text:
                return CatalogResult(json.loads(json.dumps(result.all(), ensure_ascii=False)))
            return result

    reference = storage._attest_native_schema(CompleteCatalogConnection())
    connection = DecodedConnection()
    assert storage.attest_native_schema(connection) == reference
    assert storage.attest_native_schema(connection) == reference
    rows = json.loads('[{"f1":{"oid":"23","nullable":false,"fields":[0,null,[],{}]},"f2":null}]')
    result = storage._FreshCatalogRows(rows, ("attribute", "definition"))
    expected = deepcopy(rows[0]["f1"])
    rows[0]["f1"]["fields"][2].append("driver mutation")
    mapped = result.mappings().one()
    mapped["attribute"]["fields"][3]["new"] = True
    assert result.one() == (expected, None)
    assert type(result.one()[0]["oid"]) is str
    assert type(result.one()[0]["nullable"]) is bool
    with pytest.raises(FinalizationDenied):
        result.scalar_one()


@pytest.mark.parametrize("field,value", (("attnotnull", "false"), ("attnum", 1.0), ("atttypid", True)))
def test_fresh_json_decoded_malformed_native_types_deny_complete_validator(field, value):
    import json

    connection = BatchCatalogConnection()
    assert storage.attest_native_schema(connection) == storage._attest_native_schema(CompleteCatalogConnection())
    oid = connection.relations[storage.EFFECT_TABLE]["oid"]
    attribute = connection.catalog[oid]["to_jsonb(a)"][0]["attribute"]
    attribute[field] = json.loads(json.dumps(value))
    with pytest.raises(FinalizationDenied):
        storage._attest_native_schema(connection)
    with pytest.raises(FinalizationDenied):
        storage.attest_native_schema(connection)


@pytest.mark.parametrize("container", (list, dict))
def test_fresh_scalar_fast_path_retains_exclusive_depth_bound(container):
    def nest(levels):
        value = False
        for _ in range(levels):
            value = [value] if container is list else {"value": value}
        return value

    expected = nest(64)
    assert storage._fresh_thaw(storage._fresh_freeze(expected)) == expected
    with pytest.raises(FinalizationDenied):
        storage._fresh_freeze(nest(65))
    with pytest.raises(FinalizationDenied):
        storage._fresh_freeze(False, 65)
    empty = [] if container is list else {}
    assert storage._fresh_thaw(storage._fresh_freeze(empty, 64)) == empty
    with pytest.raises(FinalizationDenied):
        storage._fresh_freeze([False] if container is list else {"value": False}, 64)


def test_boundary_local_cas_profile_reads_fresh_function_without_full_graph(monkeypatch):
    connection = CompleteCatalogConnection()
    rows = _cas_adapter_native_projection(connection)

    def _boundary_forbidden_full_graph(connection):
        pytest.fail("ordinary CAS continuity must not scan the full finalization graph")

    monkeypatch.setattr(storage, "attest_native_schema", _boundary_forbidden_full_graph)
    first = storage.validate_cas_profile(connection, rows, full_schema=False)
    assert first[0] == rows[2]["trigger_oid"] and first[2] is None
    assert storage.validate_cas_profile(connection, rows, full_schema=False) == first
    connection.functions[storage.DECISION_FUNCTION]["function"]["prosrc"] += "\n-- changed"
    with pytest.raises(FinalizationDenied):
        storage.validate_cas_profile(connection, rows, full_schema=False)


@pytest.mark.parametrize("full_schema", (None, 0, 1, "false", [], {}))
def test_boundary_cas_profile_rejects_ambiguous_mode(full_schema):
    connection = CompleteCatalogConnection()
    rows = _cas_adapter_native_projection(connection)
    with pytest.raises(FinalizationDenied):
        storage.validate_cas_profile(connection, rows, full_schema=full_schema)


@pytest.mark.parametrize(
    "field,value",
    (("trigger_enabled", "D"), ("trigger_type", 0), ("trigger_function_oid", 0), ("trigger_parent_oid", 1)),
)
def test_boundary_local_cas_profile_still_denies_trigger_damage(field, value):
    connection = CompleteCatalogConnection()
    rows = _cas_adapter_native_projection(connection)
    rows[2][field] = value
    with pytest.raises(FinalizationDenied):
        storage.validate_cas_profile(connection, rows, full_schema=False)


def test_boundary_default_cas_profile_keeps_fresh_full_attestation(monkeypatch):
    connection = CompleteCatalogConnection()
    rows = _cas_adapter_native_projection(connection)
    reads = []

    def _boundary_full_graph(actual):
        assert actual is connection
        reads.append(actual)
        return ("full-graph", len(reads))

    monkeypatch.setattr(storage, "attest_native_schema", _boundary_full_graph)
    assert storage.validate_cas_profile(connection, rows)[2] == ("full-graph", 1)
    assert storage.validate_cas_profile(connection, rows)[2] == ("full-graph", 2)
    assert len(reads) == 2


def test_boundary_local_profile_does_not_attest_damaged_effects_graph():
    connection = CompleteCatalogConnection()
    rows = _cas_adapter_native_projection(connection)
    before = storage.validate_cas_profile(connection, rows, full_schema=False)
    storage.validate_cas_profile(connection, rows)
    connection.relations[storage.EFFECT_TABLE]["relrewrite"] = "777"
    assert storage.validate_cas_profile(connection, rows, full_schema=False) == before
    with pytest.raises(FinalizationDenied):
        storage.validate_cas_profile(connection, rows)


def test_completion_transport_query_inventory():
    connection = BatchCatalogConnection()
    assert storage.attest_native_schema(connection) == storage._attest_native_schema(CompleteCatalogConnection())
    assert len(connection.queries) <= 138


def test_completion_named_capture_consumes_each_name_once_and_rechecks_live():
    connection = BatchCatalogConnection()
    observation = storage._FreshCatalogObservation(connection)
    observation.execute(storage.text(storage.VISIBILITY_SQL), {"names": list(storage.VISIBLE_AUTHORITIES)})
    source = storage.SHARED_CONSTRAINTS_SQL.replace(
        "WHERE k.conrelid=:oid", "WHERE k.conrelid=:oid AND k.conname=:name"
    )
    oid = connection.relations[storage.CHAIN]["oid"]
    name = "pk_social_ed25519_chain"
    values = {"oid": oid, "name": name}
    first = observation.execute(storage.text(source), values).mappings().one()
    first["constraint"]["conkey"].append(99)
    row = next(row for row in connection.catalog[oid]["to_jsonb(k)"] if row["constraint"]["conname"] == name)
    row["constraint"]["convalidated"] = False
    second = observation.execute(storage.text(source), values).mappings().one()
    assert second["constraint"]["convalidated"] is False
    assert 99 not in second["constraint"]["conkey"]
    assert connection.queries[-1][0] == source


@pytest.mark.parametrize(
    "names",
    [
        ("social_session_v2_offers", "social_session_v2_parents"),
        ("social_session_v2_parents", "social_session_v2_offers"),
    ],
    ids=["offers-first", "parents-first"],
)
def test_original_issuance_catalog_port_current_grouped_transport(names):
    from app.services import social_session_issuance_v2_storage as original

    connection = CompleteCatalogConnection()
    port = OriginalIssuanceCatalogPort(connection)
    specifications = [("table", {"name": name}) for name in names]
    specifications += [("role", {}), ("triggers", {"oid": connection.relations[names[0]]["oid"]})]
    sql, values, expected = original._catalog_fetch_plan(specifications)
    observed = port.sql(sql, values).scalar_one()
    assert len(observed) == len(expected) == 4
    for index, name in enumerate(names):
        assert type(observed[index][0]["f1"]) is int
        assert observed[index][0]["f1"] == connection.relations[name]["oid"]
        assert set(observed[index][0]) == {"f" + str(i) for i in range(1, 15)}
    assert observed[2][0]["f1"] is False
    assert all(row["f12"] == "\\x" for row in observed[3])
    assert port.sql(sql, values).scalar_one() == observed
    observed[0][0]["f1"] = -1
    assert port.sql(sql, values).scalar_one()[0][0]["f1"] == connection.relations[names[0]]["oid"]


def test_original_issuance_catalog_port_current_transport_reads_fresh_function_body():
    from app.services import social_session_issuance_v2_storage as original

    connection = CompleteCatalogConnection()
    port = OriginalIssuanceCatalogPort(connection)
    original.attest(port)
    connection.functions["social_session_v2_guard"]["function"]["prosrc"] = "BEGIN RETURN NEW; END;"
    with pytest.raises(original.V2IssuanceUnavailable):
        original.attest(port)
    assert port.poisoned


class PeerRoleCatalogConnection(CompleteCatalogConnection):
    """Complete existing catalog plus explicit second-role rows, no no-op guards."""

    closed = invalidated = False

    def __init__(self):
        from types import SimpleNamespace

        from tests.unit.test_social_enrollment_v2_catalog_roles import role_row, table_rows

        super().__init__()
        self.root = SimpleNamespace(is_active=True)
        self.connection = SimpleNamespace(dbapi_connection=object())
        self.peer_role = role_row()
        self.peer_tables = table_rows()
        for item in self.peer_tables:
            if item[0] in self.relations:
                relation = self.relations[item[0]]
                item[2], item[3] = relation["oid"], relation["relowner"]
                grants = self.catalog[relation["oid"]].get("aclexplode")
                if grants is not None:
                    grants.extend((relation["relowner"], 20001, privilege, False, 203) for privilege in item[4])
        fixture_direct_acls(self)

    def get_transaction(self):
        return self.root

    def get_nested_transaction(self):
        return None

    def execute(self, statement, parameters=None):
        from app.services import social_enrollment_v2_catalog_roles as roles

        if str(statement) == roles.ROLE_SQL:
            self.queries.append((str(statement), parameters))
            return CatalogResult([deepcopy(self.peer_role)])
        if str(statement) == roles.TABLES_SQL:
            self.queries.append((str(statement), parameters))
            return CatalogResult(deepcopy(self.peer_tables))
        return super().execute(statement, parameters)


def peer_catalog_scope(connection):
    from app.services.social_enrollment_v2_catalog_roles import catalog_role_scope
    from tests.unit.test_social_enrollment_v2_catalog_roles import BoundSession, pin

    session = BoundSession()
    session.bound = connection
    return catalog_role_scope(session, pin())


def test_peer_role_complete_catalog_accepts_only_explicit_scoped_registration():
    connection = PeerRoleCatalogConnection()
    with pytest.raises(FinalizationDenied):
        storage.attest_native_schema(connection)
    with peer_catalog_scope(connection):
        first = storage.attest_native_schema(connection)
        assert storage.attest_native_schema(connection) == first
    with pytest.raises(FinalizationDenied):
        storage.attest_native_schema(connection)
    assert not any("execute_social_enrollment_v2_native_effects(" in sql for sql, _ in connection.queries)


@pytest.mark.parametrize(
    "damage",
    (
        "public",
        "third_role",
        "extra_peer_insert",
        "extra_runtime_insert",
        "grant_option",
        "missing_peer_select",
        "peer_superuser",
        "peer_oid",
        "peer_native_effects",
    ),
)
def test_peer_role_complete_catalog_still_denies_bypass(damage):
    connection = PeerRoleCatalogConnection()
    with peer_catalog_scope(connection):
        storage.attest_native_schema(connection)
        name = "social_device_admission_challenges"
        owner, runtime = 202, 203
        if damage in ("public", "third_role"):
            connection.catalog[connection.relations[name]["oid"]]["aclexplode"].append(
                (owner, 0 if damage == "public" else 20002, "SELECT", False, runtime)
            )
        elif damage in ("extra_peer_insert", "extra_runtime_insert"):
            name = "social_device_admission_challenge_revisions" if damage == "extra_peer_insert" else name
            connection.catalog[connection.relations[name]["oid"]]["aclexplode"].append(
                (owner, 20001 if damage == "extra_peer_insert" else runtime, "INSERT", False, runtime)
            )
        elif damage == "grant_option":
            row = next(item for item in connection.peer_tables if item[0] == name)
            row[6] = True
        elif damage == "missing_peer_select":
            connection.peer_tables[0][4] = []
        elif damage == "peer_superuser":
            connection.peer_role[2] = True
        elif damage == "peer_oid":
            connection.peer_role[0] += 1
        else:
            connection.peer_role[15] = True
        with pytest.raises(FinalizationDenied):
            storage.attest_native_schema(connection)


def test_peer_role_config_freezes_registration_without_changing_default(final_graph):
    from dataclasses import replace

    from app.services.social_enrollment_v2_finalization_contract import FinalizationConfig, freeze_config
    from tests.unit.test_social_enrollment_v2_catalog_roles import pin

    original = final_graph.final_config
    assert original.challenge_writer_role is None
    config = replace(original, challenge_writer_role=pin())
    frozen = freeze_config(config)
    assert frozen.challenge_writer_role == config.challenge_writer_role
    assert frozen.challenge_writer_role is not config.challenge_writer_role
    with pytest.raises(FinalizationDenied):
        FinalizationConfig(challenge_writer_role=pin())
