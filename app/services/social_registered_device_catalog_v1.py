"""Closed PG16 schema/privilege checks for the opt-in registered-session owner."""

import hashlib

from sqlalchemy import text

from app.services.social_registered_device_session_contract_v1 import _deny

_PREFIX = "social_registered_device_"
_COLUMNS = {
    "challenges_v1": (
        ("challenge_id", 1043, 68),
        ("subject", 1043, 68),
        ("device_id", 1043, 68),
        ("challenge_wire", 25, -1),
        ("issued_at", 20, -1),
        ("expires_at", 20, -1),
    ),
    "sessions_v1": (
        ("session_id", 1043, 68),
        ("challenge_id", 1043, 68),
        ("credential_digest", 1043, 68),
        ("issued_at", 20, -1),
        ("expires_at", 20, -1),
    ),
    "revocations_v1": (("session_id", 1043, 68), ("revoked_at", 20, -1)),
}
_CHECKS = {
    "challenges_v1": (
        "CHECK (((challenge_id)::text ~ '^[0-9a-f]{64}$'::text))",
        "CHECK (((device_id)::text ~ '^[0-9a-f]{64}$'::text))",
        "CHECK (((expires_at > issued_at) AND ((expires_at - issued_at) <= 60000)))",
        "CHECK (((octet_length(challenge_wire) >= 1) AND (octet_length(challenge_wire) <= 4096)))",
        "CHECK (((subject)::text ~ '^[0-9a-f]{64}$'::text))",
        "CHECK ((issued_at >= 0))",
        "PRIMARY KEY (challenge_id)",
    ),
    "sessions_v1": (
        "CHECK (((credential_digest)::text ~ '^[0-9a-f]{64}$'::text))",
        "CHECK (((expires_at > issued_at) AND ((expires_at - issued_at) <= 300000)))",
        "CHECK (((session_id)::text ~ '^[0-9a-f]{64}$'::text))",
        "CHECK ((issued_at >= 0))",
        "FOREIGN KEY (challenge_id) REFERENCES social_registered_device_challenges_v1(challenge_id)",
        "PRIMARY KEY (session_id)",
        "UNIQUE (challenge_id)",
        "UNIQUE (credential_digest)",
    ),
    "revocations_v1": (
        "CHECK ((revoked_at >= 0))",
        "FOREIGN KEY (session_id) REFERENCES social_registered_device_sessions_v1(session_id)",
        "PRIMARY KEY (session_id)",
    ),
}
_FUNCTIONS = {
    "deny_social_registered_device_history_mutation_v1": (
        False,
        2279,
        "18a6805fed523ef3bbc73a31c77045985a93b9772554841a4d15205b02c388a0",
    ),
    "create_registered_device_message_challenge_v1": (
        True,
        2278,
        "e2b032b459454f1f6c36231e20871a0ef04c05c7fff84502ca8cd169e00c796e",
    ),
}


def attest_registered_device_catalog_v1(connection):
    """Lock durable relations, then close columns, constraints, guards and ACLs.

    Runtime role ownership, inherited owner powers, broad write grants, missing
    uniqueness/immutability or a substituted definer writer are all rejected.
    The original native observer independently attests historical authority.
    """
    connection.execute(
        text("LOCK TABLE " + ",".join("public." + _PREFIX + n for n in _COLUMNS) + " IN ACCESS SHARE MODE")
    )
    role = connection.execute(text("SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user")).scalar_one()
    identities, owners = [], set()
    for suffix, columns in _COLUMNS.items():
        name = _PREFIX + suffix
        r = connection.execute(
            text(
                "SELECT c.oid,c.relowner,c.relkind,c.relpersistence,c.relrowsecurity,c.relforcerowsecurity,"
                "c.relhassubclass,c.relispartition,c.relhasrules,c.reloptions,pg_has_role(current_user,c.relowner,'MEMBER') "
                "FROM pg_catalog.pg_class c WHERE c.oid=pg_catalog.to_regclass(:name)"
            ),
            dict(name="public." + name),
        ).one()
        if tuple(r[2:]) != ("r", "p", False, False, False, False, False, None, False):
            _deny()
        oid, owner = r[:2]
        owners.add(owner)
        attrs = connection.execute(
            text(
                "SELECT attname,atttypid,atttypmod,attnotnull,attisdropped,atthasdef,attidentity,attgenerated,attacl "
                "FROM pg_catalog.pg_attribute WHERE attrelid=:oid AND attnum>0 ORDER BY attnum"
            ),
            dict(oid=oid),
        ).all()
        if tuple(tuple(a) for a in attrs) != tuple((*c, True, False, False, "", "", None) for c in columns):
            _deny()
        constraints = connection.execute(
            text(
                "SELECT pg_get_constraintdef(oid,false),convalidated,condeferrable,condeferred "
                "FROM pg_catalog.pg_constraint WHERE conrelid=:oid ORDER BY pg_get_constraintdef(oid,false)"
            ),
            dict(oid=oid),
        ).all()
        if tuple(tuple(c) for c in constraints) != tuple((c, True, False, False) for c in _CHECKS[suffix]):
            _deny()
        invalid = connection.execute(
            text(
                "SELECT 1 FROM pg_catalog.pg_index WHERE indrelid=:oid AND "
                "(NOT indisvalid OR NOT indisready OR NOT indislive OR NOT indimmediate OR indpred IS NOT NULL OR indexprs IS NOT NULL)"
            ),
            dict(oid=oid),
        ).first()
        acl = connection.execute(
            text(
                "SELECT a.grantee,a.privilege_type,a.is_grantable FROM pg_catalog.pg_class c,"
                "LATERAL aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) a WHERE c.oid=:oid"
            ),
            dict(oid=oid),
        ).all()
        expected = {
            (owner, p, False) for p in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")
        }
        expected.update((role, p, False) for p in ("INSERT", "SELECT"))
        if invalid or set(tuple(a) for a in acl) != expected:
            _deny()
        stem = {"challenges_v1": "challenge", "sessions_v1": "session", "revocations_v1": "revocation"}[suffix]
        triggers = connection.execute(
            text(
                "SELECT t.tgname,t.tgtype,t.tgenabled,t.tgdeferrable,t.tginitdeferred,p.proname,p.proowner "
                "FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_proc p ON p.oid=t.tgfoid "
                "WHERE t.tgrelid=:oid AND NOT t.tgisinternal ORDER BY t.tgname"
            ),
            dict(oid=oid),
        ).all()
        wanted = [
            (
                f"registered_{stem}_immutable_v1",
                27,
                "O",
                False,
                False,
                "deny_social_registered_device_history_mutation_v1",
                owner,
            ),
            (
                f"registered_{stem}_no_truncate_v1",
                34,
                "O",
                False,
                False,
                "deny_social_registered_device_history_mutation_v1",
                owner,
            ),
        ]
        if [tuple(t) for t in triggers] != wanted:
            _deny()
        identities.append((oid, owner))
    if len(owners) != 1:
        _deny()
    owner = next(iter(owners))
    for name, (definer, result_type, digest) in _FUNCTIONS.items():
        rows = connection.execute(
            text(
                "SELECT p.oid,p.proowner,p.prosecdef,p.prorettype,p.proconfig,p.prosrc,l.lanname,p.proargtypes::text,"
                "p.provolatile,p.proisstrict,p.proretset FROM pg_catalog.pg_proc p "
                "JOIN pg_catalog.pg_language l ON l.oid=p.prolang "
                "WHERE p.pronamespace='public'::regnamespace AND p.proname=:name"
            ),
            dict(name=name),
        ).all()
        if len(rows) != 1:
            _deny()
        p = rows[0]
        if (p[1], p[2], p[3], p[4], p[6], p[7], p[8], p[9], p[10]) != (
            owner,
            definer,
            result_type,
            ["search_path=pg_catalog, public"],
            "plpgsql",
            "25 25 25 25 25" if definer else "",
            "v",
            False,
            False,
        ) or hashlib.sha256(p[5].encode("utf-8")).hexdigest() != digest:
            _deny()
        acl = connection.execute(
            text(
                "SELECT a.grantee,a.privilege_type,a.is_grantable FROM pg_catalog.pg_proc p,"
                "LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE p.oid=:oid"
            ),
            dict(oid=p[0]),
        ).all()
        expected = {(owner, "EXECUTE", False)} | ({(role, "EXECUTE", False)} if definer else set())
        if set(tuple(a) for a in acl) != expected:
            _deny()
        identities.append((p[0], p[1], digest))
    return tuple(identities)
