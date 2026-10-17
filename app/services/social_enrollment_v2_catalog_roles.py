"""Explicit dormant challenge-writer catalog policy, scoped to one caller root.

No environment, database connection, SQL execution on import, or request policy.
The default has no peer role and retains the original single-role catalog.
"""

import re
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from types import MappingProxyType


class CatalogRoleDenied(ValueError):
    def __init__(self):
        super().__init__("social enrollment v2 catalog role denied")


def _deny():
    raise CatalogRoleDenied() from None


@dataclass(frozen=True, slots=True)
class ChallengeWriterCatalogPin:
    role_name: str
    role_oid: int

    def __post_init__(self):
        if (
            type(self.role_name) is not str
            or re.fullmatch(r"[a-z][a-z0-9_]{0,62}", self.role_name) is None
            or self.role_name.startswith("pg_")
            or type(self.role_oid) is not int
            or not 16384 <= self.role_oid <= 4294967295
        ):
            _deny()


def freeze_pin(pin):
    if pin is None:
        return None
    if type(pin) is not ChallengeWriterCatalogPin:
        _deny()
    return ChallengeWriterCatalogPin(pin.role_name, pin.role_oid)


_TABLES = (
    "users",
    "oauth_clients",
    "oauth_tokens",
    "sessions",
    "oauth_codes",
    "current_entitlement_evidence",
    "oauth_browser_generations",
    "oauth_session_generations",
    "oauth_session_code_bindings",
    "social_messaging_device_bindings",
    "social_messaging_device_binding_authorization_evidence",
    "social_messaging_device_binding_authorization_replay",
    "social_messaging_device_authorization_requests",
    "social_messaging_device_authorization_binding_owners",
    "social_messaging_mobile_operations",
    "social_messaging_mobile_acceptances",
    "social_messaging_mobile_exchanges",
    "social_messaging_mobile_session_handoffs",
    "social_session_issuers",
    "social_session_pairing_parents",
    "social_session_issuances",
    "social_session_v2_offers",
    "social_session_v2_parents",
    "social_session_v2_binding_births",
    "social_session_v2_token_births",
    "social_session_v2_acceptances",
    "social_session_v2_issuances",
    "social_session_v2_invalidations",
    "social_device_admission_challenges",
    "social_device_admission_challenge_revisions",
    "social_device_ed25519_association_chains",
    "social_device_ed25519_association_events",
    "social_device_enrollment_admission_receipts",
    "social_preaccepted_enrollment_v2_atomic_acceptances",
    "social_enrollment_v2_native_associations",
    "social_enrollment_v2_native_consumptions",
    "social_enrollment_v2_native_effects",
    "social_enrollment_v2_native_decisions",
    "confidential_service_assertion_replay_markers",
)
_UPDATE = frozenset(
    (
        "users",
        "oauth_clients",
        "oauth_tokens",
        "sessions",
        "oauth_browser_generations",
        "social_session_issuers",
        "social_messaging_device_bindings",
        "current_entitlement_evidence",
        "social_device_admission_challenges",
    )
)
_INSERT = frozenset(
    (
        "oauth_tokens",
        "social_messaging_device_bindings",
        "social_device_admission_challenges",
        "social_session_v2_offers",
        "social_session_v2_parents",
        "social_session_v2_acceptances",
        "social_session_v2_issuances",
        "confidential_service_assertion_replay_markers",
    )
)
CHALLENGE_WRITER_PRIVILEGES = MappingProxyType(
    {
        name: tuple(
            sorted(("SELECT",) + (("UPDATE",) if name in _UPDATE else ()) + (("INSERT",) if name in _INSERT else ()))
        )
        for name in _TABLES
    }
)

# This lexical bridge is needed by the existing CAS validator, which receives
# the same raw Connection below the owner API. It stores no connection policy
# on the Engine/Session/pool and is reset before commit on every outcome.
_SCOPE = ContextVar("ubid_enrollment_v2_catalog_role_scope", default=None)


def _check_scope(scope):
    session, session_root, connection, root, pin = scope
    if (
        session.get_transaction() is not session_root
        or session_root.is_active is not True
        or session.get_nested_transaction() is not None
        or connection.get_transaction() is not root
        or root.is_active is not True
        or connection.get_nested_transaction() is not None
        or connection.closed is not False
        or connection.invalidated is not False
    ):
        _deny()
    return freeze_pin(pin)


@contextmanager
def catalog_role_scope(session, pin=None):
    pin = freeze_pin(pin)
    if pin is None:
        if _SCOPE.get() is not None:
            _deny()
        yield
        return
    if _SCOPE.get() is not None:
        _deny()
    session_root = session.get_transaction()
    if session_root is None or session_root.is_active is not True or session.get_nested_transaction() is not None:
        _deny()
    connection = session.connection()
    root = connection.get_transaction()
    if root is None:
        _deny()
    scope = (session, session_root, connection, root, pin)
    _check_scope(scope)
    token = _SCOPE.set(scope)
    try:
        yield
        _check_scope(scope)
    finally:
        _SCOPE.reset(token)


def catalog_pin_for(connection):
    scope = _SCOPE.get()
    if scope is None:
        return None
    if connection is not scope[2]:
        _deny()
    return _check_scope(scope)


ROLE_SQL = """
SELECT r.oid::bigint,r.rolname,r.rolsuper,r.rolinherit,r.rolcreaterole,r.rolcreatedb,
       r.rolcanlogin,r.rolreplication,r.rolbypassrls,r.rolconfig,
       ARRAY(SELECT p.rolname::text FROM pg_catalog.pg_roles p
          WHERE p.oid<>r.oid AND pg_catalog.pg_has_role(r.oid,p.oid,'MEMBER') ORDER BY p.rolname),
       (SELECT count(*) FROM pg_catalog.pg_auth_members WHERE member=r.oid),
       EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members WHERE member=r.oid AND admin_option),
       EXISTS(SELECT 1 FROM pg_catalog.pg_class WHERE relowner=r.oid)
         OR EXISTS(SELECT 1 FROM pg_catalog.pg_proc WHERE proowner=r.oid)
         OR EXISTS(SELECT 1 FROM pg_catalog.pg_namespace WHERE nspowner=r.oid)
         OR EXISTS(SELECT 1 FROM pg_catalog.pg_database WHERE datdba=r.oid)
         OR EXISTS(SELECT 1 FROM pg_catalog.pg_tablespace WHERE spcowner=r.oid)
         OR EXISTS(SELECT 1 FROM pg_catalog.pg_type WHERE typowner=r.oid)
         OR EXISTS(SELECT 1 FROM pg_catalog.pg_operator WHERE oprowner=r.oid)
         OR EXISTS(SELECT 1 FROM pg_catalog.pg_opclass WHERE opcowner=r.oid)
         OR EXISTS(SELECT 1 FROM pg_catalog.pg_opfamily WHERE opfowner=r.oid)
         OR EXISTS(SELECT 1 FROM pg_catalog.pg_collation WHERE collowner=r.oid)
         OR EXISTS(SELECT 1 FROM pg_catalog.pg_language WHERE lanowner=r.oid),
       EXISTS(SELECT 1 FROM pg_catalog.pg_namespace n WHERE n.nspname !~ '^pg_temp_'
          AND pg_catalog.has_schema_privilege(r.oid,n.oid,'CREATE'))
         OR EXISTS(SELECT 1 FROM pg_catalog.pg_database d WHERE pg_catalog.has_database_privilege(r.oid,d.oid,'CREATE')),
       EXISTS(SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
          WHERE n.nspname='public' AND p.proname='execute_social_enrollment_v2_native_effects'
          AND pg_catalog.has_function_privilege(r.oid,p.oid,'EXECUTE'))
FROM pg_catalog.pg_roles r WHERE r.oid=:role_oid AND r.rolname=:role_name
"""

TABLES_SQL = """
SELECT c.relname,c.relkind,c.oid::bigint,c.relowner::bigint,
       CASE WHEN c.relkind='S' THEN
         ARRAY(SELECT p FROM pg_catalog.unnest(ARRAY['SELECT','UPDATE','USAGE']) p
           WHERE pg_catalog.has_sequence_privilege(CAST(:role_oid AS oid),c.oid,p) ORDER BY p)
       ELSE ARRAY(SELECT p FROM pg_catalog.unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER']) p
           WHERE pg_catalog.has_table_privilege(CAST(:role_oid AS oid),c.oid,p) ORDER BY p) END,
       EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) x
         WHERE a.attrelid=c.oid AND CASE WHEN x.grantee=0 THEN true
           ELSE pg_catalog.pg_has_role(CAST(:role_oid AS oid),x.grantee,'MEMBER') END),
       EXISTS(SELECT 1 FROM pg_catalog.aclexplode(c.relacl) x WHERE x.is_grantable AND
         CASE WHEN x.grantee=0 THEN true ELSE pg_catalog.pg_has_role(CAST(:role_oid AS oid),x.grantee,'MEMBER') END)
FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','f','S') ORDER BY c.relname
"""


def attest_catalog_role(connection, pin, *, sql):
    pin = freeze_pin(pin)
    if pin is None:
        return None
    values = dict(role_name=pin.role_name, role_oid=pin.role_oid)
    rows = connection.execute(sql(ROLE_SQL), values).all()
    if len(rows) != 1 or len(rows[0]) != 16:
        _deny()
    row = tuple(rows[0])
    if (
        type(row[0]) is not int
        or row[:2] != (pin.role_oid, pin.role_name)
        or type(row[1]) is not str
        or any(type(row[n]) is not bool for n in (*range(2, 9), *range(12, 16)))
        or row[2:10] != (False, True, False, False, True, False, False, None)
        or type(row[10]) not in (tuple, list)
        or tuple(row[10]) != ("pg_read_all_settings",)
        or type(row[11]) is not int
        or row[11] != 1
        or row[12:] != (False, False, False, False)
    ):
        _deny()
    identity = [row[:10] + (tuple(row[10]),) + row[11:]]
    seen, oids = set(), set()
    for item in connection.execute(sql(TABLES_SQL), values).all():
        if len(item) != 7:
            _deny()
        name, kind, oid, owner, privileges, columns, grantable = item
        if (
            type(name) is not str
            or type(kind) is not str
            or type(oid) is not int
            or oid <= 0
            or oid in oids
            or type(owner) is not int
            or owner <= 0
            or owner == pin.role_oid
            or type(privileges) not in (tuple, list)
            or any(type(p) is not str for p in privileges)
            or columns is not False
            or grantable is not False
        ):
            _deny()
        oids.add(oid)
        privileges = tuple(privileges)
        if not privileges:
            continue
        if name in seen or kind != "r" or CHALLENGE_WRITER_PRIVILEGES.get(name) != privileges:
            _deny()
        seen.add(name)
        identity.append((name, oid, owner, privileges))
    if seen != set(CHALLENGE_WRITER_PRIVILEGES):
        _deny()
    return tuple(identity)


def peer_acl(pin, *, relation_name, owner, runtime):
    pin = freeze_pin(pin)
    if pin is None:
        return frozenset()
    if pin.role_oid in (owner, runtime) or relation_name not in CHALLENGE_WRITER_PRIVILEGES:
        _deny()
    return frozenset((pin.role_oid, privilege) for privilege in CHALLENGE_WRITER_PRIVILEGES[relation_name])
