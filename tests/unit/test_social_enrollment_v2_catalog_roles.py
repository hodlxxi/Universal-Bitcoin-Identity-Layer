"""Closed peer-role policy and lexical transaction scope; stdlib only.

Explicit rows below prove the catalog consumer, not PostgreSQL execution.
"""

import unittest
from copy import deepcopy
from dataclasses import FrozenInstanceError
from threading import Thread
from types import SimpleNamespace

from app.services import social_enrollment_v2_catalog_roles as roles


def pin():
    return roles.ChallengeWriterCatalogPin("synthetic_challenge_writer", 20001)


def role_row():
    return [
        20001,
        "synthetic_challenge_writer",
        False,
        True,
        False,
        False,
        True,
        False,
        False,
        None,
        ["pg_read_all_settings"],
        1,
        False,
        False,
        False,
        False,
    ]


def table_rows():
    return [
        [name, "r", index + 30000, 10, list(privileges), False, False]
        for index, (name, privileges) in enumerate(sorted(roles.CHALLENGE_WRITER_PRIVILEGES.items()))
    ]


class CatalogConnection:
    def __init__(self):
        self.role_rows = [role_row()]
        self.table_rows = table_rows()
        self.calls = []

    def execute(self, statement, values):
        self.calls.append((statement, values))
        if statement == roles.ROLE_SQL:
            return SimpleNamespace(all=lambda: self.role_rows)
        if statement == roles.TABLES_SQL:
            return SimpleNamespace(all=lambda: self.table_rows)
        raise AssertionError("unexpected SQL")


class BoundConnection:
    closed = invalidated = False

    def __init__(self):
        self.root = SimpleNamespace(is_active=True)
        self.nested = None

    def get_transaction(self):
        return self.root

    def get_nested_transaction(self):
        return self.nested


class BoundSession:
    def __init__(self):
        self.root = SimpleNamespace(is_active=True)
        self.bound = BoundConnection()
        self.nested = None

    def get_transaction(self):
        return self.root

    def get_nested_transaction(self):
        return self.nested

    def connection(self):
        return self.bound


class CatalogRoleContractTests(unittest.TestCase):
    def test_default_has_no_peer_and_no_catalog_queries(self):
        self.assertIsNone(roles.freeze_pin(None))
        self.assertIsNone(roles.attest_catalog_role(None, None, sql=lambda x: x))
        self.assertEqual(roles.peer_acl(None, relation_name="anything", owner=10, runtime=20), frozenset())

    def test_pin_rejects_noncanonical_names_and_oids(self):
        for name in ("", "A", "pg_monitor", "a-b", "a b", "a'", "a" * 64, True, 1, None):
            with self.subTest(name=name), self.assertRaises(roles.CatalogRoleDenied):
                roles.ChallengeWriterCatalogPin(name, 20001)
        for oid in (True, False, 0, -1, 16383, 4294967296, 20001.0, "20001", None):
            with self.subTest(oid=oid), self.assertRaises(roles.CatalogRoleDenied):
                roles.ChallengeWriterCatalogPin("writer", oid)

    def test_pin_is_copied_immutable_and_not_a_request_mapping(self):
        original = pin()
        copied = roles.freeze_pin(original)
        self.assertEqual(original, copied)
        self.assertIsNot(original, copied)
        with self.assertRaises(FrozenInstanceError):
            copied.role_oid = 20002
        for value in ({"role_name": original.role_name, "role_oid": original.role_oid}, (), True):
            with self.assertRaises(roles.CatalogRoleDenied):
                roles.freeze_pin(value)

    def test_fixed_privilege_matrix_retains_role_separation(self):
        matrix = roles.CHALLENGE_WRITER_PRIVILEGES
        self.assertEqual(len(matrix), 39)
        self.assertEqual(matrix["social_device_admission_challenges"], ("INSERT", "SELECT", "UPDATE"))
        self.assertEqual(matrix["social_device_admission_challenge_revisions"], ("SELECT",))
        self.assertEqual(matrix["social_preaccepted_enrollment_v2_atomic_acceptances"], ("SELECT",))
        for name in ("associations", "consumptions", "effects", "decisions"):
            self.assertEqual(matrix["social_enrollment_v2_native_" + name], ("SELECT",))
        self.assertFalse(any(set(value) & {"DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"} for value in matrix.values()))
        with self.assertRaises(TypeError):
            matrix["users"] = ("ALL",)

    def test_complete_role_and_tables_return_immutable_identity(self):
        c = CatalogConnection()
        identity = roles.attest_catalog_role(c, pin(), sql=lambda x: x)
        self.assertEqual(len(identity), 40)
        saved = deepcopy(identity)
        c.role_rows[0][10].append("pg_monitor")
        c.table_rows[0][4].append("DELETE")
        self.assertEqual(identity, saved)
        self.assertEqual(c.calls[0][1], {"role_name": pin().role_name, "role_oid": 20001})

    def test_role_identity_escalation_membership_and_schema_create_deny(self):
        for index, value in (
            (0, 20002),
            (1, "another_writer"),
            (2, True),
            (3, False),
            (4, True),
            (5, True),
            (6, False),
            (7, True),
            (8, True),
            (9, ["search_path=other"]),
            (10, ["pg_read_all_settings", "pg_monitor"]),
            (11, True),
            (11, 2),
            (12, True),
            (13, True),
            (14, True),
            (15, True),
            (2, 0),
        ):
            c = CatalogConnection()
            c.role_rows[0][index] = value
            with self.subTest(index=index, value=value), self.assertRaises(roles.CatalogRoleDenied):
                roles.attest_catalog_role(c, pin(), sql=lambda x: x)
        for rows in ([], [role_row(), role_row()], [role_row()[:-1]]):
            c = CatalogConnection()
            c.role_rows = rows
            with self.assertRaises(roles.CatalogRoleDenied):
                roles.attest_catalog_role(c, pin(), sql=lambda x: x)

    def test_missing_extra_and_bypass_privileges_deny(self):
        for mutation in (
            "missing",
            "extra",
            "column",
            "grant",
            "view",
            "duplicate",
            "owner",
            "unknown",
            "duplicate_oid",
        ):
            c = CatalogConnection()
            row = c.table_rows[0]
            if mutation == "missing":
                c.table_rows.pop()
            elif mutation == "extra":
                row[4].append("DELETE")
            elif mutation == "column":
                row[5] = True
            elif mutation == "grant":
                row[6] = True
            elif mutation == "view":
                row[1] = "v"
            elif mutation == "duplicate":
                extra = deepcopy(row)
                extra[2] = 99999
                c.table_rows.append(extra)
            elif mutation == "owner":
                row[3] = pin().role_oid
            elif mutation == "unknown":
                c.table_rows.append(["unregistered_table", "r", 99999, 10, ["SELECT"], False, False])
            else:
                c.table_rows[1][2] = row[2]
            with self.subTest(mutation=mutation), self.assertRaises(roles.CatalogRoleDenied):
                roles.attest_catalog_role(c, pin(), sql=lambda x: x)

    def test_unrelated_table_without_effective_peer_grants_is_ignored(self):
        c = CatalogConnection()
        c.table_rows.append(["other_table", "r", 99999, 10, [], False, False])
        self.assertEqual(len(roles.attest_catalog_role(c, pin(), sql=lambda x: x)), 40)

    def test_peer_acl_cannot_register_current_role_owner_or_unknown_table(self):
        expected = frozenset((20001, p) for p in ("SELECT", "INSERT", "UPDATE"))
        self.assertEqual(
            roles.peer_acl(pin(), relation_name="social_device_admission_challenges", owner=10, runtime=20), expected
        )
        for name, owner, runtime in (("users", 20001, 20), ("users", 10, 20001), ("unknown", 10, 20)):
            with self.assertRaises(roles.CatalogRoleDenied):
                roles.peer_acl(pin(), relation_name=name, owner=owner, runtime=runtime)

    def test_scope_is_bound_to_exact_connection_and_restores_on_success(self):
        s = BoundSession()
        with roles.catalog_role_scope(s, pin()):
            self.assertEqual(roles.catalog_pin_for(s.bound), pin())
            with self.assertRaises(roles.CatalogRoleDenied):
                roles.catalog_pin_for(BoundConnection())
        self.assertIsNone(roles.catalog_pin_for(s.bound))

    def test_scope_exception_and_nested_attempt_leave_no_policy(self):
        s = BoundSession()
        with self.assertRaisesRegex(RuntimeError, "synthetic"):
            with roles.catalog_role_scope(s, pin()):
                for value in (None, pin()):
                    with self.assertRaises(roles.CatalogRoleDenied):
                        with roles.catalog_role_scope(s, value):
                            self.fail("nested scope admitted")
                raise RuntimeError("synthetic")
        self.assertIsNone(roles.catalog_pin_for(s.bound))

    def test_scope_rejects_transaction_aba_savepoint_close_and_invalidation(self):
        for change in ("root", "session_root", "savepoint", "closed", "invalidated", "inactive"):
            s = BoundSession()
            with self.subTest(change=change), self.assertRaises(roles.CatalogRoleDenied):
                with roles.catalog_role_scope(s, pin()):
                    if change == "root":
                        s.bound.root = SimpleNamespace(is_active=True)
                    elif change == "session_root":
                        s.root = SimpleNamespace(is_active=True)
                    elif change == "savepoint":
                        s.bound.nested = object()
                    elif change == "inactive":
                        s.root.is_active = False
                    else:
                        setattr(s.bound, change, True)
                    roles.catalog_pin_for(s.bound)
            self.assertIsNone(roles.catalog_pin_for(s.bound))

    def test_scope_is_not_inherited_by_another_thread(self):
        s, observed = BoundSession(), []
        with roles.catalog_role_scope(s, pin()):
            thread = Thread(target=lambda: observed.append(roles.catalog_pin_for(s.bound)))
            thread.start()
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive())
            self.assertEqual(roles.catalog_pin_for(s.bound), pin())
        self.assertEqual(observed, [None])

    def test_scope_never_autobegins_a_session(self):
        s = BoundSession()
        s.root = None
        s.connection = lambda: self.fail("autobegin attempted")
        with self.assertRaises(roles.CatalogRoleDenied):
            with roles.catalog_role_scope(s, pin()):
                self.fail("missing root admitted")
