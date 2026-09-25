"""Offline fixed vectors and denial checks for the signed lifecycle command."""

from __future__ import annotations

import base64
import importlib.util
import json
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.services import social_messaging_active_alias_namespace_lifecycle as lifecycle

VECTORS = json.loads(
    (Path(__file__).resolve().parents[1] / "fixtures/social_messaging_active_alias_namespace_lifecycle_v1.json")
    .read_text(encoding="ascii")
)
PUBLIC = bytes.fromhex(VECTORS["publicKey"])
KEY_ID = VECTORS["keyId"]
FIXED_NOW = 1_800_000_030_000
ERROR = "social messaging alias lifecycle unavailable"


def verifier(public: bytes = PUBLIC, key_id: str = KEY_ID):
    return lifecycle.PinnedOfflineAliasLifecycleVerifierV1(public_key=public, key_id=key_id)


def vector(name: str):
    return VECTORS[name]["commandWire"].encode("ascii"), VECTORS[name]["signature"]


def signed_mutation(change):
    """Use a fresh synthetic signer in memory; never persist a private key."""

    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    data = json.loads(VECTORS["rotate"]["commandWire"])
    data.pop("commandId")
    change(data)
    wire = lifecycle.canonical_alias_lifecycle_command_v1(data)
    signature = base64.urlsafe_b64encode(
        private.sign(lifecycle.SIGNATURE_DOMAIN + b"\x00" + wire)
    ).decode("ascii").rstrip("=")
    return verifier(public), wire, signature


class SignedAliasLifecycleContractTests(unittest.TestCase):
    def assert_denied(self, operation):
        with self.assertRaisesRegex(lifecycle.AliasLifecycleCommandUnavailable, ERROR):
            operation()

    def test_fixed_public_vectors_cross_unsigned_producer_parser_and_verifier(self):
        for name, predecessor, successor in (("provision", None, 1), ("rotate", 1, 2)):
            with self.subTest(name=name):
                wire, signature = vector(name)
                parsed = lifecycle.parse_canonical_alias_lifecycle_command_v1(wire)
                unsigned = {key: value for key, value in parsed.items() if key != "commandId"}
                self.assertEqual(lifecycle.canonical_alias_lifecycle_command_v1(unsigned), wire)
                self.assertEqual(parsed["commandId"], VECTORS[name]["commandId"])
                verified = verifier().verify(wire, signature, now_ms=FIXED_NOW)
                self.assertEqual(verified.command_wire, wire)
                self.assertEqual(verified.signature, signature)
                self.assertEqual(verified.inspected.action, name)
                self.assertEqual(verified.inspected.expected_version, predecessor)
                self.assertEqual(verified.inspected.successor_version, successor)
                self.assertEqual(verified.inspected.command_id, parsed["commandId"])

    def test_signed_commitments_are_byte_identical_to_existing_namespace_owner(self):
        if importlib.util.find_spec("sqlalchemy") is None:
            self.skipTest("SQLAlchemy unavailable in the local offline test environment")
        from app.services import social_messaging_active_alias_namespace_storage as storage

        self.assertEqual(lifecycle.COMMITMENT_PREFIX, storage.SECRET_COMMITMENT_PREFIX)
        for name, secret, version in (
            ("provision", bytes(range(32)), 1),
            ("rotate", bytes(reversed(range(32))), 2),
        ):
            self.assertEqual(
                json.loads(VECTORS[name]["commandWire"])["successorCommitment"],
                storage.active_alias_namespace_secret_commitment(
                    alias_secret=secret, alias_version=version
                ),
            )

    def test_signature_domain_and_key_id_are_both_bound(self):
        wire, signature = vector("provision")
        self.assert_denied(lambda: verifier(key_id="other-offline-key").verify(
            wire, signature, now_ms=FIXED_NOW
        ))
        other = Ed25519PrivateKey.generate().public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        self.assert_denied(lambda: verifier(other).verify(wire, signature, now_ms=FIXED_NOW))
        self.assert_denied(lambda: verifier().verify(wire, signature[:-1] + "A", now_ms=FIXED_NOW))
        self.assert_denied(lambda: verifier().verify(wire, signature + "=", now_ms=FIXED_NOW))
        self.assert_denied(lambda: verifier().verify(wire, b"not a signature", now_ms=FIXED_NOW))

    def test_replay_window_never_extends_at_boundary_or_accepts_caller_boolean_clock(self):
        wire, signature = vector("rotate")
        for now in (1_799_999_999_999, 1_800_000_060_000, True, None):
            with self.subTest(now=now):
                self.assert_denied(lambda: verifier().verify(wire, signature, now_ms=now))
        self.assertEqual(verifier().verify(
            wire, signature, now_ms=1_800_000_000_000
        ).inspected.action, "rotate")

    def test_every_field_and_exact_canonical_bytes_are_signed(self):
        wire, signature = vector("rotate")
        changes = (
            lambda command: command.update(audience="other"),
            lambda command: command.update(action="provision"),
            lambda command: command.update(algorithm="RS256"),
            lambda command: command.update(keyId="other"),
            lambda command: command.update(expectedVersion=4),
            lambda command: command.update(successorVersion=4),
            lambda command: command.update(expiresAtMs=1_800_000_061_000),
            lambda command: command.update(nonce="A" * 43),
            lambda command: command.update(successorCommitment=command["expectedCommitment"]),
        )
        for change in changes:
            altered = json.loads(wire)
            change(altered)
            candidate = json.dumps(altered, sort_keys=True, separators=(",", ":")).encode("ascii")
            self.assert_denied(lambda: verifier().verify(candidate, signature, now_ms=FIXED_NOW))
        self.assert_denied(lambda: verifier().verify(
            wire.replace(b'"rotate"', b'"rot\\u0061te"'), signature, now_ms=FIXED_NOW
        ))
        self.assert_denied(lambda: verifier().verify(
            wire.replace(b'"version":1', b'"version":1,"version":1'), signature, now_ms=FIXED_NOW
        ))
        self.assert_denied(lambda: verifier().verify(wire + b" ", signature, now_ms=FIXED_NOW))
        self.assert_denied(lambda: verifier().verify(b"\xff" + wire, signature, now_ms=FIXED_NOW))

    def test_neither_a_signed_provision_relabel_nor_version_skip_is_admitted(self):
        for mutation in (
            lambda value: value.update(action="provision"),
            lambda value: value.update(expectedVersion=None),
            lambda value: value.update(expectedCommitment=None),
            lambda value: value.update(successorVersion=3),
            lambda value: value.update(successorVersion=1),
            lambda value: value.update(successorVersion=lifecycle.MAX_ALIAS_VERSION + 1),
            lambda value: value.update(issuedAtMs=True),
            lambda value: value.update(expiresAtMs=value["issuedAtMs"]),
            lambda value: value.update(expiresAtMs=value["issuedAtMs"] + lifecycle.MAX_COMMAND_LIFETIME_MS + 1),
            lambda value: value.update(nonce="A" * 42 + "B"),
            lambda value: value.update(rawSecret="forbidden"),
        ):
            with self.subTest(mutation=mutation):
                self.assert_denied(lambda: signed_mutation(mutation))

    def test_signed_configuration_cannot_be_replaced_by_a_mapping_or_flag(self):
        wire, signature = vector("provision")
        self.assert_denied(lambda: lifecycle.VerifiedAliasLifecycleCommandV1(True, {}, wire, signature))
        self.assert_denied(lambda: lifecycle.VerifiedAliasLifecycleCommandV1({}, {}, wire, signature))
        with self.assertRaises(lifecycle.AliasLifecycleCommandUnavailable):
            class InvalidSubclass(lifecycle.VerifiedAliasLifecycleCommandV1):
                pass
        self.assert_denied(lambda: verifier().verify({"authorized": True}, signature, now_ms=FIXED_NOW))
        self.assert_denied(lambda: verifier(public=b"short"))

    def test_fresh_synthetic_signature_verifies_only_the_exact_successor(self):
        instance, wire, signature = signed_mutation(
            lambda value: value.update(expiresAtMs=1_800_000_070_000)
        )
        self.assertEqual(instance.verify(wire, signature, now_ms=FIXED_NOW).inspected.successor_version, 2)
        altered = wire.replace(b'"successorVersion":2', b'"successorVersion":3')
        self.assert_denied(lambda: instance.verify(altered, signature, now_ms=FIXED_NOW))


if __name__ == "__main__":
    unittest.main()
