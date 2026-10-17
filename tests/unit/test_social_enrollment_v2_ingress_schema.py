"""Dependency-free transport rejection tests, without a Flask app."""

import json
import unittest
from urllib.parse import urlencode

from app.services import social_enrollment_v2_ingress_schema as schema


def body(command):
    values = {"issuanceId": "a" * 64}
    if command in {"reserve", "finalize"}:
        values["verificationInputWire"] = '{"exact":"wire"}'
    if command == "finalize":
        values.update(
            reservationId="b" * 64,
            reservationRevision="1",
            evidenceCompactJws="header.payload.signature",
            statementCompactJws="other.exact.signature",
        )
    return values


class EnrollmentIngressSchemaTests(unittest.TestCase):
    def test_three_closed_commands_preserve_exact_wire_bytes(self):
        for command in schema.COMMANDS:
            original = body(command)
            self.assertEqual(schema.command_body(command, json.dumps(original).encode()), original)

    def test_missing_extra_and_authority_fields_denied(self):
        for name in ("subject", "deviceId", "clock", "enabled", "verified", "freshnessProfile", "callback"):
            with self.subTest(name=name), self.assertRaises(schema.InvalidMobileRequest):
                schema.command_body("challenge", json.dumps(dict(body("challenge"), **{name: "chosen"})).encode())
        with self.assertRaises(schema.InvalidMobileRequest):
            schema.command_body("challenge", b"{}")

    def test_duplicate_json_properties_are_denied(self):
        for raw in (b'{"issuanceId":"a","issuanceId":"b"}', b'{"issuanceId":"a","\\u0069ssuanceId":"b"}'):
            with self.subTest(raw=raw), self.assertRaises(schema.InvalidMobileRequest):
                schema.command_body("challenge", raw)

    def test_nested_nonfinite_and_wrong_json_types_denied(self):
        for value in (None, True, 1, 1.0, [], {}, float("inf"), float("nan")):
            with self.subTest(value=value), self.assertRaises(schema.InvalidMobileRequest):
                schema.command_body("challenge", json.dumps({"issuanceId": value}).encode())

    def test_revision_is_exact_transport_string_one(self):
        for value in (True, 1, 1.0, "01", "2", "1.0", " 1", None):
            with self.subTest(value=value), self.assertRaises(schema.InvalidMobileRequest):
                schema.command_body("finalize", json.dumps(dict(body("finalize"), reservationRevision=value)).encode())

    def test_identifier_and_wire_encoding_bounds(self):
        for value in ("A" * 64, "a" * 63, "a" * 65, " a" * 32, "я" * 64):
            with self.subTest(value=value), self.assertRaises(schema.InvalidMobileRequest):
                schema.command_body("challenge", json.dumps({"issuanceId": value}).encode())
        for value in ("", "\n", "\u0000", "я", "a" * 24577):
            with self.subTest(value=value[:12]), self.assertRaises(schema.InvalidMobileRequest):
                schema.command_body("reserve", json.dumps(dict(body("reserve"), verificationInputWire=value)).encode())

    def test_invalid_raw_encoding_and_oversize_denied(self):
        for raw in (b"", b"\xff", b"\xef\xbb\xbf{}", b" " * (schema.MAX_BODY_BYTES + 1), b"[]", b"null"):
            with self.subTest(length=len(raw)), self.assertRaises(schema.InvalidMobileRequest):
                schema.command_body("challenge", raw)

    def test_exact_form_fields_and_percent_decoding(self):
        original = dict(
            grant_type="client_credentials",
            client_id="backend",
            client_assertion_type=schema.ASSERTION_TYPE,
            client_assertion="header.payload.signature",
            scope=schema.SCOPES["challenge"],
        )
        self.assertEqual(schema.token_form(urlencode(original).encode()), original)

    def test_repeated_extra_missing_or_malformed_form_denied(self):
        fields = dict(
            grant_type="client_credentials",
            client_id="backend",
            client_assertion_type=schema.ASSERTION_TYPE,
            client_assertion="header.payload.signature",
            scope=schema.SCOPES["challenge"],
        )
        raw = urlencode(fields).encode()
        for value in (
            raw + b"&client_id=other",
            raw + b"&extra=1",
            raw.replace(b"client_id=backend&", b""),
            raw.replace(b"backend", b"%XZ"),
            raw.replace(b"backend", b"%FF"),
            b"scope",
            b"",
        ):
            with self.subTest(length=len(value)), self.assertRaises(schema.InvalidMobileRequest):
                schema.token_form(value)

    def test_purpose_audience_scope_are_separate_per_command(self):
        self.assertEqual(len(set(schema.SCOPES.values())), 3)
        self.assertEqual(len(set(schema.PURPOSES.values())), 3)
        with self.assertRaises(TypeError):
            schema.COMMANDS["chosen"] = ()


if __name__ == "__main__":
    unittest.main()
