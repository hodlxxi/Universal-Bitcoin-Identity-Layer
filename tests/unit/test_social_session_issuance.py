"""Closed requests and explicit default-off composition, entirely offline."""

import json

import pytest
from flask import Flask

from app.services.social_mobile_authorization_ingress_schema import InvalidMobileRequest
from app.services.social_session_issuance_ingress import install_session_issuance
from app.services.social_session_issuance_schema import COMMANDS, PREFIX, command_body


@pytest.mark.parametrize("command", COMMANDS)
def test_exact_closed_vocabulary(command):
    body = {k: "a" * 64 for k in COMMANDS[command]}
    assert command_body(command, json.dumps(body).encode()) == body
    for key in body:
        with pytest.raises(InvalidMobileRequest):
            command_body(command, json.dumps({k: v for k, v in body.items() if k != key}).encode())
    for key in ("subject", "deviceId", "bindingId", "clientId", "sessionId", "eligible", "identity"):
        with pytest.raises(InvalidMobileRequest):
            command_body(command, json.dumps(dict(body, **{key: "a" * 64})).encode())


@pytest.mark.parametrize(
    "raw",
    [
        b"{}",
        b"[]",
        b'{"issuanceId":true}',
        b'{"issuanceId":{}}',
        b'{"issuanceId":"a","issuanceId":"b"}',
        b'{"issuanceId":NaN}',
        b"\xff",
        json.dumps({"issuanceId": "A" * 64}).encode(),
        json.dumps({"issuanceId": "a" * 63}).encode(),
        json.dumps({"issuanceId": "a" * 65}).encode(),
        json.dumps({"issuanceId": "\ud800"}).encode(),
    ],
)
def test_noncanonical_selectors_denied(raw):
    with pytest.raises(InvalidMobileRequest):
        command_body("resolve", raw)


def test_default_composition_has_no_routes_or_extension():
    app = Flask(__name__)
    assert install_session_issuance(app, None) is False
    assert not app.extensions
    assert all(not str(rule).startswith(PREFIX) for rule in app.url_map.iter_rules())
