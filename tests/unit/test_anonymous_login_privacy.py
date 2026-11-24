"""Anonymous login must work without Bitcoin Core and keep wallet data off the wire."""

from unittest.mock import Mock
from uuid import uuid4

import pytest
from flask import Flask, render_template_string

from app import browser_routes, factory, utils
from app.blueprints import auth


@pytest.fixture(params=["factory", "legacy_route", "legacy_alias"])
def login_client(request, monkeypatch):
    route = request.param
    if route == "legacy_alias":
        from app.app import login as alias

    # The factory and compatibility registrations keep their own handler references.
    monkeypatch.setattr(browser_routes, "_BROWSER_ROUTE_HANDLERS", {})
    challenge = str(uuid4())

    def make_client(connect):
        monkeypatch.setattr(auth, "generate_challenge", lambda: challenge)
        monkeypatch.setattr(auth, "get_rpc_connection", connect)
        monkeypatch.setattr(utils, "get_rpc_connection", connect)
        monkeypatch.setattr(utils, "AuthServiceProxy", connect)
        if route == "factory":
            app = factory.create_app()
        else:
            app = Flask("synthetic_legacy_login")
            app.secret_key = uuid4().bytes
            browser_routes.register_browser_routes(
                app,
                generate_challenge=lambda: challenge,
                logger=app.logger,
                render_template_string_func=render_template_string,
                special_names={},
                force_relay=False,
                chat_history=[],
                online_users=set(),
                purge_old_messages=lambda: None,
            )
            if route == "legacy_alias":
                app.view_functions["login"] = alias
        return app.test_client()

    return route, challenge, make_client


@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_anonymous_login_never_connects_to_bitcoin(login_client, method):
    route, challenge, make_client = login_client

    def forbidden(*args, **kwargs):
        pytest.fail("anonymous login attempted to open a Bitcoin RPC connection")

    client = make_client(forbidden)
    response = client.open("/login", method=method, base_url="https://localhost")
    assert response.status_code == 200
    with client.session_transaction(base_url="https://localhost") as session:
        assert session["challenge"] == challenge
        assert session["challenge_timestamp"] > 0
    if method == "GET":
        assert challenge.encode() in response.data
        for entry in (b"/verify_signature", b"loginWithNostr", b"/api/verify", b"/api/lnurl-auth/create"):
            assert entry in response.data
    else:
        assert response.data == b""
    if route == "factory":
        assert response.headers.getlist("Referrer-Policy") == ["no-referrer"]
        assert "default-src 'self'" in response.headers["Content-Security-Policy"]
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert all(flag in response.headers["Set-Cookie"] for flag in ("Secure", "HttpOnly", "SameSite=Lax"))


def test_private_rpc_data_absent_from_complete_login_response(login_client):
    _, _, make_client = login_client
    marker = "synthetic-private-wallet-" + uuid4().hex
    rpc = Mock()
    rpc.getbalance.return_value = marker
    rpc.getblockcount.return_value = 7
    rpc.uptime.return_value = 9
    rpc.getmempoolinfo.return_value = {}
    connect = Mock(return_value=rpc)
    response = make_client(connect).get("/login", base_url="https://localhost")
    assert response.status_code == 200
    # Inspect the entire wire representation, including scripts, attributes and headers.
    wire = response.get_data() + str(response.headers).encode()
    assert marker.encode() not in wire
    for field in (b"getbalance", b"balance=", b"wallet_balance", b"block_height=", b"mempool="):
        assert field not in wire.lower()
    connect.assert_not_called()
