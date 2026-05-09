import os

from app.blueprints.lnd_status import build_lnd_getinfo_command, resolve_lnd_env


def test_lnd_status_route_is_factory_native(app):
    matches = [r for r in app.url_map.iter_rules() if r.rule == "/api/lnd/status"]
    assert len(matches) == 1

    rule = matches[0]
    assert rule.endpoint == "lnd_status.api_lnd_status"

    view = app.view_functions[rule.endpoint]
    assert view.__module__ == "app.blueprints.lnd_status"


def test_public_status_route_remains_factory_native(app):
    matches = [r for r in app.url_map.iter_rules() if r.rule == "/api/public/status"]
    assert len(matches) == 1

    rule = matches[0]
    assert rule.endpoint == "public_status.api_public_status"

    view = app.view_functions[rule.endpoint]
    assert view.__module__ == "app.blueprints.public_status"


def test_lnd_env_resolver_prefers_canonical_names(monkeypatch):
    monkeypatch.setenv("LND_RPCSERVER", "canonical-rpc")
    monkeypatch.setenv("LND_TLSCERTPATH", "/canonical/tls.cert")
    monkeypatch.setenv("LND_MACAROONPATH", "/canonical/readonly.macaroon")
    monkeypatch.setenv("LND_TLS_CERT", "/legacy/tls.cert")
    monkeypatch.setenv("LND_READONLY_MACAROON", "/legacy/readonly.macaroon")

    resolved = resolve_lnd_env()

    assert resolved["rpcserver"] == "canonical-rpc"
    assert resolved["tlscertpath"] == "/canonical/tls.cert"
    assert resolved["macaroonpath"] == "/canonical/readonly.macaroon"


def test_lnd_env_resolver_falls_back_to_legacy_names(monkeypatch):
    for key in (
        "LND_RPCSERVER",
        "LND_TLSCERTPATH",
        "LND_MACAROONPATH",
        "LND_TLS_CERT",
        "LND_READONLY_MACAROON",
    ):
        monkeypatch.delenv(key, raising=False)

    monkeypatch.setenv("LND_RPCSERVER", "rpc")
    monkeypatch.setenv("LND_TLS_CERT", "/legacy/tls.cert")
    monkeypatch.setenv("LND_READONLY_MACAROON", "/legacy/readonly.macaroon")

    resolved = resolve_lnd_env()

    assert resolved["rpcserver"] == "rpc"
    assert resolved["tlscertpath"] == "/legacy/tls.cert"
    assert resolved["macaroonpath"] == "/legacy/readonly.macaroon"


def test_lnd_getinfo_command_uses_resolved_paths(monkeypatch):
    monkeypatch.setenv("LND_LNCLI_BIN", "/usr/local/bin/lncli")
    monkeypatch.setenv("LND_RPCSERVER", "127.0.0.1:10009")
    monkeypatch.setenv("LND_TLSCERTPATH", "/tls.cert")
    monkeypatch.setenv("LND_MACAROONPATH", "/readonly.macaroon")

    cmd = build_lnd_getinfo_command()

    assert cmd == [
        "/usr/local/bin/lncli",
        "--rpcserver=127.0.0.1:10009",
        "--tlscertpath=/tls.cert",
        "--macaroonpath=/readonly.macaroon",
        "getinfo",
    ]


def test_lnd_status_requires_login(client):
    resp = client.get("/api/lnd/status")
    assert resp.status_code == 401
    data = resp.get_json()
    assert data["ok"] is False
    assert data["error"] == "Not logged in"


def test_lnd_status_requires_full_access(client):
    with client.session_transaction() as sess:
        sess["logged_in_pubkey"] = "pubkey-test"
        sess["access_level"] = "limited"

    resp = client.get("/api/lnd/status")
    assert resp.status_code == 403
    data = resp.get_json()
    assert data["ok"] is False
    assert data["error"] == "Full access required"


def test_lnd_status_full_user_reaches_missing_env_check(client, monkeypatch):
    for key in (
        "LND_RPCSERVER",
        "LND_TLSCERTPATH",
        "LND_MACAROONPATH",
        "LND_TLS_CERT",
        "LND_READONLY_MACAROON",
    ):
        monkeypatch.delenv(key, raising=False)

    with client.session_transaction() as sess:
        sess["logged_in_pubkey"] = "pubkey-test"
        sess["access_level"] = "full"

    resp = client.get("/api/lnd/status")
    assert resp.status_code == 503
    data = resp.get_json()
    assert data["ok"] is False
    assert data["active"] is False
    assert data["state"] == "missing_env"
    assert "LND_RPCSERVER" in data["missing"]


def test_lnd_status_full_user_returns_legacy_shape(client, monkeypatch):
    monkeypatch.setenv("LND_RPCSERVER", "127.0.0.1:10009")
    monkeypatch.setenv("LND_TLSCERTPATH", "/tls.cert")
    monkeypatch.setenv("LND_MACAROONPATH", "/readonly.macaroon")

    calls = []

    def fake_run_lnd_json(args, timeout=8.0):
        calls.append(tuple(args))
        if args == ["getinfo"]:
            return {
                "alias": "HODLXXI-PAYG",
                "synced_to_chain": True,
                "synced_to_graph": True,
                "block_height": 948551,
                "num_peers": 2,
                "num_active_channels": 1,
            }
        if args == ["walletbalance"]:
            return {
                "confirmed_balance": "1000",
                "unconfirmed_balance": "0",
                "total_balance": "1000",
            }
        if args == ["channelbalance"]:
            return {
                "balance": "500",
                "pending_open_balance": "0",
            }
        if args == ["listchannels"]:
            return {
                "channels": [
                    {"local_balance": "300", "remote_balance": "700"},
                    {"local_balance": "200", "remote_balance": "800"},
                ]
            }
        raise AssertionError(args)

    monkeypatch.setattr(
        "app.blueprints.lnd_status.run_lnd_json",
        fake_run_lnd_json,
    )

    with client.session_transaction() as sess:
        sess["logged_in_pubkey"] = "pubkey-test"
        sess["access_level"] = "full"

    resp = client.get("/api/lnd/status")
    assert resp.status_code == 200

    data = resp.get_json()
    assert data["ok"] is True
    assert data["active"] is True
    assert data["state"] == "active"

    assert data["getinfo"]["alias"] == "HODLXXI-PAYG"
    assert data["getinfo"]["block_height"] == 948551
    assert data["walletbalance"]["total_balance"] == "1000"
    assert data["channelbalance"]["balance"] == "500"
    assert data["channels_summary"] == {
        "count": 2,
        "local_sum": 500,
        "remote_sum": 1500,
    }

    assert calls == [
        ("getinfo",),
        ("walletbalance",),
        ("channelbalance",),
        ("listchannels",),
    ]
