import json


def _flatten_response_text(response) -> str:
    payload = response.get_data(as_text=True)
    return payload.lower() if payload else ""


def _assert_no_secret_leaks(response) -> None:
    text = _flatten_response_text(response)
    forbidden_markers = [
        "rpc_password",
        "macaroon",
        "authorization:",
        "bearer ",
        "private key",
        "-----begin",
        "token",
        "secret",
        "postgresql://",
    ]
    for marker in forbidden_markers:
        assert marker not in text, f"secret-like marker leaked: {marker}"


def test_health_ready_contract_non_500_and_structured_json(client):
    response = client.get("/health/ready")
    assert response.status_code in {200, 503}

    body = response.get_json()
    assert isinstance(body, dict)
    assert "status" in body
    assert body["status"] in {"ready", "not_ready"}

    _assert_no_secret_leaks(response)


def test_public_status_contract_non_500_and_stable_shape(client):
    response = client.get("/api/public/status")

    assert response.status_code == 200
    body = response.get_json()
    assert isinstance(body, dict)

    stable_keys = {
        "server_time_epoch",
        "server_time_utc",
        "block_height",
        "error",
        "online_users",
        "active_sockets",
        "online_roles",
        "uptime_sec",
        "load",
        "btc",
        "lnd",
    }
    assert stable_keys.issubset(body.keys())
    assert isinstance(body["btc"], dict)
    assert isinstance(body["lnd"], dict)

    _assert_no_secret_leaks(response)


def test_agent_chain_health_contract_non_500_and_structured_json(client):
    response = client.get("/agent/chain/health")
    assert response.status_code == 200

    body = response.get_json()
    assert isinstance(body, dict)
    assert {"agent_pubkey", "count", "chain_ok"}.issubset(body.keys())
    assert isinstance(body["count"], int)
    assert isinstance(body["chain_ok"], bool)

    _assert_no_secret_leaks(response)


def test_public_status_degraded_btc_rpc_does_not_leak_secrets(client, monkeypatch):
    class _Boom:
        def __init__(self, *_args, **_kwargs):
            raise TimeoutError("RPC_PASSWORD=supersecret should not leak")

    monkeypatch.setenv("RPC_USER", "test")
    monkeypatch.setenv("RPC_PASSWORD", "test")
    monkeypatch.setenv("RPC_WALLET", "wallet")
    monkeypatch.setattr("app.blueprints.public_status.AuthServiceProxy", _Boom)

    response = client.get("/api/public/status")
    assert response.status_code == 200
    body = response.get_json()

    assert body["btc"]["error"].startswith("rpc_error:")
    assert body["btc"]["error"] != "rpc_error:RPC_PASSWORD=supersecret should not leak"
    _assert_no_secret_leaks(response)


def test_public_status_degraded_lnd_timeout_returns_structured_data(client, monkeypatch):
    def _timeout(*_args, **_kwargs):
        raise TimeoutError("timed out")

    monkeypatch.setattr("app.blueprints.public_status.subprocess.run", _timeout)
    monkeypatch.setattr("app.blueprints.public_status._LND_CACHE", {})

    response = client.get("/api/public/status")
    assert response.status_code == 200
    body = response.get_json()

    assert isinstance(body["lnd"], dict)
    assert body["lnd"]["active"] is False
    assert "state" in body["lnd"]


def test_public_status_missing_optional_env_degrades_without_500(client, monkeypatch):
    for key in ("RPC_USER", "RPC_PASSWORD", "RPC_WALLET"):
        monkeypatch.delenv(key, raising=False)

    response = client.get("/api/public/status")
    assert response.status_code == 200
    body = response.get_json()

    assert body["btc"]["error"] == "rpc_error:missing_env"
    _assert_no_secret_leaks(response)


def test_lnd_status_runtime_failure_returns_degraded_shape_not_500(client, monkeypatch):
    monkeypatch.setenv("LND_RPCSERVER", "127.0.0.1:10009")
    monkeypatch.setenv("LND_TLSCERTPATH", "/tls.cert")
    monkeypatch.setenv("LND_MACAROONPATH", "/readonly.macaroon")

    def _boom(*_args, **_kwargs):
        raise RuntimeError("lncli unavailable")

    monkeypatch.setattr("app.blueprints.lnd_status.run_lnd_json", _boom)

    with client.session_transaction() as sess:
        sess["logged_in_pubkey"] = "pubkey-test"
        sess["access_level"] = "full"

    response = client.get("/api/lnd/status")
    assert response.status_code == 200
    body = response.get_json()
    assert body == {"ok": False, "active": False, "error": "Internal server error"}
    _assert_no_secret_leaks(response)
