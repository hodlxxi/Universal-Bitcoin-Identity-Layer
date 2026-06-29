from __future__ import annotations

import pytest


@pytest.fixture
def app_client(monkeypatch):
    for name in [
        "ENABLE_DEBUG_ROUTES",
        "ENABLE_DEV_ROUTES",
        "ENABLE_PUBLIC_METRICS",
        "ENABLE_PUBLIC_TURN_CREDENTIALS",
        "ENABLE_LEGACY_WALLET_ROUTES",
        "ENABLE_OAUTH_DEV_ROUTES",
    ]:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("FLASK_ENV", "production")
    monkeypatch.setenv("DISABLE_FORCE_HTTPS", "1")
    monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")

    import app.database as database
    import app.factory as factory

    class _DummyDB:
        def execute(self, *_args, **_kwargs):
            return None

    monkeypatch.setattr(factory, "init_all", lambda: None)
    monkeypatch.setattr(factory, "init_audit_logger", lambda: None)
    monkeypatch.setattr(database, "get_db", lambda: _DummyDB())

    flask_app = factory.create_app()
    flask_app.config.update(TESTING=True)
    return flask_app, flask_app.test_client()


class FakeRPC:
    def getwalletinfo(self):
        return {"walletname": "test"}

    def listdescriptors(self):
        return {"descriptors": [{"desc": "raw(51)"}, {"desc": "wpkh(xpub/0/*)"}, {"desc": "combo(pub)"}]}

    def getbalance(self):
        return 21

    def getblockcount(self):
        return 840000

    def getreceivedbylabel(self, label):
        return {"label": label}

    def listtransactions(self):
        return []

    def listunspent(self):
        return []

    def listreceivedbylabel(self):
        return []

    def listreceivedbyaddress(self):
        return []

    def listaddressgroupings(self):
        return []

    def listlabels(self):
        return []

    def rescanblockchain(self):
        return {"start_height": 0}


@pytest.mark.parametrize(
    "path,method,json",
    [
        ("/rpc/getwalletinfo", "get", None),
        ("/export_descriptors", "get", None),
        ("/import_descriptor", "post", {"descriptor": "raw(51)"}),
        ("/set_labels_from_zpub", "post", {"zpub": "zpub", "label": "label"}),
    ],
)
def test_anonymous_covenant_wallet_routes_not_200(app_client, path, method, json):
    _app, client = app_client
    response = getattr(client, method)(path, json=json)
    assert response.status_code != 200


@pytest.mark.parametrize("level", ["guest", "limited"])
def test_guest_and_limited_covenant_wallet_routes_not_200(app_client, level):
    _app, client = app_client
    with client.session_transaction() as session:
        session["logged_in_pubkey"] = "02" + "11" * 32
        session["access_level"] = level

    assert client.get("/rpc/getwalletinfo").status_code != 200
    assert client.get("/export_descriptors").status_code != 200
    assert client.post("/import_descriptor", json={"descriptor": "raw(51)"}).status_code != 200
    assert client.post("/set_labels_from_zpub", json={"zpub": "zpub", "label": "label"}).status_code != 200


def test_full_user_reaches_rpc_allowlist(app_client, monkeypatch):
    _app, client = app_client
    import app.utils as utils

    monkeypatch.setattr(utils, "get_rpc_connection", lambda: FakeRPC())
    with client.session_transaction() as session:
        session["logged_in_pubkey"] = "02" + "11" * 32
        session["access_level"] = "full"

    response = client.get("/rpc/getwalletinfo")
    assert response.status_code == 200
    assert response.get_json() == {"walletname": "test"}


def test_full_user_export_descriptors_reaches_handler(app_client, monkeypatch):
    _app, client = app_client
    import app.app as legacy_app

    monkeypatch.setattr(legacy_app, "get_rpc_connection", lambda: FakeRPC())
    with client.session_transaction() as session:
        session["logged_in_pubkey"] = "02" + "11" * 32
        session["access_level"] = "full"

    response = client.get("/export_descriptors")
    assert response.status_code == 200
    assert response.get_json() == {"descriptors": ["raw(51)", "wpkh(xpub/0/*)"]}


def test_arbitrary_browser_rpc_command_rejected(app_client, monkeypatch):
    _app, client = app_client
    import app.utils as utils

    monkeypatch.setattr(utils, "get_rpc_connection", lambda: FakeRPC())
    with client.session_transaction() as session:
        session["logged_in_pubkey"] = "02" + "11" * 32
        session["access_level"] = "full"

    response = client.get("/rpc/stop")
    assert response.status_code == 400


def test_full_user_import_descriptor_reaches_guarded_handler(app_client, monkeypatch):
    _app, client = app_client
    import app.app as legacy_app

    def fake_import_descriptor():
        from flask import jsonify

        return jsonify({"handler": "import_descriptor"})

    monkeypatch.setattr(legacy_app, "import_descriptor", fake_import_descriptor)
    with client.session_transaction() as session:
        session["logged_in_pubkey"] = "02" + "11" * 32
        session["access_level"] = "full"

    response = client.post("/import_descriptor", json={"descriptor": "raw(51)"})
    assert response.status_code == 200
    assert response.get_json() == {"handler": "import_descriptor"}


def test_full_user_set_labels_from_zpub_reaches_guarded_handler(app_client, monkeypatch):
    _app, client = app_client
    import app.app as legacy_app

    def fake_set_labels_from_zpub():
        from flask import jsonify

        return jsonify({"handler": "set_labels_from_zpub"})

    monkeypatch.setattr(legacy_app, "set_labels_from_zpub", fake_set_labels_from_zpub)
    with client.session_transaction() as session:
        session["logged_in_pubkey"] = "02" + "11" * 32
        session["access_level"] = "full"

    response = client.post("/set_labels_from_zpub", json={"zpub": "zpub", "label": "label"})
    assert response.status_code == 200
    assert response.get_json() == {"handler": "set_labels_from_zpub"}
