import importlib


def _clear_lnd_env(monkeypatch):
    for name in [
        "LND_LNCLI_BIN",
        "LNCLI_BIN",
        "LND_DIR",
        "LNCLI_LNDDIR",
        "LND_TLSCERTPATH",
        "LND_TLS_CERT",
        "LND_READONLY_MACAROON",
        "LND_MACAROONPATH",
        "LND_MACAROON",
        "LND_RPCSERVER",
    ]:
        monkeypatch.delenv(name, raising=False)


def test_lnd_status_resolver_prefers_canonical_tls_and_readonly_macaroon(monkeypatch):
    m = importlib.import_module("app.app")
    _clear_lnd_env(monkeypatch)

    monkeypatch.setenv("LND_TLSCERTPATH", "/tmp/canonical-tls.cert")
    monkeypatch.setenv("LND_TLS_CERT", "/tmp/legacy-tls.cert")
    monkeypatch.setenv("LND_READONLY_MACAROON", "/tmp/readonly.macaroon")
    monkeypatch.setenv("LND_MACAROONPATH", "/tmp/canonical-admin.macaroon")
    monkeypatch.setenv("LND_RPCSERVER", "127.0.0.1:10009")

    existing = {
        "/tmp/canonical-tls.cert",
        "/tmp/legacy-tls.cert",
        "/tmp/readonly.macaroon",
        "/tmp/canonical-admin.macaroon",
    }
    monkeypatch.setattr(m.os.path, "exists", lambda path: path in existing)

    cfg = m._resolve_lnd_status_cli_config()

    assert cfg["tls"] == "/tmp/canonical-tls.cert"
    assert cfg["mac"] == "/tmp/readonly.macaroon"
    assert cfg["rpcserver"] == "127.0.0.1:10009"


def test_lnd_status_resolver_falls_back_to_canonical_macaroon(monkeypatch):
    m = importlib.import_module("app.app")
    _clear_lnd_env(monkeypatch)

    monkeypatch.setenv("LND_TLSCERTPATH", "/tmp/canonical-tls.cert")
    monkeypatch.setenv("LND_MACAROONPATH", "/tmp/canonical.macaroon")

    existing = {"/tmp/canonical-tls.cert", "/tmp/canonical.macaroon"}
    monkeypatch.setattr(m.os.path, "exists", lambda path: path in existing)

    cfg = m._resolve_lnd_status_cli_config()

    assert cfg["tls"] == "/tmp/canonical-tls.cert"
    assert cfg["mac"] == "/tmp/canonical.macaroon"


def test_lnd_status_resolver_keeps_legacy_fallbacks(monkeypatch):
    m = importlib.import_module("app.app")
    _clear_lnd_env(monkeypatch)

    monkeypatch.setenv("LND_LNCLI_BIN", "/custom/lncli")
    monkeypatch.setenv("LND_DIR", "/custom/lnd")
    monkeypatch.setenv("LND_TLS_CERT", "/tmp/legacy-tls.cert")
    monkeypatch.setenv("LND_READONLY_MACAROON", "/tmp/readonly.macaroon")

    existing = {"/tmp/legacy-tls.cert", "/tmp/readonly.macaroon"}
    monkeypatch.setattr(m.os.path, "exists", lambda path: path in existing)

    cfg = m._resolve_lnd_status_cli_config()

    assert cfg["lncli_bin"] == "/custom/lncli"
    assert cfg["lnddir"] == "/custom/lnd"
    assert cfg["tls"] == "/tmp/legacy-tls.cert"
    assert cfg["mac"] == "/tmp/readonly.macaroon"
