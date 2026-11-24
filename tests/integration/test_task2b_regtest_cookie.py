"""Native Bitcoin Core cookie authentication on an isolated disposable regtest."""

import base64
import http.client
from pathlib import Path

from tests.integration.isolated_bitcoin_regtest import regtest


def test_disposable_core_cookie_credentials_and_wrong_credential_denial(regtest):
    assert regtest.user == "__cookie__"
    assert regtest.password
    assert regtest.rpc().getblockchaininfo()["chain"] == "regtest"
    assert regtest.rpc("fixture-watch").getwalletinfo()["private_keys_enabled"] is False
    assert (Path(regtest.directory) / "regtest" / ".cookie").is_file()

    denied_authorization = base64.b64encode(
        b"__cookie__:invalid-test-credential"
    ).decode("ascii")
    request_body = (
        '{"jsonrpc":"1.0","id":"cookie-test",'
        '"method":"getblockchaininfo","params":[]}'
    )
    connection = http.client.HTTPConnection("127.0.0.1", regtest.port, timeout=5)
    try:
        connection.request(
            "POST",
            "/",
            body=request_body,
            headers={
                "Authorization": "Basic " + denied_authorization,
                "Content-Type": "application/json",
            },
        )
        response = connection.getresponse()
        assert response.status == 401
        response.read()
    finally:
        connection.close()
