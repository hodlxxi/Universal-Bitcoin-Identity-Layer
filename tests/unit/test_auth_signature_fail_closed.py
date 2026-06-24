from app.blueprints import auth as auth_module

VALID_COMPRESSED_PUBKEY = "02" + ("11" * 32)


class ExplodingRPC:
    def verifymessage(self, *_args, **_kwargs):
        raise RuntimeError("simulated RPC verification failure")


def test_verify_signature_fails_closed_on_rpc_error(
    client,
    monkeypatch,
):
    challenge = "fail-closed-regression-challenge"

    monkeypatch.setattr(
        auth_module,
        "get_rpc_connection",
        lambda: ExplodingRPC(),
    )

    monkeypatch.setattr(
        auth_module,
        "derive_legacy_address_from_pubkey",
        lambda _pubkey: "1RegressionTestAddress",
    )

    with client.session_transaction() as session:
        session["challenge"] = challenge
        session["challenge_timestamp"] = auth_module.time.time()

    response = client.post(
        "/verify_signature",
        json={
            "pubkey": VALID_COMPRESSED_PUBKEY,
            "signature": "attacker-controlled-signature",
            "challenge": challenge,
        },
    )

    assert response.status_code == 503
    assert response.get_json() == {
        "verified": False,
        "error": "Authentication service temporarily unavailable",
    }

    with client.session_transaction() as session:
        assert "logged_in_pubkey" not in session
        assert "access_level" not in session
        assert "login_method" not in session
