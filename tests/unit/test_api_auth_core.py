from app.auth_api_core import ACTIVE_CHALLENGES, is_valid_pubkey, mint_access_token


def test_api_auth_core_imports_and_validates_pubkeys():
    pubkey = "02" + "11" * 32

    assert isinstance(ACTIVE_CHALLENGES, dict)
    assert is_valid_pubkey(pubkey)
    assert not is_valid_pubkey("not-a-pubkey")

    token = mint_access_token(pubkey)
    assert token.startswith(pubkey + ".")
