"""Real Core watch-only imports, key-authenticated login, cascade and reorg.

Root account/evidence is an explicit isolated bootstrap fixture. Bob/Charlie
are newly generated regtest identities; no live participant's key is accessed.
"""

from decimal import Decimal
import time

from sqlalchemy import text
from sqlalchemy.orm import sessionmaker

from app.services.automatic_sponsored_admission_v1 import coordinate_automatic_pair, refresh_automatic_imports
from app.services.current_entitlement import resolve_runtime_current_entitlement
from tests.integration.isolated_bitcoin_regtest import regtest, regtest_environment
from tests.integration.test_automatic_sponsored_admission_postgres_v1 import (
    automatic_engine,
    auto_db,
    counts,
)
from tests.unit.test_covenant_wallet_routes import app_client
from tests.unit.test_automatic_sponsored_import_v1 import ALICE, _leg


def fund(node, scripts):
    addresses = [node.rpc().decodescript(script)["segwit"]["address"] for script in scripts]
    txid = node.rpc("fixture-funding").sendmany("", {address: Decimal("0.00006666") for address in addresses})
    block = node.rpc().generatetoaddress(1, node.rpc("fixture-funding").getnewaddress())[0]
    return txid, block


def post_import(client, node, script, expected_status=200):
    descriptor = node.rpc().getdescriptorinfo("raw(" + script + ")")["descriptor"]
    response = client.post("/import_descriptor", json={"descriptor": descriptor})
    assert response.status_code == expected_status
    return response.get_json()


def login(client, node, address, pubkey):
    response = client.get("/login")
    assert response.status_code == 200
    with client.session_transaction() as state:
        challenge = state["challenge"]
    signature = node.rpc("fixture-funding").signmessage(address, challenge)
    response = client.post("/verify_signature", json={"pubkey": pubkey, "signature": signature, "challenge": challenge})
    assert response.status_code == 200
    assert response.get_json()["verified"] is True
    return response


def test_real_import_login_bob_to_charlie_and_reorg_invalidate_descendants(
    auto_db, app_client, regtest_environment, monkeypatch
):
    node = regtest_environment
    import app.app as legacy

    monkeypatch.setattr(legacy, "get_db_session", sessionmaker(auto_db))
    app, alice = app_client
    # This fixture is the only root bootstrap. It is never a live Alice login.
    with alice.session_transaction() as state:
        state["logged_in_pubkey"] = ALICE
        state["canonical_verified_login_subject_v1"] = ALICE[2:]
    funding = node.rpc("fixture-funding")
    bob_address = funding.getnewaddress("fixture-bob", "legacy")
    bob = funding.getaddressinfo(bob_address)["pubkey"]
    charlie_address = funding.getnewaddress("fixture-charlie", "legacy")
    charlie = funding.getaddressinfo(charlie_address)["pubkey"]
    scripts = (_leg(ALICE, bob, 1777000, 1777777), _leg(bob, ALICE, 1777777, 1778554))
    txid, bob_block = fund(node, scripts)
    assert node.rpc("fixture-watch").getwalletinfo()["private_keys_enabled"] is False
    import app.services.automatic_sponsored_import_v1 as journal

    original_journal = journal.record_successful_sponsored_import

    def failed_journal(*args, **kwargs):
        raise RuntimeError("synthetic post-Core journal failure")

    with monkeypatch.context() as failure:
        failure.setattr(journal, "record_successful_sponsored_import", failed_journal)
        post_import(alice, node, scripts[1], expected_status=500)
    # Recovery observes exact raw+address descriptors in this isolated wallet,
    # and requires the pre-RPC authenticated sponsor intent committed by HTTP.
    recovered = journal.recover_authenticated_sponsored_imports(
        sessionmaker(auto_db),
        trusted_wallet_rpc=node.rpc("fixture-watch"),
        now=__import__("datetime").datetime.now(__import__("datetime").timezone.utc).replace(microsecond=0),
    )
    assert len(recovered) == 1
    assert journal.record_successful_sponsored_import is original_journal
    result = post_import(alice, node, scripts[0])
    assert result["automatic_sponsored_import"]["status"] == "pending_confirmed_utxo_verification"
    assert refresh_automatic_imports(sessionmaker(auto_db))["effective_eligible"] == 1
    with auto_db.connect() as connection:
        parent_pair = connection.execute(text("SELECT pair_sha256 FROM canonical_auto_effective_edges_v1")).scalar_one()
        assert (
            connection.execute(
                text("SELECT count(*) FROM users WHERE pubkey=:subject"), {"subject": bob[2:]}
            ).scalar_one()
            == 0
        )
    bob_browser = app.test_client()
    login(bob_browser, node, bob_address, bob)
    assert resolve_runtime_current_entitlement(bob[2:]).current_full_relation_satisfied
    authority = bob_browser.get("/agent/authority/current/" + bob[2:] + ".json")
    assert authority.status_code == 200 and authority.get_json()["current_full_relation_satisfied"] is True
    scripts2 = (_leg(bob, charlie, 1776223, 1777000), _leg(charlie, bob, 1777000, 1777777))
    fund(node, scripts2)
    post_import(bob_browser, node, scripts2[0])
    child = post_import(bob_browser, node, scripts2[1])
    assert child["automatic_sponsored_import"]["status"] == "pending_confirmed_utxo_verification"
    assert refresh_automatic_imports(sessionmaker(auto_db))["effective_eligible"] == 1
    charlie_browser = app.test_client()
    login(charlie_browser, node, charlie_address, charlie)
    assert resolve_runtime_current_entitlement(charlie[2:]).current_full_relation_satisfied
    assert counts(auto_db) == (2, 4, 2, 4, 2)
    post_import(alice, node, scripts[0])
    assert counts(auto_db) == (2, 4, 2, 4, 2)
    # Real consensus reorg: removes both funding blocks, without spending any
    # output belonging to a live participant or calling the existing node.
    node.rpc().invalidateblock(bob_block)
    invalid = coordinate_automatic_pair(sessionmaker(auto_db), parent_pair)
    assert not invalid.eligible
    assert not resolve_runtime_current_entitlement(bob[2:]).current_full_relation_satisfied
    assert not resolve_runtime_current_entitlement(charlie[2:]).current_full_relation_satisfied
    assert bob_browser.post("/import_descriptor", json={"descriptor": "raw(51)"}).status_code == 403
    assert counts(auto_db) == (2, 4, 2, 4, 3)
