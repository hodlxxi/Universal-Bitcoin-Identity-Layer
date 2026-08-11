import inspect
from unittest.mock import Mock

import pytest

from app.auth_api_core import canonical_xonly_pubkey
from app.blueprints import auth as auth_module
from app.db_storage import get_user_by_pubkey
from app.models import CurrentEntitlementEvidence, User
from app.services.action_authorization import IdentityClass
from app.services.current_entitlement import resolve_runtime_current_entitlement


FULL_COMPRESSED = "02311091DD9860E8E20EE13473C1155F5F69635E394704EAA74009452246CFA9B3"
LIMITED_COMPRESSED = "023049F7FFC71D744BD9BED6F42DC6A28974E3A1B9D30671F800E5D46389103C7E"
FAILED_COMPRESSED = "0234C1FD04D301BE89B31C0442D3E6AC24883928B45A9340781867D4232EC2DBDF"
PERSISTENCE_FAILURE_COMPRESSED = "021880C9AD32FBB07E1FB52A688D9D6FE6DB0DF90ECD4C9483203F636EE00926DC"
OPERATOR_COMPRESSED = "023d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923"


class NoEvidenceRepository:
    def __init__(self):
        self.calls = []

    def get_latest(self, subject):
        self.calls.append(subject)
        return None


def _canonical(compressed):
    return canonical_xonly_pubkey(compressed)


def _seed_challenge(client, challenge):
    with client.session_transaction() as browser_session:
        browser_session["challenge"] = challenge
        browser_session["challenge_timestamp"] = auth_module.time.time()


def _login(client, compressed, challenge):
    _seed_challenge(client, challenge)
    return client.post(
        "/verify_signature",
        json={
            "pubkey": compressed,
            "signature": "verified-signature",
            "challenge": challenge,
        },
    )


def _install_verified_signature(monkeypatch):
    rpc = Mock()
    rpc.verifymessage.return_value = True
    monkeypatch.setattr(auth_module, "get_rpc_connection", lambda: rpc)
    monkeypatch.setattr(auth_module, "derive_legacy_address_from_pubkey", lambda _pubkey: "1LoginPersistence")
    return rpc


def _forbid_dormant_authority_paths(monkeypatch, legacy_runtime):
    def forbidden(*_args, **_kwargs):
        pytest.fail("login invoked a dormant authority path")

    from app.services import canonical_admission_edge
    from app.services import canonical_crt_membership
    from app.services import canonical_sponsor_lineage
    from app.services.covenant_entitlement_materializer import CovenantEntitlementMaterializer
    from app.services.current_entitlement_evidence_storage import SqlAlchemyCurrentEntitlementEvidenceRepository

    monkeypatch.setattr(auth_module, "get_special_users", forbidden)
    monkeypatch.setattr(legacy_runtime, "on_successful_login", forbidden)
    monkeypatch.setattr(canonical_crt_membership, "evaluate_canonical_crt_membership", forbidden)
    monkeypatch.setattr(canonical_sponsor_lineage, "evaluate_canonical_sponsor_lineage", forbidden)
    monkeypatch.setattr(canonical_admission_edge, "evaluate_canonical_admission_edge", forbidden)
    monkeypatch.setattr(canonical_admission_edge, "evaluate_canonical_admission_edge_current", forbidden)
    monkeypatch.setattr(CovenantEntitlementMaterializer, "materialize", forbidden)
    monkeypatch.setattr(SqlAlchemyCurrentEntitlementEvidenceRepository, "append", forbidden)


def test_verified_login_persists_canonical_active_user_idempotently_without_full_evidence(
    client,
    monkeypatch,
):
    import app.app as legacy_runtime
    from app.database import session_scope

    rpc = _install_verified_signature(monkeypatch)
    balances = {
        FULL_COMPRESSED: (1, 1),
        FULL_COMPRESSED.lower(): (1, 1),
        LIMITED_COMPRESSED: (2, 1),
    }
    balance_check = Mock(side_effect=lambda pubkey: balances[pubkey])
    monkeypatch.setattr(legacy_runtime, "get_save_and_check_balances_for_pubkey", balance_check)
    _forbid_dormant_authority_paths(monkeypatch, legacy_runtime)

    full_response = _login(client, FULL_COMPRESSED, "canonical-login-full")
    limited_response = _login(client, LIMITED_COMPRESSED, "canonical-login-limited")

    assert full_response.status_code == 200
    assert full_response.get_json() == {
        "verified": True,
        "access_level": "full",
        "pubkey": FULL_COMPRESSED,
    }
    assert limited_response.status_code == 200
    assert limited_response.get_json() == {
        "verified": True,
        "access_level": "limited",
        "pubkey": LIMITED_COMPRESSED,
    }

    for compressed in (FULL_COMPRESSED, LIMITED_COMPRESSED):
        subject = _canonical(compressed)
        user = get_user_by_pubkey(subject)
        assert user is not None
        assert user["pubkey"] == subject
        assert user["is_active"] is True
        assert get_user_by_pubkey(compressed) is None
        assert get_user_by_pubkey(compressed.lower()) is None

        repository = NoEvidenceRepository()
        decision = resolve_runtime_current_entitlement(subject, repository=repository)
        assert repository.calls == [subject]
        assert decision.identity_class is IdentityClass.LIMITED
        assert decision.current_full_relation_satisfied is False
        assert decision.evidence_source == "active_persisted_user"

        assertion = client.get(f"/agent/authority/current/{subject}.json")
        assert assertion.status_code == 200
        assertion_body = assertion.get_json()
        assert assertion_body["subject"] == subject
        assert assertion_body["identity_class"] == "limited"
        assert assertion_body["current_full_relation_satisfied"] is False
        assert assertion_body["evidence_source"] == "active_persisted_user"

    full_subject = _canonical(FULL_COMPRESSED)
    original_user_id = get_user_by_pubkey(full_subject)["id"]
    repeated_response = _login(client, FULL_COMPRESSED.lower(), "canonical-login-repeat")
    assert repeated_response.status_code == 200
    assert repeated_response.get_json()["access_level"] == "full"
    assert get_user_by_pubkey(full_subject)["id"] == original_user_id

    with session_scope() as database_session:
        assert database_session.query(User).filter(User.pubkey == full_subject).count() == 1
        assert database_session.query(User).filter(User.pubkey == _canonical(LIMITED_COMPRESSED)).count() == 1
        assert (
            database_session.query(CurrentEntitlementEvidence)
            .filter(CurrentEntitlementEvidence.subject_pubkey.in_([full_subject, _canonical(LIMITED_COMPRESSED)]))
            .count()
            == 0
        )

    with client.session_transaction() as browser_session:
        assert browser_session["logged_in_pubkey"] == FULL_COMPRESSED.lower()
        assert browser_session["access_level"] == "full"
        assert browser_session["login_method"] == "legacy"
        assert "user_id" not in browser_session
        assert "plan" not in browser_session
        assert "operator" not in browser_session

    assert rpc.verifymessage.call_count == 3
    assert balance_check.call_count == 3


def test_failed_signature_does_not_persist_or_check_balance(client, monkeypatch):
    import app.app as legacy_runtime

    subject = _canonical(FAILED_COMPRESSED)
    rpc = Mock()
    rpc.verifymessage.return_value = False
    create_user = Mock(wraps=auth_module.create_user)
    balance_check = Mock(side_effect=AssertionError("balance check must follow verified signatures only"))
    monkeypatch.setattr(auth_module, "get_rpc_connection", lambda: rpc)
    monkeypatch.setattr(auth_module, "derive_legacy_address_from_pubkey", lambda _pubkey: "1FailedSignature")
    monkeypatch.setattr(auth_module, "create_user", create_user)
    monkeypatch.setattr(legacy_runtime, "get_save_and_check_balances_for_pubkey", balance_check)

    response = _login(client, FAILED_COMPRESSED, "canonical-login-invalid-signature")

    assert response.status_code == 403
    assert response.get_json() == {"verified": False, "error": "Invalid signature"}
    assert create_user.call_count == 0
    assert balance_check.call_count == 0
    assert get_user_by_pubkey(subject) is None
    with client.session_transaction() as browser_session:
        assert "logged_in_pubkey" not in browser_session
        assert "access_level" not in browser_session
        assert "login_method" not in browser_session


def test_persistence_failure_fails_closed_without_leaking_details(client, monkeypatch):
    import app.app as legacy_runtime

    subject = _canonical(PERSISTENCE_FAILURE_COMPRESSED)
    _install_verified_signature(monkeypatch)
    internal_detail = "postgresql://private-user:private-password@internal-host/canonical"
    monkeypatch.setattr(auth_module, "create_user", Mock(side_effect=RuntimeError(internal_detail)))
    monkeypatch.setattr(
        auth_module,
        "get_user_by_pubkey",
        Mock(side_effect=AssertionError("lookup must not follow failed persistence")),
    )
    balance_check = Mock(side_effect=AssertionError("balance check must not follow failed persistence"))
    monkeypatch.setattr(legacy_runtime, "get_save_and_check_balances_for_pubkey", balance_check)

    response = _login(client, PERSISTENCE_FAILURE_COMPRESSED, "canonical-login-persistence-failure")

    assert response.status_code == 503
    assert response.get_json() == {
        "verified": False,
        "error": "Authentication service temporarily unavailable",
    }
    assert internal_detail not in response.get_data(as_text=True)
    assert balance_check.call_count == 0
    assert get_user_by_pubkey(subject) is None
    with client.session_transaction() as browser_session:
        assert "logged_in_pubkey" not in browser_session
        assert "access_level" not in browser_session
        assert "login_method" not in browser_session


def test_operator_subject_gets_the_same_limited_canonical_baseline(client, monkeypatch):
    import app.app as legacy_runtime
    from app.database import session_scope

    subject = _canonical(OPERATOR_COMPRESSED)
    _install_verified_signature(monkeypatch)
    monkeypatch.setattr(auth_module, "get_special_users", lambda: pytest.fail("explicit login used special fallback"))
    monkeypatch.setattr(legacy_runtime, "get_save_and_check_balances_for_pubkey", lambda _pubkey: (1, 1))

    response = _login(client, OPERATOR_COMPRESSED, "canonical-operator-login")

    assert response.status_code == 200
    assert response.get_json()["access_level"] == "full"
    user = get_user_by_pubkey(subject)
    assert user is not None
    assert user["is_active"] is True
    assert user["metadata"] == {}

    repository = NoEvidenceRepository()
    decision = resolve_runtime_current_entitlement(subject, repository=repository)
    assert decision.identity_class is IdentityClass.LIMITED
    assert decision.current_full_relation_satisfied is False

    assertion = client.get(f"/agent/authority/current/{subject}.json")
    assert assertion.status_code == 200
    assert assertion.get_json()["identity_class"] == "limited"
    assert "operator" not in assertion.get_json()

    with session_scope() as database_session:
        assert (
            database_session.query(CurrentEntitlementEvidence)
            .filter(CurrentEntitlementEvidence.subject_pubkey == subject)
            .count()
            == 0
        )


def test_login_persistence_helper_has_no_authorization_policy_dependencies():
    source = inspect.getsource(auth_module._persist_canonical_login_identity).lower()
    assert "canonical_xonly_pubkey" in source
    assert "create_user" in source
    assert "get_user_by_pubkey" in source
    for forbidden in (
        "access_level",
        "balance",
        "full",
        "crt",
        "sponsor",
        "admission",
        "materializ",
        "operator",
        "e923",
        "on_successful_login",
    ):
        assert forbidden not in source
