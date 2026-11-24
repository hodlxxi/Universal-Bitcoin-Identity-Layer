import inspect
import re
from datetime import datetime, timedelta, timezone
from uuid import uuid4
from unittest.mock import Mock

import pytest

from app.auth_api_core import canonical_xonly_pubkey
from app.blueprints import auth as auth_module
from app.db_storage import get_user_by_pubkey
from app.models import CurrentEntitlementEvidence, User
from app.services.action_authorization import IdentityClass
from app.services.current_entitlement import resolve_runtime_current_entitlement
from app.services.current_entitlement_evidence import CONTRACT_VERSION, CurrentEntitlementEvidenceRecord
from app.services.current_entitlement_evidence_storage import SqlAlchemyCurrentEntitlementEvidenceRepository

PARITY_COMPRESSED = "02311091DD9860E8E20EE13473C1155F5F69635E394704EAA74009452246CFA9B3"
NONPARITY_COMPRESSED = "023049F7FFC71D744BD9BED6F42DC6A28974E3A1B9D30671F800E5D46389103C7E"
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
        PARITY_COMPRESSED: (1, 1),
        PARITY_COMPRESSED.lower(): (1, 1),
        NONPARITY_COMPRESSED: (2, 1),
    }
    balance_check = Mock(side_effect=lambda pubkey: balances[pubkey])
    monkeypatch.setattr(legacy_runtime, "get_save_and_check_balances_for_pubkey", balance_check)
    _forbid_dormant_authority_paths(monkeypatch, legacy_runtime)

    parity_response = _login(client, PARITY_COMPRESSED, "canonical-login-full")
    nonparity_response = _login(client, NONPARITY_COMPRESSED, "canonical-login-limited")

    assert parity_response.status_code == 200
    assert parity_response.get_json() == {
        "verified": True,
        "access_level": "limited",
        "pubkey": PARITY_COMPRESSED,
    }
    assert nonparity_response.status_code == 200
    assert nonparity_response.get_json() == {
        "verified": True,
        "access_level": "limited",
        "pubkey": NONPARITY_COMPRESSED,
    }

    for compressed in (PARITY_COMPRESSED, NONPARITY_COMPRESSED):
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

    parity_subject = _canonical(PARITY_COMPRESSED)
    original_user_id = get_user_by_pubkey(parity_subject)["id"]
    repeated_response = _login(client, PARITY_COMPRESSED.lower(), "canonical-login-repeat")
    assert repeated_response.status_code == 200
    assert repeated_response.get_json()["access_level"] == "limited"
    assert get_user_by_pubkey(parity_subject)["id"] == original_user_id

    with session_scope() as database_session:
        assert database_session.query(User).filter(User.pubkey == parity_subject).count() == 1
        assert database_session.query(User).filter(User.pubkey == _canonical(NONPARITY_COMPRESSED)).count() == 1
        assert (
            database_session.query(CurrentEntitlementEvidence)
            .filter(CurrentEntitlementEvidence.subject_pubkey.in_([parity_subject, _canonical(NONPARITY_COMPRESSED)]))
            .count()
            == 0
        )

    with client.session_transaction() as browser_session:
        assert browser_session["logged_in_pubkey"] == PARITY_COMPRESSED.lower()
        assert browser_session["access_level"] == "limited"
        assert browser_session["login_method"] == "legacy"
        assert "user_id" not in browser_session
        assert "plan" not in browser_session
        assert "operator" not in browser_session

    assert rpc.verifymessage.call_count == 3
    assert balance_check.call_count == 0


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
    assert response.get_json()["access_level"] == "limited"
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


@pytest.mark.parametrize("state", ["current", "expired", "revoked", "future", "superseded"])
def test_legacy_login_and_public_authority_agree_on_published_evidence(client, monkeypatch, state):
    from app.database import get_session
    from app.db_storage import create_user

    rpc = _install_verified_signature(monkeypatch)
    subject = _canonical(NONPARITY_COMPRESSED)
    create_user(subject)
    repository = SqlAlchemyCurrentEntitlementEvidenceRepository(get_session)
    now = datetime.now(timezone.utc)
    observed = now + timedelta(seconds=20) if state == "future" else now - timedelta(seconds=30)
    valid_until = now - timedelta(seconds=1) if state == "expired" else now + timedelta(seconds=60)

    def publish(identity, timestamp, expiration, *, revoked=None):
        repository.append(
            CurrentEntitlementEvidenceRecord(
                evidence_id=str(uuid4()),
                contract_version=CONTRACT_VERSION,
                subject_pubkey=subject,
                identity_class=identity,
                current_full_relation_satisfied=identity is IdentityClass.FULL,
                evidence_source="canonical_test_publication",
                evidence_version="v1",
                source_evidence_sha256="a" * 64,
                observed_at=timestamp,
                valid_until=expiration,
                revoked_at=revoked,
                created_at=max(now, timestamp),
            )
        )

    publish(IdentityClass.FULL, observed, valid_until, revoked=now if state == "revoked" else None)
    if state == "superseded":
        publish(IdentityClass.LIMITED, now, valid_until)

    expected = "full" if state == "current" else "limited"
    response = _login(client, NONPARITY_COMPRESSED, "published-evidence-" + state)
    assert response.status_code == 200
    assert response.get_json()["access_level"] == expected
    assertion = client.get(f"/agent/authority/current/{subject}.json").get_json()
    assert assertion["identity_class"] == expected
    assert assertion["current_full_relation_satisfied"] is (state == "current")
    with client.session_transaction() as browser_session:
        assert browser_session["access_level"] == expected
        assert "challenge" not in browser_session
        assert "challenge_timestamp" not in browser_session
    replay = client.post(
        "/verify_signature",
        json={
            "pubkey": NONPARITY_COMPRESSED,
            "signature": "verified-signature",
            "challenge": "published-evidence-" + state,
        },
    )
    assert replay.status_code == 400
    rpc.verifymessage.assert_called_once()


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


def test_logout_confirmation_preserves_the_canonical_session_until_valid_post(app, client, monkeypatch):
    from app.services.oauth_browser_authentication import BROWSER_GENERATION_KEY
    from app.services.oauth_session_lifecycle import EXTENSION, SqlAlchemyOAuthSessionLifecycle

    issuer = "https://identity.example"
    service = SqlAlchemyOAuthSessionLifecycle(
        lambda: pytest.fail("logout must not open a real database session"),
        client_id="social",
        token_config={"JWT_ISSUER": issuer, "JWKS_DIR": "synthetic"},
    )
    reference = "a" * 64
    invalidate = Mock()
    monkeypatch.setattr(service, "invalidate_browser", invalidate)
    app.extensions[EXTENSION] = service
    with client.session_transaction(base_url=issuer) as cookie:
        cookie[BROWSER_GENERATION_KEY] = reference
        cookie["logged_in_pubkey"] = PARITY_COMPRESSED
        cookie["access_level"] = "full"

    confirmation = client.get("/logout", base_url=issuer)
    assert confirmation.status_code == 200
    assert confirmation.headers["Cache-Control"] == "no-store"
    assert confirmation.headers.getlist("Referrer-Policy") == ["same-origin"]
    assert "form-action 'self'" in confirmation.headers["Content-Security-Policy"]
    assert "Set-Cookie" not in confirmation.headers
    token = re.search(rb'name="csrf_token" value="([0-9a-f]{64})"', confirmation.data)[1].decode()
    assert client.post("/logout", base_url=issuer, data={"csrf_token": token}).status_code == 403
    invalidate.assert_not_called()
    with client.session_transaction(base_url=issuer) as cookie:
        assert cookie[BROWSER_GENERATION_KEY] == reference
        assert cookie["access_level"] == "full"

    assert (
        client.post("/logout", base_url=issuer, headers={"Origin": issuer}, data={"csrf_token": token}).status_code
        == 302
    )
    invalidate.assert_called_once_with(reference)
    with client.session_transaction(base_url=issuer) as cookie:
        assert BROWSER_GENERATION_KEY not in cookie
        assert "logged_in_pubkey" not in cookie
