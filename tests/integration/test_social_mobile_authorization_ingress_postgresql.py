"""Real committed migrations, canonical OAuth, signatures and HTTP consumers."""

import base64
import json
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
from coincurve import PrivateKey
from sqlalchemy import event, func, select

from app.models import CurrentEntitlementEvidence, OAuthSessionGeneration, OAuthToken, Session
from app.services import social_messaging_mobile_authorization as protocol
from app.services.action_authorization import IdentityClass
from app.services.current_entitlement_evidence import CONTRACT_VERSION
from app.services.oauth_browser_authentication import BROWSER_GENERATION_KEY
from app.services.oauth_session_lifecycle import OAuthSessionUnavailable, SqlAlchemyOAuthSessionLifecycle
from app.services.social_messaging_mobile_authorization_storage import (
    MobileAcceptanceRow,
    MobileOperationRow,
    MobileSessionHandoffRow,
)
from app.services.social_mobile_authorization_ingress import install_mobile_ingress
from app.services.social_mobile_authorization_ingress_schema import (
    COMMANDS,
    GROUPS,
    PREFIX,
    SCOPES,
    TOKEN_PATH,
    VIEWER_HEADER,
)
from tests.integration.test_oauth_session_lifecycle_postgresql import (
    CHALLENGE,
    CLIENT,
    REDIRECT,
    VERIFIER,
    exchange,
    fresh_browser,
)
from tests.integration.test_oauth_session_lifecycle_postgresql import generation_factory as generation_factory
from tests.integration.test_oauth_session_lifecycle_postgresql import nostr_login, oauth_app
from tests.integration.test_oauth_session_lifecycle_postgresql import state as state
from tests.integration.test_social_messaging_device_binding_authorization_storage_postgresql import (
    postgres_factory as postgres_factory,
)
from tests.integration.test_social_messaging_mobile_authorization_storage_postgresql import (
    mobile_factory as mobile_factory,
)
from tests.unit.test_social_mobile_authorization_ingress import BACKEND, client_assertion
from tests.unit.test_social_mobile_authorization_ingress import material as material
from tests.unit.test_social_mobile_authorization_ingress import runtime_for

ROOT = Path(__file__).parents[2]


class ConfidentialInputs(dict):
    """Keep transient synthetic credentials/proofs out of assertion reprs."""

    def __repr__(self):
        return "<synthetic confidential inputs>"


@pytest.fixture(scope="module")
def replay_ready(generation_factory):
    with generation_factory[0].begin() as db:
        db.exec_driver_sql(
            (ROOT / "migrations/2026-08-31_confidential_service_assertion_replay_markers_v1.sql").read_text()
        )


@pytest.fixture
def live(state, replay_ready, material, monkeypatch):
    from app.blueprints.api_auth import api_auth_bp

    with state[0].begin() as db:
        db.exec_driver_sql(
            "TRUNCATE social_messaging_mobile_operations, social_messaging_device_authorization_requests, "
            "social_messaging_device_authorization_binding_owners, social_messaging_device_bindings, "
            "social_messaging_device_binding_authorization_replay, social_messaging_device_binding_authorization_evidence, "
            "current_entitlement_evidence CASCADE"
        )

    app = oauth_app(state, monkeypatch)
    app.register_blueprint(api_auth_bp)
    runtime = runtime_for(material, state[1], state[2], clock=lambda: int(state[3][0].timestamp()) + 1)
    install_mobile_ingress(app, runtime, enabled=True)
    client = app.test_client()
    verified, subject, _proof, _record = nostr_login(client, state, monkeypatch, key_number=3)
    assert verified.status_code == 200
    with client.session_transaction() as cookie:
        reference = cookie[BROWSER_GENERATION_KEY]
    state[2].test_browser_references[subject] = reference
    authorized = client.get(
        "/oauth/authorize",
        query_string=dict(
            response_type="code",
            client_id=CLIENT,
            redirect_uri=REDIRECT,
            scope="openid profile",
            code_challenge=CHALLENGE,
            code_challenge_method="S256",
        ),
    )
    assert authorized.status_code == 302
    code = parse_qs(urlparse(authorized.location).query)["code"][0]
    issued = client.post(
        "/oauth/token",
        data=dict(
            grant_type="authorization_code",
            client_id=CLIENT,
            client_secret="synthetic-secret",
            code=code,
            redirect_uri=REDIRECT,
            code_verifier=VERIFIER,
        ),
    )
    assert issued.status_code == 200
    bearer = issued.get_json()["access_token"]
    now = runtime.mobile._now()
    with state[1].begin() as db:
        db.add(
            CurrentEntitlementEvidence(
                evidence_id=str(uuid.uuid4()),
                contract_version=CONTRACT_VERSION,
                subject_pubkey=subject,
                identity_class=IdentityClass.FULL.value,
                current_full_relation_satisfied=True,
                evidence_source="synthetic-ingress",
                evidence_version="v1",
                source_evidence_sha256="ab" * 32,
                observed_at=datetime.fromtimestamp(now - 60, timezone.utc),
                valid_until=datetime.fromtimestamp(now + 600, timezone.utc),
                revoked_at=None,
                created_at=datetime.fromtimestamp(now, timezone.utc),
            )
        )
    tokens = {}
    for group in GROUPS:
        response = client.post(
            TOKEN_PATH,
            data=dict(
                grant_type="client_credentials",
                client_id=BACKEND,
                client_assertion_type="urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                client_assertion=client_assertion(material),
                scope=SCOPES[group],
            ),
        )
        assert response.status_code == 200
        tokens[group] = response.get_json()["access_token"]
    return ConfidentialInputs(
        app=app,
        client=client,
        runtime=runtime,
        bearer=bearer,
        subject=subject,
        tokens=tokens,
        state=state,
        material=material,
    )


def post(live, command, body, *, bearer=None, client=None):
    group = COMMANDS[command][0]
    headers = {"Authorization": "Bearer " + live["tokens"][group]}
    if group in {"desktop", "invalidate"}:
        headers[VIEWER_HEADER] = "Bearer " + (bearer or live["bearer"])
    return (client or live["client"]).post(PREFIX + "/" + command, json=body, headers=headers)


def stamp(second):
    return datetime.fromtimestamp(second, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def content(live, *, request_id=None):
    value = json.loads(
        json.loads((ROOT / "tests/fixtures/social_mobile_device_authorization_v1.json").read_text())["entries"][0][
            "content"
        ]
    )
    claim = value["authorization"]
    now = live["runtime"].mobile._now()
    claim.update(
        subject=live["subject"],
        requestId=request_id or uuid.uuid4().hex * 2,
        issuedAt=stamp(now),
        expiresAt=stamp(now + 240),
        bindingValidFrom=stamp(now),
        bindingExpiresAt=stamp(now + 3600),
    )
    return protocol.canonical(value)


def proposal(live, semantic=None):
    created = post(live, "qr/create", {})
    assert created.status_code == 200
    offer, qr = created.get_json()["offer"], created.get_json()["qr"]
    verifier = "d" * 64
    context = {k: offer[k] for k in ("pairingId", "secretCommitment", "desktopContext", "createdAt", "expiresAt")}
    context["exchangeCommitment"] = protocol.phone_exchange_commitment(verifier)
    source = protocol.create_authorization(
        semantic or content(live),
        protocol.canonical(context),
        protocol.QR,
        subject=live["subject"],
        now=live["runtime"].mobile._now(),
    )
    digest = protocol.digest(source)
    possession = protocol.pairing_possession_proof(protocol.parse_pairing_qr(qr)[1], digest)
    return ConfidentialInputs(
        offer=offer,
        qr=qr,
        verifier=verifier,
        source=source,
        possessionProof=possession,
        pairingId=offer["pairingId"],
        revision=offer["revision"],
        authorizationDigest=digest,
    )


def selectors(proposal):
    return {k: proposal[k] for k in ("pairingId", "revision", "authorizationDigest")}


def prepare(live, semantic=None):
    data = proposal(live, semantic)
    offered = post(live, "qr/offer", {"qr": data["qr"]})
    assert offered.status_code == 200 and offered.get_json() == data["offer"]
    scanned = post(live, "qr/scan", {k: data[k] for k in ("source", "qr", "possessionProof")})
    assert scanned.status_code == 200
    assert scanned.get_json()["status"] == "awaiting-approval"
    snapshot = post(live, "qr/snapshot", {k: data[k] for k in ("pairingId", "revision")})
    assert snapshot.get_json()["source"] == data["source"]
    claimed = post(
        live, "qr/claim", dict(selectors(data), humanCode=protocol.comparison_code(data["authorizationDigest"]))
    )
    assert claimed.get_json() == {"status": "approval-claimed"}
    unsigned = protocol.unsigned_event(
        data["source"], subject=live["subject"], expected_method=protocol.QR, now=live["runtime"].mobile._now()
    )
    signature = PrivateKey((3).to_bytes(32, "big")).sign_schnorr(bytes.fromhex(unsigned["eventId"]), b"\0" * 32).hex()
    data["proof"] = protocol.canonical(
        dict(unsigned["unsignedEvent"], pubkey=live["subject"], id=unsigned["eventId"], sig=signature)
    )
    return data


def accept(live, data, **options):
    return post(live, "qr/accept", dict(selectors(data), proof=data["proof"]), **options)


def consume(live, data, **options):
    return post(live, "phone/exchange", dict(selectors(data), verifier=data["verifier"]), **options)


def test_real_login_oauth_ingress_acceptance_and_historical_handoff(live):
    data = prepare(live)
    assert consume(live, data).status_code == 503  # Claim and QR possession confer no authorization.
    accepted = accept(live, data)
    assert accepted.status_code == 200
    first = consume(live, data)
    assert first.status_code == 200
    delivery = first.get_json()
    assert delivery["delivery"] == "created" and delivery["freshIssuanceAuthorized"] is False
    assert set(delivery["identity"]) == {
        "schema",
        "version",
        "pairingId",
        "authorizationDigest",
        "bindingId",
        "deviceId",
        "subject",
        "requestId",
        "exchangeCommitment",
        "expiresAt",
    }
    assert delivery["identity"]["bindingId"] == accepted.get_json()["bindingId"]
    live["state"][3][0] += timedelta(seconds=301)
    assert accept(live, data).get_json() == accepted.get_json()  # Exact historical proof, no second signature.
    historical = consume(live, data)
    assert historical.status_code == 200
    assert historical.get_json() == dict(delivery, delivery="recovered")
    with live["state"][1]() as db:
        assert db.scalar(select(func.count()).select_from(MobileAcceptanceRow)) == 1
        assert db.scalar(select(func.count()).select_from(MobileSessionHandoffRow)) == 1


@pytest.mark.parametrize("event_name", ["logout", "replacement"])
@pytest.mark.parametrize("boundary", ["resolver", "original-context"])
def test_logout_between_resolve_and_accept_denies_with_distinct_connections(live, monkeypatch, event_name, boundary):
    data = prepare(live)
    ready, resume = threading.Event(), threading.Event()
    target = live["runtime"].lifecycle if boundary == "resolver" else live["runtime"].mobile
    method = "resolve" if boundary == "resolver" else "original_context"
    resolve = getattr(target, method)

    def paused(*args, **kwargs):
        authority = resolve(*args, **kwargs)
        ready.set()
        assert resume.wait(10)
        return authority

    monkeypatch.setattr(target, method, paused)
    with ThreadPoolExecutor(max_workers=1) as pool:
        result = pool.submit(accept, live, data, client=live["app"].test_client())
        try:
            assert ready.wait(10)
            if event_name == "logout":
                live["state"][2].invalidate_browser(live["state"][2].test_browser_references[live["subject"]])
            else:
                fresh_browser(live["state"][2], live["subject"])
        finally:
            resume.set()
        assert result.result(timeout=15).status_code == 503
    with live["state"][1]() as db:
        assert db.scalar(select(func.count()).select_from(MobileAcceptanceRow)) == 0


def test_concurrent_accept_and_consume_are_one_shot(live):
    data = prepare(live)
    for action in (accept, consume):
        barrier = threading.Barrier(2, timeout=10)

        def concurrent():
            barrier.wait()
            return action(live, data, client=live["app"].test_client())

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = [f.result(timeout=20) for f in [pool.submit(concurrent), pool.submit(concurrent)]]
        assert [r.status_code for r in results] == [200, 200]
    with live["state"][1]() as db:
        assert db.scalar(select(func.count()).select_from(MobileAcceptanceRow)) == 1
        assert db.scalar(select(func.count()).select_from(MobileSessionHandoffRow)) == 1


def test_invalidation_retry_after_replacement_and_restart_cannot_revoke_new(live):
    assert post(live, "oauth/invalidate", {}).status_code == 200
    with pytest.raises(OAuthSessionUnavailable):
        live["runtime"].lifecycle.resolve(live["bearer"])
    new = exchange(
        live["state"][2],
        live["state"][2].authorize(
            subject=live["subject"],
            browser_generation=live["state"][2].test_browser_references[live["subject"]],
            redirect_uri=REDIRECT,
            scope="openid profile",
            code_challenge=CHALLENGE,
        ),
    )["access_token"]
    old = live["state"][2]
    replacement = SqlAlchemyOAuthSessionLifecycle(
        live["state"][1], client_id=CLIENT, token_config=live["state"][5], clock=old._clock
    )
    replacement.invalidate_original(live["bearer"])
    assert post(live, "oauth/invalidate", {}).status_code == 200
    assert replacement.resolve(new).subject == live["subject"]
    assert post(live, "qr/create", {}).status_code == 503


def test_assertion_replay_is_durable_across_recreated_runtimes(live):
    assertion = client_assertion(live["material"])
    live["runtime"].issue(assertion, SCOPES["desktop"])
    new = runtime_for(live["material"], live["state"][1], live["state"][2])
    from app.services.confidential_service_credentials import CredentialUnavailable

    with pytest.raises(CredentialUnavailable):
        new.issue(assertion, SCOPES["phone"])


@pytest.mark.parametrize("field", ["revision", "authorizationDigest", "proof"])
def test_changed_expected_identity_or_proof_denies(live, field):
    data = prepare(live)
    data[field] = "0" * 64 if field != "proof" else "{}"
    assert accept(live, data).status_code == 503


@pytest.mark.parametrize("bad", ["wrong", "qr-secret", "missing"])
def test_phone_verifier_loss_or_substitution_denies(live, bad):
    data = prepare(live)
    assert accept(live, data).status_code == 200
    body = dict(selectors(data), verifier="0" * 64 if bad == "wrong" else protocol.parse_pairing_qr(data["qr"])[1])
    if bad == "missing":
        del body["verifier"]
    assert post(live, "phone/exchange", body).status_code in {400, 503}


def test_original_proposal_recovery_and_terminal_cancellation(live):
    data = proposal(live)
    body = {k: data[k] for k in ("source", "qr", "possessionProof", "verifier", "revision")}
    assert post(live, "phone/recover", body).get_json()["status"] == "never-accepted"
    assert post(live, "qr/close", dict(pairingId=data["pairingId"], status="abandoned")).get_json() == {
        "status": "abandoned"
    }
    assert post(live, "phone/recover", body).get_json()["status"] == "abandoned"
    assert post(live, "qr/scan", {k: data[k] for k in ("source", "qr", "possessionProof")}).status_code == 503


def test_bound_legacy_reservation_and_real_bitcoin_signature(live):
    reservation = post(live, "legacy/reserve", {"content": content(live)})
    assert reservation.status_code == 200
    data = reservation.get_json()
    key = PrivateKey((3).to_bytes(32, "big"))
    compact = key.sign_recoverable(bytes.fromhex(protocol.legacy_signing_digest(data["challenge"])), hasher=None)
    signature = base64.b64encode(bytes([31 + compact[64]]) + compact[:64]).decode()
    proof = protocol.canonical(
        dict(
            method=protocol.LEGACY,
            challenge=data["challenge"],
            loginContext=data["loginContext"],
            authorizationDigest=data["authorizationDigest"],
            compressedPublicKey=key.public_key.format(compressed=True).hex(),
            signature=signature,
        )
    )
    accepted = post(
        live,
        "legacy/accept",
        dict(operationId=data["challenge"], authorizationDigest=data["authorizationDigest"], proof=proof),
    )
    assert accepted.status_code == 200
    assert post(live, "legacy/status", dict(operationId=data["challenge"])).get_json()["status"] == "accepted"
    with live["state"][1]() as db:
        assert db.scalar(select(func.count()).select_from(MobileSessionHandoffRow)) == 0


@pytest.mark.parametrize("failure", ["commit", "guard"])
def test_missing_migration_or_commit_failure_never_reports_success(live, failure):
    engine = live["state"][0]

    def deny(_connection):
        raise RuntimeError("synthetic commit unavailable")

    if failure == "guard":
        with engine.begin() as db:
            db.exec_driver_sql("ALTER TABLE oauth_session_generations DISABLE TRIGGER trg_oauth_generation_guard")
    else:
        event.listen(engine, "commit", deny)
    try:
        assert post(live, "oauth/invalidate", {}).status_code == 503
    finally:
        if failure == "commit":
            event.remove(engine, "commit", deny)
        else:
            with engine.begin() as db:
                db.exec_driver_sql("ALTER TABLE oauth_session_generations ENABLE TRIGGER trg_oauth_generation_guard")
    assert live["state"][2].resolve(live["bearer"]).subject == live["subject"]


@pytest.mark.parametrize("method", ["legacy", "qr"])
def test_fixed_consumer_bytes_against_real_durable_service(generation_factory, method):
    from app.services.social_mobile_authorization_ingress import public_snapshot
    from tests.integration import test_social_messaging_mobile_authorization_storage_postgresql as fixed

    # Reuse the unchanged synthetic data fixture against this identity-checked
    # cluster. Its source is a plain fixture body and supplies no mock authority.
    fixed.seed.__wrapped__(generation_factory)
    expected = json.loads((ROOT / "tests/fixtures/social_mobile_authorization_ingress_v1.json").read_text())
    if method == "legacy":
        reserved = protocol.parse_json(fixed.reserve(generation_factory))
        result = dict(
            schema="hodlxxi.social_mobile_legacy_reservation.v1", version=1, loginContext=fixed.LOGIN, **reserved
        )
        assert protocol.canonical(result) == expected["legacyReservation"]
        return
    offer, qr = fixed.offer(generation_factory)
    assert protocol.canonical(public_snapshot(offer)) == expected["offer"]
    fixed.scan(generation_factory, qr)
    fixed.claim(generation_factory)
    assert fixed.accept(generation_factory, protocol.QR) == expected["acceptance"]
    options = dict(
        verifier=fixed.VECTORS["exchangeVerifier"],
        revision=fixed.REVISION,
        authorization_digest=fixed.FIRST[protocol.QR]["digest"],
    )
    delivered = fixed.service(generation_factory).exchange_delivery(fixed.PAIRING, **options)
    assert delivered == expected["handoffCreated"]
    assert protocol.canonical(protocol.parse_json(delivered)["identity"]) == expected["frozenExchangeIdentity"]
    recovered = fixed.service(generation_factory, fixed.NOW + 301).exchange_delivery(fixed.PAIRING, **options)
    assert recovered == expected["handoffRecovered"]


@pytest.mark.parametrize(
    "state_change", ["revoked", "session-inactive", "expired", "wrong-owner", "unmapped", "service-as-viewer"]
)
def test_viewer_is_independent_and_current(live, monkeypatch, state_change):
    from app.jwks import get_key_by_kid
    from tests.integration.test_oauth_session_lifecycle_postgresql import OTHER, authorize

    data = proposal(live)
    token = live["bearer"]
    if state_change == "revoked":
        live["state"][2].invalidate_original(token)
    elif state_change == "session-inactive":
        authority = live["state"][2].resolve(token)
        with live["state"][1].begin() as db:
            db.get(Session, authority.session_id).is_active = False
    elif state_change == "expired":
        live["state"][3][0] += timedelta(seconds=601)
    elif state_change == "wrong-owner":
        token = exchange(live["state"][2], authorize(live["state"][2], OTHER))["access_token"]
    elif state_change == "unmapped":
        header = jwt.get_unverified_header(token)
        claims = jwt.decode(token, options={"verify_signature": False})
        claims["jti"] = uuid.uuid4().hex
        key = get_key_by_kid(live["state"][5]["JWKS_DIR"], header["kid"])
        token = jwt.encode(claims, key, algorithm="RS256", headers={"kid": header["kid"]})
    else:
        token = live["tokens"]["desktop"]
    response = post(live, "qr/status", {"pairingId": data["pairingId"]}, bearer=token)
    assert response.status_code == 503
    assert response.get_json() == {"error": "mobile_authorization_unavailable"}


def test_expired_original_credential_only_repeats_its_own_invalidation(live, monkeypatch):
    old_time = live["state"][3][0]
    future = old_time + timedelta(seconds=601)

    class FutureDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return future if tz is not None else future.replace(tzinfo=None)

    monkeypatch.setattr(jwt.api_jwt, "datetime", FutureDateTime)
    live["state"][3][0] = future
    with pytest.raises(OAuthSessionUnavailable):
        live["state"][2].resolve(live["bearer"])
    # Backend credential verification retains its independent real clock.
    assert post(live, "oauth/invalidate", {}).status_code == 200
    assert post(live, "oauth/invalidate", {}).status_code == 200
    with pytest.raises(OAuthSessionUnavailable):
        live["state"][2].resolve(live["bearer"])


def test_current_full_remains_an_independent_acceptance_requirement(live):
    data = prepare(live)
    with live["state"][0].begin() as db:
        db.exec_driver_sql("TRUNCATE current_entitlement_evidence")
    response = accept(live, data)
    assert response.status_code == 503
    with live["state"][1]() as db:
        assert db.scalar(select(func.count()).select_from(MobileAcceptanceRow)) == 0


def test_revoke_acceptance_has_no_phone_exchange(live):
    first = prepare(live)
    accepted = accept(live, first)
    assert accepted.status_code == 200
    claim = protocol.parse_json(content(live))
    claim["authorization"].update(operation="revoke", bindingVersion=2, priorBindingId=accepted.get_json()["bindingId"])
    revoke = prepare(live, protocol.canonical(claim))
    revoked = accept(live, revoke)
    assert revoked.status_code == 200
    assert consume(live, revoke).status_code == 503
    # An accepted old proof cannot create a fresh handoff after binding revoke.
    assert consume(live, first).status_code == 503


def test_phone_status_recovery_and_changed_scan_proof(live):
    data = proposal(live)
    bad = dict(source=data["source"], qr=data["qr"], possessionProof="0" * 64)
    response = post(live, "qr/scan", bad)
    assert response.status_code == 503
    good = {k: data[k] for k in ("source", "qr", "possessionProof")}
    assert post(live, "qr/scan", good).status_code == 200
    status_body = dict(selectors(data), verifier=data["verifier"])
    assert post(live, "phone/status", status_body).get_json()["status"] == "awaiting-approval"
    recovered = post(
        live, "phone/recover", {k: data[k] for k in ("source", "qr", "possessionProof", "verifier", "revision")}
    )
    assert recovered.get_json()["status"] == "awaiting-approval"
    assert post(live, "phone/status", dict(status_body, revision="0" * 64)).status_code == 503


@pytest.mark.parametrize("tamper", ["signature", "audience", "subject", "jti"])
def test_revocation_retry_requires_exact_signed_record(live, tamper):
    from app.jwks import get_key_by_kid

    token = live["bearer"]
    header = jwt.get_unverified_header(token)
    claims = jwt.decode(token, options={"verify_signature": False})
    if tamper == "signature":
        key = live["material"][1]
    else:
        key = get_key_by_kid(live["state"][5]["JWKS_DIR"], header["kid"])
        claims[{"audience": "aud", "subject": "sub", "jti": "jti"}[tamper]] = "0" * 64
    invalid = jwt.encode(claims, key, algorithm="RS256", headers={"kid": header["kid"]})
    response = post(live, "oauth/invalidate", {}, bearer=invalid)
    assert response.status_code == 503
    assert live["state"][2].resolve(token).subject == live["subject"]


def test_real_viewer_cannot_replace_backend_before_any_database_operation(live):
    statements = []

    def observed(*_args):
        statements.append(True)

    event.listen(live["state"][0], "before_cursor_execute", observed)
    try:
        response = live["client"].post(
            PREFIX + "/qr/create",
            json={},
            headers={
                "Authorization": "Bearer " + live["bearer"],
                VIEWER_HEADER: "Bearer " + live["bearer"],
            },
        )
    finally:
        event.remove(live["state"][0], "before_cursor_execute", observed)
    assert response.status_code == 401
    assert statements == []


@pytest.mark.parametrize("change", ["noncanonical", "context", "subject"])
def test_changed_source_with_matching_possession_proof_cannot_rebind_offer(live, change):
    data = proposal(live)
    source = data["source"]
    if change == "noncanonical":
        source += " "
    else:
        value = protocol.parse_json(source)
        if change == "context":
            value["context"]["desktopContext"] = "0" * 64
        else:
            semantic = protocol.parse_json(value["content"])
            semantic["authorization"]["subject"] = "a" * 64
            value["content"] = protocol.canonical(semantic)
        source = protocol.canonical(value)
    possession = protocol.pairing_possession_proof(protocol.parse_pairing_qr(data["qr"])[1], protocol.digest(source))
    response = post(live, "qr/scan", dict(source=source, qr=data["qr"], possessionProof=possession))
    assert response.status_code == 503
    assert post(live, "qr/scan", {k: data[k] for k in ("source", "qr", "possessionProof")}).status_code == 200


def test_other_viewer_client_cannot_be_used_as_mobile_deputy_or_revoked(live):
    other = SqlAlchemyOAuthSessionLifecycle(
        live["state"][1], client_id="other-client", token_config=live["state"][5], clock=live["state"][2]._clock
    )
    now = other._now()
    reference = other.complete_verified_login(
        subject=live["subject"],
        challenge="synthetic-verified-other-" + uuid.uuid4().hex,
        challenge_created=now - timedelta(seconds=1),
        challenge_expires=now + timedelta(seconds=300),
    )
    code = other.authorize(
        subject=live["subject"],
        browser_generation=reference,
        redirect_uri=REDIRECT,
        scope="openid profile",
        code_challenge=CHALLENGE,
    )
    token = exchange(other, code)["access_token"]
    assert post(live, "qr/create", {}, bearer=token).status_code == 503
    assert post(live, "oauth/invalidate", {}, bearer=token).status_code == 503
    assert other.resolve(token).subject == live["subject"]
