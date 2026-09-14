"""Real login, signed QR, durable HTTP issuance and canonical downstream bearer.

Uses only the existing identity-checked disposable PostgreSQL fixture. No live
defaults or permissive eligibility/authentication stubs are used.
"""

import hashlib
import json
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import event, func, inspect, select, text
from sqlalchemy.exc import DBAPIError

from app.models import CurrentEntitlementEvidence, OAuthClient, OAuthSessionGeneration, OAuthToken, Session, User
from app.services.oauth_bearer_validation import BearerValidationError, validate_canonical_access_token_with_config
from app.services.social_messaging_device_storage import SqlAlchemyTransactionBoundSocialMessagingDeviceStorage
from app.services.social_messaging_mobile_authorization_storage import SqlAlchemyMobileAuthorizationService
from app.services.social_session_issuance import (
    SessionIssuanceUnavailable,
    SocialSessionIssuance,
    SocialSessionIssuer,
    SqlAlchemySocialSessionIssuance,
)
from app.services.social_session_issuance_ingress import SocialSessionIssuanceIngress, install_session_issuance
from app.services.social_session_issuance_schema import PREFIX, PURPOSE, SCOPE, TOKEN_PATH
from tests.helpers.social_session_issuance_consumer import SocialConsumer
from tests.integration import test_social_mobile_authorization_ingress_postgresql as ingress
from tests.integration.test_oauth_session_lifecycle_postgresql import CLIENT, exchange, fresh_browser
from tests.integration.test_oauth_session_lifecycle_postgresql import generation_factory as generation_factory
from tests.integration.test_oauth_session_lifecycle_postgresql import state as state
from tests.integration.test_social_messaging_device_binding_authorization_storage_postgresql import (
    postgres_factory as postgres_factory,
)
from tests.integration.test_social_messaging_mobile_authorization_storage_postgresql import (
    mobile_factory as mobile_factory,
)
from tests.integration.test_social_mobile_authorization_ingress_postgresql import live as ingress_live
from tests.integration.test_social_mobile_authorization_ingress_postgresql import material as material
from tests.integration.test_social_mobile_authorization_ingress_postgresql import replay_ready as replay_ready
from tests.unit.test_social_mobile_authorization_ingress import BACKEND, ISSUER, client_assertion, configurations

MIGRATION = Path(__file__).parents[2] / "migrations/2026-09-13_social_session_issuance_v1.sql"


@pytest.fixture(scope="module")
def issuance_ready(generation_factory, replay_ready):
    engine, factory = generation_factory
    with engine.connect() as db:
        tx = db.begin()
        db.exec_driver_sql(MIGRATION.read_text())
        assert inspect(db).has_table("social_session_issuances")
        tx.rollback()
        assert not inspect(db).has_table("social_session_issuances")
        assert not inspect(db).has_table("social_session_pairing_parents")
        assert not inspect(db).has_table("social_session_issuers")
        db.rollback()
    with engine.begin() as db:
        db.exec_driver_sql(MIGRATION.read_text())
    return engine, factory


@pytest.fixture
def live(issuance_ready, monkeypatch, request):
    original_runtime = ingress.runtime_for
    original_install = ingress.install_mobile_ingress

    def runtime_for(*args, **kwargs):
        runtime = original_runtime(*args, **kwargs)
        return replace(
            runtime,
            mobile=SqlAlchemyMobileAuthorizationService(
                runtime.mobile._factory, clock=runtime.mobile._clock, issuance_client_id=CLIENT
            ),
        )

    def install(app, runtime, *, enabled):
        original_install(app, runtime, enabled=enabled)
        service = SqlAlchemySocialSessionIssuance(
            mobile=runtime.mobile,
            lifecycle=runtime.lifecycle,
            backend_id=BACKEND,
            service_principal="service:social-mobile",
        )
        config = replace(
            runtime.service_configs[0],
            token_endpoint_audience=ISSUER + TOKEN_PATH,
            service_resource_audience=ISSUER + PREFIX,
            service_scope=SCOPE,
            service_purpose=PURPOSE,
        )
        issuer = SocialSessionIssuanceIngress(
            config, runtime.service_signing_key, runtime.service_signing_kid, service, runtime.replay
        )
        install_session_issuance(app, issuer, enabled=True)
        app.issuance_runtime = issuer

    monkeypatch.setattr(ingress, "runtime_for", runtime_for)
    monkeypatch.setattr(ingress, "install_mobile_ingress", install)
    result = request.getfixturevalue("ingress_live")
    with result["state"][1].begin() as db:
        db.add(
            SocialSessionIssuer(
                client_id=CLIENT, backend_id=BACKEND, service_principal="service:social-mobile", is_active=True
            )
        )
    response = result["client"].post(
        TOKEN_PATH,
        data=dict(
            grant_type="client_credentials",
            client_id=BACKEND,
            client_assertion_type="urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            client_assertion=client_assertion(result["material"], aud=ISSUER + TOKEN_PATH),
            scope=SCOPE,
        ),
    )
    assert response.status_code == 200
    result["issuance_token"] = response.get_json()["access_token"]
    result["issuer"] = result["app"].issuance_runtime.service
    return result


def post(live, command, body, *, viewer=None, service=None):
    headers = {"Authorization": "Bearer " + (service or live["issuance_token"])}
    if viewer is not None:
        headers[ingress.VIEWER_HEADER] = "Bearer " + viewer
    return live["app"].test_client().post(PREFIX + "/" + command, json=body, headers=headers)


def prepared(live):
    proposal = ingress.prepare(live)
    assert ingress.accept(live, proposal).status_code == 200
    assert ingress.consume(live, proposal).get_json()["freshIssuanceAuthorized"] is False
    return proposal, dict(ingress.selectors(proposal), verifier=proposal["verifier"], deliveryKey="c" * 64)


def issue(live):
    proposal, data = prepared(live)
    response = post(live, "issue", data)
    assert response.status_code == 200
    value = ingress.ConfidentialInputs(response.get_json())
    assert value["currentActive"] is True
    return data, value


def resolve(live, value):
    return post(live, "resolve", {"issuanceId": value["receipt"]["issuanceId"]}, viewer=value["viewerAccessToken"])


def count(live):
    with live["state"][1]() as db:
        return db.scalar(select(func.count()).select_from(SocialSessionIssuance))


def canonical(live, value):
    # The real next consumer's persisted-record loader (patched factory only).
    return validate_canonical_access_token_with_config(
        value["viewerAccessToken"], config=live["state"][2]._validation, expected_client_id=CLIENT
    )


def test_complete_flow_and_byte_exact_recovery(live):
    data, value = issue(live)
    assert post(live, "recover", data).get_json() == value
    assert post(live, "issue", data).get_json() == value
    assert resolve(live, value).get_json()["subject"] == live["subject"]
    assert canonical(live, value).subject == live["subject"]
    # The ordinary approving desktop stays valid and mapped, the phone is not
    # inserted into oauth_session_generations or accepted as a desktop Session.
    assert live["state"][2].resolve(live["bearer"]).subject == live["subject"]
    with pytest.raises(Exception):
        live["state"][2].resolve(value["viewerAccessToken"])
    with live["state"][1]() as db:
        assert db.scalar(select(func.count()).select_from(OAuthSessionGeneration)) == 1
        assert db.scalar(select(func.count()).select_from(OAuthToken)) == 2
    invalidation = dict(issuanceId=value["receipt"]["issuanceId"])
    first = post(live, "revoke", invalidation, viewer=value["viewerAccessToken"])
    assert first.status_code == 200
    assert post(live, "revoke", invalidation, viewer=value["viewerAccessToken"]).data == first.data
    assert resolve(live, value).status_code == 503
    with pytest.raises(BearerValidationError):
        canonical(live, value)
    history = post(live, "recover", data).get_json()
    assert history["receipt"] == value["receipt"] and history["currentActive"] is False
    assert history["viewerAccessToken"] is None
    assert count(live) == 1


@pytest.mark.parametrize("stage", ["scan", "claim", "accepted", "terminal", "unsigned"])
def test_no_issuance_from_incomplete_or_unsigned_history(live, stage):
    if stage == "scan":
        proposal = ingress.proposal(live)
        assert (
            ingress.post(live, "qr/scan", {k: proposal[k] for k in ("source", "qr", "possessionProof")}).status_code
            == 200
        )
    else:
        proposal = ingress.prepare(live)
    if stage == "accepted":
        assert ingress.accept(live, proposal).status_code == 200
    elif stage == "terminal":
        assert (
            ingress.post(live, "qr/close", dict(pairingId=proposal["pairingId"], status="cancelled")).status_code == 200
        )
    elif stage == "unsigned":
        assert ingress.accept(live, dict(proposal, proof="{}")).status_code == 503
    data = dict(ingress.selectors(proposal), verifier=proposal["verifier"], deliveryKey="c" * 64)
    assert post(live, "issue", data).status_code == 503
    assert count(live) == 0


@pytest.mark.parametrize("field", ["pairingId", "revision", "authorizationDigest", "verifier", "deliveryKey"])
def test_substitution_never_issues_again_or_redirects_recovery(live, field):
    data, value = issue(live)
    assert post(live, "issue", dict(data, **{field: "e" * 64})).status_code == 503
    assert post(live, "recover", dict(data, **{field: "e" * 64})).status_code == 503
    assert resolve(live, value).status_code == 200 and count(live) == 1


@pytest.mark.parametrize("group", ingress.GROUPS)
def test_old_backend_capabilities_cannot_issue(live, group):
    proposal, data = prepared(live)
    assert post(live, "issue", data, service=live["tokens"][group]).status_code == 401
    assert count(live) == 0


@pytest.mark.parametrize("event_name", ["logout", "replacement", "session", "user", "client", "issuer", "expiry"])
@pytest.mark.parametrize("already_issued", [False, True])
def test_parent_policy_before_and_after_commit(live, event_name, already_issued):
    proposal, data = prepared(live)
    value = post(live, "issue", data).get_json() if already_issued else None
    lifecycle = live["state"][2]
    if event_name == "logout":
        lifecycle.invalidate_original(live["bearer"])
    elif event_name == "replacement":
        fresh_browser(lifecycle, live["subject"])
    elif event_name == "expiry":
        live["state"][3][0] += timedelta(seconds=301)
    else:
        with live["state"][1].begin() as db:
            if event_name == "session":
                db.execute(text("UPDATE sessions SET is_active=false"))
            elif event_name == "user":
                db.execute(text("UPDATE users SET is_active=false"))
            elif event_name == "client":
                db.get(OAuthClient, CLIENT).is_active = False
            else:
                db.get(SocialSessionIssuer, CLIENT).is_active = False
    response = post(live, "issue", data)
    if already_issued:
        assert response.status_code == 200
        assert response.get_json()["currentActive"] is False
        assert response.get_json()["receipt"] == value["receipt"]
        assert resolve(live, value).status_code == 503
        if event_name != "expiry":
            with pytest.raises(BearerValidationError):
                canonical(live, value)
    else:
        assert response.status_code == 503
    assert count(live) == int(already_issued)


def test_current_full_not_a_permanent_scope(live):
    data, value = issue(live)
    assert canonical(live, value).scopes == frozenset({"openid", "profile"})
    with live["state"][1].begin() as db:
        for row in db.scalars(select(CurrentEntitlementEvidence)):
            row.revoked_at = live["state"][3][0]
    # Authentication remains limited; separate downstream entitlement checks
    # still deny Full. No session issuance field asserts messaging readiness.
    assert resolve(live, value).status_code == 200


def test_current_full_missing_at_first_issuance_denies(live):
    proposal, data = prepared(live)
    with live["state"][1].begin() as db:
        db.execute(text("UPDATE current_entitlement_evidence SET revoked_at=observed_at"))
    assert post(live, "issue", data).status_code == 503
    assert count(live) == 0


def test_workers_restart_and_local_record_loss_recover_one(live):
    proposal, data = prepared(live)
    service = live["issuer"]
    gate = threading.Barrier(3, timeout=15)

    def worker():
        recreated = SqlAlchemySocialSessionIssuance(
            mobile=service.mobile,
            lifecycle=service.lifecycle,
            backend_id=BACKEND,
            service_principal=service.service_principal,
        )
        gate.wait()
        return recreated.issue(data)

    with ThreadPoolExecutor(max_workers=2) as pool:
        calls = [pool.submit(worker) for _ in range(2)]
        gate.wait()
        values = [call.result(timeout=20) for call in calls]
    assert values[0] == values[1]
    assert service.recover(data) == values[0]
    assert count(live) == 1


@pytest.mark.parametrize("write", ["oauth_tokens", "social_session_issuances", "commit"])
def test_write_and_commit_failure_release_no_credential(live, write):
    proposal, data = prepared(live)
    engine = live["state"][0]

    def fail_write(connection, cursor, statement, parameters, context, executemany):
        if statement.startswith("INSERT INTO " + write):
            raise RuntimeError("synthetic write failure")

    def fail_commit(connection):
        raise RuntimeError("synthetic commit failure")

    hook, target = (fail_commit, "commit") if write == "commit" else (fail_write, "before_cursor_execute")
    event.listen(engine, target, hook)
    try:
        assert post(live, "issue", data).status_code == 503
    finally:
        event.remove(engine, target, hook)
    assert count(live) == 0
    assert post(live, "recover", data).status_code == 503
    assert post(live, "issue", data).status_code == 200


def test_database_retains_identity_and_monotonic_revoke(live):
    data, value = issue(live)
    engine = live["state"][0]
    statements = [
        "DELETE FROM social_session_issuances",
        "UPDATE social_session_issuances SET backend_id='another'",
        "UPDATE social_session_pairing_parents SET parent_token_id='another'",
        "UPDATE oauth_tokens SET access_token_expires_at=access_token_expires_at+interval '1 second'",
        "INSERT INTO social_session_issuances SELECT * FROM social_session_issuances",
    ]
    for statement in statements:
        with pytest.raises(DBAPIError), engine.begin() as db:
            db.exec_driver_sql(statement)
    assert (
        post(
            live, "revoke", dict(issuanceId=value["receipt"]["issuanceId"]), viewer=value["viewerAccessToken"]
        ).status_code
        == 200
    )
    with pytest.raises(DBAPIError), engine.begin() as db:
        db.exec_driver_sql("UPDATE oauth_tokens SET is_revoked=false")
    assert count(live) == 1


def binding_change(live, original, operation, *, binding_id):
    content = json.loads(json.loads(original["source"])["content"])
    claim = content["authorization"]
    claim.update(operation=operation, bindingVersion=2, priorBindingId=binding_id, requestId=uuid.uuid4().hex * 2)
    if operation == "rotate":
        claim["publicKey"] = "26" * 32
    data = ingress.prepare(live, ingress.protocol.canonical(content))
    assert ingress.accept(live, data).status_code == 200
    return data


class CurrentRaceOracle:
    """Observations survive the product's transaction/exception boundary."""

    def __init__(self, current, *, timeout=15, wait=None):
        self.current = current
        self.timeout = timeout
        self.paused = threading.Event()
        self.release = threading.Event()
        self.wait = self.release.wait if wait is None else wait
        self.events = []
        self.synchronization_errors = []
        self.current_errors = []
        self.worker_pid = None

    def __call__(self, db, *args):
        self.worker_pid = db.connection().connection.driver_connection.get_backend_pid()
        self.events.append("history_paused")
        self.paused.set()
        try:
            if not self.wait(self.timeout):
                raise AssertionError("race release timed out")
        except BaseException as exc:
            self.synchronization_errors.append(type(exc).__name__)
            raise
        self.events.append("current_entered")
        try:
            return self.current(db, *args)
        except BaseException as exc:
            self.current_errors.append(type(exc).__name__)
            self.events.append("current_denied")
            raise

    def assert_denied(self):
        # Called only by the test thread after joining the worker. In particular,
        # SessionIssuanceUnavailable alone cannot establish any of these facts.
        assert not self.synchronization_errors, "race synchronization failed"
        assert self.events == [
            "history_paused",
            "pending_before_mutation",
            "mutation_committed",
            "pending_after_commit",
            "worker_released",
            "current_entered",
            "invalid_binding_read",
            "current_denied",
        ]
        assert self.current_errors == ["ValueError"]


@pytest.mark.parametrize("operation", ["revoke", "rotate"])
@pytest.mark.parametrize("issued_first", [False, True])
def test_real_binding_mutation_serializes_with_issuance(live, monkeypatch, request, operation, issued_first):
    original, data = prepared(live)
    binding_id = ingress.consume(live, original).get_json()["identity"]["bindingId"]
    service = live["issuer"]
    if issued_first:
        committed = threading.Event()
        release = threading.Event()
        factory = live["state"][1]

        def after_commit(db):
            if threading.current_thread().name.startswith("issuance-first"):
                committed.set()
                assert release.wait(15)

        event.listen(factory, "after_commit", after_commit)
        try:
            with ThreadPoolExecutor(max_workers=1, thread_name_prefix="issuance-first") as pool:
                pending = pool.submit(service.issue, data)
                assert committed.wait(15)
                try:
                    binding_change(live, original, operation, binding_id=binding_id)
                finally:
                    release.set()
                value = pending.result(timeout=15)
        finally:
            event.remove(factory, "after_commit", after_commit)
        consumer = SocialConsumer(
            lambda cmd, body, **kw: post(live, cmd, body, **kw), lambda: live["runtime"].mobile._now() * 1000
        )
        with pytest.raises(ValueError):
            consumer.materialize(value)  # Delayed success response cannot log in.
        with pytest.raises(BearerValidationError):
            canonical(live, value)
        assert post(live, "recover", data).get_json()["currentActive"] is False
    else:
        engine, factory = live["state"][:2]
        oracle = CurrentRaceOracle(service._current)
        lookup = SqlAlchemyTransactionBoundSocialMessagingDeviceStorage.binding_for_id
        writer_pids = set()
        worker_errors = []
        with factory() as db:
            original_tokens = set(db.scalars(select(OAuthToken.id)))

        def observe_binding(storage, identity, *, lock=True):
            value = lookup(storage, identity, lock=lock)
            if threading.current_thread().name.startswith("issuance-after-mutation") and identity == binding_id:
                oracle.events.append(
                    "invalid_binding_read" if value is not None and value.active is False else "unexpected_binding"
                )
            return value

        def observe_writer(connection, cursor, statement, parameters, context, executemany):
            if "update social_messaging_device_bindings" in statement.lower():
                writer_pids.add(connection.connection.driver_connection.get_backend_pid())

        def bound_statement_wait(db, transaction, connection):
            connection.exec_driver_sql("SET LOCAL statement_timeout = '10s'")

        monkeypatch.setattr(service, "_current", oracle)
        monkeypatch.setattr(SqlAlchemyTransactionBoundSocialMessagingDeviceStorage, "binding_for_id", observe_binding)
        event.listen(engine, "after_cursor_execute", observe_writer)
        event.listen(factory, "after_begin", bound_statement_wait)
        try:
            with ThreadPoolExecutor(max_workers=1, thread_name_prefix="issuance-after-mutation") as pool:
                pending = pool.submit(service.issue, data)
                try:
                    assert oracle.paused.wait(15), "issuer did not reach history pause"
                    assert not pending.done()
                    oracle.events.append("pending_before_mutation")
                    binding_change(live, original, operation, binding_id=binding_id)
                    # A separate connection must see the actual retirement while
                    # the issuer still holds its original history transaction.
                    with factory.begin() as observer:
                        retired = lookup(SqlAlchemyTransactionBoundSocialMessagingDeviceStorage(observer), binding_id)
                        assert retired is not None and retired.active is False
                    assert writer_pids and oracle.worker_pid not in writer_pids
                    oracle.events.append("mutation_committed")
                    assert not pending.done()
                    oracle.events.append("pending_after_commit")
                finally:
                    oracle.events.append("worker_released")
                    oracle.release.set()
                    try:
                        pending.result(timeout=15)
                    except Exception as exc:
                        worker_errors.append(type(exc).__name__)
        finally:
            event.remove(engine, "after_cursor_execute", observe_writer)
            event.remove(factory, "after_begin", bound_statement_wait)
            request.node.user_properties.append(
                (
                    "race_oracle",
                    dict(
                        events=oracle.events,
                        synchronization_errors=oracle.synchronization_errors,
                        current_errors=oracle.current_errors,
                        worker_errors=worker_errors,
                        distinct_writer_connection=bool(writer_pids) and oracle.worker_pid not in writer_pids,
                    ),
                )
            )
        oracle.assert_denied()
        assert worker_errors == ["SessionIssuanceUnavailable"]
        assert count(live) == 0
        with factory() as db:
            assert set(db.scalars(select(OAuthToken.id))) == original_tokens


@pytest.mark.parametrize("failure", ["timeout", "assertion"])
def test_race_oracle_rejects_swallowed_synchronization_failure(live, monkeypatch, request, failure):
    _original, data = prepared(live)

    def broken_wait(_timeout):
        raise AssertionError("forced race wait failure")

    oracle = CurrentRaceOracle(live["issuer"]._current, timeout=0, wait=broken_wait if failure == "assertion" else None)
    monkeypatch.setattr(live["issuer"], "_current", oracle)
    with live["state"][1]() as db:
        original_tokens = set(db.scalars(select(OAuthToken.id)))
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(live["issuer"].issue, data)
        try:
            # The actual product wrapper still converts the forced failure.
            with pytest.raises(SessionIssuanceUnavailable):
                pending.result(timeout=15)
        finally:
            oracle.release.set()
    assert oracle.synchronization_errors == ["AssertionError"]
    assert oracle.events == ["history_paused"]
    assert oracle.current_errors == []
    with pytest.raises(AssertionError, match="race synchronization failed"):
        oracle.assert_denied()  # Main-thread failure cannot become product denial.
    assert count(live) == 0
    with live["state"][1]() as db:
        assert set(db.scalars(select(OAuthToken.id))) == original_tokens
    request.node.user_properties.append(
        (
            "negative_oracle",
            dict(
                forced_failure=failure,
                synchronization_errors=oracle.synchronization_errors,
                real_current_calls=0,
                oracle_rejected=True,
            ),
        )
    )


@pytest.mark.parametrize("change", ["logout", "expiry"])
def test_actual_postgresql_lock_wait_rechecks_current_state(live, change):
    original, data = prepared(live)
    engine, factory = live["state"][:2]
    service = live["issuer"]
    entered = threading.Event()
    worker_pid = []

    def mark(connection, cursor, statement, parameters, context, executemany):
        if threading.current_thread().name.startswith("blocked-issuer") and "pg_advisory_xact_lock" in statement:
            worker_pid[:] = [connection.connection.driver_connection.get_backend_pid()]
            entered.set()

    event.listen(engine, "before_cursor_execute", mark)
    try:
        with factory() as owner, ThreadPoolExecutor(max_workers=1, thread_name_prefix="blocked-issuer") as pool:
            tx = owner.begin()
            # Real binding mutation locks, including the common User row. This
            # proves the new owner actually blocks against the existing writer.
            from app.services.social_messaging_device_binding_authorization_storage import (
                SqlAlchemySocialMessagingDeviceBindingAuthorizationStorage,
            )

            candidate = ingress.protocol.parse_json(original["source"])
            binding = ingress.protocol.inspect_claim(candidate["content"], live["subject"])
            record = json.loads(binding.binding_record)
            SqlAlchemySocialMessagingDeviceBindingAuthorizationStorage(owner)._lock_mutation(
                subject=live["subject"], device_id=record["deviceId"], public_keys=(record["publicKey"],)
            )
            pending = pool.submit(service.issue, data)
            assert entered.wait(10)
            deadline = time.monotonic() + 10
            observed = False
            try:
                with engine.connect() as observer:
                    while time.monotonic() < deadline:
                        blockers = observer.execute(
                            text("SELECT pg_blocking_pids(:pid)"), {"pid": worker_pid[0]}
                        ).scalar_one()
                        if blockers:
                            observed = True
                            break
                        threading.Event().wait(0.01)
                assert observed and not pending.done()
                if change == "logout":
                    owner.execute(text("UPDATE oauth_tokens SET is_revoked=true"))
                else:
                    live["state"][3][0] += timedelta(seconds=301)
                tx.commit()
            finally:
                if tx.is_active:
                    tx.rollback()
            with pytest.raises(SessionIssuanceUnavailable):
                pending.result(timeout=15)
    finally:
        event.remove(engine, "before_cursor_execute", mark)
    assert count(live) == 0


def test_old_logout_retry_cannot_revoke_rotation_replacement(live):
    original, data = prepared(live)
    first = live["issuer"].issue(data)
    binding_id = ingress.consume(live, original).get_json()["identity"]["bindingId"]
    replacement = binding_change(live, original, "rotate", binding_id=binding_id)
    assert ingress.consume(live, replacement).status_code == 200
    second = live["issuer"].issue(
        dict(ingress.selectors(replacement), verifier=replacement["verifier"], deliveryKey="f" * 64)
    )
    for _ in range(2):
        live["issuer"].revoke(first["receipt"]["issuanceId"], first["viewerAccessToken"])
    assert resolve(live, second).status_code == 200
    with pytest.raises(SessionIssuanceUnavailable):
        live["issuer"].revoke(second["receipt"]["issuanceId"], first["viewerAccessToken"])
    assert count(live) == 2


def test_missing_provenance_cannot_be_adopted(live):
    live["runtime"].mobile._issuance_client_id = None
    proposal, data = prepared(live)
    live["runtime"].mobile._issuance_client_id = CLIENT
    assert post(live, "issue", data).status_code == 503
    with live["state"][1]() as db:
        parent = db.scalar(select(OAuthSessionGeneration.token_id))
    with pytest.raises(DBAPIError), live["state"][0].begin() as db:
        db.execute(
            text("INSERT INTO social_session_pairing_parents VALUES (:operation,:parent,:client)"),
            dict(operation=proposal["pairingId"], parent=parent, client=CLIENT),
        )
    live["state"][3][0] += timedelta(seconds=301)
    assert ingress.consume(live, proposal).status_code == 200
    assert post(live, "issue", data).status_code == 503
    assert count(live) == 0


def test_social_consumer_absolute_expiry_restart_and_authoritative_logout(live):
    fixture = json.loads((Path(__file__).parents[1] / "fixtures/social_session_issuance_v1.json").read_text())
    social = Path("/srv/hodlxxi-social-mobile-device-authorization-phase2-v1")
    if social.is_dir():
        for path, digest in fixture["sourceSha256"].items():
            assert hashlib.sha256((social / path).read_bytes()).hexdigest() == digest
        source = (social / "src/server/social-oauth-bff.mjs").read_text()
        assert "{ subject: authentication.subject, viewerAccessToken: authentication.accessToken }" in source
        assert "const authenticatedSessionContext" in source and 'target.path === "/auth/session"' in source
    data, delivery = issue(live)

    def adapter():
        return SocialConsumer(
            lambda cmd, body, **kw: post(live, cmd, body, **kw), lambda: live["runtime"].mobile._now() * 1000
        )

    consumer = adapter()
    record = consumer.materialize(delivery)
    assert set(record) == set(fixture["mobileSessionFields"])
    assert canonical(live, delivery).subject == record["subject"]
    assert consumer.authenticated_session() == record
    consumer = adapter()  # BFF-local record lost, PostgreSQL issuance survives.
    live["state"][3][0] += timedelta(seconds=10)
    assert consumer.materialize(live["issuer"].recover(data)) == record
    consumer.logout()
    with pytest.raises(ValueError):
        adapter().materialize(delivery)
    assert count(live) == 1


def test_original_key_loss_fails_closed_without_new_grant(live, monkeypatch):
    data, delivery = issue(live)
    monkeypatch.setattr("app.services.social_session_issuance.get_key_by_kid", lambda *_: None)
    assert post(live, "recover", data).status_code == 503
    assert post(live, "issue", data).status_code == 503
    assert count(live) == 1


def test_new_transport_errors_and_assertion_replay_are_closed(live):
    original, data = prepared(live)
    for command in ("issue", "recover", "resolve", "revoke"):
        for method in ("GET", "HEAD", "OPTIONS", "PUT", "DELETE"):
            response = live["client"].open(PREFIX + "/" + command, method=method)
            assert response.status_code == 405
            assert response.headers["Cache-Control"] == "no-store"
    for field in ("subject", "deviceId", "bindingId", "clientId", "identity", "eligible"):
        assert post(live, "issue", dict(data, **{field: "a" * 64})).status_code == 400
    assert post(live, "issue", data, viewer=live["bearer"]).status_code == 400
    fields = dict(
        grant_type="client_credentials",
        client_id=BACKEND,
        client_assertion_type="urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        client_assertion=client_assertion(live["material"], aud=ISSUER + TOKEN_PATH),
        scope=SCOPE,
    )
    assert live["client"].post(TOKEN_PATH, data=fields).status_code == 200
    repeated = live["client"].post(TOKEN_PATH, data=fields)
    # The reused durable replay owner reports duplicate assertion consumption
    # through its existing generic storage-unavailable contract.
    assert repeated.status_code == 503 and repeated.get_json() == {"error": "session_issuance_unavailable"}
    assert count(live) == 0


def test_real_confidential_full_directory_viewer_dispatch(live):
    from app.services.confidential_service_credentials import SERVICE_PURPOSE, SERVICE_SCOPE
    from app.services.current_entitlement import resolve_runtime_current_entitlement
    from app.services.current_entitlement_evidence_storage import SqlAlchemyCurrentEntitlementEvidenceRepository
    from app.services.full_entitlement_snapshot import FullEntitlementSnapshotReader
    from app.services.privacy_full_directory_internal_delivery import (
        PrivacyFullDirectoryInternalDeliveryRuntime,
        ViewerCredentialDenied,
    )
    from app.services.privacy_safe_full_directory import PrivacySafeFullDirectoryDenied

    data, delivery = issue(live)
    config = replace(
        configurations(live["material"])[0],
        token_endpoint_audience=ISSUER + "/internal/v1/social/service-token",
        service_resource_audience=ISSUER + "/internal/v1/social/full-directory",
        service_scope=SERVICE_SCOPE,
        service_purpose=SERVICE_PURPOSE,
    )
    repository = SqlAlchemyCurrentEntitlementEvidenceRepository(live["state"][1])
    runtime = PrivacyFullDirectoryInternalDeliveryRuntime(
        service_config=config,
        replay_consumer=live["runtime"].replay,
        service_signing_key=live["material"][1],
        service_signing_kid="service-test",
        viewer_oauth_client_id=CLIENT,
        viewer_token_validator=lambda token: validate_canonical_access_token_with_config(
            token, config=live["state"][2]._validation, expected_client_id=CLIENT
        ),
        current_entitlement_resolver=lambda subject: resolve_runtime_current_entitlement(
            subject, repository=repository
        ),
        full_population_provider=FullEntitlementSnapshotReader(repository).current_snapshot,
        alias_secret=b"synthetic-directory-alias-secret-32",
        alias_version=1,
    )
    service_token = runtime.issue_service_token(client_assertion(live["material"], aud=config.token_endpoint_audience))
    result = runtime.current_directory(service_token, delivery["viewerAccessToken"])
    assert isinstance(result, dict)
    assert post(live, "issue", data, service=service_token).status_code == 401
    with live["state"][1].begin() as db:
        db.execute(text("UPDATE current_entitlement_evidence SET revoked_at=observed_at"))
    with pytest.raises(PrivacySafeFullDirectoryDenied):
        runtime.current_directory(service_token, delivery["viewerAccessToken"])
    live["issuer"].revoke(delivery["receipt"]["issuanceId"], delivery["viewerAccessToken"])
    with pytest.raises(ViewerCredentialDenied):
        runtime.current_directory(service_token, delivery["viewerAccessToken"])


@pytest.mark.parametrize(
    "claim,value",
    [
        ("aud", "https://other.example"),
        ("azp", "another-backend"),
        ("scope", "social:full-directory:read"),
        ("purpose", "another-purpose"),
    ],
)
def test_signed_service_claim_substitutions_denied(live, claim, value):
    import jwt

    original, data = prepared(live)
    claims = jwt.decode(live["issuance_token"], options={"verify_signature": False})
    claims[claim] = value
    forged = jwt.encode(claims, live["material"][1], algorithm="RS256", headers={"kid": "service-test"})
    assert post(live, "issue", data, service=forged).status_code == 401
    assert count(live) == 0


@pytest.mark.parametrize("fault", ["missing_guard", "unsigned_persisted_proof", "deadline_after_write"])
def test_authority_guards_and_final_write_fence(live, fault):
    original, data = prepared(live)
    engine = live["state"][0]
    if fault == "unsigned_persisted_proof":
        # Deliberately corrupt synthetic history, then restore the guard before
        # calling the owner. The real signature verifier must still reject it.
        with engine.begin() as db:
            db.exec_driver_sql(
                "ALTER TABLE social_messaging_mobile_acceptances DISABLE TRIGGER trg_social_mobile_receipt_immutable"
            )
            db.exec_driver_sql("UPDATE social_messaging_mobile_acceptances SET proof_source='{}'")
            db.exec_driver_sql(
                "ALTER TABLE social_messaging_mobile_acceptances ENABLE TRIGGER trg_social_mobile_receipt_immutable"
            )
        assert post(live, "issue", data).status_code == 503
    elif fault == "missing_guard":
        with engine.begin() as db:
            db.exec_driver_sql("ALTER TABLE oauth_tokens DISABLE TRIGGER trg_social_session_token_guard")
        try:
            assert post(live, "issue", data).status_code == 503
        finally:
            with engine.begin() as db:
                db.exec_driver_sql("ALTER TABLE oauth_tokens ENABLE TRIGGER trg_social_session_token_guard")
    else:

        def advance(connection, cursor, statement, parameters, context, executemany):
            if statement.startswith("INSERT INTO social_session_issuances"):
                live["state"][3][0] += timedelta(seconds=301)

        event.listen(engine, "after_cursor_execute", advance)
        try:
            assert post(live, "issue", data).status_code == 503
        finally:
            event.remove(engine, "after_cursor_execute", advance)
    assert count(live) == 0


def test_another_issuer_or_client_cannot_recover(live):
    data, value = issue(live)
    original = live["issuer"]
    other = SqlAlchemySocialSessionIssuance(
        mobile=original.mobile,
        lifecycle=original.lifecycle,
        backend_id="another-issuer",
        service_principal="service:social-mobile",
    )
    with pytest.raises(SessionIssuanceUnavailable):
        other.issue(data)
    with pytest.raises(SessionIssuanceUnavailable):
        other.recover(data)
    assert resolve(live, value).status_code == 200


def test_database_unique_handoff_constraint_is_the_collision_owner(live):
    data, value = issue(live)
    with pytest.raises(DBAPIError) as caught, live["state"][0].begin() as db:
        db.exec_driver_sql("INSERT INTO social_session_issuances SELECT * FROM social_session_issuances")
    assert caught.value.orig.diag.constraint_name == "social_session_issuances_pkey"
    assert count(live) == 1


def test_new_process_recovers_same_credential_from_postgresql(live):
    import os
    import subprocess
    import sys

    data, value = issue(live)
    script = """
import hashlib, json, os, sys
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from app.services.oauth_session_lifecycle import SqlAlchemyOAuthSessionLifecycle
from app.services.social_messaging_mobile_authorization_storage import SqlAlchemyMobileAuthorizationService
from app.services.social_session_issuance import SqlAlchemySocialSessionIssuance
engine = create_engine(os.environ["HODLXXI_SOCIAL_BINDING_AUTHORIZATION_POSTGRES_DSN"])
with engine.connect() as db:
    assert db.execute(text("SHOW data_directory")).scalar_one() == os.environ["HODLXXI_SOCIAL_BINDING_AUTHORIZATION_POSTGRES_DATA"]
factory = sessionmaker(engine, expire_on_commit=False)
lifecycle = SqlAlchemyOAuthSessionLifecycle(factory, client_id="synthetic-social", token_config={
    "JWT_ISSUER":"https://identity.example", "JWKS_DIR":os.environ["JWKS_DIR"]})
mobile = SqlAlchemyMobileAuthorizationService(factory, issuance_client_id="synthetic-social")
service = SqlAlchemySocialSessionIssuance(mobile=mobile, lifecycle=lifecycle,
    backend_id="synthetic-social-backend", service_principal="service:social-mobile")
value = service.recover(json.loads(sys.stdin.read()))
print(json.dumps({"receipt":value["receipt"], "credentialDigest":hashlib.sha256(value["viewerAccessToken"].encode()).hexdigest()}))
engine.dispose()
"""
    completed = subprocess.run(
        [sys.executable, "-c", script],
        input=json.dumps(data),
        text=True,
        capture_output=True,
        env=dict(os.environ),
        timeout=30,
    )
    assert completed.returncode == 0
    recovered = json.loads(completed.stdout)
    assert recovered["receipt"] == value["receipt"]
    assert recovered["credentialDigest"] == hashlib.sha256(value["viewerAccessToken"].encode()).hexdigest()
    assert count(live) == 1


def test_signed_adoption_issues_without_manufacturing_a_new_binding(live):
    from datetime import datetime, timezone

    from app.services.social_messaging_device_storage import SqlAlchemyTransactionBoundSocialMessagingDeviceStorage
    from app.services.social_messaging_mobile_authorization_storage import _binding

    proposal = ingress.proposal(live)
    now = live["runtime"].mobile._now()
    candidate = ingress.protocol.parse_authorization(
        proposal["source"], subject=live["subject"], expected_method=ingress.protocol.QR, now=now
    )
    with live["state"][1].begin() as db:
        SqlAlchemyTransactionBoundSocialMessagingDeviceStorage(db).apply_authorized(
            _binding(candidate), now=datetime.fromtimestamp(now, timezone.utc)
        )
    vectors = json.loads(
        (Path(__file__).parents[1] / "fixtures/social_mobile_device_authorization_v1.json").read_text()
    )
    source = json.loads(next(v for v in vectors["entries"] if v["operation"] == "adopt")["content"])
    source["adoption"].update(
        bindingId=candidate.semantic.binding_id,
        bindingRecord=json.loads(candidate.semantic.binding_record),
        issuedAt=ingress.stamp(now),
        expiresAt=ingress.stamp(now + 240),
        requestId=uuid.uuid4().hex * 2,
    )
    adopted = ingress.prepare(live, ingress.protocol.canonical(source))
    assert ingress.accept(live, adopted).status_code == 200
    assert ingress.consume(live, adopted).status_code == 200
    value = live["issuer"].issue(dict(ingress.selectors(adopted), verifier=adopted["verifier"], deliveryKey="f" * 64))
    assert resolve(live, value).status_code == 200
    with live["state"][1]() as db:
        assert db.execute(text("SELECT count(*) FROM social_messaging_device_bindings")).scalar_one() == 1
