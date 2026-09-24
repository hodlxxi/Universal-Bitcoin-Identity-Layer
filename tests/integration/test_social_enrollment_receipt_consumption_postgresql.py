"""Disposable PostgreSQL 16 proof of the enrollment three-row invariant.

The target must be explicit, isolated TCP on a non-live port, use synthetic
data, and have Unix sockets disabled. DATABASE_URL is never consulted.
"""

from __future__ import annotations

import json
import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from sqlalchemy import create_engine, func, inspect, select, text, update
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

from app.services import social_device_challenge_store as challenge_storage
from app.services import social_device_ed25519_association_storage as association_storage
from app.services import social_enrollment_receipt_storage as receipt_storage
from app.services import social_messaging_device_admission_contract as admission
from app.services import social_messaging_device_ed25519_association_lifecycle as lifecycle
from app.services.social_device_verification_statement import AuthenticatedSocialDeviceVerificationStatementV1
from app.services.social_messaging_device_proof_profile import parse_enrollment_v2
from tests.unit.test_social_device_challenge_store import arguments as challenge_arguments
from tests.unit.test_social_enrollment_receipt_storage import FIXTURE as RECEIPT_VECTORS
from tests.unit.test_social_enrollment_receipt_storage import durable_row
from tests.unit.test_social_enrollment_transition_authority import LIFECYCLE, VECTORS, _authorize

ROOT = Path(__file__).parents[2]
CHALLENGE_MIGRATION = ROOT / "migrations/2026-09-21_social_device_challenge_store_v1.sql"
ASSOCIATION_MIGRATION = ROOT / "migrations/2026-09-22_social_device_ed25519_association_storage_v1.sql"
RECEIPT_MIGRATION = ROOT / "migrations/2026-09-23_social_device_admission_receipt_consumption_v1.sql"
PREFIX = "HODLXXI_ENROLLMENT_RECEIPT_TEST_"
ACK = "DISPOSABLE-SOCIAL-ENROLLMENT-RECEIPT-POSTGRES-V1"


def _apply(connection, path: Path) -> None:
    with connection.connection.driver_connection.cursor() as cursor:
        cursor.execute(path.read_text(encoding="ascii"))


@pytest.fixture(scope="module")
def postgres_target():
    dsn = os.environ.get(PREFIX + "DSN")
    if not dsn:
        pytest.skip("explicit disposable enrollment-receipt PostgreSQL target not provided")
    assert os.environ.get(PREFIX + "ACK") == ACK
    data = Path(os.environ[PREFIX + "DATA"]).resolve()
    assert data.parent.parent == Path("/tmp")
    assert data.parent.name.startswith("hodlxxi-enrollment-receipt-")
    assert data.name == "data" and (data / "PG_VERSION").read_text().strip() == "16"
    port = int(os.environ[PREFIX + "PORT"])
    url = make_url(dsn)
    assert url.drivername == "postgresql+psycopg2"
    assert url.host == "127.0.0.1" and url.port == port and 49152 <= port <= 65535
    assert url.database == "hodlxxi_enrollment_receipt_test"
    assert url.username == "enrollment_receipt_test"
    assert url.password is None and not url.query
    engine = create_engine(url, poolclass=NullPool, hide_parameters=True)
    try:
        with engine.connect() as connection:
            identity = connection.execute(
                text(
                    "SELECT current_database(), current_setting('data_directory'), "
                    "current_setting('port'), current_setting('listen_addresses'), "
                    "current_setting('unix_socket_directories'), version()"
                )
            ).one()
            assert identity[0] == url.database
            assert Path(identity[1]).resolve() == data
            assert int(identity[2]) == port
            assert identity[3:5] == ("127.0.0.1", "")
            assert identity[5].startswith("PostgreSQL 16.")
        yield engine
    finally:
        engine.dispose()


@pytest.fixture
def database(postgres_target):
    schema = "enrollment_receipt_" + uuid.uuid4().hex
    with postgres_target.begin() as connection:
        connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
    engine = create_engine(
        postgres_target.url,
        poolclass=NullPool,
        hide_parameters=True,
        connect_args={"options": f"-c search_path={schema} -c statement_timeout=10000 -c lock_timeout=5000"},
    )
    try:
        with engine.begin() as connection:
            _apply(connection, CHALLENGE_MIGRATION)
            _apply(connection, ASSOCIATION_MIGRATION)
        yield engine, sessionmaker(engine, expire_on_commit=False)
    finally:
        engine.dispose()
        with postgres_target.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA "{schema}" CASCADE')


def _statement(name: str) -> AuthenticatedSocialDeviceVerificationStatementV1:
    result = object.__new__(AuthenticatedSocialDeviceVerificationStatementV1)
    for field, value in VECTORS["vectors"][name]["statementFacts"].items():
        object.__setattr__(result, field, value)
    return result


def _seed_prior(factory, name: str) -> None:
    names = VECTORS["vectors"][name]["priorEvents"]
    if not names:
        return
    events = [lifecycle.parse_association_event_v1(LIFECYCLE["eventWires"][item]) for item in names]
    first_enrollment = parse_enrollment_v2(events[0].enrollment_wire)
    with factory.begin() as session:
        session.execute(
            association_storage.SocialDeviceEd25519AssociationChain.__table__.insert().values(
                subject=first_enrollment.subject,
                device_id=first_enrollment.device_id,
                authority_epoch=0,
                last_association_id=None,
                last_association_version=None,
                current_association_id=None,
                state="empty",
            )
        )
        for event in events:
            enrollment = parse_enrollment_v2(event.enrollment_wire) if event.enrollment_wire else None
            session.execute(
                association_storage.SocialDeviceEd25519AssociationEvent.__table__.insert().values(
                    subject=first_enrollment.subject,
                    device_id=first_enrollment.device_id,
                    authority_epoch=event.authority_epoch,
                    kind=event.kind,
                    association_id=event.association_id,
                    association_version=event.association_version,
                    predecessor_association_id=event.predecessor_association_id,
                    ed25519_public_key=enrollment.ed25519_public_key if enrollment else None,
                    enrollment_challenge_id=enrollment.enrollment_challenge_id if enrollment else None,
                    event_wire=lifecycle.canonical_association_event_v1_bytes(event).decode("ascii"),
                )
            )


def _prepare(database, name: str = "initial"):
    engine, factory = database
    _seed_prior(factory, name)
    vector = VECTORS["vectors"][name]
    value = admission.parse_verification_input_v1(vector["inputWire"])
    with factory.begin() as session:
        challenge_storage.SqlAlchemyDeviceChallengeStore(session).create_issued(
            context_wire=value.context.wire,
            challenge_wire=value.challenge_wire,
        )
    with engine.begin() as connection:
        _apply(connection, RECEIPT_MIGRATION)
    return {
        "engine": engine,
        "factory": factory,
        "name": name,
        "value": value,
        "authority": _authorize(name),
        "statement": _statement(name),
    }


def _effect(session, prepared):
    authority = prepared["authority"]
    store = association_storage.SqlAlchemyEd25519AssociationStore(session)
    kwargs = {
        "input_wire": prepared["value"].wire,
        "statement": prepared["statement"],
        "now": authority.observed_at,
    }
    if authority.transition_kind == "initial":
        result = store.establish_initial(**kwargs)
    elif authority.transition_kind == "rotate":
        result = store.rotate(
            **kwargs,
            expected_predecessor=authority.pre_effect_association_id,
            expected_epoch=authority.pre_effect_authority_epoch,
        )
    else:
        result = store.reenroll(
            **kwargs,
            expected_predecessor=authority.pre_effect_association_id,
            expected_epoch=authority.pre_effect_authority_epoch,
        )
    assert result.association_id == authority.proposed_association_id


def _receipt(session, prepared):
    authority = prepared["authority"]
    return receipt_storage.SqlAlchemyEnrollmentAdmissionReceiptStore(session).store_committed(
        authority,
        proposed_association_id=authority.proposed_association_id,
        decided_at=RECEIPT_VECTORS["vectors"][prepared["name"]]["decidedAt"],
    )


def _consume(session, prepared):
    authority = prepared["authority"]
    return challenge_storage.SqlAlchemyDeviceChallengeStore(session).record_enrollment_consumed(
        authority,
        observed_at=authority.observed_at,
    )


def _counts(factory, challenge_id):
    with factory.begin() as session:
        challenge = session.get(challenge_storage.SocialDeviceAdmissionChallengeRow, challenge_id)
        receipts = session.execute(
            select(func.count()).select_from(receipt_storage.SocialEnrollmentAdmissionReceiptRow)
        ).scalar_one()
        effects = session.execute(
            select(func.count())
            .select_from(association_storage.SocialDeviceEd25519AssociationEvent)
            .where(association_storage.SocialDeviceEd25519AssociationEvent.enrollment_challenge_id == challenge_id)
        ).scalar_one()
    return challenge.state, receipts, effects


@pytest.mark.parametrize("name", ("initial", "rotation", "reenrollment"))
def test_effect_receipt_and_consumed_commit_for_all_transition_kinds(database, name):
    prepared = _prepare(database, name)
    with prepared["factory"].begin() as session:
        _effect(session, prepared)
        receipt = _receipt(session, prepared)
        consumed = _consume(session, prepared)
        assert consumed.state == "consumed"
        assert receipt.receipt.challenge_id == consumed.context.challenge_id
    assert _counts(prepared["factory"], prepared["authority"].challenge_id) == ("consumed", 1, 1)


@pytest.mark.parametrize(
    "subset",
    (
        "receipt_only",
        "consumed_only",
        "effect_only",
        "effect_receipt",
        "effect_consumed",
    ),
)
def test_incomplete_subset_commit_is_denied(database, subset):
    prepared = _prepare(database)
    authority = prepared["authority"]
    with pytest.raises(Exception):
        with prepared["factory"].begin() as session:
            if subset in {"effect_only", "effect_receipt", "effect_consumed"}:
                _effect(session, prepared)
            if subset in {"receipt_only", "effect_receipt"}:
                _receipt(session, prepared)
            if subset in {"consumed_only", "effect_consumed"}:
                session.execute(
                    update(challenge_storage.SocialDeviceAdmissionChallengeRow)
                    .where(challenge_storage.SocialDeviceAdmissionChallengeRow.challenge_id == authority.challenge_id)
                    .values(state="consumed")
                )
    assert _counts(prepared["factory"], authority.challenge_id) == ("issued", 0, 0)


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("effect_id", "01" * 32),
        ("effect_digest", "02" * 32),
        ("proposed_association_id", "03" * 32),
        ("challenge_id", "04" * 32),
        ("receipt_wire", " noncanonical"),
    ),
)
def test_wrong_effect_and_noncanonical_receipt_are_denied(database, field, replacement):
    prepared = _prepare(database)
    with pytest.raises(Exception):
        with prepared["factory"].begin() as session:
            _effect(session, prepared)
            row = durable_row("initial", **{field: replacement})
            session.execute(receipt_storage.SocialEnrollmentAdmissionReceiptRow.__table__.insert().values(**row))
            session.execute(
                update(challenge_storage.SocialDeviceAdmissionChallengeRow)
                .where(
                    challenge_storage.SocialDeviceAdmissionChallengeRow.challenge_id
                    == prepared["authority"].challenge_id
                )
                .values(state="consumed")
            )
    assert _counts(prepared["factory"], prepared["authority"].challenge_id) == ("issued", 0, 0)


def test_duplicate_receipt_effect_reuse_and_second_consumption_are_denied(database):
    prepared = _prepare(database)
    authority = prepared["authority"]
    with prepared["factory"].begin() as session:
        _effect(session, prepared)
        _receipt(session, prepared)
        _consume(session, prepared)
    reused_effect = durable_row(
        "initial",
        receipt_id="05" * 32,
        challenge_id="06" * 32,
    )
    for statement in (
        receipt_storage.SocialEnrollmentAdmissionReceiptRow.__table__.insert().values(**durable_row("initial")),
        receipt_storage.SocialEnrollmentAdmissionReceiptRow.__table__.insert().values(**reused_effect),
        update(challenge_storage.SocialDeviceAdmissionChallengeRow)
        .where(challenge_storage.SocialDeviceAdmissionChallengeRow.challenge_id == authority.challenge_id)
        .values(state="consumed"),
    ):
        with pytest.raises(Exception):
            with prepared["factory"].begin() as session:
                session.execute(statement)
    inspector = inspect(prepared["engine"])
    unique_names = {item["name"] for item in inspector.get_unique_constraints(receipt_storage.TABLE)}
    assert unique_names == {
        "uq_social_enrollment_receipt_challenge",
        "uq_social_enrollment_receipt_effect",
    }
    assert _counts(prepared["factory"], authority.challenge_id) == ("consumed", 1, 1)


def test_exact_expiry_denies_consumption_and_rolls_back_effect_and_receipt(database):
    prepared = _prepare(database)
    expires_at = json.loads(prepared["value"].challenge_wire)["expiresAt"]
    with pytest.raises(challenge_storage.SocialDeviceChallengeStorageUnavailable):
        with prepared["factory"].begin() as session:
            _effect(session, prepared)
            _receipt(session, prepared)
            challenge_storage.SqlAlchemyDeviceChallengeStore(session).record_enrollment_consumed(
                prepared["authority"],
                observed_at=expires_at,
            )
    assert _counts(prepared["factory"], prepared["authority"].challenge_id) == ("issued", 0, 0)


@pytest.mark.parametrize("terminal", ("expired", "invalidated", "cancelled"))
def test_existing_non_consumed_terminal_semantics_remain_unchanged(database, terminal):
    prepared = _prepare(database)
    authority = prepared["authority"]
    with prepared["factory"].begin() as session:
        session.execute(
            update(challenge_storage.SocialDeviceAdmissionChallengeRow)
            .where(challenge_storage.SocialDeviceAdmissionChallengeRow.challenge_id == authority.challenge_id)
            .values(state=terminal)
        )
    assert _counts(prepared["factory"], authority.challenge_id) == (terminal, 0, 0)
    with pytest.raises(Exception):
        with prepared["factory"].begin() as session:
            session.execute(
                update(challenge_storage.SocialDeviceAdmissionChallengeRow)
                .where(challenge_storage.SocialDeviceAdmissionChallengeRow.challenge_id == authority.challenge_id)
                .values(state="issued")
            )


def test_non_enrollment_challenge_cannot_use_consumed_transition(database):
    engine, factory = database
    args = challenge_arguments("ciphertextSubmit")
    with factory.begin() as session:
        created = challenge_storage.SqlAlchemyDeviceChallengeStore(session).create_issued(**args)
    with engine.begin() as connection:
        _apply(connection, RECEIPT_MIGRATION)
    with pytest.raises(Exception):
        with factory.begin() as session:
            session.execute(
                update(challenge_storage.SocialDeviceAdmissionChallengeRow)
                .where(challenge_storage.SocialDeviceAdmissionChallengeRow.challenge_id == created.context.challenge_id)
                .values(state="consumed")
            )


def test_receipt_update_delete_truncate_and_terminal_resurrection_are_denied(database):
    prepared = _prepare(database)
    authority = prepared["authority"]
    with prepared["factory"].begin() as session:
        _effect(session, prepared)
        _receipt(session, prepared)
        _consume(session, prepared)
    statements = (
        receipt_storage.SocialEnrollmentAdmissionReceiptRow.__table__.update().values(decided_at=1),
        receipt_storage.SocialEnrollmentAdmissionReceiptRow.__table__.delete(),
        text("TRUNCATE social_device_enrollment_admission_receipts"),
        update(challenge_storage.SocialDeviceAdmissionChallengeRow)
        .where(challenge_storage.SocialDeviceAdmissionChallengeRow.challenge_id == authority.challenge_id)
        .values(state="issued"),
    )
    for statement in statements:
        with pytest.raises(Exception):
            with prepared["factory"].begin() as session:
                session.execute(statement)
    assert _counts(prepared["factory"], authority.challenge_id) == ("consumed", 1, 1)


def test_all_three_provisional_mutations_roll_back_together(database):
    prepared = _prepare(database)
    authority = prepared["authority"]
    with prepared["factory"]() as session:
        transaction = session.begin()
        _effect(session, prepared)
        _receipt(session, prepared)
        _consume(session, prepared)
        assert _counts_in_transaction(session, authority.challenge_id) == ("consumed", 1, 1)
        transaction.rollback()
    assert _counts(prepared["factory"], authority.challenge_id) == ("issued", 0, 0)


def _counts_in_transaction(session, challenge_id):
    challenge = session.get(
        challenge_storage.SocialDeviceAdmissionChallengeRow,
        challenge_id,
        populate_existing=True,
    )
    receipts = session.execute(
        select(func.count()).select_from(receipt_storage.SocialEnrollmentAdmissionReceiptRow)
    ).scalar_one()
    effects = session.execute(
        select(func.count())
        .select_from(association_storage.SocialDeviceEd25519AssociationEvent)
        .where(association_storage.SocialDeviceEd25519AssociationEvent.enrollment_challenge_id == challenge_id)
    ).scalar_one()
    return challenge.state, receipts, effects


def test_concurrent_double_consumption_has_exactly_one_complete_winner(database):
    prepared = _prepare(database)

    def contender():
        try:
            with prepared["factory"].begin() as session:
                _effect(session, prepared)
                _receipt(session, prepared)
                _consume(session, prepared)
            return "committed"
        except Exception:
            return "denied"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _item: contender(), range(2)))
    assert sorted(results) == ["committed", "denied"]
    assert _counts(prepared["factory"], prepared["authority"].challenge_id) == ("consumed", 1, 1)


def test_recovery_read_preserves_wire_without_authority(database):
    prepared = _prepare(database)
    with prepared["factory"].begin() as session:
        _effect(session, prepared)
        committed = _receipt(session, prepared)
        _consume(session, prepared)
    with prepared["factory"].begin() as session:
        recovered = receipt_storage.SqlAlchemyEnrollmentAdmissionReceiptStore(session).read_by_challenge_id(
            prepared["authority"].challenge_id
        )
    assert recovered == committed
    assert recovered.receipt_wire == RECEIPT_VECTORS["vectors"]["initial"]["receiptWire"]
    assert recovered.bearer_authority == recovered.reexecution_authority == "none"


def test_migration_is_transactional(database):
    engine, _factory = database
    with engine.connect() as connection:
        transaction = connection.begin()
        _apply(connection, RECEIPT_MIGRATION)
        assert connection.execute(text("SELECT to_regclass(:name)"), {"name": receipt_storage.TABLE}).scalar_one()
        transaction.rollback()
    with engine.connect() as connection:
        assert (
            connection.execute(text("SELECT to_regclass(:name)"), {"name": receipt_storage.TABLE}).scalar_one() is None
        )
