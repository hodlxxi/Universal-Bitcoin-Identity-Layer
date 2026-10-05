from types import SimpleNamespace

import app.database as database


class _Result:
    def __init__(self, value=1):
        self.value = value
        self.closed = False

    def scalar_one(self):
        return self.value

    def close(self):
        self.closed = True


class _Transaction:
    def __init__(self):
        self.exit_error = None

    def __enter__(self):
        return self

    def __exit__(self, error_type, error, _traceback):
        self.exit_error = error


class _Connection:
    def __init__(self, *, fail_query=False):
        self.fail_query = fail_query
        self.closed = False
        self.queries = []
        self.results = []
        self.transaction = _Transaction()

    def __enter__(self):
        return self

    def __exit__(self, _error_type, _error, _traceback):
        self.closed = True

    def begin(self):
        return self.transaction

    def exec_driver_sql(self, query):
        self.queries.append(query)
        if self.fail_query and query == "SELECT 1":
            raise RuntimeError("synthetic database failure")
        result = _Result()
        self.results.append(result)
        return result


class _Engine:
    def __init__(self, connection, dialect="postgresql", database_name=None):
        self.connection = connection
        self.dialect = SimpleNamespace(name=dialect)
        self.url = SimpleNamespace(database=database_name)
        self.connect_calls = 0

    def connect(self):
        self.connect_calls += 1
        return self.connection


def _install_owner(monkeypatch, engine, *, configured=True):
    monkeypatch.setattr(database, "_engine", engine)
    monkeypatch.setattr(database, "_database_configuration_explicit", configured)


def test_postgresql_readiness_is_bounded_and_releases_every_resource(monkeypatch):
    connection = _Connection()
    engine = _Engine(connection)
    _install_owner(monkeypatch, engine)

    assert database.check_configured_database_readiness() is True
    assert engine.connect_calls == 1
    assert connection.queries == [
        f"SET LOCAL statement_timeout = {database.DATABASE_STATEMENT_TIMEOUT_MS}",
        "SELECT 1",
    ]
    assert all(result.closed for result in connection.results)
    assert connection.transaction.exit_error is None
    assert connection.closed is True


def test_postgresql_readiness_failure_releases_connection_and_transaction(monkeypatch):
    connection = _Connection(fail_query=True)
    engine = _Engine(connection)
    _install_owner(monkeypatch, engine)

    assert database.check_configured_database_readiness() is False
    assert connection.results[0].closed is True
    assert isinstance(connection.transaction.exit_error, RuntimeError)
    assert connection.closed is True


def test_readiness_fails_closed_for_missing_malformed_or_implicit_owner(monkeypatch):
    monkeypatch.setattr(database, "_engine", None)
    monkeypatch.setattr(database, "_database_configuration_explicit", True)
    assert database.check_configured_database_readiness() is False

    connection = _Connection()
    implicit_engine = _Engine(connection)
    _install_owner(monkeypatch, implicit_engine, configured=False)
    assert database.check_configured_database_readiness() is False
    assert implicit_engine.connect_calls == 0

    malformed_engine = SimpleNamespace(dialect=SimpleNamespace(name="unknown"))
    _install_owner(monkeypatch, malformed_engine)
    assert database.check_configured_database_readiness() is False


def test_database_configuration_must_be_explicit_and_complete():
    assert database._has_explicit_database_configuration({}) is False
    assert (
        database._has_explicit_database_configuration(
            {
                "DB_HOST": "127.0.0.1",
                "DB_PORT": 5432,
                "DB_USER": "test",
                "DB_PASSWORD": None,
                "DB_NAME": "test",
            }
        )
        is False
    )
    assert database._has_explicit_database_configuration({"DATABASE_URL": "sqlite:///:memory:"}) is True
    assert (
        database._has_explicit_database_configuration(
            {
                "DB_HOST": "127.0.0.1",
                "DB_PORT": 5432,
                "DB_USER": "test",
                "DB_PASSWORD": "test",
                "DB_NAME": "test",
            }
        )
        is True
    )


def test_sqlite_in_memory_configured_owner_is_supported_without_postgresql_sql(monkeypatch):
    connection = _Connection()
    engine = _Engine(connection, dialect="sqlite", database_name=":memory:")
    _install_owner(monkeypatch, engine)

    assert database.check_configured_database_readiness() is True
    assert connection.queries == ["SELECT 1"]
    assert connection.results[0].closed is True
    assert connection.closed is True


def test_file_backed_sqlite_owner_is_rejected_before_connection(monkeypatch):
    connection = _Connection()
    engine = _Engine(connection, dialect="sqlite", database_name="/srv/ubid/ubid.db")
    _install_owner(monkeypatch, engine)

    assert database.check_configured_database_readiness() is False
    assert engine.connect_calls == 0


def test_postgresql_engine_configuration_bounds_connect_pool_and_statements():
    options = database._database_engine_kwargs(echo=False, is_sqlite=False)

    assert options["pool_timeout"] == database.DATABASE_POOL_TIMEOUT_SECONDS == 3
    assert options["connect_args"]["connect_timeout"] == database.DATABASE_CONNECT_TIMEOUT_SECONDS == 3
    assert options["connect_args"]["options"] == "-c timezone=utc -c statement_timeout=3000"
    assert options["pool_pre_ping"] is True


def test_database_initialization_is_lazy_and_records_explicit_configuration(monkeypatch):
    calls = []
    fake_engine = SimpleNamespace()
    monkeypatch.setattr(database, "_engine", None)
    monkeypatch.setattr(database, "_SessionFactory", None)
    monkeypatch.setattr(database, "_database_configuration_explicit", False)
    monkeypatch.setattr(database, "get_config", lambda: {"DATABASE_URL": "sqlite:///:memory:"})
    monkeypatch.setattr(
        database,
        "create_engine",
        lambda url, **kwargs: calls.append((url, kwargs)) or fake_engine,
    )

    database.init_database()

    assert calls == [
        (
            "sqlite:///:memory:",
            {
                "echo": False,
                "pool_pre_ping": True,
                "pool_reset_on_return": None,
                "connect_args": {"check_same_thread": False},
            },
        )
    ]
    assert database._engine is fake_engine
    assert database._database_configuration_explicit is True
