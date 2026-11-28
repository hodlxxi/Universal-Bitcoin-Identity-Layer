"""Rehearse the nonce migration on an explicitly provisioned, empty PG16 cluster."""

import base64
import hashlib
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import URL
from sqlalchemy.orm import sessionmaker

from app import database
from app.db_storage import create_user, get_oauth_code
from app.models import Base, OAuthClient, OAuthToken, User


@pytest.fixture
def migration_engine(monkeypatch):
    configured_root = os.environ.get("HODLXXI_B02A_PG_ROOT")
    if not configured_root:
        pytest.skip("B02A requires a fresh socket-only PostgreSQL 16 cluster")
    root = Path(configured_root).resolve()
    assert root.parent == Path("/tmp") and root.name.startswith("hodlxxi-b02a-pg.")
    socket = root / "socket"
    dsn = URL.create(
        "postgresql+psycopg",
        username="b02a_test",
        database="hodlxxi_b02a_test",
        query={"host": str(socket), "port": "55491"},
    )
    engine = create_engine(dsn)
    try:
        with engine.connect() as connection:
            identity = connection.execute(
                text(
                    "SELECT current_database(), current_setting('data_directory'), "
                    "current_setting('unix_socket_directories'), current_setting('listen_addresses'), "
                    "current_setting('port'), current_setting('server_version_num')"
                )
            ).one()
            assert tuple(identity[:5]) == ("hodlxxi_b02a_test", str(root / "data"), str(socket), "", "55491")
            assert 160000 <= int(identity[5]) < 170000
            assert inspect(connection).get_table_names(schema="public") == []
        monkeypatch.setattr(database, "_engine", engine)
        monkeypatch.setattr(database, "_SessionFactory", sessionmaker(bind=engine))
        yield engine
    finally:
        engine.dispose()


def test_nullable_nonce_migration_preserves_old_oauth_codes_and_redemption(client, migration_engine):
    engine = migration_engine
    migration = Path(__file__).resolve().parents[2] / "migrations/2026-11-28_oauth_code_nonce.sql"
    with engine.begin() as connection:
        Base.metadata.create_all(connection, tables=[User.__table__, OAuthClient.__table__, OAuthToken.__table__])
        # Pinned pre-migration OAuthCode column, FK and index definitions.
        connection.exec_driver_sql("""
            CREATE TABLE public.oauth_codes (
                code VARCHAR(255) PRIMARY KEY,
                client_id VARCHAR(255) NOT NULL REFERENCES public.oauth_clients(client_id),
                user_id VARCHAR(36) NOT NULL REFERENCES public.users(id),
                redirect_uri TEXT NOT NULL,
                scope TEXT,
                code_challenge VARCHAR(255),
                code_challenge_method VARCHAR(10),
                created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
                expires_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
                is_used BOOLEAN
            );
            CREATE INDEX idx_code_expires ON public.oauth_codes (expires_at);
            CREATE INDEX idx_code_client ON public.oauth_codes (client_id);
        """)

    redirect_uri = "https://app.example.com/callback"
    registration = client.post(
        "/oauth/register", json={"client_name": "Migration fixture", "redirect_uris": [redirect_uri], "scope": "openid"}
    )
    assert registration.status_code == 201
    credentials = registration.get_json()
    user_id = create_user("a" * 64)
    verifier = "v" * 43
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    code = "synthetic-pre-migration-code"
    with engine.begin() as connection:
        connection.execute(
            text("""
                INSERT INTO public.oauth_codes VALUES
                (:code, :client, :user_id, :uri, 'openid', :challenge, 'S256', :now, :expires, false)
            """),
            {
                "code": code,
                "client": credentials["client_id"],
                "user_id": user_id,
                "uri": redirect_uri,
                "challenge": challenge,
                "now": now,
                "expires": now + timedelta(minutes=10),
            },
        )
        before = dict(connection.execute(text("SELECT * FROM public.oauth_codes")).mappings().one())
        schema = inspect(connection)
        keys = schema.get_foreign_keys("oauth_codes")
        primary_key = schema.get_pk_constraint("oauth_codes")
        indexes = schema.get_indexes("oauth_codes")
        connection.exec_driver_sql(migration.read_text(encoding="utf-8"))
        schema.clear_cache()
        nonce = next(column for column in schema.get_columns("oauth_codes") if column["name"] == "nonce")
        assert nonce["nullable"] is True and nonce["default"] is None
        assert schema.get_foreign_keys("oauth_codes") == keys
        assert schema.get_pk_constraint("oauth_codes") == primary_key
        assert schema.get_indexes("oauth_codes") == indexes
        after = dict(connection.execute(text("SELECT * FROM public.oauth_codes")).mappings().one())
        assert after == {**before, "nonce": None}

    assert get_oauth_code(code)["nonce"] is None
    response = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "client_id": credentials["client_id"],
            "client_secret": credentials["client_secret"],
            "redirect_uri": redirect_uri,
            "code": code,
            "code_verifier": verifier,
        },
    )
    assert response.status_code == 200
    assert "nonce" not in jwt.decode(response.get_json()["id_token"], options={"verify_signature": False})
    assert get_oauth_code(code) is None
