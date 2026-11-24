"""Fence destructive Canon V2 fixtures to CI or an explicitly marked PG16 instance."""

import os

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

DISPOSABLE_MARKER = "hodlxxi-canon-v2-disposable-pg16-v1"


def disposable_postgres_engine(url):
    parsed = make_url(url)
    configured_port = os.environ.get("CANON_V2_DISPOSABLE_PG_PORT", "")
    if (
        os.environ.get("CANON_V2_DISPOSABLE_PG_ACK") != "1"
        or not configured_port.isascii()
        or not configured_port.isdecimal()
        or not 1024 <= int(configured_port) <= 65535
        or int(configured_port) == 5432
        or parsed.drivername != "postgresql+psycopg2"
        or parsed.host not in ("localhost", "127.0.0.1")
        or parsed.port != int(configured_port)
        or parsed.username != "canonv2test"
        or parsed.database != "canonv2test"
        or parsed.query
    ):
        raise RuntimeError("refuse_non_disposable_postgres_target")
    engine = create_engine(url, future=True, pool_pre_ping=True)
    try:
        with engine.connect() as connection:
            connection.execute(text("SET TRANSACTION READ ONLY"))
            version = int(connection.execute(text("SHOW server_version_num")).scalar_one())
            if not 160000 <= version < 170000:
                raise RuntimeError("disposable_postgres_16_required")
            marker = connection.execute(
                text("SELECT shobj_description(oid, 'pg_database') FROM pg_database WHERE datname=current_database()")
            ).scalar_one()
            if marker != DISPOSABLE_MARKER:
                raise RuntimeError("refuse_unmarked_disposable_postgres")
        return engine
    except BaseException:
        engine.dispose()
        raise
