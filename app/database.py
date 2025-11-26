"""
Database connection and session management for HODLXXI.

Production-grade PostgreSQL and Redis connections with pooling.
"""

from flask import g
import sqlite3  # or your actual DB engine

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect('/srv/ubid/ubid.db')  # or your actual DB path
    return g.db

import logging
import os
from contextlib import contextmanager
from typing import Generator, Optional

import redis
from sqlalchemy import create_engine, event, exc
from sqlalchemy.orm import Session, scoped_session, sessionmaker
from sqlalchemy.pool import Pool

from app.config import get_config
from app.models import Base

logger = logging.getLogger(__name__)

# Global database engine and session factory
_engine = None
_SessionFactory = None
_redis_client = None


def get_database_url() -> str:
    """
    Get database URL from configuration.

    Returns:
        Database connection URL
    """
    config = get_config()
    db_url = config.get("DATABASE_URL")

    if not db_url:
        # Build from components if DATABASE_URL not provided
        db_host = config.get("DB_HOST", "localhost")
        db_port = config.get("DB_PORT", "5432")
        db_user = config.get("DB_USER", "hodlxxi")
        db_password = config.get("DB_PASSWORD", "hodlxxi")
        db_name = config.get("DB_NAME", "hodlxxi")

        db_url = f"postgresql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"

    return db_url


def init_database(echo: bool = False, create_tables: bool = False) -> None:
    """
    Initialize database engine and session factory.

    Args:
        echo: If True, log all SQL statements
        create_tables: If True, create all tables (not recommended for production - use migrations)
    """
    global _engine, _SessionFactory

    if _engine is not None:
        logger.warning("Database already initialized")
        return

    db_url = get_database_url()

    engine_kwargs = {
        "echo": echo,
        "pool_pre_ping": True,
    }

    if db_url.startswith("sqlite"):
        # SQLite (especially in-memory) doesn't support the same pooling args
        # as PostgreSQL. Use a simple engine configuration suitable for tests.
        engine_kwargs["connect_args"] = {"check_same_thread": False}
    else:
        engine_kwargs.update(
            {
                "pool_size": 10,
                "max_overflow": 20,
                "pool_recycle": 3600,
                "connect_args": {"connect_timeout": 10, "options": "-c timezone=utc"},
            }
        )

    # Create engine with appropriate configuration for the backend
    _engine = create_engine(db_url, **engine_kwargs)

    # Add connection pool listeners for better error handling
    @event.listens_for(Pool, "connect")
    def receive_connect(dbapi_conn, connection_record):
        """Handle new database connections."""
        logger.debug("New database connection established")

    @event.listens_for(Pool, "checkout")
    def receive_checkout(dbapi_conn, connection_record, connection_proxy):
        """Handle connection checkout from pool."""
        pass

    @event.listens_for(Pool, "checkin")
    def receive_checkin(dbapi_conn, connection_record):
        """Handle connection checkin to pool."""
        pass

    # Create session factory with scoped sessions (thread-safe)
    session_factory = sessionmaker(bind=_engine)
    _SessionFactory = scoped_session(session_factory)

    # Create tables if requested (use migrations in production)
    if create_tables:
        logger.warning("Creating database tables - use Alembic migrations in production!")
        Base.metadata.create_all(_engine)

    logger.info(f"Database initialized: {db_url.split('@')[1] if '@' in db_url else 'memory'}")


def get_session() -> Session:
    """
    Get a database session.

    Returns:
        SQLAlchemy session instance

    Raises:
        RuntimeError: If database not initialized
    """
    if _SessionFactory is None:
        raise RuntimeError("Database not initialized. Call init_database() first.")

    return _SessionFactory()


@contextmanager
def session_scope() -> Generator[Session, None, None]:
    """
    Provide a transactional scope for database operations.

    Usage:
        with session_scope() as session:
            user = session.query(User).filter_by(id=user_id).first()
            session.add(new_object)
            # Automatically commits on success, rolls back on error

    Yields:
        Database session
    """
    session = get_session()
    try:
        yield session
        session.commit()
    except Exception as e:
        session.rollback()
        logger.error(f"Database transaction failed: {e}")
        raise
    finally:
        session.close()


def close_database() -> None:
    """
    Close database connections and clean up.
    """
    global _engine, _SessionFactory

    if _SessionFactory:
        _SessionFactory.remove()
        _SessionFactory = None

    if _engine:
        _engine.dispose()
        _engine = None

    logger.info("Database connections closed")


def check_database_health() -> dict:
    """
    Check database connection health.

    Returns:
        Dictionary with health status
    """
    try:
        with session_scope() as session:
            # Simple query to test connection
            session.execute("SELECT 1")

        return {"status": "healthy", "database": "postgresql", "connected": True}
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return {"status": "unhealthy", "database": "postgresql", "connected": False, "error": str(e)}


# ============================================================================
# Redis Connection Management
# ============================================================================


def init_redis() -> None:
    """
    Initialize Redis connection for sessions and caching.
    """
    global _redis_client

    if _redis_client is not None:
        logger.warning("Redis already initialized")
        return

    config = get_config()

    redis_host = config.get("REDIS_HOST", "localhost")
    redis_port = config.get("REDIS_PORT", 6379)
    redis_password = config.get("REDIS_PASSWORD")
    redis_db = config.get("REDIS_DB", 0)

    try:
        _redis_client = redis.Redis(
            host=redis_host,
            port=redis_port,
            password=redis_password,
            db=redis_db,
            decode_responses=True,  # Return strings instead of bytes
            socket_connect_timeout=5,
            socket_timeout=5,
            max_connections=50,
            health_check_interval=30,
        )

        # Test connection
        _redis_client.ping()

        logger.info(f"Redis initialized: {redis_host}:{redis_port}")
    except Exception as e:
        logger.error(f"Failed to initialize Redis: {e}")
        logger.warning("Falling back to in-memory session storage")
        _redis_client = None


def get_redis() -> Optional[redis.Redis]:
    """
    Get Redis client instance.

    Returns:
        Redis client or None if not available
    """
    return _redis_client


def close_redis() -> None:
    """
    Close Redis connection.
    """
    global _redis_client

    if _redis_client:
        _redis_client.close()
        _redis_client = None
        logger.info("Redis connection closed")


def check_redis_health() -> dict:
    """
    Check Redis connection health.

    Returns:
        Dictionary with health status
    """
    if _redis_client is None:
        return {"status": "unavailable", "cache": "redis", "connected": False, "error": "Redis not initialized"}

    try:
        _redis_client.ping()

        # Get some stats
        info = _redis_client.info()

        return {
            "status": "healthy",
            "cache": "redis",
            "connected": True,
            "version": info.get("redis_version"),
            "uptime_seconds": info.get("uptime_in_seconds"),
            "connected_clients": info.get("connected_clients"),
            "used_memory_human": info.get("used_memory_human"),
        }
    except Exception as e:
        logger.error(f"Redis health check failed: {e}")
        return {"status": "unhealthy", "cache": "redis", "connected": False, "error": str(e)}


# ============================================================================
# Utility Functions
# ============================================================================


def execute_raw_sql(sql: str, params: dict = None) -> list:
    """
    Execute raw SQL query (use with caution).

    Args:
        sql: SQL query string
        params: Query parameters

    Returns:
        List of result rows
    """
    with session_scope() as session:
        result = session.execute(sql, params or {})
        return result.fetchall()


def get_table_count(table_name: str) -> int:
    """
    Get row count for a table.

    Args:
        table_name: Name of the table

    Returns:
        Number of rows
    """
    sql = f"SELECT COUNT(*) FROM {table_name}"
    result = execute_raw_sql(sql)
    return result[0][0] if result else 0


def vacuum_database() -> None:
    """
    Vacuum database to reclaim space and update statistics.

    Note: This should be run during maintenance windows.
    """
    with session_scope() as session:
        session.execute("VACUUM ANALYZE")
    logger.info("Database vacuumed")


# ============================================================================
# Initialization Helper
# ============================================================================


def init_all(echo: bool = False, create_tables: bool = False) -> None:
    """
    Initialize both database and Redis.

    Args:
        echo: If True, log all SQL statements
        create_tables: If True, create database tables
    """
    if not create_tables:
        try:
            if get_database_url().startswith("sqlite"):
                create_tables = True
        except Exception:
            # If configuration loading fails we fall back to the provided flag
            pass

    init_database(echo=echo, create_tables=create_tables)
    init_redis()

    logger.info("All database connections initialized")


def close_all() -> None:
    """
    Close all database connections.
    """
    close_database()
    close_redis()

    logger.info("All database connections closed")


def get_health_status() -> dict:
    """
    Get health status of all database connections.

    Returns:
        Dictionary with health status
    """
    return {"database": check_database_health(), "redis": check_redis_health()}
