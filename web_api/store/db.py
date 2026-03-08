"""Database engine initialisation.

Uses DATABASE_URL env var (Postgres on Railway, SQLite fallback for local dev).
Safe to import even when DATABASE_URL is unset – engine creation is lazy.
"""

import os
import logging

from sqlalchemy import create_engine, MetaData, event

logger = logging.getLogger("web_api.store")

metadata = MetaData()

_engine = None


def _default_url() -> str:
    """Return a SQLite file URL as the local-dev fallback."""
    base = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    db_dir = os.path.join(base, "data")
    os.makedirs(db_dir, exist_ok=True)
    return f"sqlite:///{os.path.join(db_dir, 'vpt_app.db')}"


def get_engine():
    """Return (and cache) the global SQLAlchemy engine."""
    global _engine
    if _engine is not None:
        return _engine

    url = os.environ.get("DATABASE_URL") or _default_url()

    # Railway Postgres URLs sometimes use postgres:// instead of postgresql://
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)

    logger.info("Connecting to database: %s", url.split("@")[-1] if "@" in url else url)

    kwargs = {}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}

        def _set_sqlite_pragma(dbapi_conn, connection_record):
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

        _engine = create_engine(url, echo=False, future=True, **kwargs)
        event.listen(_engine, "connect", _set_sqlite_pragma)
    else:
        _engine = create_engine(
            url, echo=False, future=True, pool_size=5, max_overflow=10
        )

    return _engine


def get_connection():
    """Convenience: return a new connection from the engine."""
    return get_engine().connect()
