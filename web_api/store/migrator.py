"""Lightweight migration runner.

Applies .sql files from the migrations/ directory in filename order and
records each applied migration in a _migrations table.  Safe to call on
every app startup (idempotent).

File-naming convention for dialect-specific migrations:
    NNN_name.sqlite.sql    – applied only when the engine dialect is SQLite
    NNN_name.postgres.sql  – applied only when the dialect is PostgreSQL
    NNN_name.sql           – applied for every dialect (generic)

The migration name recorded in _migrations strips the dialect suffix so that
e.g. ``001_initial_schema.sqlite.sql`` and ``001_initial_schema.postgres.sql``
share the logical name ``001_initial_schema`` and are never both applied.
"""

import os
import logging

from sqlalchemy import text

from web_api.store.db import get_engine

logger = logging.getLogger("web_api.store.migrator")

MIGRATIONS_DIR = os.path.join(os.path.dirname(__file__), "migrations")

# Map dialect names to the file suffixes they should pick up.
_DIALECT_SUFFIXES = {
    "sqlite": ".sqlite.sql",
    "postgresql": ".postgres.sql",
}


def _logical_name(filename: str) -> str:
    """Return the dialect-agnostic logical migration name.

    ``001_initial_schema.postgres.sql`` → ``001_initial_schema``
    ``002_add_col.sql``                 → ``002_add_col``
    """
    for suffix in (".sqlite.sql", ".postgres.sql"):
        if filename.endswith(suffix):
            return filename[: -len(suffix)]
    # Generic .sql
    return filename.removesuffix(".sql")


def _select_files_for_dialect(dialect_name: str) -> list[str]:
    """Return migration filenames applicable to *dialect_name*, sorted."""
    all_files = [f for f in os.listdir(MIGRATIONS_DIR) if f.endswith(".sql")]

    my_suffix = _DIALECT_SUFFIXES.get(dialect_name)  # e.g. ".sqlite.sql"

    selected: list[str] = []
    for f in all_files:
        is_dialect_specific = any(f.endswith(s) for s in _DIALECT_SUFFIXES.values())
        if is_dialect_specific:
            # Only include if it matches our dialect
            if my_suffix and f.endswith(my_suffix):
                selected.append(f)
        else:
            # Generic .sql → include for all dialects
            selected.append(f)

    return sorted(selected)


def _ensure_migrations_table(conn):
    """Create the bookkeeping table if it doesn't exist."""
    conn.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS _migrations (
                name VARCHAR(255) PRIMARY KEY,
                applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
    )


def _applied_migrations(conn) -> set:
    rows = conn.execute(text("SELECT name FROM _migrations")).fetchall()
    return {row[0] for row in rows}


def run_migrations():
    """Apply any pending .sql migration files."""
    engine = get_engine()
    dialect_name = engine.dialect.name  # "sqlite", "postgresql", etc.

    sql_files = _select_files_for_dialect(dialect_name)

    if not sql_files:
        logger.info("No migration files found in %s for dialect %s", MIGRATIONS_DIR, dialect_name)
        return

    with engine.begin() as conn:
        _ensure_migrations_table(conn)

    with engine.begin() as conn:
        applied = _applied_migrations(conn)

        for filename in sql_files:
            logical = _logical_name(filename)
            if logical in applied:
                continue

            filepath = os.path.join(MIGRATIONS_DIR, filename)
            logger.info("Applying migration: %s (dialect=%s)", filename, dialect_name)

            sql = open(filepath, "r").read()
            # Execute each statement separately (SQLite doesn't support multi-statement)
            for statement in sql.split(";"):
                # Strip comment-only lines and whitespace
                lines = [
                    ln for ln in statement.splitlines()
                    if ln.strip() and not ln.strip().startswith("--")
                ]
                cleaned = "\n".join(lines).strip()
                if cleaned:
                    conn.execute(text(cleaned))

            conn.execute(
                text("INSERT INTO _migrations (name) VALUES (:name)"),
                {"name": logical},
            )
            logger.info("Applied migration: %s", logical)
