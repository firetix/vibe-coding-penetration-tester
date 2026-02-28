"""Lightweight migration runner.

Applies .sql files from the migrations/ directory in filename order and
records each applied migration in a _migrations table.  Safe to call on
every app startup (idempotent).
"""

import os
import logging

from sqlalchemy import text

from web_api.store.db import get_engine

logger = logging.getLogger("web_api.store.migrator")

MIGRATIONS_DIR = os.path.join(os.path.dirname(__file__), "migrations")


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

    sql_files = sorted(
        f for f in os.listdir(MIGRATIONS_DIR) if f.endswith(".sql")
    )

    if not sql_files:
        logger.info("No migration files found in %s", MIGRATIONS_DIR)
        return

    with engine.begin() as conn:
        _ensure_migrations_table(conn)

    with engine.begin() as conn:
        applied = _applied_migrations(conn)

        for filename in sql_files:
            if filename in applied:
                continue

            filepath = os.path.join(MIGRATIONS_DIR, filename)
            logger.info("Applying migration: %s", filename)

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
                {"name": filename},
            )
            logger.info("Applied migration: %s", filename)
