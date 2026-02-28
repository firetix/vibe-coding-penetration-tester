"""SQLAlchemy Core table definitions for the app database.

These are used by the migration runner for reference and by store modules
for query building.  The actual DDL lives in the .sql migration files.
"""

from sqlalchemy import (
    Table,
    Column,
    String,
    Text,
    Integer,
    DateTime,
    ForeignKey,
    func,
)

from web_api.store.db import metadata

users = Table(
    "users",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("supabase_user_id", String(255), unique=True, nullable=False),
    Column("email", String(255), nullable=True),
    Column("display_name", String(255), nullable=True),
    Column("created_at", DateTime, server_default=func.now(), nullable=False),
    Column("updated_at", DateTime, server_default=func.now(), onupdate=func.now()),
)

scans = Table(
    "scans",
    metadata,
    Column("id", String(36), primary_key=True),  # UUID
    Column("user_id", Integer, ForeignKey("users.id"), nullable=False),
    Column("target_url", Text, nullable=False),
    Column("scan_mode", String(32), nullable=False, server_default="quick"),
    Column("status", String(32), nullable=False, server_default="pending"),
    Column("created_at", DateTime, server_default=func.now(), nullable=False),
    Column("updated_at", DateTime, server_default=func.now(), onupdate=func.now()),
)

scan_events = Table(
    "scan_events",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("scan_id", String(36), ForeignKey("scans.id"), nullable=False),
    Column("event_type", String(64), nullable=False),
    Column("data", Text, nullable=True),  # JSON blob
    Column("created_at", DateTime, server_default=func.now(), nullable=False),
)

findings = Table(
    "findings",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("scan_id", String(36), ForeignKey("scans.id"), nullable=False),
    Column("title", String(512), nullable=False),
    Column("severity", String(32), nullable=True),
    Column("detail", Text, nullable=True),
    Column("created_at", DateTime, server_default=func.now(), nullable=False),
)
