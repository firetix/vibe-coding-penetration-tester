"""Scan persistence – CRUD for scans, scan_events, and findings."""

import json
import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import select, insert, update

from web_api.store.db import get_engine
from web_api.store.schema import scans, scan_events, findings

logger = logging.getLogger("web_api.store.scan_store")


def create_scan(user_id: int, target_url: str, scan_mode: str = "quick") -> dict:
    """Insert a new scan row and return it as a dict."""
    scan_id = str(uuid.uuid4())
    engine = get_engine()

    with engine.begin() as conn:
        conn.execute(
            insert(scans).values(
                id=scan_id,
                user_id=user_id,
                target_url=target_url,
                scan_mode=scan_mode,
                status="pending",
            )
        )
        row = conn.execute(select(scans).where(scans.c.id == scan_id)).first()
        return _scan_to_dict(row)


def list_scans(user_id: int) -> list[dict]:
    """Return all scans for a user, most recent first."""
    engine = get_engine()
    with engine.connect() as conn:
        rows = conn.execute(
            select(scans)
            .where(scans.c.user_id == user_id)
            .order_by(scans.c.created_at.desc())
        ).fetchall()
        return [_scan_to_dict(r) for r in rows]


def get_scan(scan_id: str, user_id: int) -> dict | None:
    """Fetch a single scan, scoped to user."""
    engine = get_engine()
    with engine.connect() as conn:
        row = conn.execute(
            select(scans).where(scans.c.id == scan_id, scans.c.user_id == user_id)
        ).first()
        return _scan_to_dict(row) if row else None


def update_scan_status(scan_id: str, status: str) -> None:
    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(
            update(scans)
            .where(scans.c.id == scan_id)
            .values(status=status, updated_at=datetime.now(timezone.utc))
        )


# --- scan events ---


def add_scan_event(scan_id: str, event_type: str, data: dict | None = None) -> dict:
    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(
            insert(scan_events).values(
                scan_id=scan_id,
                event_type=event_type,
                data=json.dumps(data) if data else None,
            )
        )
        row = conn.execute(
            select(scan_events)
            .where(scan_events.c.scan_id == scan_id)
            .order_by(scan_events.c.id.desc())
            .limit(1)
        ).first()
        return _event_to_dict(row)


def list_scan_events(scan_id: str, user_id: int) -> list[dict]:
    """Return events for a scan (validates ownership via join)."""
    engine = get_engine()
    with engine.connect() as conn:
        # Verify scan belongs to user
        scan_row = conn.execute(
            select(scans.c.id).where(scans.c.id == scan_id, scans.c.user_id == user_id)
        ).first()
        if scan_row is None:
            return []

        rows = conn.execute(
            select(scan_events)
            .where(scan_events.c.scan_id == scan_id)
            .order_by(scan_events.c.id.asc())
        ).fetchall()
        return [_event_to_dict(r) for r in rows]


# --- helpers ---


def _scan_to_dict(row) -> dict:
    d = dict(row._mapping)
    for k in ("created_at", "updated_at"):
        if isinstance(d.get(k), datetime):
            d[k] = d[k].isoformat()
    return d


def _event_to_dict(row) -> dict:
    d = dict(row._mapping)
    if d.get("data"):
        try:
            d["data"] = json.loads(d["data"])
        except (json.JSONDecodeError, TypeError):
            pass
    if isinstance(d.get("created_at"), datetime):
        d["created_at"] = d["created_at"].isoformat()
    return d
