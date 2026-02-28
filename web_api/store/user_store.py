"""User persistence – maps Supabase user IDs to internal user records."""

import logging

from sqlalchemy import select, insert

from web_api.store.db import get_engine
from web_api.store.schema import users

logger = logging.getLogger("web_api.store.user_store")


def get_or_create_user(supabase_user_id: str, email: str = None, display_name: str = None) -> dict:
    """Look up a user by Supabase ID; create if not found.

    Returns a dict with keys: id, supabase_user_id, email, display_name, created_at.
    """
    engine = get_engine()

    with engine.begin() as conn:
        row = conn.execute(
            select(users).where(users.c.supabase_user_id == supabase_user_id)
        ).first()

        if row is not None:
            return dict(row._mapping)

        conn.execute(
            insert(users).values(
                supabase_user_id=supabase_user_id,
                email=email,
                display_name=display_name,
            )
        )

        row = conn.execute(
            select(users).where(users.c.supabase_user_id == supabase_user_id)
        ).first()

        logger.info("Created internal user id=%s for supabase_user_id=%s", row.id, supabase_user_id)
        return dict(row._mapping)


def get_user_by_id(user_id: int) -> dict | None:
    """Fetch a user by internal ID."""
    engine = get_engine()
    with engine.connect() as conn:
        row = conn.execute(select(users).where(users.c.id == user_id)).first()
        return dict(row._mapping) if row else None
