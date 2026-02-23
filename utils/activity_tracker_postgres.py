import json
import logging
import re
import threading
import time
from typing import Any, Dict, List, Optional


class PostgresActivityTracker:
    """Postgres-backed ActivityTracker (Supabase-compatible)."""

    def __init__(self, db_url: str):
        self.db_url = db_url
        self._lock = threading.Lock()
        self._logger = logging.getLogger("web_ui")
        self._init_schema()

    def _connect(self):
        try:
            import psycopg  # type: ignore
            from psycopg.rows import dict_row  # type: ignore
        except Exception as exc:  # pragma: no cover - optional dependency
            raise RuntimeError(
                "PostgresActivityTracker requires psycopg. Install with: pip install 'psycopg[binary]'"
            ) from exc
        return psycopg.connect(self.db_url, row_factory=dict_row)

    def _init_schema(self) -> None:
        with self._connect() as conn:
            # Ensure sessions table exists even if PostgresSessionManager wasn't initialized first.
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    created_at DOUBLE PRECISION NOT NULL,
                    last_activity DOUBLE PRECISION NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS activities (
                    id BIGSERIAL PRIMARY KEY,
                    session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
                    timestamp DOUBLE PRECISION NOT NULL,
                    time_text TEXT NOT NULL,
                    type TEXT NOT NULL,
                    description TEXT NOT NULL,
                    agent TEXT,
                    details JSONB
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_activities_session_time ON activities(session_id, id DESC)"
            )
            conn.commit()

    def _clean_description(self, description: str) -> str:
        description = (description or "").strip()
        description = re.sub(r"\s*Activity\s*$", "", description)
        description = re.sub(r"\'}]\}.*?$", "", description)
        description = re.sub(
            r"(\(Agent:\s*[^)]+\))\s*(\(Agent:.*?\))+", r"\1", description
        )
        return description

    def _coerce_json(self, value: Any, default: Any) -> Any:
        if value is None:
            return default
        if isinstance(value, (dict, list)):
            return value
        if isinstance(value, (bytes, bytearray)):
            try:
                value = value.decode("utf-8", errors="ignore")
            except Exception:
                return default
        if isinstance(value, str):
            try:
                return json.loads(value)
            except Exception:
                return default
        return default

    def _is_duplicate_activity(
        self,
        conn,
        session_id: str,
        activity_type: str,
        description: str,
        agent_name: Optional[str],
    ) -> Optional[Dict[str, Any]]:
        # Mimic in-memory tracker: last 10 activities, 5s window.
        recent_timeframe = 5.0
        now = time.time()
        rows = conn.execute(
            """
            SELECT id, timestamp, time_text, type, description, agent, details
            FROM activities
            WHERE session_id = %s
            ORDER BY id DESC
            LIMIT 10
            """,
            (session_id,),
        ).fetchall()

        description_fingerprint = (
            description[-100:] if len(description) > 100 else description
        )

        for row in rows:
            if now - float(row.get("timestamp") or 0) > recent_timeframe:
                continue
            if row.get("type") != activity_type:
                continue
            existing_desc = row.get("description") or ""
            existing_fingerprint = (
                existing_desc[-100:] if len(existing_desc) > 100 else existing_desc
            )
            if existing_fingerprint == description_fingerprint and row.get("agent") == agent_name:
                payload = dict(row)
                payload["details"] = self._coerce_json(payload.get("details"), {})
                return payload
        return None

    def _prune_activities(self, conn, session_id: str) -> None:
        # Keep the newest 200.
        conn.execute(
            """
            DELETE FROM activities
            WHERE session_id = %s
              AND id NOT IN (
                SELECT id FROM activities
                WHERE session_id = %s
                ORDER BY id DESC
                LIMIT 200
              )
            """,
            (session_id, session_id),
        )

    def add_activity(
        self,
        session_id: str,
        activity_type: str,
        description: str,
        details: Optional[Dict[str, Any]] = None,
        agent_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        description = self._clean_description(description)
        now = time.time()
        time_text = time.strftime("%H:%M:%S")

        with self._lock:
            with self._connect() as conn:
                # Ensure session row exists so the FK does not fail.
                conn.execute(
                    """
                    INSERT INTO sessions(session_id, created_at, last_activity)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (session_id) DO NOTHING
                    """,
                    (session_id, now, now),
                )
                dup = self._is_duplicate_activity(
                    conn, session_id, activity_type, description, agent_name
                )
                if dup is not None:
                    conn.commit()
                    return dup

                conn.execute(
                    """
                    INSERT INTO activities(session_id, timestamp, time_text, type, description, agent, details)
                    VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb)
                    """,
                    (
                        session_id,
                        now,
                        time_text,
                        activity_type,
                        description,
                        agent_name,
                        json.dumps(details or {}),
                    ),
                )
                self._prune_activities(conn, session_id)
                conn.commit()

        activity = {
            "timestamp": now,
            "time": time_text,
            "type": activity_type,
            "description": description,
            "agent": agent_name,
        }
        if details:
            activity["details"] = details
        return activity

    def get_activities(self, session_id: str) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT timestamp, time_text, type, description, agent, details
                FROM activities
                WHERE session_id = %s
                ORDER BY id ASC
                """,
                (session_id,),
            ).fetchall()

        activities: List[Dict[str, Any]] = []
        for row in rows:
            payload = {
                "timestamp": row.get("timestamp"),
                "time": row.get("time_text"),
                "type": row.get("type"),
                "description": row.get("description"),
                "agent": row.get("agent"),
            }
            details = self._coerce_json(row.get("details"), None)
            if details is not None:
                payload["details"] = details
            activities.append(payload)
        return activities

    def clear_activities(self, session_id: str) -> None:
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "DELETE FROM activities WHERE session_id = %s",
                    (session_id,),
                )
                conn.commit()
