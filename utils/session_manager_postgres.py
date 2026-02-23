import json
import threading
import time
import uuid
import logging
from typing import Any, Dict, List, Optional


class PostgresSessionManager:
    """Postgres-backed session + scan state storage (Supabase-compatible)."""

    TERMINAL_STATUSES = {"completed", "error", "cancelled"}

    def __init__(self, db_url: str):
        self.db_url = db_url
        self.lock = threading.Lock()
        self.logger = logging.getLogger("web_ui")
        self._init_schema()

    def _connect(self):
        try:
            import psycopg  # type: ignore
            from psycopg.rows import dict_row  # type: ignore
        except Exception as exc:  # pragma: no cover - optional dependency
            raise RuntimeError(
                "PostgresSessionManager requires psycopg. Install with: pip install 'psycopg[binary]'"
            ) from exc
        return psycopg.connect(self.db_url, row_factory=dict_row)

    def _init_schema(self) -> None:
        with self._connect() as conn:
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
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
                    url TEXT NOT NULL,
                    config JSONB NOT NULL DEFAULT '{}'::jsonb,
                    started_at DOUBLE PRECISION NOT NULL,
                    status TEXT NOT NULL,
                    progress INTEGER NOT NULL DEFAULT 0,
                    report_dir TEXT,
                    vulnerabilities JSONB NOT NULL DEFAULT '[]'::jsonb,
                    action_plan JSONB NOT NULL DEFAULT '[]'::jsonb,
                    current_task TEXT,
                    completed_at DOUBLE PRECISION
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_scans_session_started ON scans(session_id, started_at DESC)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_scans_session_completed ON scans(session_id, completed_at DESC)"
            )
            conn.commit()

    def _ensure_session_locked(self, conn, session_id: str) -> None:
        now = time.time()
        conn.execute(
            """
            INSERT INTO sessions(session_id, created_at, last_activity)
            VALUES (%s, %s, %s)
            ON CONFLICT (session_id) DO NOTHING
            """,
            (session_id, now, now),
        )

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

    def create_session(self) -> str:
        session_id = str(uuid.uuid4())
        now = time.time()
        with self.lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO sessions(session_id, created_at, last_activity)
                    VALUES (%s, %s, %s)
                    """,
                    (session_id, now, now),
                )
                conn.commit()
        return session_id

    def check_session(self, session_id: str) -> bool:
        now = time.time()
        with self.lock:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT 1 FROM sessions WHERE session_id = %s",
                    (session_id,),
                ).fetchone()
                if not row:
                    conn.commit()
                    return False
                conn.execute(
                    "UPDATE sessions SET last_activity = %s WHERE session_id = %s",
                    (now, session_id),
                )
                conn.commit()
                return True

    def get_all_sessions(self) -> List[str]:
        with self._connect() as conn:
            rows = conn.execute("SELECT session_id FROM sessions").fetchall()
        return [str(r["session_id"]) for r in rows]

    def start_scan(self, session_id: str, url: str, config: Dict[str, Any]) -> str:
        scan_id = str(uuid.uuid4())
        now = time.time()
        with self.lock:
            with self._connect() as conn:
                self._ensure_session_locked(conn, session_id)
                conn.execute(
                    "UPDATE sessions SET last_activity = %s WHERE session_id = %s",
                    (now, session_id),
                )
                conn.execute(
                    """
                    INSERT INTO scans(
                        scan_id, session_id, url, config, started_at, status, progress, report_dir,
                        vulnerabilities, action_plan, current_task, completed_at
                    )
                    VALUES (
                        %s, %s, %s, %s::jsonb, %s, %s, %s, %s,
                        %s::jsonb, %s::jsonb, %s, NULL
                    )
                    """,
                    (
                        scan_id,
                        session_id,
                        url,
                        json.dumps(config or {}),
                        now,
                        "initializing",
                        0,
                        None,
                        json.dumps([]),
                        json.dumps([]),
                        None,
                    ),
                )
                conn.commit()
        return scan_id

    def _scan_row_to_payload(self, scan_id: str, row: Dict[str, Any]) -> Dict[str, Any]:
        payload = dict(row)
        payload["id"] = scan_id
        # Normalize JSON fields to python objects.
        payload["config"] = self._coerce_json(payload.get("config"), {})
        payload["vulnerabilities"] = self._coerce_json(payload.get("vulnerabilities"), [])
        payload["action_plan"] = self._coerce_json(payload.get("action_plan"), [])
        # Match legacy keys.
        if "started_at" in payload and "started" not in payload:
            payload["started"] = payload.get("started_at")
        if "completed_at" in payload and payload.get("completed_at") and "completed" not in payload:
            payload["completed"] = payload.get("completed_at")
        return payload

    def get_active_scan(
        self, session_id: str, scan_id: str
    ) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT url, config, started_at, status, progress, report_dir, vulnerabilities, action_plan, current_task, completed_at
                FROM scans
                WHERE session_id = %s AND scan_id = %s
                """,
                (session_id, scan_id),
            ).fetchone()
        if not row:
            return None
        if row.get("status") in self.TERMINAL_STATUSES or row.get("completed_at"):
            return None
        return self._scan_row_to_payload(scan_id, row)

    def get_active_scans(self, session_id: str) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT scan_id, url, config, started_at, status, progress, report_dir, vulnerabilities, action_plan, current_task, completed_at
                FROM scans
                WHERE session_id = %s AND (completed_at IS NULL) AND status NOT IN ('completed','error','cancelled')
                ORDER BY started_at DESC
                """,
                (session_id,),
            ).fetchall()
        scans = []
        for row in rows:
            scan_id = row.get("scan_id")
            if not scan_id:
                continue
            scans.append(self._scan_row_to_payload(str(scan_id), row))
        return scans

    def update_scan_status(
        self,
        session_id: str,
        scan_id: str,
        status: str,
        progress: int = None,
        report_dir: str = None,
        vulnerabilities: List[Dict[str, Any]] = None,
        action_plan: List[str] = None,
        current_task: str = None,
    ) -> None:
        now = time.time()
        updates = {}
        if status:
            updates["status"] = status
        if progress is not None:
            updates["progress"] = int(progress)
        if report_dir is not None:
            updates["report_dir"] = report_dir
        if vulnerabilities is not None:
            updates["vulnerabilities"] = json.dumps(vulnerabilities)
        if action_plan is not None:
            updates["action_plan"] = json.dumps(action_plan)
        if current_task is not None:
            updates["current_task"] = current_task

        if not updates:
            return

        # Terminal transitions set completed_at.
        if status in self.TERMINAL_STATUSES:
            updates.setdefault("completed_at", now)

        # Build dynamic SQL safely.
        set_clauses = []
        params: List[Any] = []
        for key, value in updates.items():
            if key in {"vulnerabilities", "action_plan"}:
                set_clauses.append(f"{key} = %s::jsonb")
                params.append(value)
            else:
                set_clauses.append(f"{key} = %s")
                params.append(value)
        params.extend([session_id, scan_id])

        with self.lock:
            with self._connect() as conn:
                self._ensure_session_locked(conn, session_id)
                conn.execute(
                    "UPDATE sessions SET last_activity = %s WHERE session_id = %s",
                    (now, session_id),
                )
                conn.execute(
                    f"UPDATE scans SET {', '.join(set_clauses)} WHERE session_id = %s AND scan_id = %s",
                    params,
                )
                conn.commit()

    def get_completed_scans(self, session_id: str) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT scan_id, url, config, started_at, status, progress, report_dir, vulnerabilities, action_plan, current_task, completed_at
                FROM scans
                WHERE session_id = %s AND (completed_at IS NOT NULL OR status IN ('completed','error','cancelled'))
                ORDER BY completed_at DESC NULLS LAST, started_at DESC
                """,
                (session_id,),
            ).fetchall()
        scans = []
        for row in rows:
            scan_id = row.get("scan_id")
            if not scan_id:
                continue
            scans.append(self._scan_row_to_payload(str(scan_id), row))
        return scans

    def cleanup_old_sessions(self, max_age_seconds: int = 3600) -> None:
        cutoff = time.time() - float(max_age_seconds)
        with self.lock:
            with self._connect() as conn:
                conn.execute(
                    "DELETE FROM sessions WHERE last_activity < %s",
                    (cutoff,),
                )
                conn.commit()

