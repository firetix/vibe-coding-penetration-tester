import threading
import time
import uuid
from typing import Any, Dict, Optional


class InMemorySaaSStore:
    """Fallback SaaS ownership store for non-Postgres local/dev usage."""

    def __init__(self):
        self._lock = threading.Lock()
        self._users: Dict[str, Dict[str, Any]] = {}
        self._user_org: Dict[str, str] = {}
        self._memberships: Dict[str, Dict[str, str]] = {}
        self._scans: Dict[str, Dict[str, Any]] = {}

    def ensure_user_org(self, user_id: str, email: Optional[str] = None) -> Dict[str, str]:
        with self._lock:
            if user_id not in self._users:
                self._users[user_id] = {
                    "id": user_id,
                    "email": email,
                    "created_at": time.time(),
                }
            elif email and not self._users[user_id].get("email"):
                self._users[user_id]["email"] = email

            org_id = self._user_org.get(user_id)
            if not org_id:
                org_id = str(uuid.uuid4())
                self._user_org[user_id] = org_id

            org_members = self._memberships.setdefault(org_id, {})
            org_members[user_id] = "owner"
            return {"user_id": user_id, "org_id": org_id}

    def create_scan(
        self,
        org_id: str,
        created_by_user_id: str,
        target_url: str,
        mode: str,
        session_id: str,
        legacy_scan_id: str,
    ) -> str:
        with self._lock:
            scan_id = str(uuid.uuid4())
            self._scans[scan_id] = {
                "id": scan_id,
                "org_id": org_id,
                "created_by_user_id": created_by_user_id,
                "target_url": target_url,
                "mode": mode,
                "session_id": session_id,
                "legacy_scan_id": legacy_scan_id,
                "created_at": time.time(),
            }
            return scan_id

    def get_scan_for_user(self, scan_id: str, user_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            scan = self._scans.get(scan_id)
            if not scan:
                return None
            org_members = self._memberships.get(scan["org_id"], {})
            if user_id not in org_members:
                return None
            return dict(scan)


class PostgresSaaSStore:
    """Postgres-backed SaaS ownership store (Supabase-compatible)."""

    def __init__(self, db_url: str):
        self.db_url = db_url
        self._lock = threading.Lock()
        self._init_schema()

    def _connect(self):
        try:
            import psycopg  # type: ignore
            from psycopg.rows import dict_row  # type: ignore
        except Exception as exc:  # pragma: no cover - optional dependency
            raise RuntimeError(
                "PostgresSaaSStore requires psycopg. Install with: pip install 'psycopg[binary]'"
            ) from exc
        return psycopg.connect(self.db_url, row_factory=dict_row)

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    email TEXT,
                    created_at DOUBLE PRECISION NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS orgs (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    created_at DOUBLE PRECISION NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS memberships (
                    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
                    role TEXT NOT NULL,
                    created_at DOUBLE PRECISION NOT NULL,
                    PRIMARY KEY (user_id, org_id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS saas_scans (
                    id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
                    created_by_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    target_url TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    legacy_scan_id TEXT NOT NULL,
                    created_at DOUBLE PRECISION NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_memberships_user ON memberships(user_id)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_saas_scans_org_created ON saas_scans(org_id, created_at DESC)"
            )
            conn.commit()

    def ensure_user_org(self, user_id: str, email: Optional[str] = None) -> Dict[str, str]:
        now = time.time()
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO users(id, email, created_at)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (id) DO UPDATE SET
                        email = COALESCE(users.email, EXCLUDED.email)
                    """,
                    (user_id, email, now),
                )

                membership = conn.execute(
                    """
                    SELECT org_id
                    FROM memberships
                    WHERE user_id = %s
                    ORDER BY created_at ASC
                    LIMIT 1
                    """,
                    (user_id,),
                ).fetchone()
                if membership and membership.get("org_id"):
                    conn.commit()
                    return {"user_id": user_id, "org_id": str(membership["org_id"])}

                org_id = str(uuid.uuid4())
                org_name = f"{(email or user_id)[:32]} workspace"
                conn.execute(
                    "INSERT INTO orgs(id, name, created_at) VALUES (%s, %s, %s)",
                    (org_id, org_name, now),
                )
                conn.execute(
                    """
                    INSERT INTO memberships(user_id, org_id, role, created_at)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (user_id, org_id) DO NOTHING
                    """,
                    (user_id, org_id, "owner", now),
                )
                conn.commit()
                return {"user_id": user_id, "org_id": org_id}

    def create_scan(
        self,
        org_id: str,
        created_by_user_id: str,
        target_url: str,
        mode: str,
        session_id: str,
        legacy_scan_id: str,
    ) -> str:
        now = time.time()
        scan_id = str(uuid.uuid4())
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO saas_scans(
                    id, org_id, created_by_user_id, target_url, mode, session_id, legacy_scan_id, created_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    scan_id,
                    org_id,
                    created_by_user_id,
                    target_url,
                    mode,
                    session_id,
                    legacy_scan_id,
                    now,
                ),
            )
            conn.commit()
        return scan_id

    def get_scan_for_user(self, scan_id: str, user_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT s.id, s.org_id, s.created_by_user_id, s.target_url, s.mode, s.session_id, s.legacy_scan_id, s.created_at
                FROM saas_scans s
                INNER JOIN memberships m ON m.org_id = s.org_id
                WHERE s.id = %s AND m.user_id = %s
                LIMIT 1
                """,
                (scan_id, user_id),
            ).fetchone()
        if not row:
            return None
        return dict(row)
