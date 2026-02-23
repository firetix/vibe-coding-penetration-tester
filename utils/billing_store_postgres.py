import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional


class PostgresBillingStore:
    """Postgres-backed billing and entitlement persistence (Supabase-compatible)."""

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
                "PostgresBillingStore requires psycopg. Install with: pip install 'psycopg[binary]'"
            ) from exc
        return psycopg.connect(self.db_url, row_factory=dict_row)

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS accounts (
                    account_id TEXT PRIMARY KEY,
                    created_at DOUBLE PRECISION NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS entitlements (
                    account_id TEXT PRIMARY KEY REFERENCES accounts(account_id),
                    free_scans_remaining INTEGER NOT NULL DEFAULT 1,
                    deep_scan_credits INTEGER NOT NULL DEFAULT 0,
                    pro_until TEXT,
                    updated_at DOUBLE PRECISION NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS usage_events (
                    id BIGSERIAL PRIMARY KEY,
                    account_id TEXT,
                    ip TEXT,
                    event_type TEXT NOT NULL,
                    created_at DOUBLE PRECISION NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS checkout_sessions (
                    checkout_session_id TEXT PRIMARY KEY,
                    account_id TEXT NOT NULL,
                    scan_mode TEXT NOT NULL,
                    status TEXT NOT NULL,
                    price_id TEXT,
                    amount INTEGER,
                    currency TEXT,
                    created_at DOUBLE PRECISION NOT NULL,
                    updated_at DOUBLE PRECISION NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS payments (
                    id BIGSERIAL PRIMARY KEY,
                    payment_intent_id TEXT,
                    checkout_session_id TEXT,
                    account_id TEXT,
                    status TEXT,
                    amount INTEGER,
                    currency TEXT,
                    created_at DOUBLE PRECISION NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_usage_events_account_type_time
                ON usage_events(account_id, event_type, created_at)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_usage_events_ip_type_time
                ON usage_events(ip, event_type, created_at)
                """
            )
            conn.commit()

    def _is_pro_active(self, pro_until: Optional[str]) -> bool:
        if not pro_until:
            return False
        try:
            return datetime.fromisoformat(pro_until).replace(
                tzinfo=timezone.utc
            ) > datetime.now(timezone.utc)
        except Exception:
            return False

    def _entitlements_from_row(
        self, account_id: str, row: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        if not row:
            return {
                "account_id": account_id,
                "free_scans_remaining": 0,
                "deep_scan_credits": 0,
                "pro_until": None,
                "pro_active": False,
            }
        pro_until = row.get("pro_until")
        return {
            "account_id": account_id,
            "free_scans_remaining": int(row.get("free_scans_remaining", 0)),
            "deep_scan_credits": int(row.get("deep_scan_credits", 0)),
            "pro_until": pro_until,
            "pro_active": self._is_pro_active(pro_until),
        }

    def _ensure_account_locked(self, conn, account_id: str) -> None:
        now = time.time()
        conn.execute(
            """
            INSERT INTO accounts(account_id, created_at) VALUES (%s, %s)
            ON CONFLICT (account_id) DO NOTHING
            """,
            (account_id, now),
        )
        conn.execute(
            """
            INSERT INTO entitlements(account_id, free_scans_remaining, deep_scan_credits, pro_until, updated_at)
            VALUES (%s, 1, 0, NULL, %s)
            ON CONFLICT (account_id) DO NOTHING
            """,
            (account_id, now),
        )

    def ensure_account(self, account_id: str) -> None:
        with self._lock:
            with self._connect() as conn:
                self._ensure_account_locked(conn, account_id)
                conn.commit()

    def get_entitlements(self, account_id: str) -> Dict[str, Any]:
        self.ensure_account(account_id)
        with self._connect() as conn:
            row = conn.execute(
                "SELECT free_scans_remaining, deep_scan_credits, pro_until FROM entitlements WHERE account_id = %s",
                (account_id,),
            ).fetchone()
        return self._entitlements_from_row(account_id, row)

    def try_consume_entitlement_for_scan(
        self, account_id: str, scan_mode: str
    ) -> Dict[str, Any]:
        now = time.time()
        with self._lock:
            with self._connect() as conn:
                self._ensure_account_locked(conn, account_id)

                row = conn.execute(
                    """
                    SELECT free_scans_remaining, deep_scan_credits, pro_until
                    FROM entitlements
                    WHERE account_id = %s
                    FOR UPDATE
                    """,
                    (account_id,),
                ).fetchone()
                entitlements = self._entitlements_from_row(account_id, row)

                if entitlements["pro_active"]:
                    conn.commit()
                    return {
                        "allowed": True,
                        "consume": None,
                        "entitlements": entitlements,
                    }

                if scan_mode == "quick":
                    updated = conn.execute(
                        """
                        UPDATE entitlements
                        SET free_scans_remaining = free_scans_remaining - 1,
                            updated_at = %s
                        WHERE account_id = %s AND free_scans_remaining > 0
                        """,
                        (now, account_id),
                    )
                    if updated.rowcount == 1:
                        consumed_row = conn.execute(
                            "SELECT free_scans_remaining, deep_scan_credits, pro_until FROM entitlements WHERE account_id = %s",
                            (account_id,),
                        ).fetchone()
                        conn.commit()
                        return {
                            "allowed": True,
                            "consume": "free",
                            "entitlements": self._entitlements_from_row(
                                account_id, consumed_row
                            ),
                        }

                updated = conn.execute(
                    """
                    UPDATE entitlements
                    SET deep_scan_credits = deep_scan_credits - 1,
                        updated_at = %s
                    WHERE account_id = %s AND deep_scan_credits > 0
                    """,
                    (now, account_id),
                )
                if updated.rowcount == 1:
                    consumed_row = conn.execute(
                        "SELECT free_scans_remaining, deep_scan_credits, pro_until FROM entitlements WHERE account_id = %s",
                        (account_id,),
                    ).fetchone()
                    conn.commit()
                    return {
                        "allowed": True,
                        "consume": "credit",
                        "entitlements": self._entitlements_from_row(
                            account_id, consumed_row
                        ),
                    }

                conn.commit()
                return {"allowed": False, "consume": None, "entitlements": entitlements}

    def refund_consumption(self, account_id: str, consume: Optional[str]) -> None:
        if consume not in {"free", "credit"}:
            return
        now = time.time()
        with self._lock:
            with self._connect() as conn:
                self._ensure_account_locked(conn, account_id)
                if consume == "free":
                    conn.execute(
                        """
                        UPDATE entitlements
                        SET free_scans_remaining = free_scans_remaining + 1,
                            updated_at = %s
                        WHERE account_id = %s
                        """,
                        (now, account_id),
                    )
                else:
                    conn.execute(
                        """
                        UPDATE entitlements
                        SET deep_scan_credits = deep_scan_credits + 1,
                            updated_at = %s
                        WHERE account_id = %s
                        """,
                        (now, account_id),
                    )
                conn.commit()

    def decrement_free_scan(self, account_id: str) -> None:
        now = time.time()
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    UPDATE entitlements
                    SET free_scans_remaining = GREATEST(free_scans_remaining - 1, 0),
                        updated_at = %s
                    WHERE account_id = %s
                    """,
                    (now, account_id),
                )
                conn.commit()

    def decrement_credit(self, account_id: str) -> None:
        now = time.time()
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    UPDATE entitlements
                    SET deep_scan_credits = GREATEST(deep_scan_credits - 1, 0),
                        updated_at = %s
                    WHERE account_id = %s
                    """,
                    (now, account_id),
                )
                conn.commit()

    def add_credits(self, account_id: str, credits: int) -> None:
        now = time.time()
        with self._lock:
            with self._connect() as conn:
                self._ensure_account_locked(conn, account_id)
                conn.execute(
                    """
                    UPDATE entitlements
                    SET deep_scan_credits = deep_scan_credits + %s,
                        updated_at = %s
                    WHERE account_id = %s
                    """,
                    (int(credits), now, account_id),
                )
                conn.commit()

    def activate_pro(self, account_id: str, days: int = 30) -> str:
        now = datetime.now(timezone.utc)
        pro_until = (now + timedelta(days=days)).isoformat()
        with self._lock:
            with self._connect() as conn:
                self._ensure_account_locked(conn, account_id)
                conn.execute(
                    "UPDATE entitlements SET pro_until = %s, updated_at = %s WHERE account_id = %s",
                    (pro_until, time.time(), account_id),
                )
                conn.commit()
        return pro_until

    def create_checkout_session(
        self,
        checkout_session_id: str,
        account_id: str,
        scan_mode: str,
        price_id: Optional[str] = None,
        amount: Optional[int] = None,
        currency: str = "usd",
    ) -> None:
        now = time.time()
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO checkout_sessions(
                        checkout_session_id, account_id, scan_mode, status, price_id, amount, currency, created_at, updated_at
                    )
                    VALUES (%s, %s, %s, 'open', %s, %s, %s, %s, %s)
                    ON CONFLICT (checkout_session_id) DO UPDATE SET
                        account_id = EXCLUDED.account_id,
                        scan_mode = EXCLUDED.scan_mode,
                        status = 'open',
                        price_id = EXCLUDED.price_id,
                        amount = EXCLUDED.amount,
                        currency = EXCLUDED.currency,
                        created_at = EXCLUDED.created_at,
                        updated_at = EXCLUDED.updated_at
                    """,
                    (
                        checkout_session_id,
                        account_id,
                        scan_mode,
                        price_id,
                        amount,
                        currency,
                        now,
                        now,
                    ),
                )
                conn.commit()

    def get_checkout_session(
        self, checkout_session_id: str
    ) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM checkout_sessions WHERE checkout_session_id = %s",
                (checkout_session_id,),
            ).fetchone()
        return dict(row) if row else None

    def mark_checkout_completed(
        self, checkout_session_id: str
    ) -> Optional[Dict[str, Any]]:
        now = time.time()
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    """
                    SELECT * FROM checkout_sessions
                    WHERE checkout_session_id = %s
                    FOR UPDATE
                    """,
                    (checkout_session_id,),
                ).fetchone()
                if not row:
                    conn.commit()
                    return None

                if row.get("status") == "completed":
                    payload = dict(row)
                    payload["just_completed"] = False
                    conn.commit()
                    return payload

                conn.execute(
                    """
                    UPDATE checkout_sessions
                    SET status = 'completed',
                        updated_at = %s
                    WHERE checkout_session_id = %s
                    """,
                    (now, checkout_session_id),
                )
                updated = conn.execute(
                    "SELECT * FROM checkout_sessions WHERE checkout_session_id = %s",
                    (checkout_session_id,),
                ).fetchone()
                conn.commit()

                payload = dict(updated) if updated else dict(row)
                payload["just_completed"] = True
                return payload

    def record_payment(
        self,
        account_id: str,
        checkout_session_id: str,
        status: str,
        amount: Optional[int] = None,
        currency: str = "usd",
        payment_intent_id: Optional[str] = None,
    ) -> None:
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO payments(payment_intent_id, checkout_session_id, account_id, status, amount, currency, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        payment_intent_id,
                        checkout_session_id,
                        account_id,
                        status,
                        amount,
                        currency,
                        time.time(),
                    ),
                )
                conn.commit()

    def record_usage_event(self, account_id: str, ip: str, event_type: str) -> None:
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO usage_events(account_id, ip, event_type, created_at) VALUES (%s, %s, %s, %s)",
                    (account_id, ip, event_type, time.time()),
                )
                conn.commit()

    def count_recent_events_by_account(
        self, account_id: str, event_type: str, window_seconds: int
    ) -> int:
        since = time.time() - window_seconds
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT COUNT(*) AS c
                FROM usage_events
                WHERE account_id = %s AND event_type = %s AND created_at >= %s
                """,
                (account_id, event_type, since),
            ).fetchone()
        return int(row["c"]) if row else 0

    def count_recent_events_by_ip(
        self, ip: str, event_type: str, window_seconds: int
    ) -> int:
        since = time.time() - window_seconds
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT COUNT(*) AS c
                FROM usage_events
                WHERE ip = %s AND event_type = %s AND created_at >= %s
                """,
                (ip, event_type, since),
            ).fetchone()
        return int(row["c"]) if row else 0

