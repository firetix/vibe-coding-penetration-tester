import os
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional


class BillingStore:
    """SQLite-backed billing and entitlement persistence for hosted runtime."""

    def __init__(self, db_path: str = "data/vpt.db"):
        self.db_path = db_path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS accounts (
                    account_id TEXT PRIMARY KEY,
                    created_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS entitlements (
                    account_id TEXT PRIMARY KEY,
                    free_scans_remaining INTEGER NOT NULL DEFAULT 1,
                    deep_scan_credits INTEGER NOT NULL DEFAULT 0,
                    pro_until TEXT,
                    updated_at REAL NOT NULL,
                    FOREIGN KEY(account_id) REFERENCES accounts(account_id)
                );

                CREATE TABLE IF NOT EXISTS usage_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    account_id TEXT,
                    ip TEXT,
                    event_type TEXT NOT NULL,
                    created_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS checkout_sessions (
                    checkout_session_id TEXT PRIMARY KEY,
                    account_id TEXT NOT NULL,
                    scan_mode TEXT NOT NULL,
                    status TEXT NOT NULL,
                    price_id TEXT,
                    amount INTEGER,
                    currency TEXT,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS payments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    payment_intent_id TEXT,
                    checkout_session_id TEXT,
                    account_id TEXT,
                    status TEXT,
                    amount INTEGER,
                    currency TEXT,
                    created_at REAL NOT NULL
                );
                """
            )
            conn.commit()

    def _is_pro_active(self, pro_until: Optional[str]) -> bool:
        if not pro_until:
            return False
        try:
            return datetime.fromisoformat(pro_until).replace(tzinfo=timezone.utc) > datetime.now(timezone.utc)
        except Exception:
            return False

    def _entitlements_from_row(self, account_id: str, row: Optional[sqlite3.Row]) -> Dict[str, Any]:
        if not row:
            return {
                "account_id": account_id,
                "free_scans_remaining": 0,
                "deep_scan_credits": 0,
                "pro_until": None,
                "pro_active": False,
            }
        pro_until = row["pro_until"]
        return {
            "account_id": account_id,
            "free_scans_remaining": int(row["free_scans_remaining"]),
            "deep_scan_credits": int(row["deep_scan_credits"]),
            "pro_until": pro_until,
            "pro_active": self._is_pro_active(pro_until),
        }

    def _ensure_account_locked(self, conn: sqlite3.Connection, account_id: str) -> None:
        now = time.time()
        conn.execute(
            "INSERT OR IGNORE INTO accounts(account_id, created_at) VALUES (?, ?)",
            (account_id, now),
        )
        conn.execute(
            """
            INSERT OR IGNORE INTO entitlements(account_id, free_scans_remaining, deep_scan_credits, pro_until, updated_at)
            VALUES (?, 1, 0, NULL, ?)
            """,
            (account_id, now),
        )

    def ensure_account(self, account_id: str) -> None:
        now = time.time()
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "INSERT OR IGNORE INTO accounts(account_id, created_at) VALUES (?, ?)",
                    (account_id, now),
                )
                conn.execute(
                    """
                    INSERT OR IGNORE INTO entitlements(account_id, free_scans_remaining, deep_scan_credits, pro_until, updated_at)
                    VALUES (?, 1, 0, NULL, ?)
                    """,
                    (account_id, now),
                )
                conn.commit()

    def get_entitlements(self, account_id: str) -> Dict[str, Any]:
        self.ensure_account(account_id)
        with self._connect() as conn:
            row = conn.execute(
                "SELECT free_scans_remaining, deep_scan_credits, pro_until FROM entitlements WHERE account_id = ?",
                (account_id,),
            ).fetchone()
        return self._entitlements_from_row(account_id, row)

    def try_consume_entitlement_for_scan(self, account_id: str, scan_mode: str) -> Dict[str, Any]:
        """
        Atomically decide and consume entitlement for a scan start.
        Returns:
          {
            "allowed": bool,
            "consume": "free"|"credit"|None,
            "entitlements": {...}
          }
        """
        now = time.time()
        with self._lock:
            with self._connect() as conn:
                self._ensure_account_locked(conn, account_id)

                row = conn.execute(
                    "SELECT free_scans_remaining, deep_scan_credits, pro_until FROM entitlements WHERE account_id = ?",
                    (account_id,),
                ).fetchone()
                entitlements = self._entitlements_from_row(account_id, row)

                if entitlements["pro_active"]:
                    return {"allowed": True, "consume": None, "entitlements": entitlements}

                if scan_mode == "quick":
                    updated = conn.execute(
                        """
                        UPDATE entitlements
                        SET free_scans_remaining = free_scans_remaining - 1,
                            updated_at = ?
                        WHERE account_id = ? AND free_scans_remaining > 0
                        """,
                        (now, account_id),
                    )
                    if updated.rowcount == 1:
                        conn.commit()
                        consumed_row = conn.execute(
                            "SELECT free_scans_remaining, deep_scan_credits, pro_until FROM entitlements WHERE account_id = ?",
                            (account_id,),
                        ).fetchone()
                        return {
                            "allowed": True,
                            "consume": "free",
                            "entitlements": self._entitlements_from_row(account_id, consumed_row),
                        }

                updated = conn.execute(
                    """
                    UPDATE entitlements
                    SET deep_scan_credits = deep_scan_credits - 1,
                        updated_at = ?
                    WHERE account_id = ? AND deep_scan_credits > 0
                    """,
                    (now, account_id),
                )
                if updated.rowcount == 1:
                    conn.commit()
                    consumed_row = conn.execute(
                        "SELECT free_scans_remaining, deep_scan_credits, pro_until FROM entitlements WHERE account_id = ?",
                        (account_id,),
                    ).fetchone()
                    return {
                        "allowed": True,
                        "consume": "credit",
                        "entitlements": self._entitlements_from_row(account_id, consumed_row),
                    }

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
                            updated_at = ?
                        WHERE account_id = ?
                        """,
                        (now, account_id),
                    )
                elif consume == "credit":
                    conn.execute(
                        """
                        UPDATE entitlements
                        SET deep_scan_credits = deep_scan_credits + 1,
                            updated_at = ?
                        WHERE account_id = ?
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
                    SET free_scans_remaining = CASE
                        WHEN free_scans_remaining > 0 THEN free_scans_remaining - 1
                        ELSE 0
                    END,
                    updated_at = ?
                    WHERE account_id = ?
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
                    SET deep_scan_credits = CASE
                        WHEN deep_scan_credits > 0 THEN deep_scan_credits - 1
                        ELSE 0
                    END,
                    updated_at = ?
                    WHERE account_id = ?
                    """,
                    (now, account_id),
                )
                conn.commit()

    def add_credits(self, account_id: str, credits: int) -> None:
        now = time.time()
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    UPDATE entitlements
                    SET deep_scan_credits = deep_scan_credits + ?,
                        updated_at = ?
                    WHERE account_id = ?
                    """,
                    (credits, now, account_id),
                )
                conn.commit()

    def activate_pro(self, account_id: str, days: int = 30) -> str:
        now = datetime.now(timezone.utc)
        pro_until = (now + timedelta(days=days)).isoformat()
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "UPDATE entitlements SET pro_until = ?, updated_at = ? WHERE account_id = ?",
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
                    INSERT OR REPLACE INTO checkout_sessions(
                        checkout_session_id, account_id, scan_mode, status, price_id, amount, currency, created_at, updated_at
                    ) VALUES (?, ?, ?, 'open', ?, ?, ?, ?, ?)
                    """,
                    (checkout_session_id, account_id, scan_mode, price_id, amount, currency, now, now),
                )
                conn.commit()

    def get_checkout_session(self, checkout_session_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM checkout_sessions WHERE checkout_session_id = ?",
                (checkout_session_id,),
            ).fetchone()
        if not row:
            return None
        return dict(row)

    def mark_checkout_completed(self, checkout_session_id: str) -> Optional[Dict[str, Any]]:
        now = time.time()
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT * FROM checkout_sessions WHERE checkout_session_id = ?",
                    (checkout_session_id,),
                ).fetchone()
                if not row:
                    return None
                if row["status"] == "completed":
                    existing = dict(row)
                    existing["just_completed"] = False
                    return existing
                conn.execute(
                    "UPDATE checkout_sessions SET status = 'completed', updated_at = ? WHERE checkout_session_id = ?",
                    (now, checkout_session_id),
                )
                conn.commit()
                updated = conn.execute(
                    "SELECT * FROM checkout_sessions WHERE checkout_session_id = ?",
                    (checkout_session_id,),
                ).fetchone()
                if not updated:
                    return None
                updated_payload = dict(updated)
                updated_payload["just_completed"] = True
                return updated_payload

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
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (payment_intent_id, checkout_session_id, account_id, status, amount, currency, time.time()),
                )
                conn.commit()

    def record_usage_event(self, account_id: str, ip: str, event_type: str) -> None:
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO usage_events(account_id, ip, event_type, created_at) VALUES (?, ?, ?, ?)",
                    (account_id, ip, event_type, time.time()),
                )
                conn.commit()

    def count_recent_events_by_account(self, account_id: str, event_type: str, window_seconds: int) -> int:
        since = time.time() - window_seconds
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT COUNT(*) AS c
                FROM usage_events
                WHERE account_id = ? AND event_type = ? AND created_at >= ?
                """,
                (account_id, event_type, since),
            ).fetchone()
        return int(row["c"]) if row else 0

    def count_recent_events_by_ip(self, ip: str, event_type: str, window_seconds: int) -> int:
        since = time.time() - window_seconds
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT COUNT(*) AS c
                FROM usage_events
                WHERE ip = ? AND event_type = ? AND created_at >= ?
                """,
                (ip, event_type, since),
            ).fetchone()
        return int(row["c"]) if row else 0
