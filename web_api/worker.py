"""Postgres-backed worker loop for scan processing.

Queue contract:
- API inserts rows in `scans` with status `pending`
- worker claims one row using `FOR UPDATE SKIP LOCKED` and marks it `running`
- worker appends progress rows into `scan_events`
- worker marks the scan `completed` or `failed`

This intentionally simulates scan execution (sleep + fake events).
No Redis is required.
"""

from __future__ import annotations

import json
import logging
import os
import signal
import socket
import sys
import time
from dataclasses import dataclass
from typing import Any

try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:  # pragma: no cover - handled at runtime
    psycopg = None
    dict_row = None

logger = logging.getLogger("web_api.worker")

CLAIM_NEXT_SCAN_SQL = """
WITH next_scan AS (
    SELECT id
    FROM scans
    WHERE status = %s
    ORDER BY created_at ASC, id ASC
    FOR UPDATE SKIP LOCKED
    LIMIT 1
)
UPDATE scans AS s
SET status = %s,
    updated_at = NOW()
FROM next_scan
WHERE s.id = next_scan.id
RETURNING s.id, s.target_url, s.scan_mode, s.status;
"""

INSERT_SCAN_EVENT_SQL = """
INSERT INTO scan_events (scan_id, event_type, data)
VALUES (%s, %s, %s);
"""

UPDATE_SCAN_STATUS_SQL = """
UPDATE scans
SET status = %s,
    updated_at = NOW()
WHERE id = %s;
"""


class WorkerShutdown(Exception):
    """Raised when graceful shutdown is requested while processing."""


@dataclass(slots=True)
class WorkerConfig:
    """Configuration for the Postgres scan worker."""

    database_url: str
    worker_id: str
    poll_interval_seconds: float = 3.0
    step_interval_seconds: float = 1.0
    simulated_steps: int = 4
    reconnect_delay_seconds: float = 5.0
    log_level: str = "INFO"
    run_once: bool = False

    @classmethod
    def from_env(cls) -> "WorkerConfig":
        database_url = os.getenv("DATABASE_URL", "").strip()
        if not database_url:
            raise ValueError("DATABASE_URL is required")

        worker_id = os.getenv("WORKER_ID") or f"{socket.gethostname()}-{os.getpid()}"

        return cls(
            database_url=database_url,
            worker_id=worker_id,
            poll_interval_seconds=_read_float("WORKER_POLL_INTERVAL_SECONDS", 3.0),
            step_interval_seconds=_read_float("WORKER_STEP_INTERVAL_SECONDS", 1.0),
            simulated_steps=_read_int("WORKER_SIMULATED_STEPS", 4, minimum=1),
            reconnect_delay_seconds=_read_float("WORKER_RECONNECT_DELAY_SECONDS", 5.0),
            log_level=os.getenv("WORKER_LOG_LEVEL", "INFO"),
            run_once=_read_bool("WORKER_RUN_ONCE", False),
        )


class PostgresScanWorker:
    """Simple polling worker using Postgres row locking as a queue."""

    def __init__(self, config: WorkerConfig):
        self.config = config
        self._stop_requested = False

    def install_signal_handlers(self) -> None:
        def _handler(signum: int, _frame: Any) -> None:
            logger.info("Received signal %s, stopping after current step", signum)
            self._stop_requested = True

        signal.signal(signal.SIGINT, _handler)
        signal.signal(signal.SIGTERM, _handler)

    def run(self) -> None:
        if psycopg is None:
            raise RuntimeError(
                "psycopg is not installed. Install dependencies with `pip install -r requirements.txt`."
            )

        logger.info(
            "Starting worker %s (poll=%ss step=%ss steps=%s)",
            self.config.worker_id,
            self.config.poll_interval_seconds,
            self.config.step_interval_seconds,
            self.config.simulated_steps,
        )

        while not self._stop_requested:
            try:
                with psycopg.connect(self.config.database_url, connect_timeout=10) as conn:
                    self._run_connection_loop(conn)
            except WorkerShutdown:
                break
            except Exception:
                logger.exception("Worker loop crashed; reconnecting")
                if self._stop_requested:
                    break
                time.sleep(self.config.reconnect_delay_seconds)

        logger.info("Worker %s stopped", self.config.worker_id)

    def _run_connection_loop(self, conn: Any) -> None:
        while not self._stop_requested:
            scan = self._claim_next_scan(conn)
            if scan is None:
                if self.config.run_once:
                    return
                time.sleep(self.config.poll_interval_seconds)
                continue

            try:
                self._process_scan(conn, scan)
            except WorkerShutdown:
                raise

            if self.config.run_once:
                return

    def _claim_next_scan(self, conn: Any) -> dict[str, Any] | None:
        with conn.transaction():
            with self._cursor(conn) as cur:
                cur.execute(CLAIM_NEXT_SCAN_SQL, ("pending", "running"))
                row = cur.fetchone()

        if row is None:
            return None

        scan = self._normalize_claimed_row(row)
        logger.info(
            "Claimed scan %s (%s)",
            scan.get("id"),
            scan.get("target_url") or "no target_url",
        )
        self._safe_insert_event(
            conn,
            scan["id"],
            "scan.claimed",
            {
                "worker_id": self.config.worker_id,
                "status": "running",
            },
        )
        return scan

    def _process_scan(self, conn: Any, scan: dict[str, Any]) -> None:
        scan_id = scan["id"]
        target_url = scan.get("target_url")

        try:
            self._insert_event(
                conn,
                scan_id,
                "scan.started",
                {
                    "worker_id": self.config.worker_id,
                    "target_url": target_url,
                },
            )

            for step in range(1, self.config.simulated_steps + 1):
                if self._stop_requested:
                    raise WorkerShutdown("Shutdown requested")

                time.sleep(self.config.step_interval_seconds)
                progress = int((step / self.config.simulated_steps) * 100)
                self._insert_event(
                    conn,
                    scan_id,
                    "scan.progress",
                    {
                        "worker_id": self.config.worker_id,
                        "step": step,
                        "total_steps": self.config.simulated_steps,
                        "progress": progress,
                    },
                )

            self._insert_event(
                conn,
                scan_id,
                "scan.completed",
                {
                    "worker_id": self.config.worker_id,
                    "progress": 100,
                    "simulated": True,
                },
            )
            self._set_scan_status(conn, scan_id, "completed")
            logger.info("Completed scan %s", scan_id)

        except WorkerShutdown:
            self._safe_insert_event(
                conn,
                scan_id,
                "scan.failed",
                {
                    "worker_id": self.config.worker_id,
                    "reason": "worker_shutdown",
                },
            )
            self._safe_set_scan_status(conn, scan_id, "failed")
            logger.warning("Marked scan %s as failed due to shutdown", scan_id)
            raise
        except Exception as exc:
            logger.exception("Scan %s failed", scan_id)
            self._safe_insert_event(
                conn,
                scan_id,
                "scan.failed",
                {
                    "worker_id": self.config.worker_id,
                    "error": str(exc),
                },
            )
            self._safe_set_scan_status(conn, scan_id, "failed")

    def _insert_event(
        self,
        conn: Any,
        scan_id: str,
        event_type: str,
        data: dict[str, Any] | None,
    ) -> None:
        payload = json.dumps(data) if data is not None else None
        with conn.transaction():
            with conn.cursor() as cur:
                cur.execute(INSERT_SCAN_EVENT_SQL, (scan_id, event_type, payload))

    def _set_scan_status(self, conn: Any, scan_id: str, status: str) -> None:
        with conn.transaction():
            with conn.cursor() as cur:
                cur.execute(UPDATE_SCAN_STATUS_SQL, (status, scan_id))

    def _safe_insert_event(
        self,
        conn: Any,
        scan_id: str,
        event_type: str,
        data: dict[str, Any] | None,
    ) -> None:
        try:
            self._insert_event(conn, scan_id, event_type, data)
        except Exception:
            logger.exception("Failed to insert scan event %s for %s", event_type, scan_id)

    def _safe_set_scan_status(self, conn: Any, scan_id: str, status: str) -> None:
        try:
            self._set_scan_status(conn, scan_id, status)
        except Exception:
            logger.exception("Failed to set scan %s status=%s", scan_id, status)

    @staticmethod
    def _cursor(conn: Any):
        if dict_row is None:
            return conn.cursor()
        return conn.cursor(row_factory=dict_row)

    @staticmethod
    def _normalize_claimed_row(row: Any) -> dict[str, Any]:
        if isinstance(row, dict):
            return row
        if hasattr(row, "_mapping"):
            return dict(row._mapping)
        if isinstance(row, (tuple, list)):
            return {
                "id": row[0],
                "target_url": row[1] if len(row) > 1 else None,
                "scan_mode": row[2] if len(row) > 2 else None,
                "status": row[3] if len(row) > 3 else "running",
            }
        raise TypeError(f"Unsupported row type from claim query: {type(row)!r}")


def _read_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _read_int(name: str, default: int, minimum: int | None = None) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    value = int(raw)
    if minimum is not None and value < minimum:
        raise ValueError(f"{name} must be >= {minimum}")
    return value


def _read_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    return float(raw)


def _configure_logging(level: str) -> None:
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )


def main() -> int:
    try:
        config = WorkerConfig.from_env()
        _configure_logging(config.log_level)
        worker = PostgresScanWorker(config)
        worker.install_signal_handlers()
        worker.run()
        return 0
    except Exception as exc:
        print(f"Worker failed: {exc}", file=sys.stderr)
        logger.exception("Fatal worker error")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
