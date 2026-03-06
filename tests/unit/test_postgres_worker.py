"""Unit tests for the Postgres scan worker claim/lock behavior."""

from web_api.worker import PostgresScanWorker, WorkerConfig


class _FakeTransaction:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class _FakeCursor:
    def __init__(self, row=None):
        self._row = row
        self.executed = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def execute(self, sql, params=None):
        self.executed.append((sql, params))

    def fetchone(self):
        return self._row


class _FakeConnection:
    def __init__(self, row=None):
        self._row = row
        self.cursor_calls = []
        self.cursors = []

    def cursor(self, **kwargs):
        self.cursor_calls.append(kwargs)
        cursor = _FakeCursor(self._row)
        self.cursors.append(cursor)
        return cursor

    def transaction(self):
        return _FakeTransaction()


def _make_worker() -> PostgresScanWorker:
    return PostgresScanWorker(
        WorkerConfig(
            database_url="postgresql://example",
            worker_id="test-worker",
            poll_interval_seconds=0.01,
            step_interval_seconds=0.01,
            simulated_steps=1,
            run_once=True,
        )
    )


def test_claim_next_scan_uses_skip_locked_and_running_transition():
    worker = _make_worker()
    conn = _FakeConnection(
        row={
            "id": "scan-123",
            "target_url": "https://example.com",
            "scan_mode": "quick",
            "status": "running",
        }
    )

    scan = worker._claim_next_scan(conn)

    assert scan is not None
    assert scan["id"] == "scan-123"

    claim_sql, claim_params = conn.cursors[0].executed[0]
    normalized_sql = " ".join(claim_sql.upper().split())

    assert "FOR UPDATE SKIP LOCKED" in normalized_sql
    assert claim_params == ("pending", "running")


def test_claim_next_scan_returns_none_when_queue_empty():
    worker = _make_worker()
    conn = _FakeConnection(row=None)

    scan = worker._claim_next_scan(conn)

    assert scan is None
    # Only claim query runs; no event insert when nothing is claimed.
    assert len(conn.cursors) == 1


def test_claim_next_scan_normalizes_tuple_row():
    worker = _make_worker()
    conn = _FakeConnection(
        row=("scan-456", "https://example.org", "quick", "running")
    )

    scan = worker._claim_next_scan(conn)

    assert scan is not None
    assert scan["id"] == "scan-456"
    assert scan["target_url"] == "https://example.org"
