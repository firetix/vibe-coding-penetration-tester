import os
import socket
import subprocess
import sys
import threading
import time
from typing import Dict

import pytest
import requests
from werkzeug.serving import make_server

from tests.fixtures.vuln_app.app import create_app


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait_for_server(url: str, timeout: float = 15.0) -> None:
    deadline = time.time() + timeout
    last_err = None
    while time.time() < deadline:
        try:
            resp = requests.get(url, timeout=2)
            if resp.status_code in (200, 404):
                return
        except Exception as err:  # pragma: no cover - startup timing
            last_err = err
        time.sleep(0.25)
    raise RuntimeError(f"Server did not start at {url}: {last_err}")


def _spawn_flask_process(
    module_expr: str, port: int, extra_env: Dict[str, str]
) -> subprocess.Popen:
    env = os.environ.copy()
    env.update(extra_env)
    env["VPT_TEST_PORT"] = str(port)
    env.setdefault("PYTHONUNBUFFERED", "1")

    code = (
        "import os;"
        f"{module_expr};"
        "app.run(host='127.0.0.1', port=int(os.environ['VPT_TEST_PORT']), debug=False, use_reloader=False)"
    )
    return subprocess.Popen(
        [sys.executable, "-c", code],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
    )


class _WsgiServerThread(threading.Thread):
    def __init__(self, host: str, port: int, app):
        super().__init__(daemon=True)
        self._server = make_server(host, port, app)

    def run(self) -> None:  # pragma: no cover - thread wrapper
        self._server.serve_forever()

    def shutdown(self) -> None:
        self._server.shutdown()


def _poll_until_done(
    base_url: str, client: requests.Session, session_id: str, timeout: float
):
    deadline = time.time() + timeout
    last_payload = None
    while time.time() < deadline:
        resp = client.get(
            f"{base_url}/status", params={"session_id": session_id}, timeout=10
        )
        resp.raise_for_status()
        payload = resp.json()
        last_payload = payload
        if payload.get("is_running") is False and payload.get("progress", 0) >= 100:
            return payload
        time.sleep(1.0)
    raise AssertionError(
        f"Live scan did not complete within timeout. Last payload={last_payload}"
    )


@pytest.mark.e2e_live_scan
def test_live_scan_end_to_end():
    if os.environ.get("VPT_LIVE_E2E") != "1":
        pytest.skip("Set VPT_LIVE_E2E=1 to enable live scan tests")

    # Start a tiny local target app.
    target_port = _free_port()
    target_app = create_app()
    target_server = _WsgiServerThread("127.0.0.1", target_port, target_app)
    target_server.start()
    target_base = f"http://127.0.0.1:{target_port}"
    _wait_for_server(f"{target_base}/", timeout=10.0)

    # Start web_api with hosted mode disabled so localhost targets are allowed.
    api_port = _free_port()
    api_db_path = os.path.join("/tmp", f"vpt_live_e2e_web_api_{api_port}.db")
    if os.path.exists(api_db_path):
        os.remove(api_db_path)
    proc = _spawn_flask_process(
        "from web_api import create_app; app=create_app()",
        api_port,
        {
            "VPT_HOSTED_MODE": "0",
            "VPT_ALLOW_UNVERIFIED_WEBHOOKS": "1",
            "VPT_BILLING_DB_PATH": api_db_path,
        },
    )
    api_base = f"http://127.0.0.1:{api_port}"
    try:
        _wait_for_server(f"{api_base}/status", timeout=30.0)

        with requests.Session() as client:
            # Create session
            resp = client.post(
                f"{api_base}/api/session/init",
                json={"client_id": "live-e2e"},
                timeout=10,
            )
            resp.raise_for_status()
            session_id = resp.json().get("session_id")
            assert session_id

            # Start scan using the offline mock provider to avoid paid keys.
            resp = client.post(
                f"{api_base}/api/scan/start",
                json={
                    "session_id": session_id,
                    "url": target_base,
                    "scan_mode": "quick",
                    "config": {
                        "provider": "mock",
                        "model": "mock",
                        "scope": "url",
                    },
                },
                timeout=30,
            )
            resp.raise_for_status()

            # Poll until the scan completes.
            status = _poll_until_done(
                api_base, client, session_id, timeout=240.0
            )
            assert status.get("current_task") == "completed", status
            assert status.get("report_available") is True, status

            reports_resp = client.get(f"{api_base}/api/reports", timeout=20)
            reports_resp.raise_for_status()
            reports = reports_resp.json().get("reports", [])
            assert reports, reports_resp.json()
            report_id = reports[0].get("id")
            assert report_id

            report_resp = client.get(f"{api_base}/api/report/{report_id}", timeout=20)
            report_resp.raise_for_status()
            report = report_resp.json()
            assert "error" not in report
            assert report.get("findings") or report.get("markdown"), report
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:  # pragma: no cover - cleanup timing
            proc.kill()
        target_server.shutdown()

