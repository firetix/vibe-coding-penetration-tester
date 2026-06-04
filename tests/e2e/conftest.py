import os
import socket
import subprocess
import sys
import time
from typing import Dict

import pytest
import requests


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait_for_server(base_url: str, timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    request_timeout = float(os.environ.get("VPT_E2E_STARTUP_REQUEST_TIMEOUT", "5"))
    last_err = None
    while time.time() < deadline:
        try:
            response = requests.get(f"{base_url}/status", timeout=request_timeout)
            if response.status_code in (200, 401, 404):
                return
        except Exception as err:  # pragma: no cover - startup timing
            last_err = err
        time.sleep(0.25)
    raise RuntimeError(f"Server did not start at {base_url}: {last_err}")


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


@pytest.fixture(scope="session")
def web_api_server() -> str:
    port = _free_port()
    web_api_db_path = os.path.join("/tmp", f"vpt_e2e_web_api_{port}.db")
    if os.path.exists(web_api_db_path):
        os.remove(web_api_db_path)
    proc = _spawn_flask_process(
        "from web_api import create_app; app=create_app()",
        port,
        {
            "VPT_E2E_MODE": "1",
            "VPT_HOSTED_MODE": "1",
            "VPT_ALLOW_UNVERIFIED_WEBHOOKS": "1",
            "VPT_BILLING_DB_PATH": web_api_db_path,
        },
    )
    base_url = f"http://127.0.0.1:{port}"
    try:
        _wait_for_server(base_url)
        yield base_url
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.fixture(scope="session")
def legacy_server() -> str:
    port = _free_port()
    legacy_db_path = os.path.join("/tmp", f"vpt_e2e_legacy_{port}.db")
    if os.path.exists(legacy_db_path):
        os.remove(legacy_db_path)
    proc = _spawn_flask_process(
        "import web_ui; app=web_ui.app",
        port,
        {
            "VPT_E2E_MODE": "1",
            "VPT_HOSTED_MODE": "1",
            "VPT_ALLOW_UNVERIFIED_WEBHOOKS": "1",
            "VPT_BILLING_DB_PATH": legacy_db_path,
        },
    )
    base_url = f"http://127.0.0.1:{port}"
    try:
        _wait_for_server(base_url)
        yield base_url
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.fixture
def http_client() -> requests.Session:
    session = requests.Session()
    session.headers.update({"User-Agent": "vpt-e2e-tests"})
    yield session
    session.close()


@pytest.fixture
def initialized_session(web_api_server, http_client):
    response = http_client.post(
        f"{web_api_server}/api/session/init", json={"client_id": "e2e"}, timeout=10
    )
    response.raise_for_status()
    payload = response.json()
    session_id = payload.get("session_id")
    assert session_id
    return session_id


def poll_until_complete(
    base_url: str, client: requests.Session, session_id: str, timeout: float = 10.0
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
        time.sleep(0.25)
    raise AssertionError(
        f"Scan did not complete within timeout. Last payload={last_payload}"
    )
