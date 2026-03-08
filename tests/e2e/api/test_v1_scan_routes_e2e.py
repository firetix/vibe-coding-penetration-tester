import os
import socket
import subprocess
import sys
import time

import jwt
import pytest
import requests


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait_for_server(base_url: str, timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            response = requests.get(f"{base_url}/status", timeout=5)
            if response.status_code in (200, 401, 404):
                return
        except Exception:
            pass
        time.sleep(0.25)
    raise RuntimeError(f"Server did not start at {base_url}")


def _poll_v1_scan_complete(
    base_url: str, headers: dict, scan_id: str, timeout: float = 20.0
) -> dict:
    deadline = time.time() + timeout
    last_payload = None
    while time.time() < deadline:
        resp = requests.get(f"{base_url}/api/v1/scans/{scan_id}", headers=headers, timeout=10)
        assert resp.status_code == 200
        payload = resp.json()
        last_payload = payload
        scan = payload.get("scan") or {}
        if scan.get("is_running") is False and scan.get("progress", 0) >= 100:
            return payload
        time.sleep(0.25)
    raise AssertionError(f"v1 scan did not complete. Last payload={last_payload}")


def _auth_headers(secret: str, iss: str, sub: str, email: str) -> dict:
    token = jwt.encode(
        {"sub": sub, "email": email, "iss": iss},
        secret,
        algorithm="HS256",
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="module")
def v1_server():
    port = _free_port()
    db_path = os.path.join("/tmp", f"vpt_e2e_v1_{port}.db")
    if os.path.exists(db_path):
        os.remove(db_path)

    supabase_secret = "v1-e2e-secret-key-with-at-least-32-bytes"
    supabase_iss = "https://v1-e2e.supabase.test/auth/v1"
    env = os.environ.copy()
    env.update(
        {
            "VPT_TEST_PORT": str(port),
            "VPT_E2E_MODE": "1",
            "VPT_HOSTED_MODE": "0",
            "VPT_ALLOW_UNVERIFIED_WEBHOOKS": "1",
            "VPT_BILLING_DB_PATH": db_path,
            "SUPABASE_JWT_SECRET": supabase_secret,
            "SUPABASE_URL": "https://v1-e2e.supabase.test",
            "SUPABASE_JWT_ISS": supabase_iss,
            "PYTHONUNBUFFERED": "1",
        }
    )

    code = (
        "import os;"
        "from web_api import create_app;"
        "app=create_app();"
        "app.run(host='127.0.0.1', port=int(os.environ['VPT_TEST_PORT']), debug=False, use_reloader=False)"
    )
    proc = subprocess.Popen(
        [sys.executable, "-c", code],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
    )
    base_url = f"http://127.0.0.1:{port}"
    try:
        _wait_for_server(base_url)
        yield {
            "base_url": base_url,
            "supabase_secret": supabase_secret,
            "supabase_iss": supabase_iss,
        }
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.mark.e2e_api_full
def test_v1_scan_requires_auth(v1_server):
    base_url = v1_server["base_url"]
    response = requests.post(
        f"{base_url}/api/v1/scans",
        json={"url": "https://example.com", "scan_mode": "quick"},
        timeout=10,
    )
    assert response.status_code == 401


@pytest.mark.e2e_api_full
def test_v1_scan_create_status_and_report(v1_server):
    base_url = v1_server["base_url"]
    headers = _auth_headers(
        v1_server["supabase_secret"],
        v1_server["supabase_iss"],
        "user-a",
        "user-a@example.com",
    )

    create = requests.post(
        f"{base_url}/api/v1/scans",
        json={"url": "https://example.com", "scan_mode": "quick"},
        headers=headers,
        timeout=10,
    )
    assert create.status_code == 201
    create_payload = create.json()
    scan_id = ((create_payload.get("scan") or {}).get("id"))
    assert scan_id

    completed = _poll_v1_scan_complete(base_url, headers, scan_id)
    scan = completed.get("scan") or {}
    assert scan.get("is_running") is False
    assert scan.get("progress") == 100

    # Report can transiently be 202 while report_dir syncs; poll briefly for 200.
    deadline = time.time() + 10.0
    report_resp = None
    while time.time() < deadline:
        report_resp = requests.get(
            f"{base_url}/api/v1/scans/{scan_id}/report",
            headers=headers,
            timeout=10,
        )
        if report_resp.status_code == 200:
            break
        assert report_resp.status_code == 202
        time.sleep(0.25)

    assert report_resp is not None
    assert report_resp.status_code == 200
    report_payload = report_resp.json()
    report = report_payload.get("report") or {}
    assert report.get("findings") or report.get("markdown")


@pytest.mark.e2e_api_full
def test_v1_scan_enforces_org_ownership(v1_server):
    base_url = v1_server["base_url"]
    user_a_headers = _auth_headers(
        v1_server["supabase_secret"],
        v1_server["supabase_iss"],
        "owner-user",
        "owner@example.com",
    )
    user_b_headers = _auth_headers(
        v1_server["supabase_secret"],
        v1_server["supabase_iss"],
        "other-user",
        "other@example.com",
    )

    create = requests.post(
        f"{base_url}/api/v1/scans",
        json={"url": "https://example.com", "scan_mode": "quick"},
        headers=user_a_headers,
        timeout=10,
    )
    assert create.status_code == 201
    scan_id = (create.json().get("scan") or {}).get("id")
    assert scan_id

    other_status = requests.get(
        f"{base_url}/api/v1/scans/{scan_id}",
        headers=user_b_headers,
        timeout=10,
    )
    assert other_status.status_code == 404

    other_report = requests.get(
        f"{base_url}/api/v1/scans/{scan_id}/report",
        headers=user_b_headers,
        timeout=10,
    )
    assert other_report.status_code == 404
