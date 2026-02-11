import os
import socket
import subprocess
import sys
import time

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
            response = requests.get(f"{base_url}/status", timeout=2)
            if response.status_code in (200, 404):
                return
        except Exception:
            pass
        time.sleep(0.25)
    raise RuntimeError(f"Server did not start at {base_url}")


@pytest.mark.e2e_api_critical
def test_get_entitlements(web_api_server, http_client):
    # Ensure account cookie is initialized first
    http_client.get(f"{web_api_server}/status", timeout=10)
    response = http_client.get(f"{web_api_server}/api/entitlements", timeout=10)
    assert response.status_code == 200
    payload = response.json()
    assert payload.get("entitlements")
    assert "free_scans_remaining" in payload["entitlements"]


@pytest.mark.e2e_api_critical
def test_billing_checkout(web_api_server, http_client):
    http_client.get(f"{web_api_server}/status", timeout=10)
    response = http_client.post(
        f"{web_api_server}/api/billing/checkout",
        json={"scan_mode": "deep"},
        timeout=10,
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload.get("checkout_url")
    assert payload.get("checkout_session_id")


@pytest.mark.e2e_api_critical
def test_billing_webhook_idempotent(web_api_server, http_client):
    http_client.get(f"{web_api_server}/status", timeout=10)
    before = http_client.get(f"{web_api_server}/api/entitlements", timeout=10).json()["entitlements"]
    checkout = http_client.post(
        f"{web_api_server}/api/billing/checkout",
        json={"scan_mode": "deep"},
        timeout=10,
    ).json()

    event = {
        "type": "checkout.session.completed",
        "data": {"object": {"id": checkout["checkout_session_id"]}},
    }
    first = http_client.post(f"{web_api_server}/api/billing/webhook", json=event, timeout=10)
    after_first = http_client.get(f"{web_api_server}/api/entitlements", timeout=10).json()["entitlements"]
    second = http_client.post(f"{web_api_server}/api/billing/webhook", json=event, timeout=10)
    after_second = http_client.get(f"{web_api_server}/api/entitlements", timeout=10).json()["entitlements"]

    assert first.status_code == 200
    assert second.status_code == 200
    assert after_first["deep_scan_credits"] == before["deep_scan_credits"] + 5
    assert after_second["deep_scan_credits"] == after_first["deep_scan_credits"]
    assert second.json().get("message") in {"Webhook already processed", "Webhook processed"}


@pytest.mark.e2e_api_critical
def test_billing_webhook_rejects_unsigned_without_test_mode():
    port = _free_port()
    strict_db_path = os.path.join("/tmp", f"vpt_webhook_strict_{port}.db")
    if os.path.exists(strict_db_path):
        os.remove(strict_db_path)

    env = os.environ.copy()
    env.update(
        {
            "VPT_HOSTED_MODE": "1",
            "VPT_BILLING_DB_PATH": strict_db_path,
        }
    )

    code = (
        "import os;"
        "from web_api import create_app;"
        "app=create_app();"
        "app.run(host='127.0.0.1', port=int(os.environ['VPT_TEST_PORT']), debug=False, use_reloader=False)"
    )
    env["VPT_TEST_PORT"] = str(port)
    proc = subprocess.Popen(
        [sys.executable, "-c", code],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
    )

    base_url = f"http://127.0.0.1:{port}"
    try:
        _wait_for_server(base_url)
        client = requests.Session()
        client.get(f"{base_url}/status", timeout=10)
        checkout = client.post(
            f"{base_url}/api/billing/checkout",
            json={"scan_mode": "deep"},
            timeout=10,
        ).json()

        event = {
            "type": "checkout.session.completed",
            "data": {"object": {"id": checkout["checkout_session_id"]}},
        }
        response = client.post(f"{base_url}/api/billing/webhook", json=event, timeout=10)
        assert response.status_code == 400
        assert response.json().get("status") == "error"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
