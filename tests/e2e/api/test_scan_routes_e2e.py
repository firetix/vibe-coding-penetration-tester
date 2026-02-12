import pytest
import os
import socket
import subprocess
import sys
import time

from tests.e2e.conftest import poll_until_complete


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait_for_server(base_url: str, timeout: float = 30.0) -> None:
    requests = __import__("requests")
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
def test_scan_start_requires_url(web_api_server, http_client, initialized_session):
    response = http_client.post(
        f"{web_api_server}/api/scan/start",
        json={"session_id": initialized_session, "authorization_confirmed": True},
        timeout=10,
    )
    assert response.status_code == 400


@pytest.mark.e2e_api_critical
def test_scan_start_requires_authorization_in_hosted_mode(web_api_server, http_client, initialized_session):
    response = http_client.post(
        f"{web_api_server}/api/scan/start",
        json={"session_id": initialized_session, "url": "https://example.com", "scan_mode": "quick"},
        timeout=10,
    )
    assert response.status_code == 400


@pytest.mark.e2e_api_critical
def test_scan_start_success_then_status(web_api_server, http_client, initialized_session):
    start = http_client.post(
        f"{web_api_server}/api/scan/start",
        json={
            "session_id": initialized_session,
            "url": "https://example.com",
            "scan_mode": "quick",
            "authorization_confirmed": True,
        },
        timeout=10,
    )
    assert start.status_code == 200
    payload = start.json()
    assert payload.get("scan_id")

    status = http_client.post(
        f"{web_api_server}/api/scan/status",
        json={"session_id": initialized_session, "scan_id": payload["scan_id"]},
        timeout=10,
    )
    assert status.status_code == 200

    completed = poll_until_complete(web_api_server, http_client, initialized_session)
    assert completed.get("progress") == 100


@pytest.mark.e2e_api_critical
def test_scan_paywall_after_first_free_scan(web_api_server):
    client = __import__("requests").Session()
    try:
        init = client.post(f"{web_api_server}/api/session/init", json={"client_id": "paywall"}, timeout=10)
        session_id = init.json().get("session_id")

        first = client.post(
            f"{web_api_server}/api/scan/start",
            json={
                "session_id": session_id,
                "url": "https://example.com",
                "scan_mode": "quick",
                "authorization_confirmed": True,
            },
            timeout=10,
        )
        assert first.status_code == 200

        second = client.post(
            f"{web_api_server}/api/scan/start",
            json={
                "session_id": session_id,
                "url": "https://example.com",
                "scan_mode": "quick",
                "authorization_confirmed": True,
            },
            timeout=10,
        )
        assert second.status_code == 402
        body = second.json()
        assert body.get("paywall_required") is True
        assert body.get("checkout_url")
    finally:
        client.close()


@pytest.mark.e2e_api_full
def test_paywalled_attempts_return_402_not_rate_limit(web_api_server):
    client = __import__("requests").Session()
    try:
        init = client.post(f"{web_api_server}/api/session/init", json={"client_id": "paywall-402-loop"}, timeout=10)
        session_id = init.json().get("session_id")

        first = client.post(
            f"{web_api_server}/api/scan/start",
            json={
                "session_id": session_id,
                "url": "https://example.com",
                "scan_mode": "quick",
                "authorization_confirmed": True,
            },
            timeout=10,
        )
        assert first.status_code == 200

        for _ in range(6):
            response = client.post(
                f"{web_api_server}/api/scan/start",
                json={
                    "session_id": session_id,
                    "url": "https://example.com",
                    "scan_mode": "quick",
                    "authorization_confirmed": True,
                },
                timeout=10,
            )
            assert response.status_code == 402
    finally:
        client.close()


@pytest.mark.e2e_api_full
def test_hosted_checkout_url_uses_billing_route_when_mock_disabled():
    port = _free_port()
    strict_db_path = os.path.join("/tmp", f"vpt_mock_disabled_{port}.db")
    if os.path.exists(strict_db_path):
        os.remove(strict_db_path)

    env = os.environ.copy()
    env.update(
        {
            "VPT_E2E_MODE": "1",
            "VPT_HOSTED_MODE": "1",
            "VPT_ENABLE_MOCK_CHECKOUT": "0",
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

    requests = __import__("requests")
    base_url = f"http://127.0.0.1:{port}"
    try:
        _wait_for_server(base_url)
        client = requests.Session()
        session_id = client.post(f"{base_url}/api/session/init", json={"client_id": "mock-disabled"}, timeout=10).json()["session_id"]

        first = client.post(
            f"{base_url}/api/scan/start",
            json={
                "session_id": session_id,
                "url": "https://example.com",
                "scan_mode": "quick",
                "authorization_confirmed": True,
            },
            timeout=10,
        )
        assert first.status_code == 200

        second = client.post(
            f"{base_url}/api/scan/start",
            json={
                "session_id": session_id,
                "url": "https://example.com",
                "scan_mode": "quick",
                "authorization_confirmed": True,
            },
            timeout=10,
        )
        assert second.status_code == 402
        body = second.json()
        assert "/billing/checkout" in body.get("checkout_url", "")
        assert "/mock-checkout/" not in body.get("checkout_url", "")

        checkout_redirect = client.get(body["checkout_url"], allow_redirects=False, timeout=10)
        assert checkout_redirect.status_code == 503

        mock_direct = client.get(f"{base_url}/mock-checkout/cs_test", timeout=10)
        assert mock_direct.status_code == 404
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.mark.e2e_api_full
def test_scan_status_missing_scan_id(web_api_server, http_client, initialized_session):
    response = http_client.post(
        f"{web_api_server}/api/scan/status",
        json={"session_id": initialized_session},
        timeout=10,
    )
    assert response.status_code == 400


@pytest.mark.e2e_api_full
def test_scan_status_not_found(web_api_server, http_client, initialized_session):
    response = http_client.post(
        f"{web_api_server}/api/scan/status",
        json={"session_id": initialized_session, "scan_id": "missing"},
        timeout=10,
    )
    assert response.status_code == 404


@pytest.mark.e2e_api_full
def test_scan_cancel_missing_scan_id(web_api_server, http_client, initialized_session):
    response = http_client.post(
        f"{web_api_server}/api/scan/cancel",
        json={"session_id": initialized_session},
        timeout=10,
    )
    assert response.status_code == 400


@pytest.mark.e2e_api_full
def test_scan_cancel_and_list(web_api_server, http_client, initialized_session):
    start = http_client.post(
        f"{web_api_server}/api/scan/start",
        json={
            "session_id": initialized_session,
            "url": "https://example.com",
            "scan_mode": "quick",
            "authorization_confirmed": True,
        },
        timeout=10,
    )
    assert start.status_code == 200
    scan_id = start.json()["scan_id"]

    cancel = http_client.post(
        f"{web_api_server}/api/scan/cancel",
        json={"session_id": initialized_session, "scan_id": scan_id},
        timeout=10,
    )
    assert cancel.status_code == 200

    listing = http_client.post(
        f"{web_api_server}/api/scan/list",
        json={"session_id": initialized_session},
        timeout=10,
    )
    assert listing.status_code == 200
    payload = listing.json()
    assert "active" in payload and "completed" in payload
