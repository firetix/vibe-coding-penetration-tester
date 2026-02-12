import pytest

from tests.e2e.conftest import poll_until_complete


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
