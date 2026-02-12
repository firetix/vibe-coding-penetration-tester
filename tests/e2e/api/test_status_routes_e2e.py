import pytest


@pytest.mark.e2e_api_critical
def test_status_without_session(web_api_server, http_client):
    response = http_client.get(f"{web_api_server}/status", timeout=10)
    assert response.status_code == 200
    payload = response.json()
    assert "is_running" in payload
    assert "entitlements" in payload
    assert "paywall_state" in payload


@pytest.mark.e2e_api_full
def test_api_logs_route(web_api_server, http_client):
    response = http_client.get(f"{web_api_server}/api/logs", timeout=10)
    assert response.status_code == 200
    payload = response.json()
    assert "logs" in payload


@pytest.mark.e2e_api_full
def test_status_with_invalid_session(web_api_server, http_client):
    response = http_client.get(
        f"{web_api_server}/status", params={"session_id": "invalid"}, timeout=10
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload.get("message") == "Invalid session"


@pytest.mark.e2e_api_critical
def test_status_with_running_or_completed_scan(
    web_api_server, http_client, initialized_session
):
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

    response = http_client.get(
        f"{web_api_server}/status",
        params={"session_id": initialized_session},
        timeout=10,
    )
    assert response.status_code == 200
    payload = response.json()
    assert "progress" in payload
    assert "entitlements" in payload
    assert "paywall_state" in payload
