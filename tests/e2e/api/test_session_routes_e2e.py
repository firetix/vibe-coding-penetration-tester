import pytest


@pytest.mark.e2e_api_critical
def test_session_init_returns_session_id(web_api_server, http_client):
    response = http_client.post(f"{web_api_server}/api/session/init", json={"client_id": "e2e"}, timeout=10)
    assert response.status_code == 200
    payload = response.json()
    assert payload.get("status") == "success"
    assert payload.get("session_id")


@pytest.mark.e2e_api_critical
def test_session_check_requires_session_id(web_api_server, http_client):
    response = http_client.post(f"{web_api_server}/api/session/check", json={}, timeout=10)
    assert response.status_code == 400


@pytest.mark.e2e_api_critical
def test_session_check_valid(web_api_server, http_client, initialized_session):
    response = http_client.post(
        f"{web_api_server}/api/session/check",
        json={"session_id": initialized_session},
        timeout=10,
    )
    assert response.status_code == 200


@pytest.mark.e2e_api_full
def test_session_reset_requires_session(web_api_server, http_client):
    response = http_client.post(f"{web_api_server}/api/session/reset", json={}, timeout=10)
    assert response.status_code == 400


@pytest.mark.e2e_api_critical
def test_session_state_without_session(web_api_server, http_client):
    response = http_client.get(f"{web_api_server}/api/session/state", timeout=10)
    assert response.status_code == 200
    payload = response.json()
    assert payload.get("state") is None


@pytest.mark.e2e_api_full
def test_session_state_with_session(web_api_server, http_client, initialized_session):
    response = http_client.post(
        f"{web_api_server}/api/session/state",
        json={"session_id": initialized_session},
        timeout=10,
    )
    assert response.status_code == 200
    payload = response.json()
    assert "state" in payload
