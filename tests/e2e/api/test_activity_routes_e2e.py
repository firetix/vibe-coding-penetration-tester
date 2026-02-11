import pytest


@pytest.mark.e2e_api_full
def test_activity_requires_session(web_api_server, http_client):
    response = http_client.post(f"{web_api_server}/api/activity", json={}, timeout=10)
    assert response.status_code == 400


@pytest.mark.e2e_api_full
def test_activity_with_session(web_api_server, http_client, initialized_session):
    response = http_client.post(
        f"{web_api_server}/api/activity",
        json={"session_id": initialized_session},
        timeout=10,
    )
    assert response.status_code == 200
    payload = response.json()
    assert "activities" in payload
