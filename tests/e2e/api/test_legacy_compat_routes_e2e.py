import pytest


@pytest.mark.e2e_api_full
@pytest.mark.compat_legacy
def test_legacy_scan_start_and_state(web_api_server, http_client, initialized_session):
    start = http_client.post(
        f"{web_api_server}/scan",
        data={
            "session_id": initialized_session,
            "url": "https://example.com",
            "scan_mode": "quick",
            "authorization_confirmed": "true",
        },
        timeout=10,
    )
    assert start.status_code in (200, 402)

    state = http_client.get(
        f"{web_api_server}/api/state",
        params={"session_id": initialized_session},
        timeout=10,
    )
    assert state.status_code == 200


@pytest.mark.e2e_api_full
@pytest.mark.compat_legacy
def test_legacy_reset(web_api_server, http_client, initialized_session):
    reset = http_client.post(
        f"{web_api_server}/reset",
        data={"session_id": initialized_session},
        timeout=10,
    )
    assert reset.status_code == 200
