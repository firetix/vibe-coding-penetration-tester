import pytest
import requests


@pytest.mark.compat_legacy
@pytest.mark.e2e_api_full
def test_web_ui_compat_core_endpoints(legacy_server):
    client = requests.Session()
    try:
        init = client.post(f"{legacy_server}/api/session/init", json={"client_id": "legacy"}, timeout=10)
        assert init.status_code == 200
        session_id = init.json().get("session_id")
        assert session_id

        scan = client.post(
            f"{legacy_server}/scan",
            data={
                "session_id": session_id,
                "url": "https://example.com",
                "scan_mode": "quick",
                "authorization_confirmed": "true",
            },
            timeout=10,
        )
        assert scan.status_code in (200, 402)

        status = client.get(f"{legacy_server}/status", params={"session_id": session_id}, timeout=10)
        assert status.status_code == 200

        report = client.get(f"{legacy_server}/report", params={"session_id": session_id}, timeout=10)
        assert report.status_code in (200, 202, 404)

        reset = client.post(f"{legacy_server}/reset", data={"session_id": session_id}, timeout=10)
        assert reset.status_code == 200

        state = client.get(f"{legacy_server}/api/state", params={"session_id": session_id}, timeout=10)
        assert state.status_code == 200
    finally:
        client.close()
