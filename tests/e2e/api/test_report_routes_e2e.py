import pytest

from tests.e2e.conftest import poll_until_complete


@pytest.mark.e2e_api_full
def test_api_reports_list(web_api_server, http_client):
    response = http_client.get(f"{web_api_server}/api/reports", timeout=10)
    assert response.status_code == 200
    payload = response.json()
    assert "reports" in payload


@pytest.mark.e2e_api_full
def test_api_report_missing(web_api_server, http_client):
    response = http_client.get(
        f"{web_api_server}/api/report/does-not-exist", timeout=10
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload.get("error") == "Report not found"


@pytest.mark.e2e_api_critical
def test_legacy_report_endpoint_after_scan(
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

    poll_until_complete(web_api_server, http_client, initialized_session)

    report = http_client.get(
        f"{web_api_server}/report",
        params={"session_id": initialized_session},
        timeout=10,
    )
    assert report.status_code in (200, 202)
    payload = report.json()
    assert (
        payload.get("status") in {"success", "error"}
        or payload.get("markdown") is not None
    )


@pytest.mark.e2e_api_full
def test_reports_file_serving_path(web_api_server, http_client, initialized_session):
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
    completed = poll_until_complete(web_api_server, http_client, initialized_session)
    report_dir = completed.get("report_dir")
    assert report_dir

    file_resp = http_client.get(
        f"{web_api_server}/reports/{report_dir}/report.json", timeout=10
    )
    assert file_resp.status_code == 200


@pytest.mark.e2e_api_full
def test_api_report_fetch_by_id_after_scan(
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

    completed = poll_until_complete(web_api_server, http_client, initialized_session)
    report_dir = completed.get("report_dir")
    assert report_dir

    reports_payload = http_client.get(f"{web_api_server}/api/reports", timeout=10).json()
    reports = reports_payload.get("reports") or []
    assert any(r.get("id") == report_dir for r in reports)

    report = http_client.get(f"{web_api_server}/api/report/{report_dir}", timeout=10)
    assert report.status_code == 200
    payload = report.json()
    assert payload.get("error") != "Report not found"
    assert isinstance(payload.get("findings"), list)
    assert payload.get("findings")
