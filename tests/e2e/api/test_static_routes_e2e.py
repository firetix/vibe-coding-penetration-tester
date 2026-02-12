import pytest


@pytest.mark.e2e_api_full
def test_root_page_loads(web_api_server, http_client):
    response = http_client.get(f"{web_api_server}/", timeout=10)
    assert response.status_code == 200
    assert "Start Security Scan" in response.text


@pytest.mark.e2e_api_full
def test_static_favicon_route(web_api_server, http_client):
    response = http_client.get(f"{web_api_server}/static/favicon.ico", timeout=10)
    assert response.status_code == 200


@pytest.mark.e2e_api_full
def test_favicon_route(web_api_server, http_client):
    response = http_client.get(f"{web_api_server}/favicon.ico", timeout=10)
    assert response.status_code == 200
