import pytest


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
    second = http_client.post(f"{web_api_server}/api/billing/webhook", json=event, timeout=10)

    assert first.status_code == 200
    assert second.status_code == 200
