import os
import time

import pytest
import requests


pytest.importorskip("playwright.sync_api")
from playwright.sync_api import sync_playwright


def _get_base_url() -> str:
    base_url = os.environ.get("VPT_BASE_URL") or os.environ.get("VERCEL_PREVIEW_URL")
    if not base_url:
        pytest.skip("No preview URL set. Provide VPT_BASE_URL or VERCEL_PREVIEW_URL.")
    return base_url.rstrip("/")


def _bypass_headers() -> dict:
    bypass_token = os.environ.get("VERCEL_BYPASS_TOKEN")
    if not bypass_token:
        return {}
    return {
        "x-vercel-protection-bypass": bypass_token,
        "x-vercel-set-bypass-cookie": "true",
    }


def _is_panel_visible(page, selector: str) -> bool:
    classes = page.get_attribute(selector, "class") or ""
    return "d-none" not in classes


@pytest.mark.e2e_vercel_preview
def test_vercel_preview_api_bootstrap():
    base_url = _get_base_url()
    session = requests.Session()
    headers = _bypass_headers()

    index_response = session.get(f"{base_url}/", headers=headers, timeout=20)
    if index_response.status_code == 401:
        pytest.fail(
            "Preview is protected by Vercel authentication. "
            "Set VERCEL_BYPASS_TOKEN (GitHub secret VERCEL_AUTOMATION_BYPASS_SECRET) for E2E automation."
        )
    assert index_response.status_code == 200

    status_response = session.get(f"{base_url}/status", headers=headers, timeout=20)
    assert status_response.status_code == 200

    init_response = session.post(
        f"{base_url}/api/session/init",
        json={"client_id": "gha_vercel_smoke"},
        headers=headers,
        timeout=20,
    )
    assert init_response.status_code == 200
    payload = init_response.json()
    assert payload.get("session_id")


@pytest.mark.e2e_vercel_preview
def test_vercel_preview_frontend_scan_path():
    base_url = _get_base_url()
    headers = _bypass_headers()

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context_kwargs = {}
        if headers:
            context_kwargs["extra_http_headers"] = headers
        context = browser.new_context(**context_kwargs)
        page = context.new_page()
        try:
            page.goto(base_url, wait_until="networkidle", timeout=60000)
            if "vercel.com/login" in page.url:
                pytest.fail(
                    "Preview redirected to Vercel login. "
                    "Set VERCEL_BYPASS_TOKEN (GitHub secret VERCEL_AUTOMATION_BYPASS_SECRET)."
                )
            page.fill("#url", "https://example.com")
            page.select_option("#scan_mode", "quick")
            page.check("#authorization_confirmed")
            page.click("#start-scan-btn")

            signal = None
            deadline = time.time() + 30
            while time.time() < deadline:
                if _is_panel_visible(page, "#paywall-alert"):
                    signal = "paywall"
                    break
                if _is_panel_visible(page, "#scan-status-panel"):
                    signal = "scan-status"
                    break
                if _is_panel_visible(page, "#error-container"):
                    signal = "error"
                    break
                page.wait_for_timeout(500)

            assert signal is not None
        finally:
            context.close()
            browser.close()
