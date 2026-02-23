import pytest


pytest.importorskip("playwright.sync_api")
from playwright.sync_api import sync_playwright


@pytest.mark.e2e_frontend_smoke
def test_frontend_one_click_quick_scan_flow(web_api_server):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        try:
            page.goto(web_api_server, wait_until="networkidle")
            page.fill("#url", "https://example.com")
            page.select_option("#scan_mode", "quick")
            page.check("#authorization_confirmed")
            page.click("#start-scan-btn")

            page.wait_for_selector("#scan-status-panel", timeout=10000)
            # Wait until the report panel is actually revealed.
            page.wait_for_selector("#report-container:not(.d-none)", timeout=30000)
        finally:
            browser.close()
