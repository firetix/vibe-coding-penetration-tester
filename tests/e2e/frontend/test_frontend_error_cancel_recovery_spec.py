import pytest


pytest.importorskip("playwright.sync_api")
from playwright.sync_api import sync_playwright


@pytest.mark.e2e_frontend_full
def test_frontend_cancel_and_retry_flow(web_api_server):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        try:
            page.goto(web_api_server, wait_until="networkidle")

            page.fill("#url", "https://example.com")
            page.select_option("#scan_mode", "quick")
            page.check("#authorization_confirmed")
            page.click("#start-scan-btn")
            page.wait_for_timeout(1000)

            page.on("dialog", lambda d: d.accept())
            page.click("#cancel-btn")
            page.wait_for_timeout(1000)

            # Start button should be enabled again after reset.
            assert not page.is_disabled("#start-scan-btn")

            # Trigger client-side validation error then retry successfully.
            page.uncheck("#authorization_confirmed")
            page.on("dialog", lambda d: d.accept())
            page.click("#start-scan-btn")
            page.wait_for_timeout(500)

            page.check("#authorization_confirmed")
            page.click("#start-scan-btn")
            page.wait_for_timeout(1500)
            assert page.locator("#scan-status-panel").count() == 1
        finally:
            browser.close()


@pytest.mark.e2e_frontend_full
def test_frontend_paywall_after_first_free_scan(web_api_server):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        try:
            page.goto(web_api_server, wait_until="networkidle")

            # First free scan
            page.fill("#url", "https://example.com")
            page.select_option("#scan_mode", "quick")
            page.check("#authorization_confirmed")
            page.click("#start-scan-btn")
            page.wait_for_timeout(3500)

            # Start a second quick scan in same account/session to trigger paywall.
            page.click("#new-scan-btn")
            page.wait_for_load_state("networkidle")
            page.fill("#url", "https://example.com")
            page.select_option("#scan_mode", "quick")
            page.check("#authorization_confirmed")
            page.click("#start-scan-btn")
            page.wait_for_timeout(1200)

            classes = page.get_attribute("#paywall-alert", "class") or ""
            assert "d-none" not in classes
            assert page.get_attribute("#upgrade-link", "href")
        finally:
            browser.close()
