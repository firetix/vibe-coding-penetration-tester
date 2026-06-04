import pytest


pytest.importorskip("playwright.sync_api")
from playwright.sync_api import sync_playwright


@pytest.mark.e2e_frontend_full
def test_frontend_state_restore_after_reload(web_api_server):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        try:
            page.goto(web_api_server, wait_until="networkidle")
            page.fill("#url", "https://example.com")
            page.select_option("#scan_mode", "quick")
            page.check("#authorization_confirmed")
            page.click("#start-scan-btn")
            page.wait_for_selector("#scan-status-panel:not(.d-none)", timeout=30000)

            page.reload(wait_until="networkidle")
            page.wait_for_function(
                """() => {
                    const isVisible = (selector) => {
                        const el = document.querySelector(selector);
                        return !!el && !el.classList.contains('d-none');
                    };
                    return isVisible('#scan-status-panel') || isVisible('#report-container');
                }""",
                timeout=45000,
            )

            status_classes = page.get_attribute("#scan-status-panel", "class") or ""
            report_classes = page.get_attribute("#report-container", "class") or ""
            # After reload either scan panel remains visible or report is already visible.
            assert ("d-none" not in status_classes) or ("d-none" not in report_classes)
        finally:
            browser.close()
