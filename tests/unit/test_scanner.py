import pytest
from unittest.mock import patch, MagicMock

from core.scanner import Scanner


class TestScanner:

    @patch("core.scanner.sync_playwright")
    def test_scanner_initialization(self, mock_playwright):
        # Arrange
        mock_playwright_instance = MagicMock()
        mock_playwright.return_value.start.return_value = mock_playwright_instance

        mock_browser = MagicMock()
        mock_context = MagicMock()

        mock_playwright_instance.chromium.launch.return_value = mock_browser
        mock_browser.new_context.return_value = mock_context

        # Act
        scanner = Scanner(headless=True, slow_mo=50, timeout=30000)
        scanner.start()

        # Assert
        assert scanner.playwright == mock_playwright_instance
        assert scanner.browser == mock_browser
        assert scanner.context == mock_context
        mock_playwright.return_value.start.assert_called_once()
        # Include default args added by Scanner
        mock_playwright_instance.chromium.launch.assert_called_once_with(
            headless=True,
            slow_mo=50,
            args=['--disable-web-security', '--disable-features=IsolateOrigins,site-per-process', '--disable-site-isolation-trials']
        )
        mock_browser.new_context.assert_called_once()

    @patch("core.scanner.sync_playwright")
    def test_scanner_cleanup(self, mock_playwright):
        # Arrange
        mock_playwright_instance = MagicMock()
        mock_playwright.return_value.start.return_value = mock_playwright_instance

        mock_browser = MagicMock()
        mock_context = MagicMock()

        mock_playwright_instance.chromium.launch.return_value = mock_browser
        mock_browser.new_context.return_value = mock_context

        scanner = Scanner()
        scanner.start()

        # Act
        scanner.stop()

        # Assert
        mock_context.close.assert_called_once()
        mock_browser.close.assert_called_once()
        mock_playwright_instance.stop.assert_called_once()

    @patch("core.scanner.sync_playwright")
    def test_load_page_success(self, mock_playwright):
        # Arrange
        mock_playwright_instance = MagicMock()
        mock_playwright.return_value.start.return_value = mock_playwright_instance

        mock_browser = MagicMock()
        mock_context = MagicMock()
        mock_page_initial = MagicMock() # First page attempt
        mock_page_retry1 = MagicMock() # Second page attempt
        mock_page_retry2 = MagicMock() # Third page attempt

        mock_playwright_instance.chromium.launch.return_value = mock_browser
        mock_browser.new_context.return_value = mock_context

        # Mock new_page to return different mock pages on successive calls
        mock_context.new_page.side_effect = [mock_page_initial, mock_page_retry1, mock_page_retry2]

        # Simulate initial goto failure, then success on retry 1
        mock_page_initial.goto.side_effect = Exception("Initial load failed")
        mock_page_retry1.goto.return_value = MagicMock(status=200) # Simulate successful response
        mock_page_retry2.goto.return_value = MagicMock(status=200) # Should not be called

        scanner = Scanner()
        scanner.start()

        # Act
        result = scanner.load_page("https://example.com")

        # Assert
        # The result should be the page from the successful retry
        assert result == mock_page_retry1
        # new_page should have been called twice (initial + retry 1)
        mock_context.new_page.call_count == 2
        # goto should have been called on the initial page and the first retry page
        mock_page_initial.goto.assert_called_once()
        mock_page_retry1.goto.assert_called_once()
        # The second retry page's goto should not have been called
        mock_page_retry2.goto.assert_not_called()
        # new_context should only be called once during scanner.start
        mock_browser.new_context.assert_called_once()

    @patch("core.scanner.sync_playwright")
    @patch("core.scanner.time.sleep", return_value=None) # Mock sleep to speed up test
    def test_load_page_failure(self, mock_sleep, mock_playwright):
        # Arrange
        mock_playwright_instance = MagicMock()
        mock_playwright.return_value.start.return_value = mock_playwright_instance

        mock_browser = MagicMock()
        mock_context_initial = MagicMock() # Initial context
        mock_context_js_disabled = MagicMock() # Context with JS disabled

        # Create mock pages with mocked goto methods
        mock_page_initial = MagicMock()
        mock_page_initial.goto.side_effect = Exception("Failed to load page 1")

        mock_page_retry1 = MagicMock()
        mock_page_retry1.goto.side_effect = Exception("Failed to load page 2")

        mock_page_retry2 = MagicMock()
        mock_page_retry2.goto.side_effect = Exception("Failed to load page 3")

        mock_playwright_instance.chromium.launch.return_value = mock_browser

        # Mock new_context to return different contexts
        mock_browser.new_context.side_effect = [mock_context_initial, mock_context_js_disabled]

        # Mock new_page calls on both contexts to return the pre-configured mock pages
        mock_context_initial.new_page.side_effect = [mock_page_initial, mock_page_retry1]
        mock_context_js_disabled.new_page.return_value = mock_page_retry2 # This page should be created

        scanner = Scanner()
        scanner.start() # This calls new_context once

        # Act
        result = scanner.load_page("https://example.com")

        # Assert
        # load_page should return None after all failures
        assert result is None
        # new_context should be called twice (initial start + JS disabled retry)
        assert mock_browser.new_context.call_count == 2
        # new_page should be called twice on the initial context and once on the JS disabled context
        assert mock_context_initial.new_page.call_count == 2
        mock_context_js_disabled.new_page.assert_called_once()
        # goto should be called once on each of the three mock pages
        mock_page_initial.goto.assert_called_once()
        mock_page_retry1.goto.assert_called_once()
        mock_page_retry2.goto.assert_called_once()
        # sleep should be called between retries
        assert mock_sleep.call_count == 2 # 2 sleeps for 3 attempts

    @patch("core.scanner.sync_playwright")
    def test_extract_page_info(self, mock_playwright):
        # Arrange
        mock_playwright_instance = MagicMock()
        mock_playwright.return_value.start.return_value = mock_playwright_instance

        mock_browser = MagicMock()
        mock_context = MagicMock()
        mock_page = MagicMock()

        mock_playwright_instance.chromium.launch.return_value = mock_browser
        mock_browser.new_context.return_value = mock_context

        # Setup page mock
        mock_page.url = "https://example.com"
        mock_page.title.return_value = "Example Page"
        mock_page.content.return_value = "<html><body>Test jQuery page</body></html>"

        mock_links = [{"href": "https://example.com/page1", "text": "Page 1", "id": "", "class": ""}]
        mock_forms = [{"id": "login-form", "name": "login", "action": "/login", "method": "post", "inputs": [{"name": "username", "id": "username", "type": "text", "value": "", "placeholder": "Username"}]}]
        mock_inputs = [{"name": "username", "id": "username", "type": "text", "value": ""}]
        mock_scripts = ["https://example.com/jquery.min.js"]

        mock_page.evaluate.side_effect = [mock_links, mock_forms, mock_inputs, mock_scripts]

        # Setup cookies
        mock_page.context.cookies.return_value = [{"name": "session", "value": "123"}]

        scanner = Scanner()
        scanner.start()

        # Act
        page_info = scanner.extract_page_info(mock_page)

        # Assert
        assert page_info["url"] == "https://example.com"
        assert page_info["title"] == "Example Page"
        assert page_info["html"] == "<html><body>Test jQuery page</body></html>"
        assert page_info["links"] == mock_links
        assert page_info["forms"] == mock_forms
        assert page_info["inputs"] == mock_inputs
        assert page_info["scripts"] == mock_scripts
        assert page_info["cookies"] == [{"name": "session", "value": "123"}]
        assert "jQuery" in page_info["technologies"]

    @patch("core.scanner.sync_playwright")
    def test_execute_javascript(self, mock_playwright):
        # Arrange
        mock_playwright_instance = MagicMock()
        mock_playwright.return_value.start.return_value = mock_playwright_instance

        mock_browser = MagicMock()
        mock_context = MagicMock()
        mock_page = MagicMock()

        mock_playwright_instance.chromium.launch.return_value = mock_browser
        mock_browser.new_context.return_value = mock_context

        mock_page.evaluate.return_value = {"result": "success"}

        scanner = Scanner()
        scanner.start()

        # Act
        result = scanner.execute_javascript(mock_page, "return {result: 'success'}")

        # Assert
        assert result == {"result": "success"}
        mock_page.evaluate.assert_called_once_with("return {result: 'success'}")

    @patch("core.scanner.sync_playwright")
    def test_fill_form(self, mock_playwright):
        # Arrange
        mock_playwright_instance = MagicMock()
        mock_playwright.return_value.start.return_value = mock_playwright_instance

        mock_browser = MagicMock()
        mock_context = MagicMock()
        mock_page = MagicMock()

        mock_playwright_instance.chromium.launch.return_value = mock_browser
        mock_browser.new_context.return_value = mock_context

        mock_page.fill.return_value = None

        scanner = Scanner()
        scanner.start()

        # Act
        result = scanner.fill_form(mock_page, "#username", "testuser")

        # Assert
        assert result is True
        mock_page.fill.assert_called_once_with("#username", "testuser")

    @patch("core.scanner.sync_playwright")
    def test_click_element(self, mock_playwright):
        # Arrange
        mock_playwright_instance = MagicMock()
        mock_playwright.return_value.start.return_value = mock_playwright_instance

        mock_browser = MagicMock()
        mock_context = MagicMock()
        mock_page = MagicMock()

        mock_playwright_instance.chromium.launch.return_value = mock_browser
        mock_browser.new_context.return_value = mock_context

        mock_page.click.return_value = None

        scanner = Scanner()
        scanner.start()

        # Act
        result = scanner.click_element(mock_page, "#submit-button")

        # Assert
        assert result is True
        mock_page.click.assert_called_once_with("#submit-button")