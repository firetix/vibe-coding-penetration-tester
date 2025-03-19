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
        mock_playwright_instance.chromium.launch.assert_called_once_with(headless=True, slow_mo=50)
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
        mock_page = MagicMock()
        
        mock_playwright_instance.chromium.launch.return_value = mock_browser
        mock_browser.new_context.return_value = mock_context
        mock_context.new_page.return_value = mock_page
        
        scanner = Scanner()
        scanner.start()
        
        # Act
        result = scanner.load_page("https://example.com")
        
        # Assert
        assert result == mock_page
        mock_context.new_page.assert_called_once()
        mock_page.goto.assert_called_once_with("https://example.com", wait_until="networkidle")
    
    @patch("core.scanner.sync_playwright")
    def test_load_page_failure(self, mock_playwright):
        # Arrange
        mock_playwright_instance = MagicMock()
        mock_playwright.return_value.start.return_value = mock_playwright_instance
        
        mock_browser = MagicMock()
        mock_context = MagicMock()
        mock_page = MagicMock()
        
        mock_playwright_instance.chromium.launch.return_value = mock_browser
        mock_browser.new_context.return_value = mock_context
        mock_context.new_page.return_value = mock_page
        
        # Simulate a failure
        mock_page.goto.side_effect = Exception("Failed to load page")
        
        scanner = Scanner()
        scanner.start()
        
        # Act
        result = scanner.load_page("https://example.com")
        
        # Assert
        assert result is None
        mock_context.new_page.assert_called_once()
        mock_page.goto.assert_called_once()
    
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