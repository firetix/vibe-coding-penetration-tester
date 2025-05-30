import unittest
from unittest.mock import Mock, patch, MagicMock
import pytest
import json
import re

from agents.security.xss_agent import XSSAgent
from core.llm import LLMProvider
from core.scanner import Scanner
from core.scanner_context import ScannerContext


@pytest.mark.integration
class TestXSSEnhancedDetection(unittest.TestCase):
    def setUp(self):
        # Create mocks for dependencies
        self.llm_provider_mock = Mock(spec=LLMProvider)
        self.scanner_mock = Mock(spec=Scanner)

        # Configure mock responses for LLM
        def mock_think(input_data, system_prompt):
            # Simplified response simulation for testing
            if "xss" in system_prompt.lower():
                return {"content": "Found XSS vulnerability in the application"}
            return {"content": "No vulnerabilities found"}

        self.llm_provider_mock.query = mock_think

        # Create a mock Page object for Playwright
        self.page_mock = MagicMock()
        self.page_mock.url = "http://example.com/search?q=test"
        self.page_mock.content.return_value = "<html><body>Test content</body></html>"
        self.page_mock.evaluate.return_value = False

        # Create the XSS agent with the mock page
        self.xss_agent = XSSAgent(self.llm_provider_mock, self.scanner_mock, self.page_mock)

        # Create a scanner context (not used for page_info anymore)
        self.context = ScannerContext()

        # Mock scanner methods that agents interact with
        self.scanner_mock.extract_page_info.return_value = {"title": "Test Page", "url": "http://example.com"}

    @patch("playwright.sync_api.Page")
    def test_basic_xss_detection_in_url(self, mock_playwright_page):
        """Test basic XSS detection in URL parameters."""
        # Configure the mock page
        page = mock_playwright_page.return_value
        page.url = "http://example.com/search?q=<script>alert(1)</script>"
        page.content.return_value = """
        <html>
        <body>
            <div>Search results for: <script>alert(1)</script></div>
        </body>
        </html>
        """
        page.evaluate.return_value = True  # Simulate successful script execution

        # Create a task to test
        task = {
            "type": "xss_test",
            "target": "search form",
            "parameters": {
                "q": "<script>alert(1)</script>"
            }
        }

        # Mock tool call that simulates URL navigation
        tool_call = MagicMock()
        tool_result = {
            "success": True,
            "url": page.url
        }

        # Invoke the vulnerability check method directly
        result = {"vulnerability_found": False, "details": {}}
        updated_result = self.xss_agent._check_for_vulnerabilities(
            "goto", tool_result, result, page, tool_call
        )

        # Assert that an XSS vulnerability was detected
        self.assertTrue(updated_result["vulnerability_found"])
        self.assertEqual(updated_result["vulnerability_type"], "Reflected Cross-Site Scripting (XSS)")
        self.assertEqual(updated_result["severity"], "high")

    @patch("playwright.sync_api.Page")
    def test_dom_based_xss_detection(self, mock_playwright_page):
        """Test DOM-based XSS detection."""
        # Configure the mock page
        page = mock_playwright_page.return_value
        page.url = "http://example.com/#<script>alert(1)</script>"
        page.content.return_value = """
        <html>
        <body>
            <div id="content"></div>
            <script>
                document.getElementById('content').innerHTML = location.hash.substring(1);
            </script>
        </body>
        </html>
        """
        page.evaluate.return_value = True  # Simulate successful script execution

        # Create js_code and result that would trigger DOM XSS detection
        js_code = "document.write(location.hash.substring(1))"
        js_result = "alert(1) executed successfully"

        # Mock tool call for JavaScript execution
        tool_call = MagicMock()
        tool_call.function.arguments.js_code = js_code

        tool_result = {
            "success": True,
            "result": js_result
        }

        # Invoke the vulnerability check method directly
        result = {"vulnerability_found": False, "details": {}}
        updated_result = self.xss_agent._check_for_vulnerabilities(
            "execute_js", tool_result, result, page, tool_call
        )

        # Assert that a DOM-based XSS vulnerability was detected
        self.assertTrue(updated_result["vulnerability_found"])
        self.assertEqual(updated_result["vulnerability_type"], "DOM-based Cross-Site Scripting (XSS)")
        self.assertEqual(updated_result["severity"], "high")

    @patch("playwright.sync_api.Page")
    def test_stored_xss_detection_in_forms(self, mock_playwright_page):
        """Test stored XSS detection in form submissions."""
        # Configure the mock page
        page = mock_playwright_page.return_value
        page.url = "http://example.com/feedback"
        page.content.return_value = """
        <html>
        <body>
            <div>Your feedback: <script>alert(1)</script></div>
        </body>
        </html>
        """
        page.evaluate.return_value = False  # Script not executed yet

        # Mock tool call for form submission
        tool_call = MagicMock()
        tool_call.function.arguments.selector = "#feedback-form"
        tool_call.function.arguments.value = "<script>alert(1)</script>"

        tool_result = {
            "success": True
        }

        # Invoke the vulnerability check method directly
        result = {"vulnerability_found": False, "details": {}}
        updated_result = self.xss_agent._check_for_vulnerabilities(
            "fill", tool_result, result, page, tool_call
        )

        # Assert that a stored XSS vulnerability was detected
        self.assertTrue(updated_result["vulnerability_found"])
        self.assertEqual(updated_result["vulnerability_type"], "Stored Cross-Site Scripting (XSS)")
        self.assertEqual(updated_result["severity"], "high")

    @patch("playwright.sync_api.Page")
    def test_sanitization_bypass_detection(self, mock_playwright_page):
        """Test detection of XSS sanitization bypasses."""
        # Configure the mock page
        page = mock_playwright_page.return_value
        page.url = "http://example.com/feedback"
        page.content.return_value = """
        <html>
        <body>
            <div>Your feedback: <<script>alert(1)</script></div>
            <script>alert(1)</script>
        </body>
        </html>
        """
        page.evaluate.return_value = True  # Script executed

        # Mock tool call for form submission with sanitization bypass
        tool_call = MagicMock()
        tool_call.function.arguments.selector = "#feedback-form"
        tool_call.function.arguments.value = "<<script>alert(1)</script>"

        tool_result = {
            "success": True
        }

        # Invoke the vulnerability check method directly
        result = {"vulnerability_found": False, "details": {}}
        updated_result = self.xss_agent._check_for_vulnerabilities(
            "fill", tool_result, result, page, tool_call
        )

        # Assert that a sanitization bypass was detected
        self.assertTrue(updated_result["vulnerability_found"])
        self.assertIn("Sanitization Bypass", updated_result["vulnerability_type"])
        self.assertEqual(updated_result["severity"], "critical")

    @patch("playwright.sync_api.Page")
    def test_api_based_xss_detection(self, mock_playwright_page):
        """Test XSS detection in API calls."""
        # Configure the mock page
        page = mock_playwright_page.return_value
        page.url = "http://example.com/api/comments"

        # Mock tool call for API request with XSS payload
        tool_call = MagicMock()
        tool_call.method = "POST" # Add method attribute
        tool_call.__str__ = lambda self: "POST /api/comments"
        # Explicitly mock the function attribute and its arguments
        tool_call.function = MagicMock()
        tool_call.function.arguments = {
            "body": json.dumps({
                "comment": "<script>alert(1)</script>",
                "author": "test"
            })
        }

        tool_result = {
            "success": True,
            "url": page.url
        }

        # Invoke the vulnerability check method directly
        result = {"vulnerability_found": False, "details": {}}
        updated_result = self.xss_agent._check_for_vulnerabilities(
            "goto", tool_result, result, page, tool_call
        )

        # Assert that an API-based XSS vulnerability was detected
        self.assertTrue(updated_result["vulnerability_found"])
        self.assertIn("Client-Side Validation Bypass", updated_result["vulnerability_type"])
        self.assertEqual(updated_result["severity"], "high")

    @patch("playwright.sync_api.Page")
    def test_context_detection_in_xss(self, mock_playwright_page):
        """Test context detection for XSS payloads."""
        # Configure the mock page
        page = mock_playwright_page.return_value
        page.url = "http://example.com/search"
        page.content.return_value = """
        <html>
        <body>
            <input type="text" value="<script>alert(1)</script>">
            <div onclick="javascript:<script>alert(1)</script>">Click me</div>
            <script>
                var userInput = "<script>alert(1)</script>";
            </script>
        </body>
        </html>
        """

        # Test different context detection
        html_context = self.xss_agent._determine_reflection_context(page, "<script>alert(1)</script>")

        # The evaluate method should return different contexts
        page.evaluate.side_effect = [
            "value attribute in <input> element",  # First call
            "onclick attribute in <div> element",  # Second call
            "JavaScript context in <script> tag"   # Third call
        ]

        # Mock the page.evaluate method to return context information
        self.assertIsNotNone(html_context)


if __name__ == "__main__":
    unittest.main()