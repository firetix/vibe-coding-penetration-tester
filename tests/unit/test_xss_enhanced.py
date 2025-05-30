import unittest
from unittest.mock import Mock, patch, MagicMock
import pytest

from agents.security.xss_agent import XSSAgent
from core.llm import LLMProvider
from core.scanner import Scanner


class TestXSSAgent(unittest.TestCase):
    def setUp(self):
        # Create mocks for dependencies
        self.llm_provider_mock = Mock(spec=LLMProvider)
        self.scanner_mock = Mock(spec=Scanner)

        # Create a mock Page object to simulate Playwright
        self.page_mock = MagicMock()

        # Set up the page mock to return HTML content
        self.page_mock.content.return_value = "<html><body>Test content</body></html>"
        self.page_mock.url = "http://example.com"

        # Mock evaluate method
        self.page_mock.evaluate.return_value = False
        
        # Create the XSS agent after all mocks are set up
        self.xss_agent = XSSAgent(self.llm_provider_mock, self.scanner_mock, self.page_mock)

    def test_init(self):
        """Test initialization of XSS agent."""
        self.assertEqual(self.xss_agent.name, "XSSAgent")
        self.assertEqual(self.xss_agent.role, "xss_specialist")
        self.assertEqual(self.xss_agent.security_type, "xss")

        # Verify patterns are initialized
        self.assertIsNotNone(self.xss_agent.xss_basic_patterns)
        self.assertIsNotNone(self.xss_agent.context_patterns)
        self.assertIsNotNone(self.xss_agent.evasion_patterns)
        self.assertIsNotNone(self.xss_agent.dom_xss_sources)
        self.assertIsNotNone(self.xss_agent.dom_xss_sinks)

    def test_check_url_for_xss_with_no_parameters(self):
        """Test URL XSS check with no parameters."""
        url = "http://example.com"
        result = self.xss_agent._check_url_for_xss(url, self.page_mock)
        self.assertIsNone(result)

    def test_check_url_for_xss_with_safe_parameters(self):
        """Test URL XSS check with safe parameters."""
        url = "http://example.com/?q=safe&id=123"
        result = self.xss_agent._check_url_for_xss(url, self.page_mock)
        self.assertIsNone(result)

    def test_check_url_for_xss_with_xss_payload(self):
        """Test URL XSS check with suspicious XSS payload."""
        url = "http://example.com/?q=<script>alert(1)</script>"

        # Mock that the payload is reflected in the HTML
        self.page_mock.content.return_value = """
        <html>
        <body>
            <div>Search results for: <script>alert(1)</script></div>
        </body>
        </html>
        """

        # Execute the test
        result = self.xss_agent._check_url_for_xss(url, self.page_mock)

        # Verify results
        self.assertIsNotNone(result)
        self.assertEqual(result["issue_type"], "Reflected XSS")
        self.assertEqual(result["injection_point"], "URL parameter")
        self.assertEqual(result["parameter"], "q")
        self.assertEqual(result["payload"], "<script>alert(1)</script>")

    def test_check_url_for_xss_with_encoded_payload(self):
        """Test URL XSS check with URL-encoded XSS payload."""
        url = "http://example.com/?q=%3Cscript%3Ealert(1)%3C/script%3E"

        # Mock that the decoded payload is reflected in the HTML
        self.page_mock.content.return_value = """
        <html>
        <body>
            <div>Search results for: <script>alert(1)</script></div>
        </body>
        </html>
        """

        # Execute the test
        result = self.xss_agent._check_url_for_xss(url, self.page_mock)

        # Verify results
        self.assertIsNotNone(result)
        self.assertEqual(result["issue_type"], "Reflected XSS")
        self.assertEqual(result["injection_point"], "URL parameter")
        self.assertEqual(result["parameter"], "q")
        self.assertEqual(result["payload"], "<script>alert(1)</script>")

    def test_check_for_dom_xss_no_code(self):
        """Test DOM XSS check with no JS code."""
        result = self.xss_agent._check_for_dom_xss("", "", self.page_mock)
        self.assertIsNone(result)

    def test_check_for_dom_xss_with_source_and_sink(self):
        """Test DOM XSS check with source and sink."""
        js_code = "document.write(location.hash.substring(1))"
        js_result = "XSS executed"

        # Mock that the evaluation is successful
        self.page_mock.evaluate.return_value = True

        # Execute the test
        result = self.xss_agent._check_for_dom_xss(js_code, js_result, self.page_mock)

        # Verify results
        self.assertIsNotNone(result)
        self.assertEqual(result["source"], "location")
        self.assertEqual(result["sink"], "document.write")

    def test_check_for_reflected_content_with_direct_reflection(self):
        """Test reflected content check with direct reflection."""
        input_value = "<script>alert(1)</script>"

        # Mock the page content with direct reflection
        self.page_mock.content.return_value = """
        <html>
        <body>
            <div>You searched for: <script>alert(1)</script></div>
        </body>
        </html>
        """

        # Mock the context detection
        self.page_mock.evaluate.return_value = "HTML content in <div> element"

        # Execute the test
        result = self.xss_agent._check_for_reflected_content(self.page_mock, input_value)

        # Verify results
        self.assertIsNotNone(result)
        self.assertEqual(result["context"], "HTML content in <div> element")
        self.assertFalse(result["bypass"])

    def test_check_for_reflected_content_with_encoded_reflection(self):
        """Test reflected content check with encoded reflection."""
        input_value = "<script>alert(1)</script>"

        # Mock the page content with encoded reflection
        self.page_mock.content.return_value = """
        <html>
        <body>
            <div>You searched for: &lt;script&gt;alert(1)&lt;/script&gt;</div>
        </body>
        </html>
        """

        # Execute the test
        result = self.xss_agent._check_for_reflected_content(self.page_mock, input_value)

        # Verify results
        self.assertIsNotNone(result)
        self.assertEqual(result["evidence"], "XSS payload reflected in page content (encoded)")
        self.assertEqual(result["context"], "Encoded content")

    def test_check_for_sanitization_bypass_with_nested_tags(self):
        """Test sanitization bypass check with nested tags."""
        input_value = "<<script>alert(1)</script>"

        # Mock the page URL to simulate a feedback form
        self.page_mock.url = "http://example.com/feedback"

        # Mock the page content with successful bypass
        self.page_mock.content.return_value = """
        <html>
        <body>
            <div>Your feedback: <<script>alert(1)</script></div>
            <script>alert(1)</script>
        </body>
        </html>
        """

        # Execute the test
        result = self.xss_agent._check_for_sanitization_bypass(self.page_mock, input_value)

        # Verify results
        self.assertIsNotNone(result)
        self.assertIn("Nested Tags", result["type"])
        self.assertEqual(result["payload"], input_value)

    def test_check_for_api_xss_with_xss_payload(self):
        """Test API XSS check with XSS payload."""
        # Mock API endpoint URL
        self.page_mock.url = "http://example.com/api/comments"

        # Create a tool call mock with nested structure and method
        tool_call_mock = MagicMock()
        tool_call_mock.function.arguments = {"body": '{"comment": "<script>alert(1)</script>"}'}
        tool_call_mock.method = "POST"

        # Execute the test
        result = self.xss_agent._check_for_api_xss(self.page_mock, tool_call_mock)

        # Verify results
        self.assertIsNotNone(result)
        self.assertEqual(result["issue_type"], "Stored XSS via API")
        self.assertEqual(result["api_operation"], "comments")
        self.assertIn("<script>alert(1)</script>", result["payload"])

    def test_determine_xss_type_with_reflected_url(self):
        """Test XSS type determination with URL likely to be reflected."""
        url = "http://example.com/search?q=test"
        xss_type = self.xss_agent._determine_xss_type(url)
        self.assertEqual(xss_type, "Reflected")

    def test_determine_xss_type_with_stored_url(self):
        """Test XSS type determination with URL likely to store data."""
        url = "http://example.com/feedback"
        xss_type = self.xss_agent._determine_xss_type(url)
        self.assertEqual(xss_type, "Stored")

    def test_check_sanitization_bypass(self):
        """Test sanitization bypass detection."""
        html_content = "<div>Your comment: <<script>alert(1)</script></div>"
        input_value = "<<script>alert(1)</script>"
        result = self.xss_agent._check_sanitization_bypass(html_content, input_value)
        self.assertTrue(result)


if __name__ == "__main__":
    unittest.main()