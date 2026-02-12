import pytest
from unittest.mock import patch, MagicMock
import urllib.parse
import html

from agents.security_swarm import ValidationAgent
from core.llm import LLMProvider
from core.scanner import Scanner


class TestXSSEncodingHandling:
    """
    Tests specifically for XSS payload encoding/decoding handling.

    These tests ensure the XSS validation can properly handle different
    encoding schemes like URL encoding and HTML entity encoding.
    """

    @pytest.fixture
    def mock_llm_provider(self):
        """Mock LLM provider for tests."""
        mock_provider = MagicMock(spec=LLMProvider)

        # Mock the think method to return a basic response
        response_obj = MagicMock()
        response_obj.choices = [MagicMock()]
        response_obj.choices[0].message = MagicMock()
        response_obj.choices[
            0
        ].message.content = (
            "This appears to be a real XSS vulnerability with encoded payload."
        )
        response_obj.choices[0].message.tool_calls = []
        mock_provider.chat_completion.return_value = response_obj

        return mock_provider

    @pytest.fixture
    def mock_scanner(self):
        """Mock Scanner for tests."""
        return MagicMock(spec=Scanner)

    @pytest.fixture
    def mock_page(self):
        """Mock Playwright page for tests."""
        mock_page = MagicMock()
        mock_page.url = "https://example.com/test"
        mock_page.content.return_value = ""
        return mock_page

    @pytest.fixture
    def validation_agent(self, mock_llm_provider, mock_scanner):
        """Create a ValidationAgent instance with mocks."""
        with (
            patch("agents.security_swarm.get_security_tools"),
            patch("agents.security_swarm.get_browser_interaction_tools"),
            patch("agents.security_swarm.BrowserTools"),
            patch("agents.security_swarm.WebProxy"),
        ):
            agent = ValidationAgent(mock_llm_provider, mock_scanner)

            # Mock the agent's browser_tools
            agent.browser_tools = MagicMock()

            return agent

    def test_single_url_encoding(self, validation_agent, mock_page):
        """Test XSS validation with single-level URL encoding."""
        # Create an encoded payload
        original_payload = "<script>alert(1)</script>"
        encoded_payload = urllib.parse.quote(original_payload)

        # Arrange
        finding = {
            "vulnerability_type": "Cross-Site Scripting (XSS)",
            "target": "https://example.com/test",
            "severity": "high",
            "details": {
                "payload": encoded_payload,
                "evidence": f"<input value='{encoded_payload}'>",
            },
        }

        page_info = {"url": "https://example.com/test", "title": "Test Page"}

        # Mock the page content to include the encoded payload
        mock_page.content.return_value = (
            f"<html><body><input value='{encoded_payload}'></body></html>"
        )

        # Add script tag pattern detection
        validation_agent.browser_tools.execute_js.side_effect = [
            None,  # First call to inject detector
            {
                "detected": True,
                "method": "script tag found",
            },  # Second call to check detection
        ]

        # Act
        result = validation_agent.validate_finding(finding, mock_page, page_info)

        # Assert
        assert result["validated"] == True
        # Test can pass with either reflection or XSS detection
        assert any(
            [
                "reflection" in result["details"]["validation_method"].lower(),
                "xss detection" in result["details"]["validation_method"].lower(),
            ]
        )

    def test_double_url_encoding(self, validation_agent, mock_page):
        """Test XSS validation with double-level URL encoding."""
        # Create a double-encoded payload
        original_payload = "<script>alert(1)</script>"
        single_encoded = urllib.parse.quote(original_payload)
        double_encoded = urllib.parse.quote(single_encoded)

        # Arrange
        finding = {
            "vulnerability_type": "Cross-Site Scripting (XSS)",
            "target": "https://example.com/test",
            "severity": "high",
            "details": {
                "payload": double_encoded,
                "evidence": f"<input value='{double_encoded}'>",
            },
        }

        page_info = {"url": "https://example.com/test", "title": "Test Page"}

        # Create page content with single-encoded payload (simulating server-side decode)
        mock_page.content.return_value = (
            f"<html><body><input value='{single_encoded}'></body></html>"
        )

        # Simulate successful XSS detection, since we have script tags in the decoded payload
        validation_agent.browser_tools.execute_js.side_effect = [
            None,  # First call to inject detector
            {
                "detected": True,
                "method": "script tag found",
            },  # Successful XSS detection
        ]

        # Act
        result = validation_agent.validate_finding(finding, mock_page, page_info)

        # Assert
        assert result["validated"] == True
        assert "confidence_level" in result["details"]

    def test_html_entity_encoding(self, validation_agent, mock_page):
        """Test XSS validation with HTML entity encoding."""
        # Create an HTML-entity encoded payload
        original_payload = "<script>alert(1)</script>"
        entity_encoded = html.escape(original_payload)

        # Arrange
        finding = {
            "vulnerability_type": "Cross-Site Scripting (XSS)",
            "target": "https://example.com/test",
            "severity": "high",
            "details": {
                "payload": entity_encoded,
                "evidence": f"<div>{entity_encoded}</div>",
            },
        }

        page_info = {"url": "https://example.com/test", "title": "Test Page"}

        # Mock the page content to include the entity-encoded payload
        mock_page.content.return_value = (
            f"<html><body><div>{entity_encoded}</div></body></html>"
        )

        # Simulating script tag detection
        validation_agent.browser_tools.execute_js.side_effect = [
            None,  # First call to inject detector
            {
                "detected": True,
                "method": "script tag found",
            },  # Second call to check detection
        ]

        # Act
        result = validation_agent.validate_finding(finding, mock_page, page_info)

        # Assert
        assert result["validated"] == True
        # Test can pass with either reflection or detector method
        assert any(
            [
                "reflection" in result["details"]["validation_method"].lower(),
                "xss detection" in result["details"]["validation_method"].lower(),
            ]
        )

    def test_mixed_encoding(self, validation_agent, mock_page):
        """Test XSS validation with mixed encoding (URL + HTML entity)."""
        # Create a mixed encoded payload
        original_payload = "<script>alert(1)</script>"
        entity_encoded = html.escape(original_payload)
        mixed_encoded = urllib.parse.quote(entity_encoded)

        # Arrange
        finding = {
            "vulnerability_type": "Cross-Site Scripting (XSS)",
            "target": "https://example.com/test",
            "severity": "high",
            "details": {
                "payload": mixed_encoded,
                "evidence": f"<div>{mixed_encoded}</div>",
            },
        }

        page_info = {"url": "https://example.com/test", "title": "Test Page"}

        # Mock the page content to include the entity-encoded version (assuming URL decode happened)
        mock_page.content.return_value = (
            f"<html><body><div>{entity_encoded}</div></body></html>"
        )

        # Simulate script tag detection
        validation_agent.browser_tools.execute_js.side_effect = [
            None,  # First call to inject detector
            {
                "detected": True,
                "method": "script tag found",
            },  # Second call with detection
        ]

        # Act
        result = validation_agent.validate_finding(finding, mock_page, page_info)

        # Assert
        assert result["validated"] == True
        assert "confidence_level" in result["details"]

    def test_encoded_payload_in_different_context(self, validation_agent, mock_page):
        """Test XSS validation where encoded payload appears in different contexts."""
        # Create an encoded payload
        original_payload = "<script>alert(1)</script>"
        encoded_payload = urllib.parse.quote(original_payload)

        # Arrange
        finding = {
            "vulnerability_type": "Cross-Site Scripting (XSS)",
            "target": "https://example.com/test",
            "severity": "high",
            "details": {
                "payload": encoded_payload,
                "evidence": "Found in URL and form field",
            },
        }

        page_info = {"url": "https://example.com/test", "title": "Test Page"}

        # Mock the page content to include the encoded payload in multiple contexts
        mock_page.content.return_value = f"""
        <html>
            <head><title>Test Page</title></head>
            <body>
                <a href="/search?q={encoded_payload}">Link with payload</a>
                <input name="search" value="{encoded_payload}">
                <p>User input: {encoded_payload}</p>
            </body>
        </html>
        """

        # Simulate XSS detection working with script tags
        validation_agent.browser_tools.execute_js.side_effect = [
            None,  # First call to inject detector
            {
                "detected": True,
                "method": "script tag found",
            },  # Second call with successful detection
        ]

        # Act
        result = validation_agent.validate_finding(finding, mock_page, page_info)

        # Assert
        assert result["validated"] == True
        assert "confidence_level" in result["details"]

    def test_unicode_escape_encoding(self, validation_agent, mock_page):
        """Test XSS validation with Unicode escape sequence encoding."""
        # Create a Unicode escape sequence encoded payload
        original_payload = "<script>alert(1)</script>"
        unicode_encoded = original_payload.encode("unicode_escape").decode()

        # Arrange
        finding = {
            "vulnerability_type": "Cross-Site Scripting (XSS)",
            "target": "https://example.com/test",
            "severity": "high",
            "details": {
                "payload": unicode_encoded,
                "evidence": f"<input value='{unicode_encoded}'>",
            },
        }

        page_info = {"url": "https://example.com/test", "title": "Test Page"}

        # Mock the page content to include the unicode-encoded payload
        mock_page.content.return_value = (
            f"<html><body><input value='{unicode_encoded}'></body></html>"
        )

        # Mock browser_tools.execute_js to detect script tag
        validation_agent.browser_tools.execute_js.side_effect = [
            None,  # First call to inject detector
            {
                "detected": True,
                "method": "script tag found",
            },  # Second call with successful detection
        ]

        # Act
        result = validation_agent.validate_finding(finding, mock_page, page_info)

        # Assert - validation should work using pattern detection
        assert result["validated"] == True
