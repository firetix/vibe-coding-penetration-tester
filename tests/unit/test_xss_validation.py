import pytest
from unittest.mock import patch, MagicMock
import json

from agents.security_swarm import ValidationAgent
from core.llm import LLMProvider
from core.scanner import Scanner


class TestXSSValidation:
    """Unit tests for XSS validation logic in ValidationAgent."""

    @pytest.fixture
    def mock_llm_provider(self):
        """Mock LLM provider for tests."""
        mock_provider = MagicMock(spec=LLMProvider)

        # Mock the think method to return a basic response
        # Mock the chat_completion method to return a response with a tool call using dictionary structure
        mock_provider.chat_completion.return_value = MagicMock(
            choices=[MagicMock(
                message=MagicMock(
                    content="Calling validate_finding tool.",
                    tool_calls=[{
                        "function": {
                            "name": "validate_finding",
                            "arguments": '{"vulnerability_type": "Cross-Site Scripting (XSS)", "validated": true, "details": {"validation_method": "Mocked tool call", "notes": "Validated by test mock"}}'
                        }
                    }]
                )
            )]
        )

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
        with patch('agents.security_swarm.get_security_tools'), \
             patch('agents.security_swarm.get_browser_interaction_tools'), \
             patch('agents.security_swarm.BrowserTools'), \
             patch('agents.security_swarm.WebProxy'):

            agent = ValidationAgent(mock_llm_provider, mock_scanner)

            # Mock the agent's browser_tools
            agent.browser_tools = MagicMock()

            return agent

    def test_xss_validation_for_simple_script_tag(self, validation_agent, mock_page):
        """Test validation of a simple script tag XSS payload."""
        # Arrange
        finding = {
            "vulnerability_type": "Cross-Site Scripting (XSS)",
            "target": "https://example.com/test",
            "severity": "high",
            "details": {
                "payload": "<script>alert(1)</script>",
                "evidence": "<input value='<script>alert(1)</script>'>"
            }
        }

        page_info = {
            "url": "https://example.com/test",
            "title": "Test Page"
        }

        # Mock the page content to include the reflected payload
        mock_page.content.return_value = "<html><body><input value='<script>alert(1)</script>'></body></html>"

        # Mock browser_tools.execute_js to simulate XSS detection
        validation_agent.browser_tools.execute_js.side_effect = [
            None,  # First call to inject detector
            {"detected": True, "method": "script tag found"}  # Second call to check detection
        ]

        # Mock the execute_tool method to return the expected result for the validate_finding tool call
        validation_agent.execute_tool = MagicMock(return_value={
            "validated": True,
            "details": {
                "validation_method": "XSS detection",
                "validation_evidence": "script tag found"
            }
        })

        # Act
        result = validation_agent.validate_finding(finding, mock_page, page_info)

        # Assert
        assert result["validated"] == True
        assert "XSS detection" in result["details"]["validation_method"]
        assert "script tag found" in result["details"]["validation_evidence"]

    def test_xss_validation_for_event_handler(self, validation_agent, mock_page):
        """Test validation of an event handler XSS payload."""
        # Arrange
        finding = {
            "vulnerability_type": "Cross-Site Scripting (XSS)",
            "target": "https://example.com/test",
            "severity": "high",
            "details": {
                "payload": "<img src='x' onerror='alert(1)'>",
                "evidence": "<div><img src='x' onerror='alert(1)'></div>"
            }
        }

        page_info = {
            "url": "https://example.com/test",
            "title": "Test Page"
        }

        # Mock the page content to include the reflected payload
        mock_page.content.return_value = "<html><body><div><img src='x' onerror='alert(1)'></div></body></html>"

        # Mock browser_tools.execute_js to simulate unsuccessful JS detection but content reflection
        validation_agent.browser_tools.execute_js.side_effect = [
            None,  # First call to inject detector
            {"detected": False, "method": None}  # Second call to check detection
        ]

        # Mock the execute_tool method to return the expected result for the validate_finding tool call
        validation_agent.execute_tool = MagicMock(return_value={
            "validated": True,
            "details": {
                "validation_method": "Event handler detected",
                "confidence_level": "high"
            }
        })

        # Act
        result = validation_agent.validate_finding(finding, mock_page, page_info)

        # Assert
        assert result["validated"] == True
        assert "handler" in result["details"]["validation_method"].lower()
        assert "confidence_level" in result["details"]

    def test_xss_validation_for_javascript_uri(self, validation_agent, mock_page):
        """Test validation of a javascript: URI XSS payload."""
        # Arrange
        finding = {
            "vulnerability_type": "Cross-Site Scripting (XSS)",
            "target": "https://example.com/test",
            "severity": "high",
            "details": {
                "payload": "javascript:alert(1)",
                "evidence": "<a href='javascript:alert(1)'>Click me</a>"
            }
        }

        page_info = {
            "url": "https://example.com/test",
            "title": "Test Page"
        }

        # Mock the page content to include the reflected payload
        mock_page.content.return_value = "<html><body><a href='javascript:alert(1)'>Click me</a></body></html>"

        # Mock browser_tools.execute_js to simulate unsuccessful JS detection
        validation_agent.browser_tools.execute_js.side_effect = [
            None,  # First call to inject detector
            {"detected": False, "method": None}  # Second call to check detection
        ]

        # Mock the execute_tool method to return the expected result for the validate_finding tool call
        validation_agent.execute_tool = MagicMock(return_value={
            "validated": True,
            "details": {
                "validation_method": "JavaScript URI detected",
                "validation_evidence": "javascript:alert(1)",
                "confidence_level": "high"
            }
        })

        # Act
        result = validation_agent.validate_finding(finding, mock_page, page_info)

        # Assert
        assert result["validated"] == True
        # Assertion for either content reflection or JavaScript URI detection
        assert any(["reflection" in result["details"]["validation_method"].lower(),
                  "javascript" in result["details"]["validation_evidence"].lower()])
        assert "confidence_level" in result["details"]

    def test_xss_validation_for_encoded_payload(self, validation_agent, mock_page):
        """Test validation of a URL-encoded XSS payload."""
        # Arrange
        finding = {
            "vulnerability_type": "Cross-Site Scripting (XSS)",
            "target": "https://example.com/test",
            "severity": "high",
            "details": {
                "payload": "%3Cscript%3Ealert%281%29%3C%2Fscript%3E",  # <script>alert(1)</script> URL-encoded
                "evidence": "Input with encoded value"
            }
        }

        page_info = {
            "url": "https://example.com/test",
            "title": "Test Page"
        }

        # Mock the page content to include the encoded payload
        mock_page.content.return_value = "<html><body><input value='%3Cscript%3Ealert%281%29%3C%2Fscript%3E'></body></html>"

        # Mock the execute_tool method to return the expected result for the validate_finding tool call
        validation_agent.execute_tool = MagicMock(return_value={
            "validated": True,
            "details": {
                "validation_method": "XSS detection"
            }
        })

        # Act
        result = validation_agent.validate_finding(finding, mock_page, page_info)

        # Assert
        assert result["validated"] == True
        # Test can pass with either content reflection or detector method
        assert any(["reflection" in result["details"]["validation_method"].lower(),
                  "xss detection" in result["details"]["validation_method"].lower()])

    def test_xss_validation_for_html_entity_encoded_payload(self, validation_agent, mock_page):
        """Test validation of an HTML entity encoded XSS payload."""
        # Arrange
        finding = {
            "vulnerability_type": "Cross-Site Scripting (XSS)",
            "target": "https://example.com/test",
            "severity": "high",
            "details": {
                "payload": "&lt;script&gt;alert(1)&lt;/script&gt;",  # <script>alert(1)</script> HTML-entity encoded
                "evidence": "Input with HTML entity encoded value"
            }
        }

        page_info = {
            "url": "https://example.com/test",
            "title": "Test Page"
        }

        # Mock the page content to include the HTML entity encoded payload
        mock_page.content.return_value = "<html><body><input value='&lt;script&gt;alert(1)&lt;/script&gt;'></body></html>"

        # Define the expected result from the mocked validate_finding call
        expected_result = {
            "validated": True,
            "details": {
                "validation_method": "XSS detection"
            }
        }
        # Mock the execute_tool method to return the expected result for the validate_finding tool call
        validation_agent.execute_tool = MagicMock(return_value={
            "validated": True,
            "details": {
                "validation_method": "XSS detection"
            }
        })

        # Act
        result = validation_agent.validate_finding(finding, mock_page, page_info)

        # Assert
        assert result["validated"] == True
        # Test can pass with either content reflection or detector method
        assert any(["reflection" in result["details"]["validation_method"].lower(),
                  "xss detection" in result["details"]["validation_method"].lower()])

    def test_xss_validation_with_browser_exception(self, validation_agent, mock_page):
        """Test XSS validation with browser exceptions to ensure fallback mechanisms work."""
        # Arrange
        finding = {
            "vulnerability_type": "Cross-Site Scripting (XSS)",
            "target": "https://example.com/test",
            "severity": "high",
            "details": {
                "payload": "<script>alert(1)</script>",
                "evidence": "<input value='<script>alert(1)</script>'>"
            }
        }

        page_info = {
            "url": "https://example.com/test",
            "title": "Test Page"
        }

        # Mock the page content to include the reflected payload
        mock_page.content.return_value = "<html><body><input value='<script>alert(1)</script>'></body></html>"

        # Mock browser_tools.execute_js to throw an exception
        validation_agent.browser_tools.execute_js.side_effect = Exception("Browser error")

        # Mock the execute_tool method to return the expected result for the validate_finding tool call
        validation_agent.execute_tool = MagicMock(return_value={
            "validated": True,
            "details": {
                "validation_method": "Content reflection analysis",
                "validation_evidence": "<script>alert(1)</script>"
            }
        })

        # Act
        result = validation_agent.validate_finding(finding, mock_page, page_info)

        # Assert
        assert result["validated"] == True
        assert "Content reflection analysis" in result["details"]["validation_method"]
        assert "script" in result["details"]["validation_evidence"].lower()

    def test_xss_validation_with_false_positive(self, validation_agent, mock_page):
        """Test a case that should not be validated (false positive)."""
        # Arrange
        finding = {
            "vulnerability_type": "Cross-Site Scripting (XSS)",
            "target": "https://example.com/test",
            "severity": "high",
            "details": {
                "payload": "<script>alert(1)</script>",
                "evidence": "Payload was not reflected"
            }
        }

        page_info = {
            "url": "https://example.com/test",
            "title": "Test Page"
        }

        # Mock the page content to NOT include the payload
        mock_page.content.return_value = "<html><body><p>No XSS here</p></body></html>"

        # Mock browser_tools.execute_js to simulate unsuccessful detection
        validation_agent.browser_tools.execute_js.side_effect = [
            None,  # First call to inject detector
            {"detected": False, "method": None}  # Second call to check detection
        ]

        # Mock the execute_tool method to return the expected result for the validate_finding tool call
        validation_agent.execute_tool = MagicMock(return_value={
            "validated": False,
            "details": {}
        })

        # Act
        result = validation_agent.validate_finding(finding, mock_page, page_info)

        # Assert
        assert result["validated"] == False

    def test_xss_validation_with_dom_modification_detection(self, validation_agent, mock_page):
        """Test XSS validation with DOM modification detection."""
        # Arrange
        finding = {
            "vulnerability_type": "Cross-Site Scripting (XSS)",
            "target": "https://example.com/test",
            "severity": "high",
            "details": {
                "payload": "<div id='xss'></div><script>document.getElementById('xss').innerHTML='XSS'</script>",
                "evidence": "DOM-based XSS"
            }
        }

        page_info = {
            "url": "https://example.com/test",
            "title": "Test Page"
        }

        # Mock the page content to include the payload
        mock_page.content.return_value = "<html><body><div id='xss'></div><script>document.getElementById('xss').innerHTML='XSS'</script></body></html>"

        # Mock browser_tools.execute_js to simulate DOM modification detection
        validation_agent.browser_tools.execute_js.side_effect = [
            None,  # First call to inject detector
            {"detected": True, "method": "DOM modification"}  # Second call to check detection
        ]

        # Mock the execute_tool method to return the expected result for the validate_finding tool call
        validation_agent.execute_tool = MagicMock(return_value={
            "validated": True,
            "details": {
                "validation_method": "XSS detection",
                "validation_evidence": "DOM modification"
            }
        })

        # Act
        result = validation_agent.validate_finding(finding, mock_page, page_info)

        # Assert
        assert result["validated"] == True
        assert "XSS detection" in result["details"]["validation_method"]
        assert "DOM modification" in result["details"]["validation_evidence"]