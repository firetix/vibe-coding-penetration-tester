import pytest
from unittest.mock import patch, MagicMock

from agents.security_swarm import ValidationAgent
from core.llm import LLMProvider
from core.scanner import Scanner


class TestDOMBasedXSSValidation:
    """Tests specifically for DOM-based XSS validation."""

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
        ].message.content = "This appears to be a DOM-based XSS vulnerability."
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

    def test_dom_xss_with_mutation_observer(self, validation_agent, mock_page):
        """Test DOM XSS validation using MutationObserver detection."""
        # Arrange
        finding = {
            "vulnerability_type": "Cross-Site Scripting (XSS)",
            "target": "https://example.com/test#<img src=x onerror=alert(1)>",
            "severity": "high",
            "details": {
                "payload": "<img src=x onerror=alert(1)>",
                "evidence": "DOM manipulation via fragment",
                "dom_based": True,
            },
        }

        page_info = {"url": "https://example.com/test", "title": "Test Page"}

        # Mock the page content - DOM XSS often won't show in initial HTML
        mock_page.content.return_value = """
        <html>
            <head><title>Test Page</title></head>
            <body>
                <div id="output"></div>
                <script>
                    // Example vulnerable code that takes fragment and writes to DOM
                    var fragment = location.hash.slice(1);
                    document.getElementById('output').innerHTML = decodeURIComponent(fragment);
                </script>
            </body>
        </html>
        """

        # Make sure the payload shows up in the page content
        mock_page.content.return_value += f"<!-- {finding['details']['payload']} -->"

        # Mock browser_tools.execute_js to simulate DOM mutation detection
        validation_agent.browser_tools.execute_js.side_effect = [
            None,  # First call to inject detector
            {
                "detected": True,
                "method": "DOM modification",
            },  # Second call to check detection
        ]

        # Act
        result = validation_agent.validate_finding(finding, mock_page, page_info)

        # Assert
        assert result["validated"] == True
        assert any(
            [
                "dom" in result["details"]["validation_method"].lower(),
                "xss detection" in result["details"]["validation_method"].lower(),
            ]
        )

    def test_dom_xss_script_execution(self, validation_agent, mock_page):
        """Test DOM XSS validation with script execution detection."""
        # Arrange
        finding = {
            "vulnerability_type": "Cross-Site Scripting (XSS)",
            "target": "https://example.com/test?name=<script>alert(1)</script>",
            "severity": "high",
            "details": {
                "payload": "<script>alert(1)</script>",
                "evidence": "DOM manipulation via query parameter",
                "dom_based": True,
            },
        }

        page_info = {"url": "https://example.com/test", "title": "Test Page"}

        # Mock the page content - no visible evidence of XSS in source
        mock_page.content.return_value = """
        <html>
            <head><title>Test Page</title></head>
            <body>
                <div id="greeting"></div>
                <script>
                    // Example vulnerable code that takes query param and writes to DOM
                    var urlParams = new URLSearchParams(window.location.search);
                    var name = urlParams.get('name');
                    document.getElementById('greeting').innerHTML = 'Hello, ' + name;
                </script>
            </body>
        </html>
        """

        # Make sure the payload shows up in the page content
        mock_page.content.return_value += f"<!-- {finding['details']['payload']} -->"

        # Mock browser_tools.execute_js to simulate alert() function call detection
        validation_agent.browser_tools.execute_js.side_effect = [
            None,  # First call to inject detector
            {"detected": True, "method": "alert()"},  # Second call to check detection
        ]

        # Act
        result = validation_agent.validate_finding(finding, mock_page, page_info)

        # Assert
        assert result["validated"] == True
        assert "XSS detection" in result["details"]["validation_method"]
        assert "confidence_level" in result["details"]

    def test_dom_xss_with_eval(self, validation_agent, mock_page):
        """Test DOM XSS validation with eval() detection."""
        # Arrange
        finding = {
            "vulnerability_type": "Cross-Site Scripting (XSS)",
            "target": "https://example.com/test?code=alert(1)",
            "severity": "high",
            "details": {
                "payload": "alert(1)",
                "evidence": "eval() execution of user input",
                "dom_based": True,
            },
        }

        page_info = {"url": "https://example.com/test", "title": "Test Page"}

        # Mock the page content - page with eval() vulnerability
        mock_page.content.return_value = """
        <html>
            <head><title>Test Page</title></head>
            <body>
                <div id="result"></div>
                <script>
                    // Example vulnerable code that evals query param
                    var urlParams = new URLSearchParams(window.location.search);
                    var code = urlParams.get('code');
                    eval(code);
                </script>
            </body>
        </html>
        """

        # Make sure the payload shows up in page content (via a comment or something)
        mock_page.content.return_value += f"<!-- {finding['details']['payload']} -->"

        # Mock browser_tools.execute_js to simulate eval() function call detection
        validation_agent.browser_tools.execute_js.side_effect = [
            None,  # First call to inject detector
            {"detected": True, "method": "eval()"},  # Second call to check detection
        ]

        # Act
        result = validation_agent.validate_finding(finding, mock_page, page_info)

        # Assert
        assert result["validated"] == True
        assert "XSS detection" in result["details"]["validation_method"]
        assert "confidence_level" in result["details"]

    def test_dom_xss_multiple_detection_methods(self, validation_agent, mock_page):
        """Test DOM XSS with multiple detection methods."""
        # Arrange
        finding = {
            "vulnerability_type": "Cross-Site Scripting (XSS)",
            "target": "https://example.com/test?exec=document.write('<img src=x onerror=alert(1)>')",
            "severity": "high",
            "details": {
                "payload": "document.write('<img src=x onerror=alert(1)>')",
                "evidence": "DOM manipulation via document.write",
                "dom_based": True,
            },
        }

        page_info = {"url": "https://example.com/test", "title": "Test Page"}

        # Mock the page content
        mock_page.content.return_value = """
        <html>
            <head><title>Test Page</title></head>
            <body>
                <script>
                    var urlParams = new URLSearchParams(window.location.search);
                    var exec = urlParams.get('exec');
                    eval(exec);
                </script>
            </body>
        </html>
        """

        # Add the payload to the content so the pattern matching can find it
        mock_page.content.return_value += f"<!-- {finding['details']['payload']} -->"
        # Also include the actual img tag for better detection
        mock_page.content.return_value += "<!-- <img src=x onerror=alert(1)> -->"

        # Mock browser_tools.execute_js to simulate multiple detection methods
        detection_result = {
            "detected": True,
            "method": "multiple",
            "details": ["DOM modification", "alert()", "eval()"],
        }

        validation_agent.browser_tools.execute_js.side_effect = [
            None,  # First call to inject detector
            detection_result,  # Second call to check detection
        ]

        # Act
        result = validation_agent.validate_finding(finding, mock_page, page_info)

        # Assert
        assert result["validated"] == True
        assert "XSS detection" in result["details"]["validation_method"]
        assert "confidence_level" in result["details"]

    def test_dom_xss_browser_exception_with_fallback(self, validation_agent, mock_page):
        """Test DOM XSS when browser tools throw exceptions but pattern matching works."""
        # Arrange
        finding = {
            "vulnerability_type": "Cross-Site Scripting (XSS)",
            "target": "https://example.com/test#<script>alert(1)</script>",
            "severity": "high",
            "details": {
                "payload": "<script>alert(1)</script>",
                "evidence": "DOM manipulation via fragment",
                "dom_based": True,
            },
        }

        page_info = {"url": "https://example.com/test", "title": "Test Page"}

        # Mock the page content - DOM XSS often won't show in initial HTML
        mock_page.content.return_value = """
        <html>
            <head><title>Test Page</title></head>
            <body>
                <div id="output"></div>
                <script>
                    // Example vulnerable code that takes fragment and writes to DOM
                    var fragment = location.hash.slice(1);
                    document.getElementById('output').innerHTML = decodeURIComponent(fragment);
                </script>
                <!-- For testing, we'll include the payload in a comment -->
                <!-- <script>alert(1)</script> -->
            </body>
        </html>
        """

        # Mock browser_tools.execute_js to throw exceptions
        validation_agent.browser_tools.execute_js.side_effect = Exception(
            "Browser error"
        )

        # Act
        result = validation_agent.validate_finding(finding, mock_page, page_info)

        # Assert - still validates based on pattern matching
        assert result["validated"] == True
        assert "Content reflection analysis" in result["details"]["validation_method"]

    def test_dom_xss_false_positive(self, validation_agent, mock_page):
        """Test DOM XSS false positive detection."""
        # Arrange
        finding = {
            "vulnerability_type": "Cross-Site Scripting (XSS)",
            "target": "https://example.com/test?safe=<script>alert(1)</script>",
            "severity": "high",
            "details": {
                "payload": "<script>alert(1)</script>",
                "evidence": "DOM manipulation via query parameter",
                "dom_based": True,
            },
        }

        page_info = {"url": "https://example.com/test", "title": "Test Page"}

        # Mock the page content - safe handling of user input
        mock_page.content.return_value = """
        <html>
            <head><title>Test Page</title></head>
            <body>
                <div id="output"></div>
                <script>
                    // Safe code that escapes user input
                    function escapeHTML(str) {
                        return str.replace(/[&<>'"]/g, 
                            tag => ({
                                '&': '&amp;',
                                '<': '&lt;',
                                '>': '&gt;',
                                "'": '&#39;',
                                '"': '&quot;'
                            }[tag]));
                    }
                    
                    var urlParams = new URLSearchParams(window.location.search);
                    var safe = urlParams.get('safe');
                    document.getElementById('output').textContent = safe; // Safe assignment using textContent
                </script>
            </body>
        </html>
        """

        # Mock browser_tools.execute_js to simulate no XSS detection
        validation_agent.browser_tools.execute_js.side_effect = [
            None,  # First call to inject detector
            {"detected": False, "method": None},  # Second call to check detection
        ]

        # Act
        result = validation_agent.validate_finding(finding, mock_page, page_info)

        # Assert - should not validate
        assert result["validated"] == False
