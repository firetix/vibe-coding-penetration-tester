import pytest
import os
import json
from unittest.mock import patch, MagicMock

from playwright.sync_api import Page

from agents.security_swarm import ValidationAgent, XSSAgent, PlannerAgent
from core.llm import LLMProvider
from core.scanner import Scanner
from utils.reporter import Reporter


class TestXSSValidationIntegration:
    """Integration tests for XSS validation with simulated browser interaction."""
    
    @pytest.fixture
    def mock_config(self):
        return {
            "llm": {
                "openai": {
                    "api_key": "test_key",
                    "models": {"gpt-4o": {"temperature": 0.7}}
                }
            },
            "agents": {
                "default_tools": ["browse", "analyze_page", "test_xss"],
                "system_message": "You are a security testing agent."
            },
            "scan": {
                "max_urls": 10,
                "max_depth": 2,
                "timeout": 30
            },
            "security": {
                "xss_payloads": ["<script>alert(1)</script>", "javascript:alert(1)"],
                "sqli_payloads": ["' OR 1=1--", "1; DROP TABLE users--"]
            }
        }
    
    @pytest.fixture
    def llm_provider(self):
        with patch.dict(os.environ, {"OPENAI_API_KEY": "test_key"}):
            with patch("core.llm.OpenAI") as mock_openai:
                mock_client = MagicMock()
                mock_openai.return_value = mock_client
                
                # Mock LLM responses
                mock_response = MagicMock()
                mock_response.choices = [MagicMock()]
                mock_response.choices[0].message = MagicMock()
                mock_response.choices[0].message.content = """
                This appears to be a valid XSS vulnerability. The payload was successfully reflected in the page content 
                and is likely to execute when the page loads. The payload contains a script tag which can execute 
                arbitrary JavaScript code.
                
                Validation Steps:
                1. Verified payload reflection in page source
                2. Checked for proper context (unencoded script tag)
                3. Confirmed no Content-Security-Policy headers blocking script execution
                
                Evidence:
                The input contains an unfiltered script tag: <script>alert(1)</script>
                """
                mock_response.choices[0].message.tool_calls = []
                mock_response.choices[0].finish_reason = "stop"
                mock_response.model = "gpt-4o"
                
                mock_client.chat.completions.create.return_value = mock_response
                
                provider = LLMProvider(provider="openai", model="gpt-4o")
                yield provider
    
    @pytest.fixture
    def scanner(self):
        with patch("core.scanner.sync_playwright") as mock_playwright:
            # Setup Playwright mocks
            mock_playwright_instance = MagicMock()
            mock_playwright.return_value.start.return_value = mock_playwright_instance
            
            mock_browser = MagicMock()
            mock_context = MagicMock()
            mock_page = MagicMock()
            
            mock_playwright_instance.chromium.launch.return_value = mock_browser
            mock_browser.new_context.return_value = mock_context
            mock_context.new_page.return_value = mock_page
            
            # Configure mock page
            mock_page.url = "https://example.com/vulnerable"
            mock_page.title.return_value = "Vulnerable Example"
            mock_page.content.return_value = """
            <html>
                <head><title>Vulnerable Example</title></head>
                <body>
                    <h1>Test Form</h1>
                    <form id="search_form" action="/search">
                        <input id="search" name="q" type="text" value="<script>alert(1)</script>">
                        <button type="submit">Search</button>
                    </form>
                </body>
            </html>
            """
            
            # Mock JavaScript evaluation
            mock_page.evaluate.return_value = {"detected": True, "method": "script tag found"}
            
            scanner_instance = Scanner()
            scanner_instance._page = mock_page
            scanner_instance._browser = mock_browser
            scanner_instance._context = mock_context
            scanner_instance._playwright = mock_playwright_instance
            
            yield scanner_instance
    
    @pytest.fixture
    def mock_page(self, scanner):
        return scanner._page
    
    def test_xss_agent_and_validation(self, mock_config, llm_provider, scanner, mock_page):
        """Test the full XSS detection and validation workflow."""
        # Create XSS agent
        xss_agent = XSSAgent(llm_provider, scanner)
        
        # Create validation agent
        validation_agent = ValidationAgent(llm_provider, scanner)
        
        # Configure browser_tools direct access for testing
        validation_agent.browser_tools = MagicMock()
        validation_agent.browser_tools.execute_js.side_effect = [
            None,  # First call to inject detector
            {"detected": True, "method": "script tag found"}  # Second call to check detection
        ]
        
        # Mock simple page info
        page_info = {
            "url": "https://example.com/vulnerable",
            "title": "Vulnerable Example",
            "forms": [{
                "id": "search_form",
                "action": "/search",
                "inputs": [{"id": "search", "name": "q", "type": "text"}]
            }]
        }
        
        # Test XSS agent execution
        with patch.object(xss_agent, 'execute_tool', return_value={"result": "XSS payload was reflected in page"}):
            xss_result = xss_agent.execute_task({
                "type": "xss",
                "target": "search_form",
                "details": {"input_field": "search"}
            }, mock_page, page_info)
            
            # Verify XSS agent found vulnerability
            assert xss_result["vulnerability_found"] == True
            assert xss_result["vulnerability_type"] == "Cross-Site Scripting (XSS)"
            assert "<script>alert(1)</script>" in str(xss_result["details"]["payload"])
            
            # Now test validation of the finding
            validation_result = validation_agent.validate_finding(xss_result, mock_page, page_info)
            
            # Verify validation succeeded
            assert validation_result["validated"] == True
            assert "XSS detection" in validation_result["details"]["validation_method"]
            assert "script tag found" in validation_result["details"]["validation_evidence"]
    
    def test_full_xss_workflow(self, mock_config, llm_provider, scanner, mock_page):
        """Test the full XSS workflow from planning to validation."""
        # Create agents
        planner = PlannerAgent(llm_provider, scanner)
        xss_agent = XSSAgent(llm_provider, scanner)
        validation_agent = ValidationAgent(llm_provider, scanner)
        
        # Mock the validation agent's browser tools
        validation_agent.browser_tools = MagicMock()
        validation_agent.browser_tools.execute_js.side_effect = [
            None,  # First call to inject detector
            {"detected": True, "method": "script tag found"}  # Second call to check detection
        ]
        
        # Mock page info
        page_info = {
            "url": "https://example.com/vulnerable",
            "title": "Vulnerable Example",
            "forms": [{
                "id": "search_form",
                "action": "/search",
                "inputs": [{"id": "search", "name": "q", "type": "text"}]
            }]
        }
        
        # Mock planner
        response_obj = MagicMock()
        response_obj.choices = [MagicMock()]
        response_obj.choices[0].message = MagicMock()
        response_obj.choices[0].message.content = json.dumps({
            "tasks": [
                {
                    "type": "xss",
                    "target": "search_form",
                    "priority": "high",
                    "details": {"input_field": "search"}
                }
            ]
        })
        response_obj.choices[0].message.tool_calls = []
        
        with patch.object(planner.llm_provider, 'chat_completion', return_value=response_obj):
            # Get the plan
            plan = planner.create_plan(page_info)
            
            # Verify plan includes XSS task
            assert len(plan["tasks"]) == 1
            assert plan["tasks"][0]["type"] == "xss"
            
            # Execute XSS task
            with patch.object(xss_agent, 'execute_tool', return_value={"result": "XSS payload was reflected in page"}):
                xss_result = xss_agent.execute_task(plan["tasks"][0], mock_page, page_info)
                
                # Verify XSS task execution found a vulnerability
                assert xss_result["vulnerability_found"] == True
                assert xss_result["vulnerability_type"] == "Cross-Site Scripting (XSS)"
                
                # Validate the finding
                validation_result = validation_agent.validate_finding(xss_result, mock_page, page_info)
                
                # Verify the validation succeeded
                assert validation_result["validated"] == True
                assert "XSS detection" in validation_result["details"]["validation_method"]
                
                # Create a report with the finding
                reporter = Reporter("/tmp")
                with patch.object(reporter, '_create_report_dir', return_value="/tmp/example"):
                    report_path = reporter.generate_report([{
                        **xss_result,
                        "validation": validation_result
                    }])
                    
                    # Assert something about the report path
                    assert isinstance(report_path, str)
                    assert "example" in report_path