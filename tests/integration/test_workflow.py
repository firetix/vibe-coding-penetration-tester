import pytest
from unittest.mock import patch, MagicMock
import os
import json

from core.coordinator import SwarmCoordinator
from core.llm import LLMProvider
from core.scanner import Scanner
from agents.agent_factory import create_agent_swarm
from utils.reporter import Reporter


class TestBasicWorkflow:
    """Integration tests for the basic workflow involving real component interactions."""
    
    @pytest.fixture
    def sample_config(self):
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
                "sqli_payloads": ["' OR 1=1--", "1; DROP TABLE users--"],
                "directories": ["admin", "backup", "config"]
            }
        }
    
    @pytest.fixture
    def temp_output_dir(self, tmp_path):
        """Create a temporary directory for test outputs."""
        output_dir = tmp_path / "reports"
        output_dir.mkdir()
        return str(output_dir)
    
    @patch.dict(os.environ, {"OPENAI_API_KEY": "test_key"})
    @patch("core.llm.OpenAI")  # Correct patching for OpenAI
    @patch("core.scanner.sync_playwright")
    def test_end_to_end_simple_url(self, mock_playwright, mock_openai, sample_config, temp_output_dir):
        """Test the entire workflow from start to finish with a single URL."""
        # Arrange
        mock_client = MagicMock()
        mock_openai.return_value = mock_client
        
        # Setup LLM mock responses
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message = MagicMock()
        mock_response.choices[0].message.content = "Test response"
        mock_response.choices[0].finish_reason = "stop"
        mock_response.model = "gpt-4o"
        
        # For tool calls
        mock_tool_response = MagicMock()
        mock_tool_response.choices = [MagicMock()]
        mock_tool_response.choices[0].message = MagicMock()
        mock_tool_response.choices[0].message.content = None
        mock_tool_response.choices[0].message.tool_calls = [
            MagicMock(
                id="call_123",
                type="function",
                function=MagicMock(
                    name="test_xss",
                    arguments='{"url": "https://example.com", "element_id": "search"}'
                )
            )
        ]
        mock_tool_response.choices[0].finish_reason = "tool_calls"
        mock_tool_response.model = "gpt-4o"
        
        # For tool call results
        mock_tool_result_response = MagicMock()
        mock_tool_result_response.choices = [MagicMock()]
        mock_tool_result_response.choices[0].message = MagicMock()
        mock_tool_result_response.choices[0].message.content = "Found XSS vulnerability"
        mock_tool_result_response.choices[0].finish_reason = "stop"
        mock_tool_result_response.model = "gpt-4o"
        
        # Setup response sequence
        mock_client.chat.completions.create.side_effect = [
            mock_tool_response,  # First call returns a tool call
            mock_tool_result_response  # Second call returns the result
        ]
        
        # Setup Playwright mocks
        mock_playwright_instance = MagicMock()
        mock_playwright.return_value.start.return_value = mock_playwright_instance
        
        mock_browser = MagicMock()
        mock_context = MagicMock()
        mock_page = MagicMock()
        
        mock_playwright_instance.chromium.launch.return_value = mock_browser
        mock_browser.new_context.return_value = mock_context
        mock_context.new_page.return_value = mock_page
        
        # Mock page content
        mock_page.url = "https://example.com"
        mock_page.title.return_value = "Example Domain"
        mock_page.content.return_value = "<html><body><h1>Example Domain</h1></body></html>"
        
        mock_links = []
        mock_forms = []
        mock_inputs = []
        mock_scripts = []
        
        mock_page.evaluate.side_effect = [mock_links, mock_forms, mock_inputs, mock_scripts]
        
        # Create coordinator with mocks
        with patch("agents.agent_factory.BaseAgent.execute_tool") as mock_execute_tool, \
             patch("agents.security_swarm.PlannerAgent.create_plan") as mock_create_plan, \
             patch("agents.security_swarm.XSSAgent.execute_task") as mock_xss_execute_task, \
             patch("agents.security_swarm.ValidationAgent.validate_finding") as mock_validate_finding:
            
            # Mock the planner to return a valid plan
            mock_create_plan.return_value = {
                "tasks": [
                    {
                        "type": "xss",
                        "target": "search_form",
                        "priority": "high",
                        "details": {}
                    }
                ]
            }
            
            # Mock the XSS agent's execute_task method
            mock_xss_execute_task.return_value = {
                "task_type": "xss",
                "target": "search_form",
                "vulnerability_found": True,
                "vulnerability_type": "Cross-Site Scripting (XSS)",
                "severity": "high",
                "details": {
                    "payload": "<script>alert(1)</script>",
                    "evidence": "<input id='search' value='<script>alert(1)</script>'>"
                }
            }
            
            # Mock the validation agent
            mock_validate_finding.return_value = {
                "validated": True,
                "details": {
                    "validation_method": "payload_execution",
                    "confidence": "high"
                }
            }
            
            # Mock the tool execution
            mock_execute_tool.return_value = {
                "result": "Found XSS vulnerability in element #search",
                "details": {"payload": "<script>alert(1)</script>", "severity": "high"},
                "xss_found": True,  # For XSSAgent
                "vulnerability_found": True  # For result processing
            }
            
            # Act
            coordinator = SwarmCoordinator(
                url="https://example.com",
                model="gpt-4o",
                provider="openai",
                scope="url",
                output_dir=temp_output_dir,
                config=sample_config
            )
            
            results = coordinator.run()
            
            # Assert
            assert results["urls_discovered"] == 1
            assert results["urls_scanned"] == 1
            assert results["vulnerabilities_found"] > 0
            assert os.path.exists(results["report_path"])
            
            # Check that the workflow called the necessary methods
            mock_playwright.return_value.start.assert_called_once()
            mock_playwright_instance.chromium.launch.assert_called_once()
            mock_context.new_page.assert_called_once()
            mock_page.goto.assert_called_once()
            mock_page.title.assert_called_once()
            mock_page.content.assert_called_once()
            # Note: We don't check LLM calls since we're mocking the agents directly
            
            # Verify the scanner has been stopped
            mock_browser.close.assert_called_once()
            mock_playwright_instance.stop.assert_called_once()
    
    @patch.dict(os.environ, {"OPENAI_API_KEY": "test_key"})
    @patch("core.llm.OpenAI")  # Patch the correct import
    @patch("playwright.sync_api.sync_playwright")
    def test_real_components_with_mock_data(self, mock_playwright, mock_openai, sample_config, temp_output_dir):
        """Test with real LLMProvider and Scanner instances but mock API responses."""
        # Arrange
        mock_client = MagicMock()
        mock_openai.return_value = mock_client
        
        # Mock OpenAI API responses
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message = MagicMock()
        mock_response.choices[0].message.content = "Test response"
        mock_response.choices[0].finish_reason = "stop"
        mock_response.model = "gpt-4o"
        
        mock_client.chat.completions.create.return_value = mock_response
        
        # Setup Playwright mocks
        mock_playwright_instance = MagicMock()
        mock_playwright.return_value.start.return_value = mock_playwright_instance
        
        mock_browser = MagicMock()
        mock_context = MagicMock()
        mock_page = MagicMock()
        
        mock_playwright_instance.chromium.launch.return_value = mock_browser
        mock_browser.new_context.return_value = mock_context
        mock_context.new_page.return_value = mock_page
        
        # Mock page properties
        mock_page.url = "https://example.com"
        mock_page.title.return_value = "Example Domain"
        mock_page.content.return_value = "<html><body><h1>Example Domain</h1></body></html>"
        
        mock_links = []
        mock_forms = []
        mock_inputs = []
        mock_scripts = []
        
        mock_page.evaluate.side_effect = [mock_links, mock_forms, mock_inputs, mock_scripts]
        
        # Use real LLMProvider and Scanner with mocked dependencies
        with patch("core.coordinator.create_agent_swarm") as mock_create_swarm:
            # Mock agent swarm
            mock_agent_swarm = MagicMock()
            mock_agent_swarm.run.return_value = [
                {
                    "type": "XSS",
                    "url": "https://example.com",
                    "element": "#search",
                    "payload": "<script>alert(1)</script>",
                    "severity": "high",
                    "details": "Cross-site scripting vulnerability in search form",
                    "poc": "<form><input id='search' value='<script>alert(1)</script>'></form>"
                }
            ]
            mock_create_swarm.return_value = mock_agent_swarm
            
            # Act
            coordinator = SwarmCoordinator(
                url="https://example.com",
                model="gpt-4o",
                provider="openai",
                scope="url",
                output_dir=temp_output_dir,
                config=sample_config
            )
            
            results = coordinator.run()
            
            # Assert
            assert results["urls_discovered"] == 1
            assert results["urls_scanned"] == 1
            assert results["vulnerabilities_found"] == 1
            assert os.path.exists(results["report_path"])
            
            # Verify report content
            with open(results["report_path"], "r") as f:
                report_content = f.read()
                assert "XSS" in report_content
                assert "https://example.com" in report_content
                assert "high" in report_content