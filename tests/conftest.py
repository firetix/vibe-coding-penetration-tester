import os
import sys
import pytest
from unittest.mock import MagicMock

# Add the project root to the path for proper imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.logger import setup_logger
from utils.config import load_config
from core.llm import LLMProvider

# Setup test logger
@pytest.fixture
def logger():
    return setup_logger("DEBUG")

# Mock config fixture
@pytest.fixture
def mock_config():
    return {
        "llm": {
            "openai": {
                "api_key": "test_openai_key",
                "models": {
                    "gpt-4o": {
                        "temperature": 0.7,
                        "max_tokens": 4000
                    }
                }
            },
            "anthropic": {
                "api_key": "test_anthropic_key",
                "models": {
                    "claude-3-opus": {
                        "temperature": 0.7,
                        "max_tokens": 4000
                    }
                }
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

# Mock LLM provider
@pytest.fixture
def mock_llm():
    mock = MagicMock(spec=LLMProvider)
    
    # Mock the get_completion method to return a basic response
    def mock_completion(prompt, tools=None, tool_choice=None):
        if tools and tool_choice:
            return {
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_123",
                        "type": "function", 
                        "function": {
                            "name": "analyze_page",
                            "arguments": '{"url": "https://example.com"}'
                        }
                    }
                ]
            }
        return {"content": "This is a test response"}
    
    mock.get_completion = MagicMock(side_effect=mock_completion)
    return mock

# Mock browser fixture
@pytest.fixture
def mock_browser():
    mock = MagicMock()
    mock.goto = MagicMock(return_value=None)
    mock.content = MagicMock(return_value="<html><body>Test page</body></html>")
    mock.evaluate = MagicMock(return_value={"forms": [], "links": []})
    return mock

# Mock scanner
@pytest.fixture
def mock_scanner(mock_browser):
    mock = MagicMock()
    mock.browser = mock_browser
    mock.navigate = MagicMock(return_value=True)
    mock.get_page_content = MagicMock(return_value="<html><body>Test page</body></html>")
    mock.extract_page_info = MagicMock(return_value={"forms": [], "links": []})
    return mock