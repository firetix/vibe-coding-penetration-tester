from typing import Dict, Any
from playwright.sync_api import Page

from core.llm import LLMProvider
from core.scanner import Scanner
from agents.security.specialized_agent import SpecializedSecurityAgent
from utils.logger import get_logger


class SSRFAgent(SpecializedSecurityAgent):
    """Agent specializing in Server-Side Request Forgery testing."""
    
    def __init__(self, llm_provider: LLMProvider, scanner: Scanner):
        super().__init__("SSRFAgent", "ssrf_specialist", "ssrf", llm_provider, scanner)
    
    def _get_system_prompt(self) -> str:
        """Get the system prompt for SSRF testing."""
        return """
        You are a Server-Side Request Forgery (SSRF) security specialist. Your job is to identify and exploit SSRF vulnerabilities in web applications.
        
        Focus on testing:
        1. URL input fields
        2. API endpoints that fetch remote resources
        3. File import/export functionality
        4. Webhooks configuration
        5. Any functionality that processes URLs or remote resources
        
        You have access to specialized SSRF testing tools and browser interaction tools:
        
        SSRF TOOLS:
        - test_ssrf_vulnerability: Test for Server-Side Request Forgery vulnerabilities
        - generate_ssrf_payloads: Generate SSRF payloads for testing
        
        BROWSER INTERACTION TOOLS:
        - goto: Navigate to a URL
        - click: Click an element on the page
        - fill: Fill a form field with a value
        - submit: Submit a form
        - execute_js: Execute JavaScript on the page
        
        Common SSRF targets to test:
        - Cloud instance metadata services (169.254.169.254, metadata.google.internal)
        - Internal services (localhost, 127.0.0.1, 0.0.0.0, internal hostnames)
        - File system access (file://)
        - Port scanning internal networks
        """
    
    def _check_for_vulnerabilities(self, tool_name: str, tool_result: Dict[str, Any], 
                                  result: Dict[str, Any], page: Page, tool_call: Any) -> Dict[str, Any]:
        """Check for SSRF vulnerabilities in tool results."""
        logger = get_logger()
        
        # Check for direct SSRF issues reported by tools
        if tool_result.get("ssrf_found", False):
            result["vulnerability_found"] = True
            result["vulnerability_type"] = "Server-Side Request Forgery (SSRF)"
            result["severity"] = tool_result.get("severity", "high")
            result["details"] = tool_result
            
            logger.security(f"Found SSRF vulnerability via {tool_result.get('injection_point', '')}")
        
        # Check if form fills or URL navigation might be part of SSRF testing
        elif tool_name in ["fill", "goto"] and tool_result.get("success", False):
            # Extract the action data from the tool call
            action_data = self._extract_action_data(tool_name, tool_call)
            
            # Check if this contains SSRF payloads
            ssrf_indicators = ["localhost", "127.0.0.1", "file://", "169.254.169.254", 
                            "metadata.google", "instance-data", "0.0.0.0"]
            
            if any(indicator in str(action_data).lower() for indicator in ssrf_indicators):
                # This might be a SSRF test, but we need to wait for the actual response
                result["details"]["suspected_ssrf_test"] = {
                    "tool": tool_name,
                    "payload": action_data
                }
        
        return result
    
    def _extract_action_data(self, tool_name: str, tool_call: Any) -> str:
        """Extract action data from a tool call based on the tool name."""
        if tool_name == "fill":
            if hasattr(tool_call, 'function') and hasattr(tool_call.function, 'arguments'):
                return getattr(tool_call.function.arguments, 'value', "")
            return tool_call.get('function', {}).get('arguments', {}).get("value", "")
            
        elif tool_name == "goto":
            if hasattr(tool_call, 'function') and hasattr(tool_call.function, 'arguments'):
                return getattr(tool_call.function.arguments, 'url', "")
            return tool_call.get('function', {}).get('arguments', {}).get("url", "")
            
        return ""
    
    def _process_followup_response(self, response: Dict[str, Any], result: Dict[str, Any], page: Page) -> None:
        """Check the follow-up response for SSRF evidence."""
        if not response.get("followup_response") or result["vulnerability_found"]:
            return
            
        logger = get_logger()
        followup_content = response["followup_response"].get("content", "").lower()
        
        # Check for SSRF language in the followup
        ssrf_success_indicators = [
            "ssrf vulnerability", "server made a request", "internal service accessed",
            "successful ssrf", "callback received", "accessed internal"
        ]
        
        if any(indicator in followup_content for indicator in ssrf_success_indicators) and result["details"].get("suspected_ssrf_test"):
            # This appears to be a successful SSRF test
            suspected_test = result["details"]["suspected_ssrf_test"]
            result["vulnerability_found"] = True
            result["vulnerability_type"] = "Server-Side Request Forgery (SSRF)"
            result["severity"] = "high"
            result["details"] = {
                "issue_type": "Server-Side Request Forgery (SSRF)",
                "url": page.url,
                "injection_point": suspected_test["tool"],
                "payload": suspected_test["payload"],
                "evidence": followup_content
            }
            
            logger.security(f"Found SSRF vulnerability via {suspected_test['tool']} with payload: {suspected_test['payload']}")