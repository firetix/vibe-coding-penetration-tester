from typing import Dict, Any
from playwright.sync_api import Page

from core.llm import LLMProvider
from core.scanner import Scanner
from agents.security.specialized_agent import SpecializedSecurityAgent
from utils.logger import get_logger


class AccessControlAgent(SpecializedSecurityAgent):
    """Agent specializing in Broken Access Control testing."""

    def __init__(self, llm_provider: LLMProvider, scanner: Scanner):
        super().__init__(
            "AccessControlAgent",
            "access_control_specialist",
            "access_control",
            llm_provider,
            scanner,
        )

    def _get_system_prompt(self) -> str:
        """Get the system prompt for access control testing."""
        return """
        You are an Access Control security specialist. Your job is to identify and exploit broken access control vulnerabilities in web applications.
        
        Focus on testing:
        1. Direct access to restricted resources without proper authorization
        2. Privilege escalation possibilities
        3. Horizontal access control issues (accessing other users' data)
        4. Vertical access control issues (accessing higher privilege functions)
        5. Insecure access control mechanisms
        
        You have access to specialized access control testing tools and browser interaction tools:
        
        ACCESS CONTROL TOOLS:
        - test_access_control: Test for broken access control vulnerabilities
        - check_role_escalation: Check for privilege escalation vulnerabilities
        
        BROWSER INTERACTION TOOLS:
        - goto: Navigate to a URL
        - click: Click an element on the page
        - fill: Fill a form field with a value
        - submit: Submit a form
        - execute_js: Execute JavaScript on the page
        - refresh: Refresh the current page
        - presskey: Press a keyboard key
        
        Common access control bypass techniques include:
        - Directly accessing protected URLs
        - Modifying resource IDs in URLs
        - Using alternative HTTP methods
        - Manipulating cookies or session data
        - Browser-based attacks (XSS, CSRF) that lead to access control bypasses
        """

    def _check_for_vulnerabilities(
        self,
        tool_name: str,
        tool_result: Dict[str, Any],
        result: Dict[str, Any],
        page: Page,
        tool_call: Any,
    ) -> Dict[str, Any]:
        """Check for access control vulnerabilities in tool results."""
        logger = get_logger()

        # Check for direct access control issues
        if tool_result.get("access_control_issue_found", False):
            result["vulnerability_found"] = True
            result["vulnerability_type"] = "Broken Access Control"
            result["severity"] = tool_result.get("severity", "high")
            result["details"] = tool_result

            logger.security(
                f"Found Broken Access Control vulnerability at {tool_result.get('resource', '')}"
            )

        # Check for privilege escalation
        elif tool_result.get("escalation_found", False):
            result["vulnerability_found"] = True
            result["vulnerability_type"] = "Privilege Escalation"
            result["severity"] = tool_result.get("severity", "critical")
            result["details"] = tool_result

            logger.security(
                f"Found Privilege Escalation vulnerability via {tool_result.get('vulnerable_path', '')}"
            )

        # Check if browser interaction revealed access control issues
        elif (
            tool_name in ["goto", "click"]
            and "admin" in str(tool_result).lower()
            and "success" in str(tool_result).lower()
        ):
            # This could be a successful access to admin functionality
            result["vulnerability_found"] = True
            result["vulnerability_type"] = "Broken Access Control"
            result["severity"] = "high"
            result["details"] = {
                "issue_type": "Unauthorized Access to Admin Functionality",
                "url": page.url,
                "evidence": f"Successfully accessed admin functionality via {tool_name}",
                "affected_resource": str(tool_result),
            }

            logger.security(
                "Found potential unauthorized access to admin functionality"
            )

        return result
