from typing import Dict, Any
from playwright.sync_api import Page

from core.llm import LLMProvider
from core.scanner import Scanner
from agents.security.specialized_agent import SpecializedSecurityAgent
from utils.logger import get_logger


class DataIntegrityAgent(SpecializedSecurityAgent):
    """Agent specializing in Software and Data Integrity Failures testing."""

    def __init__(self, llm_provider: LLMProvider, scanner: Scanner):
        super().__init__(
            "DataIntegrityAgent",
            "integrity_specialist",
            "data_integrity",
            llm_provider,
            scanner,
        )

    def _get_system_prompt(self) -> str:
        """Get the system prompt for data integrity testing."""
        return """
        You are a Software and Data Integrity security specialist. Your job is to identify and report integrity failures in web applications.
        
        Focus on testing:
        1. Insecure update mechanisms
        2. Lack of data integrity verification
        3. Insecure deserialization
        4. Unsigned code or data
        5. Integrity check bypasses
        
        You have access to specialized data integrity testing tools and browser interaction tools:
        
        DATA INTEGRITY TOOLS:
        - check_data_integrity: Check for software and data integrity failures
        - test_deserialization: Test for insecure deserialization vulnerabilities
        
        BROWSER INTERACTION TOOLS:
        - goto: Navigate to a URL
        - click: Click an element on the page
        - fill: Fill a form field with a value
        - submit: Submit a form
        - execute_js: Execute JavaScript on the page
        
        Common data integrity issues to look for:
        - Missing digital signatures for updates
        - Lack of integrity checking for critical data
        - Insecure deserialization of user-controllable data
        - Unsigned/unvalidated plugins or extensions
        - CI/CD pipeline weaknesses
        """

    def _check_for_vulnerabilities(
        self,
        tool_name: str,
        tool_result: Dict[str, Any],
        result: Dict[str, Any],
        page: Page,
        tool_call: Any,
    ) -> Dict[str, Any]:
        """Check for data integrity vulnerabilities in tool results."""
        logger = get_logger()

        # Check for integrity issues
        if tool_result.get("integrity_issue_found", False):
            result["vulnerability_found"] = True
            result["vulnerability_type"] = "Software and Data Integrity Failure"
            result["severity"] = tool_result.get("severity", "high")
            result["details"] = tool_result

            logger.security(
                f"Found Data Integrity issue: {', '.join(tool_result.get('issues', ['Unknown issue']))}"
            )

        # Check for deserialization issues
        elif tool_result.get("deserialization_issue_found", False):
            result["vulnerability_found"] = True
            result["vulnerability_type"] = "Insecure Deserialization"
            result["severity"] = tool_result.get("severity", "critical")
            result["details"] = tool_result

            logger.security(
                f"Found Insecure Deserialization in {tool_result.get('data_format', '')} data"
            )

        return result
