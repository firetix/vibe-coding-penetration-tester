from typing import Dict, Any
from urllib.parse import urlparse
from playwright.sync_api import Page

from core.llm import LLMProvider
from core.scanner import Scanner
from agents.security.specialized_agent import SpecializedSecurityAgent
from utils.logger import get_logger


class CryptoFailureAgent(SpecializedSecurityAgent):
    """Agent specializing in Cryptographic Failures testing."""

    def __init__(self, llm_provider: LLMProvider, scanner: Scanner):
        super().__init__(
            "CryptoFailureAgent", "crypto_specialist", "crypto", llm_provider, scanner
        )

    def _create_input_data(
        self, task: Dict[str, Any], page: Page, page_info: Dict[str, Any]
    ) -> Dict[str, str]:
        """Create input data with hostname for TLS checks."""
        parsed_url = urlparse(page.url)
        target_host = parsed_url.netloc

        return {
            "content": f"Test for cryptographic failures on: {page.url}\n\nTarget host: {target_host}\n\nTask details: {task}\n\nPage information: {page_info}"
        }

    def _get_system_prompt(self) -> str:
        """Get the system prompt for cryptographic testing."""
        return """
        You are a Cryptography security specialist. Your job is to identify and report cryptographic failures in web applications.
        
        Focus on testing:
        1. TLS/SSL configuration issues
        2. Certificate problems
        3. Weak cryptographic implementations
        4. Missing security headers related to encryption
        5. Sensitive data transmission and storage
        
        You have access to specialized cryptographic testing tools and browser interaction tools:
        
        CRYPTO TOOLS:
        - check_tls_configuration: Check TLS/SSL configuration for security issues
        - analyze_crypto_implementation: Analyze cryptographic implementation for weaknesses
        
        BROWSER INTERACTION TOOLS:
        - goto: Navigate to a URL
        - click: Click an element on the page
        - fill: Fill a form field with a value
        - submit: Submit a form
        - execute_js: Execute JavaScript on the page
        
        Common cryptographic issues to look for:
        - Outdated TLS protocols (SSLv3, TLSv1.0, TLSv1.1)
        - Weak cipher suites
        - Certificate validation issues
        - Missing security headers (HSTS, Content-Security-Policy)
        - Weak hashing algorithms for sensitive data
        - Cleartext transmission of sensitive information
        """

    def _check_for_vulnerabilities(
        self,
        tool_name: str,
        tool_result: Dict[str, Any],
        result: Dict[str, Any],
        page: Page,
        tool_call: Any,
    ) -> Dict[str, Any]:
        """Check for cryptographic vulnerabilities in tool results."""
        logger = get_logger()

        # Check for crypto issues reported by tools
        if tool_result.get("crypto_issue_found", False):
            result["vulnerability_found"] = True
            result["vulnerability_type"] = "Cryptographic Failure"
            result["severity"] = tool_result.get("severity", "high")
            result["details"] = tool_result

            logger.security(
                f"Found Cryptographic Failure: {', '.join(tool_result.get('issues', ['Unknown issue']))}"
            )

        # Check if JavaScript execution revealed sensitive data exposure
        elif tool_name == "execute_js" and tool_result.get("success", False):
            js_result = str(tool_result.get("result", ""))

            # Check for crypto-related sensitive data in results
            crypto_indicators = [
                "password",
                "token",
                "api_key",
                "apikey",
                "secret",
                "private",
                "key",
            ]
            if any(indicator in js_result.lower() for indicator in crypto_indicators):
                result["vulnerability_found"] = True
                result["vulnerability_type"] = "Sensitive Data Exposure"
                result["severity"] = "high"
                result["details"] = {
                    "issue_type": "Sensitive Data Exposure in Client-Side JavaScript",
                    "url": page.url,
                    "evidence": js_result,
                    "description": "Sensitive data found in client-side JavaScript",
                }

                logger.security("Found Sensitive Data Exposure in JavaScript")

        return result
