from typing import Dict, List, Any
from playwright.sync_api import Page

from core.llm import LLMProvider
from core.scanner import Scanner
from agents.agent_factory import BaseAgent
from utils.logger import get_logger
from tools.browser_tools import BrowserTools
from tools.browser_tools_impl import get_browser_interaction_tools


class ValidationAgent(BaseAgent):
    """Agent responsible for validating security findings and confirming vulnerabilities."""

    def __init__(self, llm_provider: LLMProvider, scanner: Scanner):
        # Use specialized validation tools and browser interaction tools
        validation_tools = [
            {
                "type": "function",
                "function": {
                    "name": "validate_finding",
                    "description": "Validate a security finding by analyzing the evidence and confirming the vulnerability",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "vulnerability_type": {
                                "type": "string",
                                "description": "Type of vulnerability (e.g., XSS, CSRF, SQLi)"
                            },
                            "evidence": {
                                "type": "string",
                                "description": "Evidence supporting the finding"
                            },
                            "validated": {
                                "type": "boolean",
                                "description": "Whether the vulnerability is validated"
                            },
                            "verification_steps": {
                                "type": "array",
                                "items": {
                                    "type": "string"
                                },
                                "description": "Steps taken to verify the vulnerability"
                            },
                            "details": {
                                "type": "object",
                                "description": "Additional details about the validation"
                            }
                        },
                        "required": ["vulnerability_type", "validated"]
                    }
                }
            }
        ]

        # Add browser tools for validation actions
        browser_tools = get_browser_interaction_tools()
        tools = validation_tools + browser_tools

        super().__init__("ValidationAgent", "security_validator", llm_provider, tools)
        self.scanner = scanner
        self.browser_tools = BrowserTools(debug=True)

    def validate_finding(self, finding: Dict[str, Any], page: Page, page_info: Dict[str, Any]) -> Dict[str, Any]:
        """Validate a security finding to confirm if it's a real vulnerability."""
        logger = get_logger()
        logger.info(f"Validating {finding.get('vulnerability_type', 'unknown')} vulnerability")
        logger.debug(f"Finding details: {finding}")
        logger.debug(f"Page info: {page_info}")

        # Create system prompt based on the type of vulnerability
        system_prompt = self._get_validation_prompt(finding)

        # Create input data with the finding details
        input_data = {
            "content": f"Validate the following security finding:\n\n{self._format_finding(finding)}\n\nPage information: {page_info}"
        }

        # Use the LLM to analyze the finding
        response = self.think(input_data, system_prompt)
        logger.debug(f"LLM response: {response}")

        # Initialize validation result
        validation_result = {
            "validated": False,
            "details": {
                "validation_method": "expert_analysis",
                "notes": "Validation pending"
            }
        }

        # Check if any tool was called
        if response.get("tool_calls"):
            # Process validation from tool calls
            for tool_call in response["tool_calls"]:
                tool_name = self._get_tool_name(tool_call)
                logger.info(f"ValidationAgent using tool: {tool_name}", color="cyan")
                logger.debug(f"Tool call details: {tool_call}") # Add logging for tool call details

                # Execute the tool
                tool_result = self.execute_tool(tool_call)
                logger.debug(f"Tool execution result: {tool_result}") # Add logging for tool result

                # If it's the validate_finding tool, use its result
                if tool_name == "validate_finding" and isinstance(tool_result, dict):
                    validation_result["validated"] = tool_result.get("validated", False)
                    validation_result["details"] = tool_result.get("details", {})

                    # Log the validation outcome
                    if validation_result["validated"]:
                        logger.success(f"Validated {finding.get('vulnerability_type', 'unknown')} vulnerability")
                    else:
                        logger.warning(f"Could not validate {finding.get('vulnerability_type', 'unknown')} vulnerability")
        else:
            # Use the followup response to determine validation
            content = response.get("content", "").lower()
            # Improved text parsing to identify validation from LLM's natural language response
            if any(keyword in content for keyword in ["validated", "confirmed", "verified", "appears to be a real", "is a real"]):
                validation_result["validated"] = True
                validation_result["details"]["validation_method"] = "expert_analysis_text_fallback"
                validation_result["details"]["notes"] = f"Validated through expert analysis of LLM text response: {content}"
                validation_result["details"]["confidence_level"] = "high" # Add confidence level for fallback
                logger.success(f"Validated {finding.get('vulnerability_type', 'unknown')} through expert analysis text fallback")
            elif any(keyword in content for keyword in ["cannot validate", "not validated", "false positive", "not a vulnerability"]):
                validation_result["validated"] = False
                validation_result["details"]["validation_method"] = "expert_analysis_text_fallback"
                validation_result["details"]["notes"] = f"Could not validate through expert analysis of LLM text response: {content}"
                validation_result["details"]["confidence_level"] = "low" # Add confidence level for fallback
                logger.warning(f"Could not validate {finding.get('vulnerability_type', 'unknown')} - likely a false positive based on LLM text fallback")

        return validation_result

    def _get_tool_name(self, tool_call: Any) -> str:
        """Extract the tool name from a tool call."""
        if hasattr(tool_call, 'function') and hasattr(tool_call.function, 'name'):
            return tool_call.function.name
        return tool_call.get('function', {}).get('name', 'unknown_tool')

    def _format_finding(self, finding: Dict[str, Any]) -> str:
        """Format a finding for the validation prompt."""
        formatted = f"Vulnerability Type: {finding.get('vulnerability_type', 'Unknown')}\n"
        formatted += f"Severity: {finding.get('severity', 'medium')}\n"
        formatted += f"Target: {finding.get('target', 'Unknown')}\n"

        # Add details if available
        if finding.get("details"):
            formatted += "Details:\n"
            for key, value in finding.get("details", {}).items():
                formatted += f"- {key}: {value}\n"

        # Add any evidence
        if finding.get("evidence") or (finding.get("details") and finding.get("details").get("evidence")):
            evidence = finding.get("evidence", finding.get("details", {}).get("evidence", ""))
            formatted += f"Evidence: {evidence}\n"

        # Add actions performed
        if finding.get("actions_performed"):
            formatted += "Actions Performed:\n"
            for action in finding.get("actions_performed", []):
                formatted += f"- {action.get('tool', 'unknown')}: {action.get('success', False)}\n"

        return formatted

    def _get_validation_prompt(self, finding: Dict[str, Any]) -> str:
        """Get a specific validation prompt based on the vulnerability type."""
        vuln_type = finding.get("vulnerability_type", "").lower()

        # Base prompt for all validations
        base_prompt = """
        You are a Security Validation Expert. Your role is to confirm or reject security findings.
        Analyze the evidence provided and determine if the reported vulnerability is legitimate.

        For a vulnerability to be validated, it should have:
        1. Clear evidence of the vulnerability's existence
        2. Confirmation that the vulnerability can be exploited
        3. Proper context and details to understand the issue

        You have access to validation tools and browser interaction tools:

        VALIDATION TOOLS:
        - validate_finding: Confirm or reject a security finding. Use this tool to report your final validation decision (validated: true/false) along with any relevant details.

        BROWSER INTERACTION TOOLS:
        - goto: Navigate to a URL
        - click: Click an element on the page
        - fill: Fill a form field with a value
        - submit: Submit a form
        - execute_js: Execute JavaScript on the page
        """

        # Add specialized validation guidance based on vulnerability type
        if "xss" in vuln_type:
            base_prompt += """
            For Cross-Site Scripting (XSS) validation:
            - Check if the payload was actually executed in the browser context
            - Verify that the script has access to the document object
            - Confirm that the script can perform actions like alert(), document.cookie access, etc.
            - For stored XSS, verify the payload remains after page refresh
            """
        elif "sqli" in vuln_type or "sql" in vuln_type:
            base_prompt += """
            For SQL Injection validation:
            - Verify that database information was exposed or modified
            - Check if authentication was bypassed
            - Look for error messages that reveal database structure
            - Confirm the ability to extract data or modify queries
            """
        elif "csrf" in vuln_type:
            base_prompt += """
            For Cross-Site Request Forgery (CSRF) validation:
            - Verify that actions can be performed without proper tokens
            - Check if the application accepts requests from different origins
            - Confirm that authenticated actions can be triggered without user consent
            """
        elif "auth" in vuln_type or "authentication" in vuln_type:
            base_prompt += """
            For Authentication Issues validation:
            - Verify if bypass techniques actually worked
            - Check if session management is properly implemented
            - Confirm if credentials are properly validated
            - Test for session fixation or hijacking possibilities
            """
        elif "idor" in vuln_type:
            base_prompt += """
            For Insecure Direct Object Reference (IDOR) validation:
            - Verify that restricted resources can be accessed by modifying identifiers
            - Confirm access to other users' data
            - Test if changing parameters allows unauthorized access
            """
        elif "access control" in vuln_type or "privilege" in vuln_type:
            base_prompt += """
            For Access Control validation:
            - Verify unauthorized access to restricted functions
            - Confirm privilege escalation is possible
            - Test vertical and horizontal access control issues
            - Check if authorization checks are missing or bypassed
            """
        elif "crypto" in vuln_type or "cryptographic" in vuln_type:
            base_prompt += """
            For Cryptographic Failures validation:
            - Verify weak encryption or hashing algorithms
            - Confirm TLS/SSL misconfigurations
            - Check for sensitive data exposure
            - Test for insufficient key sizes or poor key management
            """
        elif "insecure design" in vuln_type:
            base_prompt += """
            For Insecure Design validation:
            - Verify architectural flaws in the application
            - Confirm missing security controls at design level
            - Test for business logic bypasses
            - Check for rate limiting issues or lack of defense in depth
            """
        elif "data integrity" in vuln_type or "deserialization" in vuln_type:
            base_prompt += """
            For Data Integrity/Deserialization validation:
            - Verify if user-controlled data can be manipulated for untrusted deserialization
            - Confirm lack of integrity checks
            - Test for code execution via deserialization
            - Check for improper handling of user inputs in critical operations
            """
        elif "ssrf" in vuln_type:
            base_prompt += """
            For Server-Side Request Forgery (SSRF) validation:
            - Verify the server makes requests to attacker-controlled destinations
            - Confirm access to internal resources
            - Test for information leakage from internal services
            - Check if the server could be used as a proxy for further attacks
            """

        return base_prompt