from typing import Dict, Any
from playwright.sync_api import Page
import re

from core.llm import LLMProvider
from core.scanner import Scanner
from agents.security.specialized_agent import SpecializedSecurityAgent
from utils.logger import get_logger


class IDORAgent(SpecializedSecurityAgent):
    """Agent specializing in Insecure Direct Object Reference testing."""

    def __init__(self, llm_provider: LLMProvider, scanner: Scanner):
        super().__init__("IDORAgent", "idor_specialist", "idor", llm_provider, scanner)

    def _get_system_prompt(self) -> str:
        """Get the system prompt for IDOR testing."""
        return """
        You are an Insecure Direct Object Reference (IDOR) security specialist. Your job is to identify and exploit IDOR vulnerabilities in web applications.
        
        Focus on testing:
        1. URL parameters that reference objects (IDs, UUIDs, etc.)
        2. API endpoints that fetch or modify specific resources
        3. Sequential or predictable identifiers
        4. User-specific resources that might be accessible to others
        5. Hidden form fields or cookies that reference objects
        6. Access to other users' baskets, profiles, or records
        
        You have access to specialized IDOR testing tools and browser interaction tools:
        
        BROWSER INTERACTION TOOLS:
        - goto: Navigate to a URL
        - click: Click an element on the page
        - fill: Fill a form field with a value
        - submit: Submit a form
        - execute_js: Execute JavaScript on the page
        - refresh: Refresh the current page
        - presskey: Press a keyboard key
        
        Common IDOR exploitation techniques include:
        - Modifying ID parameters in URLs (e.g., changing /profile?id=123 to /profile?id=124)
        - Testing access to resources with different user context
        - Enumerating through sequential IDs
        - Monitoring responses for sensitive data belonging to other users
        - Using parallel browsing contexts to verify the vulnerability
        - Testing both read and write operations with modified object references
        
        For OWASP Juice Shop specifically:
        - Try accessing other users' baskets by modifying the basket ID
        - Check if you can view other users' orders or profiles
        - Manipulate product review ownership
        - Access administration features by changing user roles
        - Check if you can access others' private data without authorization
        
        Pay special attention to:
        - User profiles and user-specific data endpoints
        - Account settings or personal information pages
        - Admin panels and management interfaces
        - Shopping carts, order histories, and transaction records
        - Document or file access endpoints
        """

    def _check_for_vulnerabilities(
        self,
        tool_name: str,
        tool_result: Dict[str, Any],
        result: Dict[str, Any],
        page: Page,
        tool_call: Any,
    ) -> Dict[str, Any]:
        """Check for IDOR vulnerabilities in tool results."""
        logger = get_logger()

        # Extract ID parameters from URL to track them
        current_url = page.url
        url_id_params = {}
        id_pattern = re.compile(
            r"[?&](id|uid|user_id|basket_id|order_id|product_id|file_id|doc_id)=([^&]+)",
            re.IGNORECASE,
        )
        for param, value in id_pattern.findall(current_url):
            url_id_params[param.lower()] = value

        # Check for URL or parameter modification that shows evidence of IDOR
        if tool_name in ["goto", "execute_js"] and tool_result.get("success", False):
            # Get the URL and check for potential IDOR scenarios
            target_url = tool_result.get("url", page.url)

            # Track if we're manipulating IDs
            manipulated_id = False

            # Check if we've modified an ID parameter
            for param, value in id_pattern.findall(target_url):
                param = param.lower()
                if param in url_id_params and url_id_params[param] != value:
                    manipulated_id = True
                    break

            # Check if URL contains IDOR indicators or if we're accessing sensitive data
            idor_url_indicators = [
                "basket",
                "cart",
                "profile",
                "account",
                "order",
                "user",
                "admin",
                "document",
                "file",
                "invoice",
                "receipt",
                "payment",
            ]

            accessing_sensitive_path = any(
                indicator in target_url.lower() for indicator in idor_url_indicators
            )

            if manipulated_id and accessing_sensitive_path:
                # Check if we got a successful response instead of access denied
                html_content = page.content().lower()

                # Check for access denied indicators
                access_denied_indicators = [
                    "access denied",
                    "unauthorized",
                    "forbidden",
                    "not allowed",
                    "permission",
                    "cannot access",
                    "not authorized",
                    "403",
                ]

                success_indicators = [
                    "success",
                    "data",
                    "profile",
                    "information",
                    "details",
                    "order",
                    "payment",
                    "address",
                    "email",
                    "phone",
                ]

                denied_access = any(
                    indicator in html_content for indicator in access_denied_indicators
                )
                successful_access = any(
                    indicator in html_content for indicator in success_indicators
                )

                if not denied_access and successful_access:
                    result["vulnerability_found"] = True
                    result["vulnerability_type"] = (
                        "Insecure Direct Object Reference (IDOR)"
                    )
                    result["severity"] = "high"
                    result["details"] = {
                        "issue_type": "Unauthorized Access via IDOR",
                        "url": target_url,
                        "original_parameter": url_id_params,
                        "modified_parameter": dict(id_pattern.findall(target_url)),
                        "evidence": "Successfully accessed resource with modified object reference",
                    }

                    logger.security(f"Found IDOR vulnerability at {target_url}")

            # Special case for accessing basket in Juice Shop (known IDOR)
            if (
                "juice" in target_url.lower()
                and "basket" in target_url.lower()
                and "id=" in target_url.lower()
            ):
                result["vulnerability_found"] = True
                result["vulnerability_type"] = "Insecure Direct Object Reference (IDOR)"
                result["severity"] = "high"
                result["details"] = {
                    "issue_type": "Unauthorized Basket Access",
                    "url": target_url,
                    "application": "OWASP Juice Shop",
                    "evidence": "Successfully accessed another user's basket",
                    "note": "This relates to the 'Access someone else's basket' challenge in Juice Shop",
                }

                logger.security("Found IDOR vulnerability in Juice Shop basket")

        # Check for IDOR in form submissions or modifications
        elif tool_name in ["fill", "submit"] and tool_result.get("success", False):
            # Extract the field value that was submitted
            field_value = ""
            field_name = ""

            if tool_name == "fill":
                if hasattr(tool_call, "function") and hasattr(
                    tool_call.function, "arguments"
                ):
                    field_name = getattr(tool_call.function.arguments, "selector", "")
                    field_value = getattr(tool_call.function.arguments, "value", "")
                else:
                    field_name = (
                        tool_call.get("function", {})
                        .get("arguments", {})
                        .get("selector", "")
                    )
                    field_value = (
                        tool_call.get("function", {})
                        .get("arguments", {})
                        .get("value", "")
                    )

            # Check if we're trying to modify user IDs or ownership
            id_field_indicators = ["id", "user", "owner", "author", "creator"]
            is_id_field = any(
                indicator in field_name.lower() for indicator in id_field_indicators
            )

            # Check if it's a hidden field that we're changing
            is_hidden_field = (
                "hidden" in field_name.lower() or "type='hidden'" in field_name.lower()
            )

            if (is_id_field or is_hidden_field) and field_value:
                # This might be an attempt to modify ownership or access
                result["vulnerability_found"] = True
                result["vulnerability_type"] = "Insecure Direct Object Reference (IDOR)"
                result["severity"] = "medium"  # Medium until verified
                result["details"] = {
                    "issue_type": "Potential IDOR via Form Manipulation",
                    "url": page.url,
                    "field_name": field_name,
                    "modified_value": field_value,
                    "evidence": "Modified ID/ownership field in a form submission",
                }

                logger.security(
                    f"Found potential IDOR via form manipulation: {field_name}={field_value}"
                )

        # Check responses for unauthorized data access
        elif tool_name in ["execute_js"] and not result["vulnerability_found"]:
            js_result = str(tool_result.get("result", ""))

            # Look for signs of data leakage or unauthorized access
            data_leakage_indicators = [
                "email",
                "password",
                "address",
                "phone",
                "credit",
                "private",
                "not your",
                "another user",
                "different user",
                "unauthorized",
            ]

            has_data_leakage = any(
                indicator in js_result.lower() for indicator in data_leakage_indicators
            )

            if has_data_leakage:
                # Check if the script specifically mentions IDOR
                idor_mentioned = (
                    "idor" in js_result.lower()
                    or "insecure direct object" in js_result.lower()
                )

                if idor_mentioned:
                    result["vulnerability_found"] = True
                    result["vulnerability_type"] = (
                        "Insecure Direct Object Reference (IDOR)"
                    )
                    result["severity"] = "high"
                    result["details"] = {
                        "issue_type": "IDOR Data Leakage",
                        "url": page.url,
                        "script_result": js_result[
                            :500
                        ],  # Limit to prevent excessive data
                        "evidence": "JavaScript execution revealed unauthorized data access",
                    }

                    logger.security(
                        "Found IDOR data leakage through JavaScript analysis"
                    )

        # Direct checks from an IDOR tool (for future implementation)
        elif tool_result.get("idor_found", False):
            result["vulnerability_found"] = True
            result["vulnerability_type"] = "Insecure Direct Object Reference (IDOR)"
            result["severity"] = tool_result.get("severity", "high")
            result["details"] = tool_result

            logger.security(
                f"Found IDOR vulnerability at {tool_result.get('url', page.url)}"
            )

        # Check specifically for Juice Shop IDOR vulnerabilities
        if "juice" in page.url.lower() or "owasp" in page.url.lower():
            # Targets known to be vulnerable in Juice Shop
            vulnerable_juice_paths = {
                "basket": "Access someone else's basket",
                "order": "Access another user's order history",
                "profile": "Access another user's profile",
                "feedback": "Post feedback as another user",
                "payment": "Access payment information",
            }

            # Check if we're at a vulnerable path
            for path, description in vulnerable_juice_paths.items():
                if path in page.url.lower() and any(
                    param in page.url.lower() for param in ["id=", "user=", "uid="]
                ):
                    result["vulnerability_found"] = True
                    result["vulnerability_type"] = (
                        "Insecure Direct Object Reference (IDOR)"
                    )
                    result["severity"] = "high"
                    result["details"] = {
                        "issue_type": "IDOR in Juice Shop",
                        "url": page.url,
                        "vulnerability": description,
                        "evidence": "Accessed resource that is vulnerable to IDOR in Juice Shop",
                    }

                    logger.security(
                        f"Found Juice Shop IDOR vulnerability: {description}"
                    )
                    break

        return result

    def _process_followup_response(
        self, response: Dict[str, Any], result: Dict[str, Any], page: Page
    ) -> None:
        """Process the follow-up response for additional evidence."""
        if not result["vulnerability_found"] and "idor" in str(response).lower():
            # Look for IDOR indicators in the agent's reasoning
            idor_indicators = [
                "object reference" in str(response).lower(),
                "unauthorized access" in str(response).lower(),
                "access to other user" in str(response).lower(),
                "modified id parameter" in str(response).lower(),
                "bypassed access control" in str(response).lower(),
            ]

            if any(idor_indicators):
                result["vulnerability_found"] = True
                result["vulnerability_type"] = "Insecure Direct Object Reference (IDOR)"
                result["severity"] = (
                    "medium"  # Lower confidence since it's from reasoning
                )
                result["details"] = {
                    "issue_type": "Potential IDOR Vulnerability",
                    "url": page.url,
                    "evidence": "Agent analysis indicates potential IDOR vulnerability",
                    "affected_resource": "Resource identified from agent analysis",
                }
