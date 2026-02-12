"""
API Security Agent - Tests REST and GraphQL APIs for common vulnerabilities.

This agent focuses on OWASP API Security Top 10 vulnerabilities:
- Broken Object Level Authorization (BOLA)
- Broken Authentication
- Excessive Data Exposure
- Lack of Resources & Rate Limiting
- Broken Function Level Authorization
- Mass Assignment
- Security Misconfiguration
- Injection
- Improper Assets Management
- Insufficient Logging & Monitoring
"""

from typing import Dict, Any, List
from urllib.parse import urlparse
import json
import re
from playwright.sync_api import Page

from core.llm import LLMProvider
from core.scanner import Scanner
from agents.security.specialized_agent import SpecializedSecurityAgent
from utils.logger import get_logger


class APISecurityAgent(SpecializedSecurityAgent):
    """Agent specializing in API Security testing (REST/GraphQL)."""

    def __init__(self, llm_provider: LLMProvider, scanner: Scanner):
        super().__init__(
            "APISecurityAgent", "api_security_specialist", "api", llm_provider, scanner
        )
        self.discovered_endpoints: List[Dict[str, Any]] = []
        self.tested_endpoints: List[str] = []

    def _create_input_data(
        self, task: Dict[str, Any], page: Page, page_info: Dict[str, Any]
    ) -> Dict[str, str]:
        """Create input data with API-specific context."""
        parsed_url = urlparse(page.url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

        # Try to detect API type from page content
        api_type = self._detect_api_type(page_info)

        return {
            "content": f"""Test for API security vulnerabilities on: {page.url}

Base URL: {base_url}
Detected API Type: {api_type}

Task details: {task}

Page information: {page_info}

Discovered endpoints: {json.dumps(self.discovered_endpoints, indent=2) if self.discovered_endpoints else "None yet"}

Focus on:
1. Discovering API endpoints from JavaScript, network requests, and page content
2. Testing for Broken Object Level Authorization (BOLA/IDOR)
3. Testing for authentication and session issues
4. Checking for excessive data exposure in responses
5. Testing for mass assignment vulnerabilities
6. Checking rate limiting and resource constraints
7. Testing for injection vulnerabilities in API parameters"""
        }

    def _detect_api_type(self, page_info: Dict[str, Any]) -> str:
        """Detect the type of API being used."""
        content = str(page_info)

        if (
            "graphql" in content.lower()
            or "__schema" in content
            or "query {" in content
        ):
            return "GraphQL"
        elif (
            "/api/v" in content
            or "application/json" in content
            or "REST" in content.upper()
        ):
            return "REST"
        elif "swagger" in content.lower() or "openapi" in content.lower():
            return "REST (Swagger/OpenAPI)"
        else:
            return "Unknown (likely REST)"

    def _get_system_prompt(self) -> str:
        """Get the system prompt for API security testing."""
        return """
You are an API Security specialist focused on testing REST and GraphQL APIs. Your job is to identify and report API-specific vulnerabilities based on the OWASP API Security Top 10.

KEY VULNERABILITY TYPES TO TEST:

1. **Broken Object Level Authorization (BOLA/IDOR)**
   - Manipulate object IDs in requests (sequential IDs, GUIDs)
   - Test accessing other users' resources by changing IDs
   - Look for: /api/users/{id}, /api/orders/{id}, etc.

2. **Broken Authentication**
   - Test for missing or weak authentication on endpoints
   - Check if sensitive endpoints allow anonymous access
   - Test JWT vulnerabilities (none algorithm, weak secrets)
   - Look for exposed tokens in responses

3. **Excessive Data Exposure**
   - Check if API returns more data than needed
   - Look for sensitive fields (password, SSN, tokens) in responses
   - Test if filtering happens client-side vs server-side

4. **Lack of Resources & Rate Limiting**
   - Test for missing rate limiting
   - Check for resource-intensive operations without limits
   - Look for endpoints vulnerable to DoS

5. **Broken Function Level Authorization**
   - Test if regular users can access admin endpoints
   - Check for HTTP method switching (GET vs DELETE)
   - Look for hidden/undocumented admin functions

6. **Mass Assignment**
   - Test adding extra fields to requests
   - Try setting admin/role/premium flags
   - Check for privilege escalation through parameter injection

7. **Security Misconfiguration**
   - Check CORS configuration
   - Look for debug endpoints
   - Test for verbose error messages
   - Check for exposed API documentation

8. **Injection**
   - Test SQL/NoSQL injection in parameters
   - Check for command injection
   - Test GraphQL injection attacks

You have access to API security testing tools and browser interaction tools:

API SECURITY TOOLS:
- discover_api_endpoints: Find API endpoints from page content and JavaScript
- test_bola_vulnerability: Test for Broken Object Level Authorization
- test_api_authentication: Test API authentication security
- test_rate_limiting: Check for rate limiting on endpoints
- test_mass_assignment: Test for mass assignment vulnerabilities
- analyze_api_response: Analyze API response for data exposure
- test_graphql_introspection: Test GraphQL introspection and injection

BROWSER INTERACTION TOOLS:
- goto: Navigate to a URL
- click: Click an element on the page
- fill: Fill a form field with a value
- execute_js: Execute JavaScript on the page (useful for API calls)

TESTING APPROACH:
1. First, discover API endpoints by analyzing:
   - JavaScript files for fetch/axios calls
   - Network requests captured during page load
   - Links and forms in page content
   - API documentation if available

2. For each endpoint found:
   - Identify the HTTP methods supported
   - Determine authentication requirements
   - Test for BOLA by manipulating IDs
   - Check for excessive data exposure
   - Test for injection vulnerabilities

3. Report findings with:
   - Clear reproduction steps
   - Evidence (request/response samples)
   - Impact assessment
   - Remediation recommendations
"""

    def _check_for_vulnerabilities(
        self,
        tool_name: str,
        tool_result: Dict[str, Any],
        result: Dict[str, Any],
        page: Page,
        tool_call: Any,
    ) -> Dict[str, Any]:
        """Check for API security vulnerabilities in tool results."""
        logger = get_logger()

        # Track discovered endpoints
        if tool_name == "discover_api_endpoints" and tool_result.get("endpoints"):
            self.discovered_endpoints.extend(tool_result["endpoints"])
            logger.info(f"Discovered {len(tool_result['endpoints'])} API endpoints")

        # Check for BOLA vulnerability
        if tool_result.get("bola_found", False):
            result["vulnerability_found"] = True
            result["vulnerability_type"] = "Broken Object Level Authorization (BOLA)"
            result["severity"] = "critical"
            result["details"] = tool_result
            logger.security(
                f"Found BOLA vulnerability: {tool_result.get('description', 'ID manipulation allowed unauthorized access')}"
            )

        # Check for authentication issues
        elif tool_result.get("auth_bypass_found", False):
            result["vulnerability_found"] = True
            result["vulnerability_type"] = "Broken API Authentication"
            result["severity"] = "critical"
            result["details"] = tool_result
            logger.security(
                f"Found API Authentication bypass: {tool_result.get('description', 'Endpoint accessible without authentication')}"
            )

        # Check for excessive data exposure
        elif tool_result.get("data_exposure_found", False):
            result["vulnerability_found"] = True
            result["vulnerability_type"] = "Excessive Data Exposure"
            result["severity"] = tool_result.get("severity", "high")
            result["details"] = tool_result
            logger.security(
                f"Found Excessive Data Exposure: {tool_result.get('exposed_fields', [])}"
            )

        # Check for rate limiting issues
        elif tool_result.get("rate_limit_missing", False):
            result["vulnerability_found"] = True
            result["vulnerability_type"] = "Lack of Rate Limiting"
            result["severity"] = "medium"
            result["details"] = tool_result
            logger.security(
                f"Missing rate limiting on endpoint: {tool_result.get('endpoint', 'unknown')}"
            )

        # Check for mass assignment
        elif tool_result.get("mass_assignment_found", False):
            result["vulnerability_found"] = True
            result["vulnerability_type"] = "Mass Assignment"
            result["severity"] = "high"
            result["details"] = tool_result
            logger.security(
                f"Found Mass Assignment vulnerability: {tool_result.get('injectable_fields', [])}"
            )

        # Check for GraphQL vulnerabilities
        elif tool_result.get("graphql_vulnerability_found", False):
            result["vulnerability_found"] = True
            result["vulnerability_type"] = (
                f"GraphQL Security Issue: {tool_result.get('issue_type', 'Unknown')}"
            )
            result["severity"] = tool_result.get("severity", "high")
            result["details"] = tool_result
            logger.security(
                f"Found GraphQL vulnerability: {tool_result.get('issue_type', 'Unknown')}"
            )

        # Check for security misconfiguration
        elif tool_result.get("misconfiguration_found", False):
            result["vulnerability_found"] = True
            result["vulnerability_type"] = "API Security Misconfiguration"
            result["severity"] = tool_result.get("severity", "medium")
            result["details"] = tool_result
            logger.security(
                f"Found API misconfiguration: {tool_result.get('issue', 'Unknown')}"
            )

        # Check if JavaScript execution revealed API patterns
        elif tool_name == "execute_js" and tool_result.get("success", False):
            js_result = str(tool_result.get("result", ""))
            api_patterns = self._extract_api_patterns(js_result)
            if api_patterns:
                logger.info(
                    f"Found {len(api_patterns)} potential API patterns in JavaScript"
                )
                for pattern in api_patterns:
                    if pattern not in [
                        ep.get("endpoint") for ep in self.discovered_endpoints
                    ]:
                        self.discovered_endpoints.append(
                            {
                                "endpoint": pattern,
                                "source": "javascript",
                                "method": "unknown",
                            }
                        )

        return result

    def _extract_api_patterns(self, content: str) -> List[str]:
        """Extract potential API endpoints from content."""
        patterns = []

        # Common API URL patterns
        api_regex_patterns = [
            r"/api/v\d+/\w+",
            r"/api/\w+",
            r"/v\d+/\w+",
            r"/graphql",
            r"/rest/\w+",
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.[a-z]+\(["\']([^"\']+)["\']',
            r'url:\s*["\']([^"\']+/api[^"\']*)["\']',
        ]

        for pattern in api_regex_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            patterns.extend(matches)

        # Deduplicate and return
        return list(set(patterns))

    def get_discovered_endpoints(self) -> List[Dict[str, Any]]:
        """Return the list of discovered API endpoints."""
        return self.discovered_endpoints

    def reset_discovered_endpoints(self) -> None:
        """Reset the discovered endpoints list."""
        self.discovered_endpoints = []
        self.tested_endpoints = []
