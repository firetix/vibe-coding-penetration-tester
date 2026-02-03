from typing import Dict, Any
from playwright.sync_api import Page
import json
import re

from core.llm import LLMProvider
from core.scanner import Scanner
from agents.security.specialized_agent import SpecializedSecurityAgent
from utils.logger import get_logger


class APISecurityAgent(SpecializedSecurityAgent):
    """Agent specializing in REST API Security testing.
    
    Tests for common API vulnerabilities including:
    - Broken Authentication (API keys, tokens, session management)
    - Rate Limiting Issues (missing or insufficient rate limiting)
    - Sensitive Data Exposure (PII, credentials in responses)
    - Missing Security Headers (CORS, Content-Type, etc.)
    - Mass Assignment vulnerabilities
    - Improper Error Handling (stack traces, verbose errors)
    """
    
    def __init__(self, llm_provider: LLMProvider, scanner: Scanner):
        super().__init__("APISecurityAgent", "api_specialist", "api", llm_provider, scanner)
        self.api_endpoints_tested = []
        self.rate_limit_attempts = {}
    
    def _get_system_prompt(self) -> str:
        """Get the system prompt for API security testing."""
        return """
        You are an API Security specialist. Your job is to identify and exploit API vulnerabilities in web applications.
        
        Focus on testing:
        1. Broken Authentication
           - Missing or weak API key validation
           - JWT token vulnerabilities (weak secrets, algorithm confusion, missing expiration)
           - Session management issues
           - Default or hardcoded credentials
        
        2. Rate Limiting Issues
           - Missing rate limiting on authentication endpoints
           - Insufficient rate limiting allowing brute force attacks
           - Rate limit bypass techniques (IP rotation headers, different endpoints)
        
        3. Sensitive Data Exposure
           - PII in API responses (emails, phone numbers, SSN)
           - Credentials or tokens in responses
           - Internal IDs or database information exposed
           - Debug information in production
        
        4. Missing Security Headers
           - CORS misconfigurations (wildcard origins, credentials with wildcard)
           - Missing Content-Type validation
           - Missing security headers (X-Content-Type-Options, etc.)
        
        5. Mass Assignment
           - Unprotected fields that can be modified (roles, permissions, prices)
           - Hidden fields that accept user input
        
        6. Improper Error Handling
           - Stack traces in error responses
           - Database errors exposing schema information
           - Verbose error messages revealing implementation details
        
        You have access to specialized API testing tools and browser interaction tools:
        
        API SECURITY TOOLS:
        - test_api_auth: Test API authentication mechanisms
        - check_rate_limiting: Test rate limiting on an endpoint
        - scan_api_response: Analyze API response for sensitive data
        - test_cors_config: Test CORS configuration
        
        BROWSER INTERACTION TOOLS:
        - goto: Navigate to a URL
        - click: Click an element on the page
        - fill: Fill a form field with a value
        - submit: Submit a form
        - execute_js: Execute JavaScript on the page (useful for API calls)
        
        Common API vulnerabilities to look for:
        - API endpoints without authentication
        - Missing or misconfigured CORS headers
        - Sensitive data in error messages
        - JWT tokens that can be manipulated
        - Rate limiting that can be bypassed
        - API versioning exposing deprecated vulnerable endpoints
        - GraphQL introspection enabled in production
        
        When testing APIs:
        1. First identify API endpoints from page content and network traffic
        2. Test authentication on discovered endpoints
        3. Check for rate limiting on sensitive endpoints
        4. Analyze responses for sensitive data exposure
        5. Test CORS configuration if applicable
        """
    
    def _check_for_vulnerabilities(self, tool_name: str, tool_result: Dict[str, Any], 
                                   result: Dict[str, Any], page: Page, tool_call: Any) -> Dict[str, Any]:
        """Check for API security vulnerabilities in tool results."""
        logger = get_logger()
        
        # Check for API authentication issues
        if tool_result.get("api_auth_issue", False):
            result["vulnerability_found"] = True
            result["vulnerability_type"] = "Broken API Authentication"
            result["severity"] = tool_result.get("severity", "high")
            result["details"] = tool_result
            
            logger.security(f"Found API authentication vulnerability: {tool_result.get('issue_type', 'Unknown issue')}")
        
        # Check for rate limiting issues
        elif tool_name == "check_rate_limiting" or tool_result.get("rate_limit_issue", False):
            if not tool_result.get("rate_limited", True):
                result["vulnerability_found"] = True
                result["vulnerability_type"] = "Missing Rate Limiting"
                result["severity"] = "medium"
                result["details"] = {
                    "issue_type": "Missing Rate Limiting",
                    "url": page.url,
                    "requests_sent": tool_result.get("requests_sent", 0),
                    "evidence": "Endpoint does not implement rate limiting"
                }
                
                logger.security(f"Found missing rate limiting vulnerability")
        
        # Check for sensitive data in API responses
        elif tool_name == "scan_api_response" or self._is_api_response(tool_result):
            sensitive_patterns = self._check_sensitive_data(tool_result)
            if sensitive_patterns:
                result["vulnerability_found"] = True
                result["vulnerability_type"] = "Sensitive Data Exposure in API"
                result["severity"] = "high"
                result["details"] = {
                    "issue_type": "Sensitive Data Exposure",
                    "url": page.url,
                    "sensitive_patterns_found": sensitive_patterns,
                    "evidence": "API response contains sensitive data"
                }
                
                logger.security(f"Found sensitive data exposure in API response")
        
        # Check for CORS misconfigurations
        elif tool_name == "test_cors_config" or tool_result.get("cors_issue", False):
            cors_issues = self._check_cors_issues(tool_result)
            if cors_issues:
                result["vulnerability_found"] = True
                result["vulnerability_type"] = "CORS Misconfiguration"
                result["severity"] = cors_issues.get("severity", "medium")
                result["details"] = {
                    "issue_type": "CORS Misconfiguration",
                    "url": page.url,
                    "issues": cors_issues.get("issues", []),
                    "headers": tool_result.get("cors_headers", {}),
                    "evidence": "API has CORS misconfiguration allowing potential cross-origin attacks"
                }
                
                logger.security(f"Found CORS misconfiguration")
        
        # Check for improper error handling via JavaScript execution
        elif tool_name == "execute_js":
            error_issues = self._check_error_handling(tool_result, page)
            if error_issues:
                result["vulnerability_found"] = True
                result["vulnerability_type"] = "Improper API Error Handling"
                result["severity"] = "medium"
                result["details"] = error_issues
                
                logger.security(f"Found improper error handling in API")
        
        # Check for security headers in goto/navigation results
        elif tool_name in ["goto", "submit"]:
            header_issues = self._check_api_security_headers(page)
            if header_issues:
                result["vulnerability_found"] = True
                result["vulnerability_type"] = "Missing API Security Headers"
                result["severity"] = "low"
                result["details"] = {
                    "issue_type": "Missing Security Headers",
                    "url": page.url,
                    "missing_headers": header_issues,
                    "evidence": "API responses missing recommended security headers"
                }
                
                logger.security(f"Found missing API security headers")
            
            # Also check for API endpoints in the page content
            api_endpoints = self._discover_api_endpoints(page)
            if api_endpoints and not self._has_tested_endpoints(api_endpoints):
                # Store discovered endpoints for later testing
                self.api_endpoints_tested.extend(api_endpoints)
                result["details"]["discovered_endpoints"] = api_endpoints
        
        # Check for mass assignment vulnerabilities in form submissions
        elif tool_name == "fill" and self._is_api_form(page):
            mass_assignment_check = self._check_mass_assignment(tool_call, tool_result)
            if mass_assignment_check:
                result["vulnerability_found"] = True
                result["vulnerability_type"] = "Mass Assignment Vulnerability"
                result["severity"] = "high"
                result["details"] = mass_assignment_check
                
                logger.security(f"Found mass assignment vulnerability")
        
        return result
    
    def _is_api_response(self, tool_result: Dict[str, Any]) -> bool:
        """Check if the tool result appears to be from an API response."""
        if not isinstance(tool_result, dict):
            return False
        
        # Look for common API response indicators
        api_indicators = ["data", "results", "response", "items", "payload", "body"]
        return any(key in tool_result for key in api_indicators)
    
    def _check_sensitive_data(self, tool_result: Dict[str, Any]) -> list:
        """Check for sensitive data patterns in API response."""
        sensitive_patterns = []
        result_str = json.dumps(tool_result) if isinstance(tool_result, dict) else str(tool_result)
        result_lower = result_str.lower()
        
        # Email patterns
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        if re.search(email_pattern, result_str):
            sensitive_patterns.append("email_addresses")
        
        # Phone number patterns
        phone_pattern = r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'
        if re.search(phone_pattern, result_str):
            sensitive_patterns.append("phone_numbers")
        
        # SSN patterns
        ssn_pattern = r'\b\d{3}-\d{2}-\d{4}\b'
        if re.search(ssn_pattern, result_str):
            sensitive_patterns.append("ssn")
        
        # Credit card patterns
        cc_pattern = r'\b(?:\d{4}[-\s]?){3}\d{4}\b'
        if re.search(cc_pattern, result_str):
            sensitive_patterns.append("credit_card_numbers")
        
        # API keys and tokens
        if any(key in result_lower for key in ["api_key", "apikey", "api-key", "secret_key", "secretkey", 
                                                 "access_token", "accesstoken", "private_key", "privatekey",
                                                 "bearer", "authorization"]):
            sensitive_patterns.append("api_keys_or_tokens")
        
        # Passwords
        if any(key in result_lower for key in ["password", "passwd", "pwd", "secret"]):
            # Only flag if there appears to be an actual password value
            if re.search(r'["\']?(password|passwd|pwd|secret)["\']?\s*[:=]\s*["\']?[^"\'\s,}]+', result_lower):
                sensitive_patterns.append("passwords")
        
        # Database information
        if any(key in result_lower for key in ["_id", "objectid", "primary_key", "foreign_key", 
                                                 "table_name", "column_name", "database"]):
            sensitive_patterns.append("database_information")
        
        # Internal IP addresses
        internal_ip_pattern = r'\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b'
        if re.search(internal_ip_pattern, result_str):
            sensitive_patterns.append("internal_ip_addresses")
        
        # Stack traces
        if any(trace in result_lower for trace in ["traceback", "stack trace", "exception", 
                                                     "at line", "file \"", "in <module>"]):
            sensitive_patterns.append("stack_traces")
        
        return sensitive_patterns
    
    def _check_cors_issues(self, tool_result: Dict[str, Any]) -> Dict[str, Any]:
        """Check for CORS misconfigurations."""
        issues = []
        severity = "low"
        
        cors_headers = tool_result.get("cors_headers", {})
        if not cors_headers and isinstance(tool_result, dict):
            cors_headers = tool_result
        
        # Check for wildcard origin
        acao = cors_headers.get("access-control-allow-origin", "").lower()
        if acao == "*":
            issues.append("Wildcard origin allowed (Access-Control-Allow-Origin: *)")
            severity = "medium"
        
        # Check for credentials with wildcard
        acac = cors_headers.get("access-control-allow-credentials", "").lower()
        if acac == "true" and acao == "*":
            issues.append("Credentials allowed with wildcard origin - critical misconfiguration")
            severity = "critical"
        
        # Check for reflected origin (potential)
        if "reflected" in str(tool_result).lower():
            issues.append("Origin header appears to be reflected - potential CORS bypass")
            severity = "high"
        
        # Check for null origin allowed
        if acao == "null":
            issues.append("Null origin allowed - potential sandbox bypass")
            severity = "medium"
        
        # Check for overly permissive methods
        acam = cors_headers.get("access-control-allow-methods", "")
        if any(method in acam.upper() for method in ["DELETE", "PUT", "PATCH"]):
            if acao == "*" or acac == "true":
                issues.append(f"Dangerous methods allowed with permissive CORS: {acam}")
                severity = "high" if severity != "critical" else severity
        
        if issues:
            return {"issues": issues, "severity": severity}
        return None
    
    def _check_error_handling(self, tool_result: Dict[str, Any], page: Page) -> Dict[str, Any]:
        """Check for improper error handling in API responses."""
        result_str = str(tool_result)
        issues = []
        
        # Check for stack traces
        stack_trace_indicators = [
            "Traceback (most recent call last)",
            "at Object.",
            "at Module.",
            "at Function.",
            "Exception in thread",
            "java.lang.",
            "System.Exception",
            "php error",
            "Fatal error:",
            "Warning: ",
            "Parse error:",
        ]
        
        for indicator in stack_trace_indicators:
            if indicator.lower() in result_str.lower():
                issues.append(f"Stack trace detected: {indicator}")
        
        # Check for database errors
        db_error_indicators = [
            "SQL syntax",
            "mysql_",
            "mysqli_",
            "pg_query",
            "ORA-",
            "SQLite",
            "MongoDB",
            "SQLSTATE",
        ]
        
        for indicator in db_error_indicators:
            if indicator.lower() in result_str.lower():
                issues.append(f"Database error message detected: {indicator}")
        
        # Check for verbose error messages with paths
        path_pattern = r'[/\\](?:var|usr|home|app|src|www)[/\\][^\s"\'<>]+'
        if re.search(path_pattern, result_str):
            issues.append("Server file paths exposed in error message")
        
        if issues:
            return {
                "issue_type": "Improper Error Handling",
                "url": page.url,
                "issues": issues,
                "evidence": "API exposes sensitive information in error responses"
            }
        return None
    
    def _check_api_security_headers(self, page: Page) -> list:
        """Check for missing security headers in API responses."""
        missing_headers = []
        
        try:
            # Execute JavaScript to get response headers from the page
            # Note: This only works for the main document, not XHR requests
            headers_script = """
            () => {
                const entries = performance.getEntriesByType('resource');
                const headers = {};
                // Try to get headers from fetch API if available
                return JSON.stringify(document.contentType || 'unknown');
            }
            """
            
            # For API testing, we mainly check common security header patterns
            # These should be present in API responses
            recommended_headers = [
                "X-Content-Type-Options",
                "X-Frame-Options", 
                "Content-Security-Policy",
                "Strict-Transport-Security",
                "X-XSS-Protection",  # Deprecated but still useful for legacy browsers
            ]
            
            # Note: Actual header checking would require intercepting network requests
            # For now, we flag this as a potential issue for manual review
            if "/api/" in page.url or "api." in page.url:
                missing_headers.append("Recommend verifying security headers on API endpoints")
                
        except Exception as e:
            pass
        
        return missing_headers
    
    def _discover_api_endpoints(self, page: Page) -> list:
        """Discover API endpoints from page content."""
        endpoints = []
        
        try:
            # Get page content
            content = page.content()
            
            # Look for API endpoint patterns
            api_patterns = [
                r'["\'](?:https?://[^"\']*)?/api/v?\d*/[^"\']+["\']',
                r'["\'](?:https?://[^"\']*)?/rest/[^"\']+["\']',
                r'["\'](?:https?://[^"\']*)?/graphql["\']',
                r'fetch\s*\(\s*["\'][^"\']+["\']',
                r'axios\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*["\'][^"\']+["\']',
                r'\.ajax\s*\(\s*\{[^}]*url\s*:\s*["\'][^"\']+["\']',
            ]
            
            for pattern in api_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    # Clean up the match
                    endpoint = re.sub(r'^["\']|["\']$', '', match)
                    endpoint = re.sub(r'^(fetch|axios\.\w+|\\.ajax)\s*\(\s*["\']', '', endpoint)
                    if endpoint and endpoint not in endpoints:
                        endpoints.append(endpoint)
            
        except Exception as e:
            pass
        
        return endpoints[:10]  # Limit to 10 endpoints
    
    def _has_tested_endpoints(self, endpoints: list) -> bool:
        """Check if we've already tested these endpoints."""
        return all(ep in self.api_endpoints_tested for ep in endpoints)
    
    def _is_api_form(self, page: Page) -> bool:
        """Check if the current page appears to be an API form/interface."""
        url = page.url.lower()
        return any(indicator in url for indicator in ["/api/", "/rest/", "/graphql", "swagger", "postman"])
    
    def _check_mass_assignment(self, tool_call: Any, tool_result: Dict[str, Any]) -> Dict[str, Any]:
        """Check for mass assignment vulnerability indicators."""
        # Extract field information from tool call
        field_name = ""
        if hasattr(tool_call, 'function') and hasattr(tool_call.function, 'arguments'):
            args = tool_call.function.arguments
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except:
                    args = {}
            field_name = args.get("selector", "")
        
        # Check if the field appears to be a sensitive/protected field
        sensitive_fields = ["role", "admin", "is_admin", "isadmin", "permission", "price", 
                          "discount", "balance", "credit", "verified", "status", "active"]
        
        field_lower = field_name.lower()
        for sensitive in sensitive_fields:
            if sensitive in field_lower:
                return {
                    "issue_type": "Potential Mass Assignment",
                    "field": field_name,
                    "evidence": f"Field '{field_name}' appears to be a sensitive/protected field that may be vulnerable to mass assignment"
                }
        
        return None
