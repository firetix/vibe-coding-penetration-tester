from typing import Dict, Any, List
from playwright.sync_api import Page
import re
from urllib.parse import urlparse, parse_qs

from core.llm import LLMProvider
from core.scanner import Scanner
from agents.security.specialized_agent import SpecializedSecurityAgent
from utils.logger import get_logger


class SSRFAgent(SpecializedSecurityAgent):
    """Agent specializing in Server-Side Request Forgery testing."""
    
    def __init__(self, llm_provider: LLMProvider, scanner: Scanner):
        super().__init__("SSRFAgent", "ssrf_specialist", "ssrf", llm_provider, scanner)
        self.observed_url_parameters = set()
        self.observed_file_uploads = set()
        self.observed_api_endpoints = set()
        self.potential_ssrf_endpoints = []
    
    def _get_system_prompt(self) -> str:
        """Get the system prompt for SSRF testing."""
        return """
        You are a Server-Side Request Forgery (SSRF) security specialist. Your job is to identify and exploit SSRF vulnerabilities in web applications.
        
        # What is SSRF?
        Server-Side Request Forgery (SSRF) is a vulnerability where an attacker can induce a server to make requests to unintended locations. This happens when an application fetches remote resources based on user-provided input without proper validation.
        
        # Key patterns to look for:
        1. URL parameters or input fields that might fetch remote content (e.g., ?url=, ?file=, ?path=, ?document=, ?resource=)
        2. API endpoints for data import/export or resource retrieval
        3. File upload/download functionality that processes remote URLs
        4. PDF generators, image processors, or document converters that fetch remote content
        5. Webhooks or callback configurations
        6. Proxy or gateway functionalities
        7. Preview or thumbnail generation from URLs
        8. Form fields that accept URLs (import functionality, linking, sharing, etc.)
        
        # Testing methodology:
        1. Identify potential SSRF entry points by looking for URL parameters, API endpoints, or forms that handle URLs
        2. Begin with simple tests using localhost/127.0.0.1 to see if requests are made internally
        3. Try different bypass techniques if basic tests are blocked
        4. Use cloud-metadata specific payloads when testing cloud-hosted applications
        5. Test for blind SSRF using external callback servers
        6. Check both GET and POST parameters
        
        # Common SSRF vectors in popular web applications:
        - E-commerce platforms: Product imports, image URLs, webhooks, tracking integrations
        - Content Management Systems: Media imports, remote content embedding, RSS feeds
        - Project Management Tools: File attachments, external integrations, webhook configurations
        - Developer Tools: Repository imports, CI/CD integrations, webhook configurations
        
        # OWASP Juice Shop SSRF patterns:
        - Track order functionality that might process external URLs
        - Product image URLs that could be manipulated
        - B2B customer and supplier integrations
        - Delivery tracking features
        - Coupon redemption systems that may validate against external services
        
        # Testing tools available to you:
        
        SSRF TOOLS:
        - test_ssrf_vulnerability: Test if a specific endpoint is vulnerable to SSRF
        - generate_ssrf_payloads: Generate various SSRF payloads for different targets
        
        BROWSER INTERACTION TOOLS:
        - goto: Navigate to a URL
        - click: Click an element on the page
        - fill: Fill a form field with a value
        - submit: Submit a form
        - execute_js: Execute JavaScript on the page
        
        # Common SSRF payloads to test:
        - Internal services: http://localhost/, http://127.0.0.1/, http://0.0.0.0/
        - Cloud metadata: http://169.254.169.254/ (AWS), http://metadata.google.internal/ (GCP)
        - File access: file:///etc/passwd
        - Protocol smuggling: gopher://, dict://, ftp://, ldap://
        - IP encoding bypass: http://0177.0.0.1/, http://2130706433/, http://0x7f.0x0.0x0.0x1/
        - DNS rebinding: http://attacker-controlled-domain/ (which resolves to internal IP)
        
        # Validation techniques:
        1. Check if the application makes requests to the provided URLs
        2. Look for evidence in responses that internal systems were accessed
        3. Use external callback servers to confirm blind SSRF
        4. Check for error messages that might reveal successful internal connections
        5. Observe timing differences that might indicate successful connections
        
        Always document your findings clearly, including the injection point, payload used, and evidence of the vulnerability.
        """
    
    def _initialize_scan(self, page: Page) -> None:
        """Initialize scan-specific data structures."""
        super()._initialize_scan(page)
        self.observed_url_parameters = set()
        self.observed_file_uploads = set()
        self.observed_api_endpoints = set()
        self.potential_ssrf_endpoints = []
        
        # Add initial context for SSRF detection
        current_url = page.url
        self._analyze_url_for_potential_ssrf(current_url)
    
    def _analyze_url_for_potential_ssrf(self, url: str) -> None:
        """Analyze URL for potential SSRF entry points."""
        logger = get_logger()
        
        # Parse the URL
        parsed_url = urlparse(url)
        
        # Check for API endpoints that might handle external resources
        path = parsed_url.path.lower()
        api_patterns = [
            r'/api/.*/(fetch|proxy|import|export|url|resource|webhook|callback|remote|external)',
            r'/(fetch|proxy|import|export|webhook|callback|preview|thumbnail)',
            r'/(load|render|generate|convert).*\.(pdf|image|doc)',
            r'/track(ing)?/',
            r'/(product|order|delivery)/.*/(track|status)'
        ]
        
        for pattern in api_patterns:
            if re.search(pattern, path):
                self.observed_api_endpoints.add(path)
                self.potential_ssrf_endpoints.append({
                    "url": url,
                    "type": "api_endpoint",
                    "pattern": pattern,
                    "confidence": "medium"
                })
                logger.info(f"Identified potential SSRF API endpoint: {path}")
        
        # Check for URL parameters that might be used for SSRF
        query_params = parse_qs(parsed_url.query)
        ssrf_param_patterns = [
            'url', 'uri', 'link', 'src', 'source', 'path', 'file', 'document',
            'resource', 'redirect', 'return', 'return_to', 'next', 'target',
            'callback', 'webhook', 'api', 'proxy', 'fetch', 'load', 'import',
            'export', 'upload', 'preview', 'thumbnail', 'image', 'media',
            'download', 'remote', 'external', 'address', 'endpoint'
        ]
        
        for param in query_params:
            param_lower = param.lower()
            for pattern in ssrf_param_patterns:
                if pattern in param_lower:
                    self.observed_url_parameters.add(param)
                    self.potential_ssrf_endpoints.append({
                        "url": url,
                        "type": "url_parameter",
                        "parameter": param,
                        "value": query_params[param][0],
                        "confidence": "high"
                    })
                    logger.info(f"Identified potential SSRF parameter: {param}={query_params[param][0]}")
    
    def _check_for_vulnerabilities(self, tool_name: str, tool_result: Dict[str, Any], 
                                  result: Dict[str, Any], page: Page, tool_call: Any) -> Dict[str, Any]:
        """Check for SSRF vulnerabilities in tool results."""
        logger = get_logger()
        
        # Update SSRF detection context based on tool usage
        if tool_name == "goto":
            url = self._extract_action_data(tool_name, tool_call)
            self._analyze_url_for_potential_ssrf(url)
        
        # Check for direct SSRF issues reported by tools
        if tool_result.get("ssrf_found", False):
            result["vulnerability_found"] = True
            result["vulnerability_type"] = "Server-Side Request Forgery (SSRF)"
            result["severity"] = tool_result.get("severity", "high")
            result["details"] = tool_result
            
            logger.security(f"Found SSRF vulnerability via {tool_result.get('injection_point', '')}")
        
        # Check if form fills or URL navigation might be part of SSRF testing
        elif tool_name in ["fill", "goto", "submit"] and tool_result.get("success", False):
            # Extract the action data from the tool call
            action_data = self._extract_action_data(tool_name, tool_call)
            
            # Enhanced SSRF indicators with obfuscation techniques
            ssrf_indicators = [
                # Basic internal targets
                "localhost", "127.0.0.1", "0.0.0.0", "::1",
                # File access
                "file://", "file:/", "file:",
                # Cloud metadata
                "169.254.169.254", "metadata.google", "instance-data", 
                "meta-data", "computeMetadata", "metadata.azure", "100.100.100.200",
                # IP obfuscation
                "0177.0.0.1", "2130706433", "0x7f.0x0.0x0.0x1", "127.1",
                # Protocol handlers
                "gopher://", "dict://", "ftp://", "ldap://",
                # Bypass techniques
                "%00", "%2e%2e%2f", "%252e", "..."
            ]
            
            if isinstance(action_data, str) and any(indicator in str(action_data).lower() for indicator in ssrf_indicators):
                # This might be a SSRF test, but we need to wait for the actual response
                result["details"]["suspected_ssrf_test"] = {
                    "tool": tool_name,
                    "payload": action_data,
                    "timestamp": tool_result.get("timestamp", "")
                }
                logger.info(f"Potential SSRF payload detected: {action_data}")
            
            # Also check for URL parameters that might be used for SSRF
            if tool_name == "fill":
                field_name = self._extract_field_name(tool_call)
                if field_name:
                    for pattern in ["url", "uri", "link", "src", "source", "webhook", "callback", "import"]:
                        if pattern in field_name.lower():
                            logger.info(f"Identified potential SSRF input field: {field_name} with value: {action_data}")
                            self.potential_ssrf_endpoints.append({
                                "url": page.url,
                                "type": "input_field",
                                "field_name": field_name,
                                "confidence": "medium"
                            })
        
        # Additional check for JSON data in responses that might indicate successful SSRF
        if "response" in result and result.get("response", {}).get("content"):
            content = result["response"]["content"].lower()
            
            # Look for JSON-like content with internal IP addresses or system information
            internal_ip_indicators = [
                "\"host\"", "\"ip\"", "\"address\"", "\"internal\"", "\"private\"",
                "\"10.0.", "\"172.16.", "\"192.168.", "\"127.0.0"
            ]
            
            if any(indicator in content for indicator in internal_ip_indicators) and "suspected_ssrf_test" in result.get("details", {}):
                suspected_test = result["details"]["suspected_ssrf_test"]
                result["vulnerability_found"] = True
                result["vulnerability_type"] = "Server-Side Request Forgery (SSRF)"
                result["severity"] = "high"
                result["details"] = {
                    "issue_type": "Server-Side Request Forgery (SSRF)",
                    "url": page.url,
                    "injection_point": suspected_test["tool"],
                    "payload": suspected_test["payload"],
                    "evidence": f"Response contains internal network information: {content}"
                }
                
                logger.security(f"Found SSRF vulnerability via JSON response with internal information")
        
        return result
    
    def _extract_field_name(self, tool_call: Any) -> str:
        """Extract field name from a fill tool call."""
        if hasattr(tool_call, 'function') and hasattr(tool_call.function, 'arguments'):
            return getattr(tool_call.function.arguments, 'selector', "")
        field_data = tool_call.get('function', {}).get('arguments', {}).get("selector", "")
        
        # Try to extract input name from selector
        if field_data and isinstance(field_data, str):
            name_match = re.search(r'name="([^"]+)"', field_data)
            if name_match:
                return name_match.group(1)
            id_match = re.search(r'id="([^"]+)"', field_data)
            if id_match:
                return id_match.group(1)
        
        return field_data
    
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
            
        elif tool_name == "submit":
            # For form submissions, we don't have direct payload data
            # but we can mark it as a potential SSRF point for later investigation
            if hasattr(tool_call, 'function') and hasattr(tool_call.function, 'arguments'):
                return getattr(tool_call.function.arguments, 'selector', "")
            return tool_call.get('function', {}).get('arguments', {}).get("selector", "")
            
        return ""
    
    def _process_followup_response(self, response: Dict[str, Any], result: Dict[str, Any], page: Page) -> None:
        """Check the follow-up response for SSRF evidence."""
        if not response.get("followup_response") or result["vulnerability_found"]:
            return
            
        logger = get_logger()
        followup_content = response["followup_response"].get("content", "").lower()
        
        # Enhanced SSRF indicators in response content
        ssrf_success_indicators = [
            # Direct SSRF indication
            "ssrf vulnerability", "server made a request", "internal service accessed",
            "successful ssrf", "callback received", "accessed internal",
            # System file contents
            "root:x:", "bin:x:", "nobody:x:", "www-data", "apache:", "nginx:",
            # Cloud metadata content
            "\"instanceid\"", "\"region\"", "\"availabilityzone\"", "\"privateip\"",
            "\"ami-id\"", "\"instance-type\"", "\"account-id\"",
            # Internal services
            "\"database\":", "\"redis\":", "\"elasticsearch\":", "\"mongodb\":",
            # Port scanning evidence
            "port 22 is open", "port 3306 is open", "mysql running", "ssh running",
            # Error messages revealing SSRF
            "connection refused", "timeout exceeded", "no route to host", 
            "name resolution", "unknown host",
            # Application-specific evidence
            "internal api key", "secret key", "access key", "private key",
            "environment variables", "configuration file"
        ]
        
        # Also check for HTML content that might indicate successful SSRF
        html_indicators = [
            "<html", "<body", "<title>", "<!doctype", "<head>", 
            "<h1>", "<div", "<span", "<table", "<form"
        ]
        
        # Check if response contains raw HTML when we were testing SSRF
        html_response = any(indicator in followup_content for indicator in html_indicators)
        ssrf_indication = any(indicator in followup_content for indicator in ssrf_success_indicators)
        
        if (ssrf_indication or html_response) and result["details"].get("suspected_ssrf_test"):
            # This appears to be a successful SSRF test
            suspected_test = result["details"]["suspected_ssrf_test"]
            result["vulnerability_found"] = True
            result["vulnerability_type"] = "Server-Side Request Forgery (SSRF)"
            result["severity"] = "high"
            
            # Determine evidence type
            evidence_type = "specific SSRF indicators" if ssrf_indication else "HTML content from internal service"
            
            # Create detailed evidence
            if html_response:
                evidence = "Response contains HTML content from an internal service or external URL"
                if len(followup_content) > 200:
                    evidence += f": {followup_content[:200]}..."
                else:
                    evidence += f": {followup_content}"
            else:
                matching_indicators = [i for i in ssrf_success_indicators if i in followup_content]
                evidence = f"Response contains SSRF indicators: {', '.join(matching_indicators[:3])}"
            
            result["details"] = {
                "issue_type": "Server-Side Request Forgery (SSRF)",
                "url": page.url,
                "injection_point": suspected_test["tool"],
                "payload": suspected_test["payload"],
                "evidence_type": evidence_type,
                "evidence": evidence,
                "recommendation": "Implement proper URL validation and restrict requests to trusted domains only. Consider using allowlist-based approaches rather than blocklists."
            }
            
            logger.security(f"Found SSRF vulnerability via {suspected_test['tool']} with payload: {suspected_test['payload']}")
            
    def _generate_report(self) -> Dict[str, Any]:
        """Generate a report of findings for the scan."""
        basic_report = super()._generate_report()
        
        # Add SSRF-specific context to the report
        if self.potential_ssrf_endpoints:
            if "additional_info" not in basic_report:
                basic_report["additional_info"] = {}
            
            basic_report["additional_info"]["potential_ssrf_endpoints"] = self.potential_ssrf_endpoints
            basic_report["additional_info"]["observed_url_parameters"] = list(self.observed_url_parameters)
            basic_report["additional_info"]["observed_api_endpoints"] = list(self.observed_api_endpoints)
        
        return basic_report