"""
API Security Agent - Tests REST/GraphQL APIs for OWASP API Security Top 10 vulnerabilities.

This agent focuses on:
- BOLA (Broken Object Level Authorization) - API1:2023
- Broken Authentication - API2:2023  
- Broken Object Property Level Authorization - API3:2023
- Unrestricted Resource Consumption - API4:2023
- Broken Function Level Authorization - API5:2023
- Mass Assignment - API6:2023
- Server Side Request Forgery - API7:2023
- Security Misconfiguration - API8:2023
- Improper Inventory Management - API9:2023
- Unsafe Consumption of APIs - API10:2023
"""

from typing import Dict, List, Any, Optional
import json
import re
from urllib.parse import urlparse, urljoin

from agents.security.specialized_agent import SpecializedSecurityAgent
from core.llm import LLMProvider
from core.scanner import Scanner
from utils.logger import get_logger


class APISecurityAgent(SpecializedSecurityAgent):
    """Agent specialized in testing API endpoints for security vulnerabilities."""
    
    # Common API patterns to identify
    API_PATTERNS = [
        r'/api/v\d+/',
        r'/api/',
        r'/rest/',
        r'/graphql',
        r'/v\d+/',
        r'\.json$',
        r'/swagger',
        r'/openapi',
    ]
    
    # Common sensitive endpoints
    SENSITIVE_ENDPOINTS = [
        '/users', '/user', '/account', '/accounts',
        '/admin', '/management', '/config',
        '/orders', '/payments', '/transactions',
        '/files', '/uploads', '/documents',
        '/tokens', '/auth', '/session',
    ]
    
    # BOLA test payloads - try to access other users' resources
    BOLA_PAYLOADS = [
        {'original': '1', 'test': ['2', '0', '-1', '999999', 'admin', '../1']},
        {'original': 'me', 'test': ['1', 'admin', 'other', '*']},
    ]
    
    # Mass assignment test fields
    MASS_ASSIGNMENT_FIELDS = [
        'role', 'isAdmin', 'is_admin', 'admin', 'permissions',
        'verified', 'is_verified', 'active', 'status',
        'balance', 'credits', 'price', 'discount',
        'password', 'email', 'user_id', 'userId',
    ]

    def __init__(self, llm_provider: LLMProvider, scanner: Scanner):
        super().__init__(
            name="APISecurityAgent",
            role="API Security Testing Specialist",
            llm_provider=llm_provider,
            scanner=scanner
        )
        self.logger = get_logger()
        self.discovered_apis = []
        self.vulnerabilities = []

    def get_system_prompt(self) -> str:
        return """You are an expert API security tester specializing in the OWASP API Security Top 10.

Your responsibilities:
1. Identify API endpoints from page content, JavaScript, and network traffic
2. Test for BOLA (Broken Object Level Authorization) by manipulating resource IDs
3. Test for Broken Authentication by checking token handling
4. Test for Mass Assignment by adding unexpected fields to requests
5. Test for Security Misconfiguration in API responses
6. Check for sensitive data exposure in API responses
7. Identify GraphQL-specific vulnerabilities if applicable

When testing:
- Always try to escalate privileges or access unauthorized resources
- Look for patterns like /api/v1/users/{id} and try different IDs
- Check if authentication can be bypassed
- Look for verbose error messages that leak information
- Test rate limiting and resource consumption limits

Report findings with:
- Vulnerability type (OWASP API category)
- Affected endpoint
- Proof of concept request/response
- Severity assessment
- Remediation recommendations"""

    def analyze(self, url: str, page, page_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Main entry point for API security analysis."""
        self.logger.security(f"APISecurityAgent: Starting API security analysis on {url}")
        
        vulnerabilities = []
        
        # Step 1: Discover API endpoints
        api_endpoints = self._discover_api_endpoints(url, page_info)
        self.logger.info(f"Discovered {len(api_endpoints)} potential API endpoints")
        
        if not api_endpoints:
            self.logger.info("No API endpoints discovered, checking for common paths")
            api_endpoints = self._probe_common_api_paths(url)
        
        # Step 2: Analyze each endpoint
        for endpoint in api_endpoints:
            self.logger.debug(f"Testing API endpoint: {endpoint}")
            
            # Test for various API vulnerabilities
            bola_vulns = self._test_bola(endpoint, page_info)
            vulnerabilities.extend(bola_vulns)
            
            auth_vulns = self._test_broken_auth(endpoint, page_info)
            vulnerabilities.extend(auth_vulns)
            
            mass_assignment_vulns = self._test_mass_assignment(endpoint, page_info)
            vulnerabilities.extend(mass_assignment_vulns)
            
            misconfig_vulns = self._test_security_misconfiguration(endpoint, page_info)
            vulnerabilities.extend(misconfig_vulns)
        
        # Step 3: Check for GraphQL specific issues
        graphql_vulns = self._test_graphql_security(url, page_info)
        vulnerabilities.extend(graphql_vulns)
        
        # Step 4: Use LLM to analyze findings and suggest additional tests
        if vulnerabilities or api_endpoints:
            llm_analysis = self._llm_deep_analysis(url, api_endpoints, vulnerabilities, page_info)
            vulnerabilities.extend(llm_analysis)
        
        self.logger.security(f"APISecurityAgent: Found {len(vulnerabilities)} potential vulnerabilities")
        return vulnerabilities

    def _discover_api_endpoints(self, url: str, page_info: Dict[str, Any]) -> List[str]:
        """Discover API endpoints from page content and JavaScript."""
        endpoints = set()
        base_url = urlparse(url)
        
        # Check page HTML for API references
        html_content = page_info.get('html', '')
        
        # Look for API URLs in HTML
        url_pattern = r'["\']((https?://[^"\']+|/[^"\']*api[^"\']*|/v\d+/[^"\']+))["\']'
        matches = re.findall(url_pattern, html_content, re.IGNORECASE)
        for match in matches:
            endpoint = match[0] if isinstance(match, tuple) else match
            if any(re.search(pattern, endpoint, re.IGNORECASE) for pattern in self.API_PATTERNS):
                if endpoint.startswith('/'):
                    endpoint = f"{base_url.scheme}://{base_url.netloc}{endpoint}"
                endpoints.add(endpoint)
        
        # Check JavaScript files for API calls
        scripts = page_info.get('scripts', [])
        for script in scripts:
            script_content = script.get('content', '')
            # Look for fetch/axios/XMLHttpRequest patterns
            api_patterns = [
                r'fetch\s*\(\s*["\']([^"\']+)["\']',
                r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',
                r'\.ajax\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']',
                r'XMLHttpRequest[^;]*\.open\s*\([^,]+,\s*["\']([^"\']+)["\']',
            ]
            for pattern in api_patterns:
                matches = re.findall(pattern, script_content, re.IGNORECASE)
                for endpoint in matches:
                    if endpoint.startswith('/'):
                        endpoint = f"{base_url.scheme}://{base_url.netloc}{endpoint}"
                    endpoints.add(endpoint)
        
        # Check network traffic if available
        traffic = page_info.get('network_traffic', [])
        for request in traffic:
            req_url = request.get('url', '')
            if any(re.search(pattern, req_url, re.IGNORECASE) for pattern in self.API_PATTERNS):
                endpoints.add(req_url)
        
        return list(endpoints)

    def _probe_common_api_paths(self, url: str) -> List[str]:
        """Probe for common API paths when none are discovered."""
        base_url = urlparse(url)
        base = f"{base_url.scheme}://{base_url.netloc}"
        
        common_paths = [
            '/api', '/api/v1', '/api/v2',
            '/graphql', '/graphql/v1',
            '/rest', '/rest/v1',
            '/swagger.json', '/openapi.json', '/api-docs',
        ]
        
        discovered = []
        for path in common_paths:
            test_url = urljoin(base, path)
            # Note: In production, we would actually probe these endpoints
            # For now, we add them as candidates for testing
            discovered.append(test_url)
        
        return discovered

    def _test_bola(self, endpoint: str, page_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for Broken Object Level Authorization (BOLA/IDOR in APIs)."""
        vulnerabilities = []
        
        # Look for ID patterns in the endpoint
        id_patterns = [
            (r'/(\d+)(?:/|$)', 'numeric'),
            (r'/([a-f0-9-]{36})(?:/|$)', 'uuid'),
            (r'/([a-zA-Z0-9_-]+)(?:/|$)', 'string'),
        ]
        
        for pattern, id_type in id_patterns:
            match = re.search(pattern, endpoint)
            if match:
                original_id = match.group(1)
                self.logger.debug(f"Found {id_type} ID in endpoint: {original_id}")
                
                # Generate test IDs
                if id_type == 'numeric':
                    test_ids = ['1', '2', '0', '-1', str(int(original_id) + 1), str(int(original_id) - 1)]
                elif id_type == 'uuid':
                    test_ids = ['00000000-0000-0000-0000-000000000000', '11111111-1111-1111-1111-111111111111']
                else:
                    test_ids = ['admin', 'test', '1', 'null', '../' + original_id]
                
                # Note: In production implementation, we would make actual requests
                # and compare responses to detect BOLA
                vulnerabilities.append({
                    'vulnerability_type': 'BOLA (API1:2023)',
                    'severity': 'high',
                    'target': endpoint,
                    'description': f'Potential BOLA vulnerability - endpoint contains {id_type} ID that should be tested for unauthorized access',
                    'test_payload': f'Replace {original_id} with {test_ids}',
                    'evidence': f'ID pattern detected: {original_id}',
                    'remediation': 'Implement proper authorization checks that validate the requesting user has access to the requested resource',
                    'validated': False,
                    'owasp_category': 'API1:2023 - Broken Object Level Authorization'
                })
                break
        
        return vulnerabilities

    def _test_broken_auth(self, endpoint: str, page_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for Broken Authentication vulnerabilities."""
        vulnerabilities = []
        
        # Check if endpoint might handle authentication
        auth_keywords = ['auth', 'login', 'token', 'session', 'jwt', 'oauth']
        if any(keyword in endpoint.lower() for keyword in auth_keywords):
            vulnerabilities.append({
                'vulnerability_type': 'Broken Authentication (API2:2023)',
                'severity': 'high',
                'target': endpoint,
                'description': 'Authentication endpoint detected - should be tested for weak password policies, credential stuffing, and token vulnerabilities',
                'test_payload': 'Test with weak passwords, expired tokens, manipulated JWTs',
                'evidence': 'Authentication-related endpoint pattern detected',
                'remediation': 'Implement rate limiting, strong password policies, secure token handling, and account lockout mechanisms',
                'validated': False,
                'owasp_category': 'API2:2023 - Broken Authentication'
            })
        
        return vulnerabilities

    def _test_mass_assignment(self, endpoint: str, page_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for Mass Assignment vulnerabilities."""
        vulnerabilities = []
        
        # Check if endpoint likely accepts POST/PUT/PATCH data
        data_endpoints = ['user', 'account', 'profile', 'setting', 'update', 'create', 'register']
        if any(keyword in endpoint.lower() for keyword in data_endpoints):
            vulnerabilities.append({
                'vulnerability_type': 'Mass Assignment (API6:2023)',
                'severity': 'medium',
                'target': endpoint,
                'description': 'Endpoint may accept user input - test for mass assignment by adding privileged fields',
                'test_payload': f'Add fields: {", ".join(self.MASS_ASSIGNMENT_FIELDS[:5])}',
                'evidence': 'Data modification endpoint pattern detected',
                'remediation': 'Use allowlists for acceptable input fields, implement proper input validation',
                'validated': False,
                'owasp_category': 'API6:2023 - Mass Assignment'
            })
        
        return vulnerabilities

    def _test_security_misconfiguration(self, endpoint: str, page_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for Security Misconfiguration."""
        vulnerabilities = []
        
        # Check for exposed documentation/debug endpoints
        debug_patterns = ['swagger', 'openapi', 'api-docs', 'debug', 'test', 'dev']
        if any(pattern in endpoint.lower() for pattern in debug_patterns):
            vulnerabilities.append({
                'vulnerability_type': 'Security Misconfiguration (API8:2023)',
                'severity': 'medium',
                'target': endpoint,
                'description': 'Potentially sensitive API documentation or debug endpoint exposed',
                'test_payload': 'Access endpoint to check for sensitive information disclosure',
                'evidence': 'Debug/documentation endpoint pattern detected',
                'remediation': 'Disable or protect API documentation and debug endpoints in production',
                'validated': False,
                'owasp_category': 'API8:2023 - Security Misconfiguration'
            })
        
        return vulnerabilities

    def _test_graphql_security(self, url: str, page_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for GraphQL-specific security issues."""
        vulnerabilities = []
        
        # Check if GraphQL is in use
        html_content = page_info.get('html', '')
        scripts = page_info.get('scripts', [])
        
        graphql_indicators = ['graphql', 'gql', '__schema', '__typename', 'query {', 'mutation {']
        
        is_graphql = any(
            indicator in html_content.lower() or
            any(indicator in str(s.get('content', '')).lower() for s in scripts)
            for indicator in graphql_indicators
        )
        
        if is_graphql:
            # Test for introspection
            vulnerabilities.append({
                'vulnerability_type': 'GraphQL Introspection Enabled',
                'severity': 'low',
                'target': url,
                'description': 'GraphQL detected - introspection may be enabled allowing schema discovery',
                'test_payload': '{ __schema { types { name } } }',
                'evidence': 'GraphQL indicators found in page content',
                'remediation': 'Disable introspection in production, implement query depth limiting',
                'validated': False,
                'owasp_category': 'API8:2023 - Security Misconfiguration'
            })
            
            # Test for query complexity attacks
            vulnerabilities.append({
                'vulnerability_type': 'GraphQL Query Complexity',
                'severity': 'medium',
                'target': url,
                'description': 'GraphQL endpoint should be tested for query complexity/depth attacks',
                'test_payload': 'Deeply nested queries to test for DoS',
                'evidence': 'GraphQL indicators found in page content',
                'remediation': 'Implement query depth limiting, complexity analysis, and rate limiting',
                'validated': False,
                'owasp_category': 'API4:2023 - Unrestricted Resource Consumption'
            })
        
        return vulnerabilities

    def _llm_deep_analysis(self, url: str, endpoints: List[str], 
                          current_vulns: List[Dict], page_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Use LLM for deeper API security analysis."""
        
        prompt = f"""Analyze the following API security assessment data and identify any additional vulnerabilities I may have missed.

Target URL: {url}

Discovered API Endpoints:
{json.dumps(endpoints[:20], indent=2)}

Current Findings:
{json.dumps([{'type': v['vulnerability_type'], 'target': v['target']} for v in current_vulns[:10]], indent=2)}

Page Info Summary:
- Forms found: {len(page_info.get('forms', []))}
- Scripts found: {len(page_info.get('scripts', []))}
- Links found: {len(page_info.get('links', []))}

Based on the OWASP API Security Top 10 (2023), identify:
1. Any additional API endpoints that should be tested
2. Specific attack vectors based on the endpoint patterns
3. Additional security tests that should be performed
4. Risk assessment and prioritization

Respond in JSON format with a list of additional findings."""

        try:
            response = self.llm_provider.chat_completion(
                messages=[
                    {"role": "system", "content": self.get_system_prompt()},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3
            )
            
            # Parse LLM response for additional findings
            content = response.get('content', '')
            
            # Try to extract JSON from response
            json_match = re.search(r'\[[\s\S]*\]', content)
            if json_match:
                try:
                    additional_findings = json.loads(json_match.group())
                    # Convert to our vulnerability format
                    formatted_vulns = []
                    for finding in additional_findings:
                        if isinstance(finding, dict):
                            formatted_vulns.append({
                                'vulnerability_type': finding.get('type', 'API Security Issue'),
                                'severity': finding.get('severity', 'medium'),
                                'target': finding.get('target', url),
                                'description': finding.get('description', 'LLM-identified API security issue'),
                                'evidence': finding.get('evidence', 'Identified by AI analysis'),
                                'remediation': finding.get('remediation', 'Review and address the identified issue'),
                                'validated': False,
                                'llm_identified': True
                            })
                    return formatted_vulns
                except json.JSONDecodeError:
                    pass
            
        except Exception as e:
            self.logger.warning(f"LLM analysis failed: {str(e)}")
        
        return []
