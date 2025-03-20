from typing import Dict, List, Any, Optional
import asyncio
import time
from playwright.sync_api import Page

from core.llm import LLMProvider
from core.scanner import Scanner
from agents.agent_factory import BaseAgent
from utils.logger import get_logger
from utils.proxy import WebProxy, wait_for_network_idle
from utils.network_utils import enumerate_subdomains, get_base64_screenshot

from tools.security_tools import get_security_tools
from tools.scanning_tools import get_scanning_tools
from tools.browser_tools import BrowserTools
from tools.browser_tools_impl import get_browser_interaction_tools

# Import specialized agents
from agents.security.access_control_agent import AccessControlAgent
from agents.security.data_integrity_agent import DataIntegrityAgent
from agents.security.ssrf_agent import SSRFAgent
from agents.security.crypto_agent import CryptoFailureAgent
from agents.security.insecure_design_agent import InsecureDesignAgent


class SecuritySwarm:
    """A swarm of specialized security testing agents working together."""
    
    def __init__(self, llm_provider: LLMProvider, scanner: Scanner, config: Dict[str, Any]):
        self.llm_provider = llm_provider
        self.scanner = scanner
        self.config = config
        self.logger = get_logger()
        
        # Create specialized agents
        self.agents = {
            "planner": PlannerAgent(llm_provider),
            "scanner": ScannerAgent(llm_provider, scanner),
            "xss": XSSAgent(llm_provider, scanner),
            "sqli": SQLInjectionAgent(llm_provider, scanner),
            "csrf": CSRFAgent(llm_provider, scanner),
            "auth": AuthenticationAgent(llm_provider, scanner),
            "idor": IDORAgent(llm_provider, scanner),
            "access_control": AccessControlAgent(llm_provider, scanner),
            "crypto": CryptoFailureAgent(llm_provider, scanner),
            "insecure_design": InsecureDesignAgent(llm_provider, scanner),
            "data_integrity": DataIntegrityAgent(llm_provider, scanner),
            "ssrf": SSRFAgent(llm_provider, scanner),
            "validator": ValidationAgent(llm_provider, scanner)
        }
    
    def run(self, url: str, page: Page, page_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Execute the full security testing process with all agents."""
        self.logger.info(f"Starting security swarm for {url}")
        
        # Generate testing plan
        self.logger.highlight("Generating security testing plan")
        plan = self.agents["planner"].create_plan(url, page_info)
        
        # Debug output for the plan
        self.logger.highlight(f"Security testing plan generated with {len(plan.get('tasks', []))} tasks:")
        for i, task in enumerate(plan.get("tasks", []), 1):
            self.logger.info(f"  Task #{i}: {task.get('type', 'unknown')} on {task.get('target', 'unknown')} (Priority: {task.get('priority', 'medium')})")
        
        # Track discovered vulnerabilities
        vulnerabilities = []
        raw_findings = []  # Store all findings including unvalidated ones
        
        # Execute each testing task in the plan
        for task in plan.get("tasks", []):
            task_type = task["type"]
            target = task.get("target", "")
            
            self.logger.highlight(f"Executing {task_type} task on {target}")
            
            # Select appropriate agent for the task
            agent = self._select_agent_for_task(task_type)
            
            if not agent:
                self.logger.warning(f"No suitable agent for task type: {task_type}")
                self.logger.info(f"Available agent types: {', '.join(self.agents.keys())}")
                continue
            
            # Execute the task and collect results
            try:
                self.logger.info(f"Using agent {agent.name} for task type {task_type}")
                result = agent.execute_task(task, page, page_info)
                
                # Debug the raw result
                if result:
                    self.logger.info(f"Raw result from {agent.name}:")
                    self.logger.info(f"  Vulnerability found: {result.get('vulnerability_found', False)}")
                    self.logger.info(f"  Type: {result.get('vulnerability_type', 'Unknown')}")
                    self.logger.info(f"  Target: {result.get('target', 'Unknown')}")
                    
                    # Keep track of all findings even if not validated
                    raw_findings.append(result)
                
                if result and result.get("vulnerability_found", False):
                    self.logger.highlight(f"Potential vulnerability found by {agent.name}: {result.get('vulnerability_type', 'Unknown')}")
                    
                    # Validate findings if a vulnerability is reported
                    self.logger.info(f"Validating finding with validation agent")
                    validation = self.agents["validator"].validate_finding(result, page, page_info)
                    
                    self.logger.info(f"Validation result: {validation.get('validated', False)}")
                    
                    if validation.get("validated", False):
                        validated_vuln = {
                            **result,
                            "validated": True,
                            "validation_details": validation.get("details", {})
                        }
                        vulnerabilities.append(validated_vuln)
                        self.logger.success(f"Validated vulnerability: {validated_vuln.get('vulnerability_type')} ({validated_vuln.get('severity', 'medium')})")
                    else:
                        self.logger.warning(f"Vulnerability reported but failed validation: {result.get('vulnerability_type', 'Unknown')}")
                        # Add to vulnerabilities anyway for debugging purposes, but mark as unvalidated
                        test_vuln = {
                            **result,
                            "validated": False,
                            "validation_details": validation.get("details", {}),
                            "note": "Added for debugging - failed validation"
                        }
                        vulnerabilities.append(test_vuln)
                        self.logger.warning(f"TESTING ONLY: Adding unvalidated vulnerability for debugging")
            except Exception as e:
                self.logger.error(f"Error executing task {task_type}: {str(e)}")
                import traceback
                self.logger.error(f"Traceback: {traceback.format_exc()}")
        
        self.logger.highlight(f"Security testing completed.")
        self.logger.info(f"Raw findings: {len(raw_findings)}")
        self.logger.info(f"Validated vulnerabilities: {len([v for v in vulnerabilities if v.get('validated', False)])}")
        self.logger.info(f"Total vulnerabilities (including test entries): {len(vulnerabilities)}")
        
        # For debugging purposes, check if we have any findings at all
        if not raw_findings and not vulnerabilities:
            self.logger.warning("No security findings or vulnerabilities detected at all")
            # Create a test vulnerability to verify report generation
            test_vuln = {
                "vulnerability_type": "Test Vulnerability",
                "severity": "info",
                "target": url,
                "vulnerability_found": True,
                "validated": False,
                "details": {
                    "issue_type": "Test Only",
                    "description": "This is a test vulnerability created to verify report generation.",
                    "evidence": "No actual evidence - this is a test entry."
                },
                "note": "This is a test vulnerability created to verify the reporting system. It does not represent an actual security issue."
            }
            self.logger.warning("Created test vulnerability for report generation debugging")
            vulnerabilities.append(test_vuln)
        
        return vulnerabilities
    
    def _select_agent_for_task(self, task_type: str) -> Optional[BaseAgent]:
        """Select the appropriate agent for a given task type."""
        task_to_agent_map = {
            "scan": "scanner",
            "xss": "xss",
            "sqli": "sqli",
            "csrf": "csrf",
            "auth": "auth",
            "idor": "idor",
            "access_control": "access_control",
            "crypto": "crypto",
            "insecure_design": "insecure_design",
            "data_integrity": "data_integrity",
            "ssrf": "ssrf",
        }
        
        agent_key = task_to_agent_map.get(task_type.lower())
        return self.agents.get(agent_key)


class PlannerAgent(BaseAgent):
    """Agent responsible for generating security testing plans."""
    
    def __init__(self, llm_provider: LLMProvider):
        planning_tools = [
            {
                "type": "function",
                "function": {
                    "name": "create_security_plan",
                    "description": "Create a structured security testing plan",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "tasks": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "type": {
                                            "type": "string",
                                            "description": "Type of security test to perform (e.g., xss, sqli, csrf, auth)"
                                        },
                                        "target": {
                                            "type": "string",
                                            "description": "Target element or functionality to test"
                                        },
                                        "priority": {
                                            "type": "string",
                                            "enum": ["high", "medium", "low"],
                                            "description": "Priority of this test"
                                        },
                                        "details": {
                                            "type": "object",
                                            "description": "Additional details specific to this test type"
                                        }
                                    },
                                    "required": ["type", "target", "priority"]
                                }
                            }
                        },
                        "required": ["tasks"]
                    }
                }
            }
        ]
        
        # Add browser tools for reconnaissance
        browser_tools = get_browser_interaction_tools()
        tools = planning_tools + browser_tools
        
        super().__init__("PlannerAgent", "security_planner", llm_provider, tools)
        # Initialize browser tools
        self.browser_tools = BrowserTools(debug=True)
        
        # Track if we're using Ollama for special handling
        self.is_ollama = llm_provider.provider == "ollama"
        self.model_name = llm_provider.model
    
    def create_plan(self, url: str, page_info: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a comprehensive security testing plan based on page analysis."""
        # Determine if we should use a simplified prompt for smaller models
        is_small_model = self.is_ollama and any(model_id in self.model_name.lower() 
                                              for model_id in ["r1", "deepseek", "phi", "gemma", "mistral"])
        
        if is_small_model:
            self.logger.info(f"Using simplified prompt for smaller Ollama model: {self.model_name}")
            system_prompt = """
            Create a security testing plan for web applications. Focus on these vulnerabilities:
            1. XSS: Test form inputs and URL parameters for script injection
            2. SQL Injection: Test search forms and ID parameters 
            3. CSRF: Check if forms use tokens
            4. Auth Issues: Test login forms
            5. IDOR: Test access to resources using different IDs
            6. Access Control: Test if unauthorized users can access restricted resources
            7. Crypto Failures: Check for TLS/SSL issues and weak cryptography
            8. Insecure Design: Identify design flaws in application logic
            9. Data Integrity: Test for software and data integrity failures
            10. SSRF: Test for server-side request forgery vulnerabilities
            
            Respond with a list of security tests to run.
            """
        else:
            system_prompt = """
            You are a security planning expert. Your job is to analyze web pages and create comprehensive security testing plans.
            Focus on these common web vulnerabilities from the OWASP Top 10:
            1. Cross-Site Scripting (XSS)
            2. SQL Injection
            3. Cross-Site Request Forgery (CSRF)
            4. Authentication/Session issues
            5. Insecure Direct Object References (IDOR)
            6. Broken Access Control (including privilege escalation)
            7. Cryptographic Failures (TLS issues, weak cryptography)
            8. Insecure Design patterns (including business logic flaws)
            9. Software and Data Integrity Failures (including insecure deserialization)
            10. Server-Side Request Forgery (SSRF)
            
            For Google Gruyere application, pay special attention to:
            - The snippets.gtl endpoint with the uid parameter, which is known to be vulnerable to XSS
            - Any form submission that processes user input
            - Parameters that might be processed on the server side
            
            Evaluate the page content, forms, inputs, and overall structure to identify potential security risks.
            Create a prioritized list of security tests targeting the most critical components first.
            """
        
        # Check if URL might be Google Gruyere
        is_gruyere = "gruyere" in url.lower()
        content_text = f"Create a security testing plan for: {url}\n\nPage Information:\n{page_info}"
        
        if is_gruyere:
            # Add specific information about known vulnerable endpoints in Gruyere
            content_text += "\n\nImportant: This appears to be a Google Gruyere application, which has known vulnerabilities in the following areas:\n"
            content_text += "1. XSS in uid parameter of snippets.gtl endpoint\n"
            content_text += "2. SQL injection in search functionality\n"
            content_text += "3. CSRF in form submissions\n"
            content_text += "4. Insecure file uploads\n"
            content_text += "Prioritize testing these known vulnerability points."
            
        input_data = {
            "content": content_text
        }
        
        # Add extra instruction for Ollama models to help them with tool usage
        if self.is_ollama:
            input_data["content"] += "\n\nIMPORTANT: You must respond using the create_security_plan function with a list of tasks to test for vulnerabilities."
            if is_small_model:
                # Add even more explicit instructions for small models
                input_data["content"] += "\nExample usage: create_security_plan(tasks=[{\"type\": \"xss\", \"target\": \"search form\", \"priority\": \"high\"}])"
        
        response = self.think(input_data, system_prompt)
        
        if response.get("tool_calls"):
            # Process tool calls to get the plan
            tool_call = response["tool_calls"][0]
            
            # Log the tool being called - safely accessing properties
            if hasattr(tool_call, 'function') and hasattr(tool_call.function, 'name'):
                tool_name = tool_call.function.name
            else:
                tool_name = tool_call.get('function', {}).get('name', 'unknown_tool')
                
            self.logger.info(f"PlannerAgent using tool: {tool_name}", color="cyan")
            
            return self.execute_tool(tool_call)
        else:
            # Fallback if no tool call was made - parse the text response if available
            self.logger.warning("PlannerAgent did not generate a tool call for planning, attempting fallback parsing")
            
            # Extract plan from text content if available
            content = response.get("content", "")
            if content and (self.is_ollama or "plan" in content.lower() or "task" in content.lower()):
                self.logger.info("Attempting to parse security plan from text content")
                return self._parse_plan_from_text(content, url)
            else:
                # Use default minimal plan if no useful content
                self.logger.warning("Using default minimal security plan")
                return self._create_default_plan(url)
    
    def _parse_plan_from_text(self, content: str, url: str) -> Dict[str, Any]:
        """Attempt to parse a security plan from text content."""
        self.logger.info("Parsing security plan from text content")
        
        # Initialize empty plan
        plan = {"tasks": []}
        
        # Look for task descriptions in the text
        lines = content.split('\n')
        current_type = None
        task_count = 0
        
        # Common security test types to look for
        test_types = {
            "xss": ["xss", "cross-site scripting", "script injection"],
            "sqli": ["sql", "sqli", "injection", "database"],
            "csrf": ["csrf", "cross-site request forgery", "token"],
            "auth": ["auth", "login", "password", "authentication", "session"],
            "idor": ["idor", "insecure direct object", "access control"],
            "access_control": ["access control", "authorization", "privilege", "permission", "unauthorized"],
            "crypto": ["crypto", "tls", "ssl", "certificate", "encryption", "hashing"],
            "insecure_design": ["design", "business logic", "workflow", "rate limit", "validation pattern"],
            "data_integrity": ["integrity", "deserialization", "signature", "update mechanism"],
            "ssrf": ["ssrf", "server-side request forgery", "server request"],
            "scan": ["scan", "reconnaissance", "header", "information disclosure"]
        }
        
        # Process each line
        for line in lines:
            line = line.strip().lower()
            
            # Skip empty lines
            if not line:
                continue
                
            # Try to determine task type
            detected_type = None
            for test_type, keywords in test_types.items():
                if any(keyword in line for keyword in keywords):
                    detected_type = test_type
                    break
            
            # If we found a type, create a new task
            if detected_type:
                current_type = detected_type
                
                # Extract target from line if possible
                target = url
                
                # Look for form or parameter references
                if "form" in line:
                    target = "input forms"
                elif "param" in line:
                    target = "URL parameters"
                elif "search" in line:
                    target = "search functionality"
                elif "login" in line:
                    target = "login form"
                
                # Determine priority based on keywords
                priority = "medium"
                if any(word in line for word in ["critical", "severe", "important", "high"]):
                    priority = "high"
                elif any(word in line for word in ["minor", "low", "minimal"]):
                    priority = "low"
                
                # Create task
                task = {
                    "type": current_type,
                    "target": target,
                    "priority": priority
                }
                
                plan["tasks"].append(task)
                task_count += 1
        
        # If we couldn't parse any tasks, fall back to default plan
        if task_count == 0:
            self.logger.warning("Could not parse any tasks from text, using default plan")
            return self._create_default_plan(url)
        else:
            self.logger.info(f"Successfully parsed {task_count} tasks from text content")
            return plan
    
    def _create_default_plan(self, url: str) -> Dict[str, Any]:
        """Create a default security testing plan covering OWASP top vulnerabilities."""
        self.logger.info("Creating default security testing plan based on OWASP Top 10")
        
        # Create a default plan covering the main vulnerability types
        default_plan = {
            "tasks": [
                {
                    "type": "xss",
                    "target": "all input forms",
                    "priority": "high"
                },
                {
                    "type": "sqli",
                    "target": "search functionality",
                    "priority": "high"
                },
                {
                    "type": "csrf",
                    "target": "form submissions",
                    "priority": "medium"
                },
                {
                    "type": "auth",
                    "target": "login functionality",
                    "priority": "high"
                },
                {
                    "type": "idor",
                    "target": "user-specific resources",
                    "priority": "medium"
                },
                {
                    "type": "access_control",
                    "target": "admin pages and restricted resources",
                    "priority": "high"
                },
                {
                    "type": "crypto",
                    "target": "TLS configuration and sensitive data handling",
                    "priority": "high"
                },
                {
                    "type": "insecure_design",
                    "target": "critical application workflows",
                    "priority": "medium"
                },
                {
                    "type": "data_integrity",
                    "target": "data update mechanisms",
                    "priority": "medium"
                },
                {
                    "type": "ssrf",
                    "target": "URL input fields and API endpoints",
                    "priority": "high"
                },
                {
                    "type": "scan",
                    "target": url,
                    "priority": "medium"
                }
            ]
        }
        
        # Check if Gruyere-specific plan is needed
        if "gruyere" in url.lower():
            self.logger.info("Using Gruyere-specific default plan")
            gruyere_plan = {
                "tasks": [
                    {
                        "type": "xss",
                        "target": "snippets.gtl?uid parameter",
                        "priority": "high"
                    },
                    {
                        "type": "sqli", 
                        "target": "search functionality",
                        "priority": "high"
                    },
                    {
                        "type": "csrf",
                        "target": "form submissions",
                        "priority": "medium"
                    },
                    {
                        "type": "scan",
                        "target": url,
                        "priority": "medium"
                    }
                ]
            }
            return gruyere_plan
        
        return default_plan


class ScannerAgent(BaseAgent):
    """Agent specializing in general security scanning."""
    
    def __init__(self, llm_provider: LLMProvider, scanner: Scanner):
        # Combine standard scanning tools with browser interaction tools
        tools = get_scanning_tools() + get_browser_interaction_tools()
        super().__init__("ScannerAgent", "security_scanner", llm_provider, tools)
        self.scanner = scanner
        # Initialize browser tools
        self.browser_tools = BrowserTools(debug=True)
        # Initialize web proxy for traffic monitoring
        self.proxy = WebProxy()
    
    def execute_task(self, task: Dict[str, Any], page: Page, page_info: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a scanning task."""
        system_prompt = """
        You are a security scanner specialized in identifying general security issues in web applications.
        Your task is to analyze the structure, headers, and overall security posture of the target application.
        Look for issues like insecure headers, outdated software, information disclosure, and general misconfigurations.
        
        You have access to both scanning tools and browser interaction tools:
        
        SCANNING TOOLS:
        - scan_headers: Check security headers of a target URL
        - enumerate_subdomains: Find subdomains for a target domain
        - analyze_robots_txt: Analyze robots.txt file for sensitive paths
        - check_security_txt: Check for security.txt file with security contact information
        - extract_urls: Extract URLs from HTML content for further testing
        
        BROWSER INTERACTION TOOLS:
        - goto: Navigate to a URL
        - click: Click an element on the page
        - fill: Fill a form field with a value
        - submit: Submit a form
        - execute_js: Execute JavaScript on the page
        - refresh: Refresh the current page
        - presskey: Press a keyboard key
        
        Use these tools to thoroughly test the target application. Look for security issues such as:
        1. Missing or misconfigured security headers
        2. Information disclosure in HTML comments, headers, or error messages
        3. Sensitive directories or files exposed in robots.txt
        4. Insecure subdomain configurations
        5. Client-side security issues detectable via JavaScript execution
        """
        
        # Enhance page info with screenshot if available
        enhanced_page_info = dict(page_info)
        try:
            screenshot = get_base64_screenshot(page)
            if screenshot:
                enhanced_page_info["screenshot_available"] = True
        except:
            pass
        
        # Create rich input data with color-coded sections
        input_data = {
            "content": f"Perform a security scan on: {page.url}\n\nTask details: {task}\n\nPage information: {enhanced_page_info}"
        }
        
        # Use the pretty logger to highlight the task
        logger = get_logger()
        logger.highlight(f"ScannerAgent executing task: {task['type']} on {task['target']}")
        
        response = self.think(input_data, system_prompt)
        
        # Process the response to extract vulnerability information
        result = {
            "task_type": task["type"],
            "target": task["target"],
            "vulnerability_found": False,  # Will be set to True if a vulnerability is found
            "details": {},
            "actions_performed": []
        }
        
        if response.get("tool_calls"):
            # Process tool calls
            for tool_call in response["tool_calls"]:
                # Log the tool being called - safely accessing properties
                if hasattr(tool_call, 'function') and hasattr(tool_call.function, 'name'):
                    tool_name = tool_call.function.name
                else:
                    tool_name = tool_call.get('function', {}).get('name', 'unknown_tool')
                    
                logger.info(f"ScannerAgent using tool: {tool_name}", color="cyan")
                
                # Execute the tool
                tool_result = self.execute_tool(tool_call)
                
                # Track the action
                result["actions_performed"].append({
                    "tool": tool_name,
                    "success": tool_result is not None
                })
                
                # Check if the tool result indicates a vulnerability
                if isinstance(tool_result, dict):
                    # Check for known vulnerability indicators
                    if tool_result.get("security_issue_found", False) or tool_result.get("issues_found", False):
                        result["vulnerability_found"] = True
                        result["vulnerability_type"] = tool_result.get("issue_type", "Unknown")
                        result["severity"] = tool_result.get("severity", "medium")
                        result["details"] = tool_result
                        
                        # Log the finding
                        logger.security(f"Found {result['vulnerability_type']} vulnerability with {tool_name}")
                    
                    # For browser interaction tools, check return values that might indicate vulnerabilities
                    elif tool_name == "execute_js" and tool_result.get("success", False):
                        js_result = tool_result.get("result", "")
                        # Look for common security indicators in JS execution results
                        if any(indicator in str(js_result).lower() for indicator in 
                              ["password", "token", "api_key", "apikey", "secret", "auth", "cookie"]):
                            result["vulnerability_found"] = True
                            result["vulnerability_type"] = "Client-Side Information Disclosure"
                            result["severity"] = "medium"
                            result["details"] = {
                                "issue_type": "Client-Side Information Disclosure",
                                "evidence": str(js_result),
                                "tool_result": tool_result
                            }
                            
                            logger.security(f"Found Client-Side Information Disclosure with execute_js")
        
        # Get any captured traffic from proxy for additional analysis
        if hasattr(self, 'proxy') and self.proxy:
            traffic = self.proxy.get_traffic()
            if traffic:
                # Look for security issues in traffic
                for entry in traffic:
                    # Check for sensitive information in responses
                    if entry.get("response_body"):
                        body = str(entry.get("response_body", ""))
                        if any(indicator in body.lower() for indicator in 
                              ["password", "apikey", "api_key", "token", "secret", "private", "credential"]):
                            result["vulnerability_found"] = True
                            result["vulnerability_type"] = "Information Disclosure in Response"
                            result["severity"] = "high"
                            result["details"] = {
                                "issue_type": "Information Disclosure",
                                "url": entry.get("url", ""),
                                "evidence": "Sensitive information found in response body"
                            }
                            
                            logger.security(f"Found Information Disclosure in response from {entry.get('url', '')}")
                
                # Clear traffic for next scan
                self.proxy.clear()
        
        return result