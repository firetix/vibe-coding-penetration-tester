from typing import Dict, List, Any, Optional
import json
from playwright.sync_api import Page

from core.llm import LLMProvider
from core.scanner import Scanner
from agents.agent_factory import BaseAgent
from utils.logger import get_logger
from utils.proxy import WebProxy
from utils.network_utils import get_base64_screenshot

from tools.scanning_tools import get_scanning_tools
from tools.security_tools import get_security_tools
from tools.browser_tools import BrowserTools
from tools.browser_tools_impl import get_browser_interaction_tools

# Import specialized agents
from agents.security.access_control_agent import AccessControlAgent
from agents.security.data_integrity_agent import DataIntegrityAgent
from agents.security.ssrf_agent import SSRFAgent
from agents.security.crypto_agent import CryptoFailureAgent
from agents.security.insecure_design_agent import InsecureDesignAgent
from agents.security.validator_agent import ValidationAgent
from agents.security.idor_agent import IDORAgent
from agents.security.xss_agent import XSSAgent
from agents.security.sqli_agent import SQLInjectionAgent
from agents.security.csrf_agent import CSRFAgent
from agents.security.auth_agent import AuthenticationAgent
from agents.security.api_security_agent import APISecurityAgent


class SecuritySwarm:
    """A swarm of specialized security testing agents working together."""

    def __init__(
        self, llm_provider: LLMProvider, scanner: Scanner, config: Dict[str, Any]
    ):
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
            "api": APISecurityAgent(llm_provider, scanner),
            "validator": ValidationAgent(llm_provider, scanner),
        }

    def run(
        self, url: str, page: Page, page_info: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Execute the full security testing process with all agents."""
        self.logger.info(f"Starting security swarm for {url}")
        self.logger.debug(f"Security swarm has {len(self.agents)} agents available")

        # Log available agents for debugging
        agent_names = list(self.agents.keys())
        self.logger.debug(f"Available agents: {agent_names}")

        # Generate testing plan
        self.logger.highlight("Generating security testing plan")

        # Log a specific activity that should show up in the UI
        self.logger.security("Security Swarm: Planning security testing strategy")

        plan = self.agents["planner"].create_plan(url, page_info)

        # Debug output for the plan
        self.logger.highlight(
            f"Security testing plan generated with {len(plan.get('tasks', []))} tasks:"
        )

        # Create and publish action plan for UI display
        action_plan = [f"Security Testing Plan for {url}"]

        for i, task in enumerate(plan.get("tasks", []), 1):
            task_type = task.get("type", "unknown")
            target = task.get("target", "unknown")
            priority = task.get("priority", "medium")

            self.logger.info(
                f"  Task #{i}: {task_type} on {target} (Priority: {priority})"
            )
            # Log each task as a distinct activity
            self.logger.security(f"Planned Task: {task_type} test on {target}")

            # Add to action plan for UI with pending status
            action_plan.append(
                f"Step {i}: {task_type.upper()} test on {target} (Priority: {priority}) (Pending)"
            )

        # Publish action plan for UI display
        action_plan_json = json.dumps(action_plan)
        print(f"ACTION_PLAN: {action_plan_json}")

        # Also log as activity
        self.logger.info(f"Published action plan with {len(action_plan) - 1} tasks")

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
                self.logger.info(
                    f"Available agent types: {', '.join(self.agents.keys())}"
                )

                # Log that we're skipping this task to action plan
                print(
                    f'ACTION_PLAN: ["Skip task: {task_type} - No suitable agent found"]'
                )
                continue

            # Log current task as the active one for UI
            current_task = f"{agent.__class__.__name__}: Testing {target} for {task_type} vulnerabilities"
            print(
                f'ACTIVITY: {{"type": "current_task", "description": "{current_task}", "agent": "{agent.__class__.__name__}"}}'
            )

            # Execute the task and collect results
            try:
                self.logger.info(f"Using agent {agent.name} for task type {task_type}")

                # Log this as an activity that should show up in the UI
                self.logger.security(
                    f"Running {agent.name} to test {task.get('target', 'application')} for vulnerabilities"
                )

                # Execute the actual task
                result = agent.execute_task(task, page, page_info)

                # Log the completion of the task
                self.logger.security(
                    f"Completed {agent.name} testing of {task.get('target', 'application')}"
                )

                # Update action plan to mark this task as completed
                completed_task = f"Step {i}: {task_type.upper()} test on {target} (Priority: {priority}) (Completed)"
                print(f'ACTION_PLAN: ["{completed_task}"]')

                # Debug the raw result
                if result:
                    self.logger.info(f"Raw result from {agent.name}:")
                    self.logger.info(
                        f"  Vulnerability found: {result.get('vulnerability_found', False)}"
                    )
                    self.logger.info(
                        f"  Type: {result.get('vulnerability_type', 'Unknown')}"
                    )
                    self.logger.info(f"  Target: {result.get('target', 'Unknown')}")

                    # For agent activity display, log any findings
                    if result.get("vulnerability_found", False):
                        self.logger.security(
                            f"{agent.name}: Found {result.get('vulnerability_type', 'Unknown')} vulnerability in {result.get('target', 'Unknown')}"
                        )
                    else:
                        # Even if no vulnerability, log what was tested
                        self.logger.security(
                            f"{agent.name}: No vulnerabilities found in {result.get('target', 'Unknown')}"
                        )

                    # Keep track of all findings even if not validated
                    raw_findings.append(result)

                if result and result.get("vulnerability_found", False):
                    self.logger.highlight(
                        f"Potential vulnerability found by {agent.name}: {result.get('vulnerability_type', 'Unknown')}"
                    )

                    # Validate findings if a vulnerability is reported
                    self.logger.info("Validating finding with validation agent")
                    validation = self.agents["validator"].validate_finding(
                        result, page, page_info
                    )

                    self.logger.info(
                        f"Validation result: {validation.get('validated', False)}"
                    )

                    if validation.get("validated", False):
                        validated_vuln = {
                            **result,
                            "validated": True,
                            "validation_details": validation.get("details", {}),
                        }
                        vulnerabilities.append(validated_vuln)

                        # Log validated vulnerability as a success
                        vuln_type = validated_vuln.get("vulnerability_type", "Unknown")
                        severity = validated_vuln.get("severity", "medium")
                        self.logger.success(
                            f"Validated vulnerability: {vuln_type} ({severity})"
                        )

                        # Add to action plan
                        vuln_item = f"Found {vuln_type} vulnerability in {target} (Severity: {severity}) (Completed)"
                        print(f'ACTION_PLAN: ["{vuln_item}"]')
                    else:
                        self.logger.warning(
                            f"Vulnerability reported but failed validation: {result.get('vulnerability_type', 'Unknown')}"
                        )
                        # Add to vulnerabilities anyway for debugging purposes, but mark as unvalidated
                        test_vuln = {
                            **result,
                            "validated": False,
                            "validation_details": validation.get("details", {}),
                            "note": "Added for debugging - failed validation",
                        }
                        vulnerabilities.append(test_vuln)

                        # Add potential (unvalidated) vulnerability to action plan
                        vuln_type = test_vuln.get("vulnerability_type", "Unknown")
                        severity = test_vuln.get("severity", "medium")
                        vuln_item = f"Potential {vuln_type} vulnerability found but not validated (Severity: {severity}) (Completed)"
                        print(f'ACTION_PLAN: ["{vuln_item}"]')

                        self.logger.warning(
                            "TESTING ONLY: Adding unvalidated vulnerability for debugging"
                        )
            except Exception as e:
                self.logger.error(f"Error executing task {task_type}: {str(e)}")
                import traceback

                self.logger.error(f"Traceback: {traceback.format_exc()}")

        self.logger.highlight("Security testing completed.")
        self.logger.info(f"Raw findings: {len(raw_findings)}")
        self.logger.info(
            f"Validated vulnerabilities: {len([v for v in vulnerabilities if v.get('validated', False)])}"
        )
        self.logger.info(
            f"Total vulnerabilities (including test entries): {len(vulnerabilities)}"
        )

        # For debugging purposes, check if we have any findings at all
        if not raw_findings and not vulnerabilities:
            self.logger.warning(
                "No security findings or vulnerabilities detected at all"
            )
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
                    "evidence": "No actual evidence - this is a test entry.",
                },
                "note": "This is a test vulnerability created to verify the reporting system. It does not represent an actual security issue.",
            }
            self.logger.warning(
                "Created test vulnerability for report generation debugging"
            )
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
            "api": "api",
            "api_security": "api",
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
                                            "description": "Type of security test to perform (e.g., xss, sqli, csrf, auth)",
                                        },
                                        "target": {
                                            "type": "string",
                                            "description": "Target element or functionality to test",
                                        },
                                        "priority": {
                                            "type": "string",
                                            "enum": ["high", "medium", "low"],
                                            "description": "Priority of this test",
                                        },
                                        "details": {
                                            "type": "object",
                                            "description": "Additional details specific to this test type",
                                        },
                                    },
                                    "required": ["type", "target", "priority"],
                                },
                            }
                        },
                        "required": ["tasks"],
                    },
                },
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
        is_small_model = self.is_ollama and any(
            model_id in self.model_name.lower()
            for model_id in ["r1", "deepseek", "phi", "gemma", "mistral"]
        )

        if is_small_model:
            self.logger.info(
                f"Using simplified prompt for smaller Ollama model: {self.model_name}"
            )
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
            You are a security planning expert. Your job is to analyze web applications and create comprehensive, generalized security testing plans that work across different types of websites.
            
            Focus on these common web vulnerabilities from the OWASP Top 10:
            1. Cross-Site Scripting (XSS)
               - Test all input fields, especially search, comment, and user profile forms
               - Use various payload techniques (basic, event handlers, encoded, nested)
               - Look for both reflected and stored XSS opportunities
            
            2. SQL Injection
               - Test authentication mechanisms, search functionality, and ID parameters
               - Try various techniques: error-based, boolean-based, time-based, and UNION-based
               - Look for data extraction opportunities and authentication bypasses
            
            3. Cross-Site Request Forgery (CSRF)
               - Examine forms that change state or modify data
               - Check for missing CSRF tokens and cookie security attributes
               - Test redirect functionality for open redirect vulnerabilities
            
            4. Authentication/Session Issues
               - Test for weak credential validation and default passwords
               - Check for missing account lockout and password policies
               - Examine session management for fixation and timeout issues
            
            5. Insecure Direct Object References (IDOR)
               - Test URL parameters containing IDs or references to objects
               - Look for sequential and predictable IDs in user-specific resources
               - Check if you can access resources belonging to other users
            
            6. Broken Access Control
               - Test access to administrative functions and protected resources
               - Check for horizontal and vertical privilege escalation
               - Examine API endpoints for missing authorization
            
            7. Cryptographic Failures
               - Check TLS configuration and certificate validity
               - Look for sensitive data transmitted in cleartext
               - Examine password hashing and storage methods
            
            8. Insecure Design Patterns
               - Identify business logic flaws and race conditions
               - Test for missing rate limiting and validation bypass
               - Look for mass assignment vulnerabilities
            
            9. Software and Data Integrity Failures
               - Check for insecure deserialization
               - Test integrity verification mechanisms
               - Look for untrusted data processing
            
            10. Server-Side Request Forgery (SSRF)
                - Test URL input fields and file import functionality
                - Look for server-side API calls that process user input
                - Check for internal service access
            
            Look for patterns that are common across different applications:
            - Any input fields are potential XSS and injection points
            - Login forms often have SQL injection or weak password validation vulnerabilities
            - URL parameters with IDs are prime targets for IDOR testing
            - State-changing operations need CSRF protection
            - Nested and encoded payloads can bypass security filters
            
            Evaluate the page content, forms, inputs, and overall structure to identify potential security risks.
            Create a prioritized and generalized testing plan that would work on many different types of applications.
            """

        # For specific known applications, add contextual information but maintain generalizability
        is_gruyere = "gruyere" in url.lower()
        is_juice_shop = "juice" in url.lower() or "owasp" in url.lower()
        content_text = f"Create a comprehensive security testing plan for: {url}\n\nPage Information:\n{page_info}"

        # Always add general vulnerability patterns to check regardless of site
        content_text += "\n\nKey areas to thoroughly test on any web application:"
        content_text += (
            "\n1. Input fields, search functionality, and forms for XSS vulnerabilities"
        )
        content_text += "\n2. Authentication mechanisms for SQL injection and weak credential validation"
        content_text += "\n3. URL parameters containing IDs for IDOR vulnerabilities"
        content_text += "\n4. State-changing operations for missing CSRF protections"
        content_text += "\n5. Redirect functionality for open redirect vulnerabilities"
        content_text += (
            "\n6. API endpoints and data access patterns for authorization issues"
        )
        content_text += "\n7. File upload functionality for insecure file handling"
        content_text += "\n8. Header configurations for security misconfigurations"

        # Add application-specific context only as additional information
        if is_gruyere:
            content_text += "\n\nAdditional context: This appears to be a Google Gruyere application, which commonly has vulnerabilities in:"
            content_text += "\n- The snippets.gtl endpoint with uid parameter (XSS)"
            content_text += "\n- Search functionality (SQL injection)"
            content_text += "\n- Form submissions (CSRF)"
            content_text += "\n- File uploads (insecure handling)"

        elif is_juice_shop:
            content_text += "\n\nAdditional context: This appears to be an OWASP Juice Shop-like application, which commonly has:"
            content_text += "\n- Search functionality vulnerable to XSS"
            content_text += "\n- Login forms vulnerable to SQL injection"
            content_text += (
                "\n- User-specific endpoints (baskets, profiles) vulnerable to IDOR"
            )
            content_text += "\n- Form submissions often missing CSRF protection"
            content_text += "\n- Redirect functionality vulnerable to manipulation"

        input_data = {"content": content_text}

        # Add extra instruction for Ollama models to help them with tool usage
        if self.is_ollama:
            input_data["content"] += (
                "\n\nIMPORTANT: You must respond using the create_security_plan function with a list of tasks to test for vulnerabilities."
            )
            if is_small_model:
                # Add even more explicit instructions for small models
                input_data["content"] += (
                    '\nExample usage: create_security_plan(tasks=[{"type": "xss", "target": "search form", "priority": "high"}])'
                )

        response = self.think(input_data, system_prompt)

        if response.get("tool_calls"):
            # Process tool calls to get the plan
            tool_call = response["tool_calls"][0]

            # Log the tool being called - safely accessing properties
            if hasattr(tool_call, "function") and hasattr(tool_call.function, "name"):
                tool_name = tool_call.function.name
            else:
                tool_name = tool_call.get("function", {}).get("name", "unknown_tool")

            self.logger.info(f"PlannerAgent using tool: {tool_name}", color="cyan")

            return self.execute_tool(tool_call)
        else:
            # Fallback if no tool call was made - parse the text response if available
            self.logger.warning(
                "PlannerAgent did not generate a tool call for planning, attempting fallback parsing"
            )

            # Extract plan from text content if available
            content = response.get("content", "")
            if content and (
                self.is_ollama or "plan" in content.lower() or "task" in content.lower()
            ):
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
        lines = content.split("\n")
        current_type = None
        task_count = 0

        # Common security test types to look for
        test_types = {
            "xss": ["xss", "cross-site scripting", "script injection"],
            "sqli": ["sql", "sqli", "injection", "database"],
            "csrf": ["csrf", "cross-site request forgery", "token"],
            "auth": ["auth", "login", "password", "authentication", "session"],
            "idor": ["idor", "insecure direct object", "access control"],
            "access_control": [
                "access control",
                "authorization",
                "privilege",
                "permission",
                "unauthorized",
            ],
            "crypto": ["crypto", "tls", "ssl", "certificate", "encryption", "hashing"],
            "insecure_design": [
                "design",
                "business logic",
                "workflow",
                "rate limit",
                "validation pattern",
            ],
            "data_integrity": [
                "integrity",
                "deserialization",
                "signature",
                "update mechanism",
            ],
            "ssrf": ["ssrf", "server-side request forgery", "server request"],
            "api": [
                "api",
                "rest",
                "graphql",
                "endpoint",
                "bola",
                "mass assignment",
                "openapi",
                "swagger",
            ],
            "scan": ["scan", "reconnaissance", "header", "information disclosure"],
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
                if any(
                    word in line for word in ["critical", "severe", "important", "high"]
                ):
                    priority = "high"
                elif any(word in line for word in ["minor", "low", "minimal"]):
                    priority = "low"

                # Create task
                task = {"type": current_type, "target": target, "priority": priority}

                plan["tasks"].append(task)
                task_count += 1

        # If we couldn't parse any tasks, fall back to default plan
        if task_count == 0:
            self.logger.warning(
                "Could not parse any tasks from text, using default plan"
            )
            return self._create_default_plan(url)
        else:
            self.logger.info(
                f"Successfully parsed {task_count} tasks from text content"
            )
            return plan

    def _create_default_plan(self, url: str) -> Dict[str, Any]:
        """Create a default security testing plan covering OWASP top vulnerabilities."""
        self.logger.info("Creating default security testing plan based on OWASP Top 10")

        # Create a comprehensive, pattern-based security testing plan covering OWASP top vulnerabilities
        default_plan = {
            "tasks": [
                # XSS testing - check various contexts and techniques
                {
                    "type": "xss",
                    "target": "search functionality",
                    "priority": "high",
                    "details": {
                        "technique": "reflected",
                        "context": "html",
                        "payloads": ["basic", "event_handlers", "encoded"],
                    },
                },
                {
                    "type": "xss",
                    "target": "comment/feedback forms",
                    "priority": "high",
                    "details": {
                        "technique": "stored",
                        "context": "html",
                        "payloads": ["basic", "nested", "sanitization_bypass"],
                    },
                },
                {
                    "type": "xss",
                    "target": "user profile fields",
                    "priority": "medium",
                    "details": {
                        "technique": "stored",
                        "context": "attribute",
                        "payloads": ["attribute_breakout", "event_handlers"],
                    },
                },
                # SQL Injection testing - various contexts and techniques
                {
                    "type": "sqli",
                    "target": "login form",
                    "priority": "critical",
                    "details": {
                        "technique": "authentication_bypass",
                        "context": "login",
                    },
                },
                {
                    "type": "sqli",
                    "target": "search functionality",
                    "priority": "high",
                    "details": {
                        "technique": "union_based",
                        "context": "data_extraction",
                    },
                },
                {
                    "type": "sqli",
                    "target": "URL parameters with IDs",
                    "priority": "high",
                    "details": {
                        "technique": "error_based",
                        "context": "parameter_tampering",
                    },
                },
                # CSRF testing
                {
                    "type": "csrf",
                    "target": "profile/account update forms",
                    "priority": "high",
                    "details": {
                        "check_for": [
                            "csrf_tokens",
                            "samesite_cookies",
                            "origin_validation",
                        ]
                    },
                },
                {
                    "type": "csrf",
                    "target": "payment/checkout forms",
                    "priority": "critical",
                    "details": {"check_for": ["csrf_tokens", "referrer_validation"]},
                },
                # Authentication testing
                {
                    "type": "auth",
                    "target": "login functionality",
                    "priority": "high",
                    "details": {
                        "check_for": [
                            "default_credentials",
                            "weak_passwords",
                            "account_lockout",
                            "password_policy",
                        ]
                    },
                },
                {
                    "type": "auth",
                    "target": "session management",
                    "priority": "high",
                    "details": {
                        "check_for": ["session_cookies", "timeout", "fixation"]
                    },
                },
                # IDOR testing
                {
                    "type": "idor",
                    "target": "user-specific resources",
                    "priority": "high",
                    "details": {
                        "check_for": [
                            "sequential_ids",
                            "predictable_references",
                            "horizontal_access",
                        ]
                    },
                },
                {
                    "type": "idor",
                    "target": "API endpoints with IDs",
                    "priority": "high",
                    "details": {
                        "check_for": ["direct_reference", "missing_authorization"]
                    },
                },
                # Other critical tests
                {
                    "type": "access_control",
                    "target": "admin pages and restricted resources",
                    "priority": "high",
                    "details": {
                        "check_for": [
                            "vertical_escalation",
                            "horizontal_escalation",
                            "role_verification",
                        ]
                    },
                },
                {
                    "type": "crypto",
                    "target": "TLS configuration and sensitive data handling",
                    "priority": "high",
                    "details": {
                        "check_for": [
                            "weak_ciphers",
                            "certificate_issues",
                            "sensitive_data_exposure",
                        ]
                    },
                },
                {
                    "type": "insecure_design",
                    "target": "critical application workflows",
                    "priority": "medium",
                    "details": {
                        "check_for": [
                            "business_logic_flaws",
                            "race_conditions",
                            "missing_validations",
                        ]
                    },
                },
                {
                    "type": "data_integrity",
                    "target": "data update mechanisms",
                    "priority": "medium",
                    "details": {
                        "check_for": [
                            "insecure_deserialization",
                            "integrity_verification",
                            "untrusted_data",
                        ]
                    },
                },
                {
                    "type": "ssrf",
                    "target": "URL input fields and API endpoints",
                    "priority": "high",
                    "details": {
                        "check_for": [
                            "url_validation",
                            "server_requests",
                            "internal_service_access",
                        ]
                    },
                },
                {
                    "type": "api",
                    "target": "REST/GraphQL API endpoints",
                    "priority": "high",
                    "details": {
                        "check_for": [
                            "bola",
                            "auth_bypass",
                            "mass_assignment",
                            "data_exposure",
                            "rate_limiting",
                        ]
                    },
                },
                {"type": "scan", "target": url, "priority": "medium"},
            ]
        }

        # Check for site-specific test plans
        if "gruyere" in url.lower():
            self.logger.info("Using Gruyere-specific default plan")
            gruyere_plan = {
                "tasks": [
                    {
                        "type": "xss",
                        "target": "snippets.gtl?uid parameter",
                        "priority": "high",
                    },
                    {
                        "type": "sqli",
                        "target": "search functionality",
                        "priority": "high",
                    },
                    {
                        "type": "csrf",
                        "target": "form submissions",
                        "priority": "medium",
                    },
                    {"type": "scan", "target": url, "priority": "medium"},
                ]
            }
            return gruyere_plan

        # For OWASP Juice Shop and e-commerce applications, provide a pattern-based plan with some informed patterns
        elif (
            "juice" in url.lower()
            or "owasp" in url.lower()
            or "shop" in url.lower()
            or "store" in url.lower()
        ):
            self.logger.info("Using e-commerce application optimized security plan")
            ecommerce_plan = {
                "tasks": [
                    # XSS testing for common e-commerce elements
                    {
                        "type": "xss",
                        "target": "product search fields",
                        "priority": "high",
                        "details": {
                            "technique": "reflected",
                            "context": "html",
                            "pattern": "Search fields often display user input directly",
                            "common_payloads": [
                                "<script>alert(1)</script>",
                                "<img src=x onerror=alert(1)>",
                            ],
                        },
                    },
                    {
                        "type": "xss",
                        "target": "product review/feedback forms",
                        "priority": "high",
                        "details": {
                            "technique": "stored",
                            "context": "html",
                            "pattern": "Review forms often store and display user content",
                            "common_payloads": [
                                "basic script tags",
                                "nested payloads to bypass sanitization",
                            ],
                        },
                    },
                    # SQL Injection patterns common in e-commerce
                    {
                        "type": "sqli",
                        "target": "login functionality",
                        "priority": "critical",
                        "details": {
                            "technique": "authentication_bypass",
                            "pattern": "Login forms often connect directly to user database",
                            "common_payloads": [
                                "' OR 1=1;--",
                                "' OR '1'='1",
                                "admin'--",
                            ],
                        },
                    },
                    {
                        "type": "sqli",
                        "target": "product search/filtering",
                        "priority": "high",
                        "details": {
                            "technique": "union_based",
                            "pattern": "Product search often uses direct SQL queries",
                            "common_payloads": [
                                "' UNION SELECT statements",
                                "query for user tables",
                            ],
                        },
                    },
                    # IDOR patterns common in e-commerce
                    {
                        "type": "idor",
                        "target": "customer-specific resources",
                        "priority": "high",
                        "details": {
                            "pattern": "E-commerce sites often use sequential/predictable IDs for user resources",
                            "check_areas": [
                                "shopping baskets",
                                "orders",
                                "wishlists",
                                "profiles",
                                "payment info",
                            ],
                        },
                    },
                    # CSRF patterns common in e-commerce
                    {
                        "type": "csrf",
                        "target": "profile management",
                        "priority": "high",
                        "details": {
                            "pattern": "Profile forms often lack proper CSRF protection",
                            "check_areas": [
                                "address updates",
                                "payment methods",
                                "account settings",
                            ],
                        },
                    },
                    {
                        "type": "csrf",
                        "target": "order processing",
                        "priority": "critical",
                        "details": {
                            "pattern": "Order forms that change state might be vulnerable"
                        },
                    },
                    # Redirect vulnerabilities common in e-commerce
                    {
                        "type": "csrf",
                        "target": "redirect functionality",
                        "priority": "medium",
                        "details": {
                            "pattern": "E-commerce often uses redirects for payment processing or login",
                            "check_for": [
                                "open redirects",
                                "unvalidated redirects",
                                "null byte injection",
                            ],
                        },
                    },
                    # Authentication patterns common in e-commerce
                    {
                        "type": "auth",
                        "target": "login functionality",
                        "priority": "high",
                        "details": {
                            "pattern": "E-commerce sites often have weak password policies",
                            "check_for": [
                                "default credentials",
                                "weak password policies",
                                "missing account lockout",
                            ],
                        },
                    },
                    # Additional common e-commerce tests
                    {
                        "type": "insecure_design",
                        "target": "pricing and discounts",
                        "priority": "high",
                        "details": {
                            "pattern": "Discount handling may have business logic flaws",
                            "check_for": [
                                "negative values",
                                "price manipulation",
                                "coupon code issues",
                            ],
                        },
                    },
                    {
                        "type": "data_integrity",
                        "target": "product information",
                        "priority": "medium",
                        "details": {
                            "pattern": "Product data updates might lack integrity checks"
                        },
                    },
                    {"type": "scan", "target": url, "priority": "medium"},
                ]
            }
            return ecommerce_plan

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

    def execute_task(
        self, task: Dict[str, Any], page: Page, page_info: Dict[str, Any]
    ) -> Dict[str, Any]:
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
        logger.highlight(
            f"ScannerAgent executing task: {task['type']} on {task['target']}"
        )

        response = self.think(input_data, system_prompt)

        # Process the response to extract vulnerability information
        result = {
            "task_type": task["type"],
            "target": task["target"],
            "vulnerability_found": False,  # Will be set to True if a vulnerability is found
            "details": {},
            "actions_performed": [],
        }

        if response.get("tool_calls"):
            # Process tool calls
            for tool_call in response["tool_calls"]:
                # Log the tool being called - safely accessing properties
                if hasattr(tool_call, "function") and hasattr(
                    tool_call.function, "name"
                ):
                    tool_name = tool_call.function.name
                else:
                    tool_name = tool_call.get("function", {}).get(
                        "name", "unknown_tool"
                    )

                logger.info(f"ScannerAgent using tool: {tool_name}", color="cyan")

                # Execute the tool
                tool_result = self.execute_tool(tool_call)

                # Track the action
                result["actions_performed"].append(
                    {"tool": tool_name, "success": tool_result is not None}
                )

                # Check if the tool result indicates a vulnerability
                if isinstance(tool_result, dict):
                    # Check for known vulnerability indicators
                    if tool_result.get(
                        "security_issue_found", False
                    ) or tool_result.get("issues_found", False):
                        result["vulnerability_found"] = True
                        result["vulnerability_type"] = tool_result.get(
                            "issue_type", "Unknown"
                        )
                        result["severity"] = tool_result.get("severity", "medium")
                        result["details"] = tool_result

                        # Log the finding
                        logger.security(
                            f"Found {result['vulnerability_type']} vulnerability with {tool_name}"
                        )

                    # For browser interaction tools, check return values that might indicate vulnerabilities
                    elif tool_name == "execute_js" and tool_result.get(
                        "success", False
                    ):
                        js_result = tool_result.get("result", "")
                        # Look for common security indicators in JS execution results
                        if any(
                            indicator in str(js_result).lower()
                            for indicator in [
                                "password",
                                "token",
                                "api_key",
                                "apikey",
                                "secret",
                                "auth",
                                "cookie",
                            ]
                        ):
                            result["vulnerability_found"] = True
                            result["vulnerability_type"] = (
                                "Client-Side Information Disclosure"
                            )
                            result["severity"] = "medium"
                            result["details"] = {
                                "issue_type": "Client-Side Information Disclosure",
                                "evidence": str(js_result),
                                "tool_result": tool_result,
                            }

                            logger.security(
                                "Found Client-Side Information Disclosure with execute_js"
                            )

        # Get any captured traffic from proxy for additional analysis
        if hasattr(self, "proxy") and self.proxy:
            traffic = self.proxy.get_traffic()
            if traffic:
                # Look for security issues in traffic
                for entry in traffic:
                    # Check for sensitive information in responses
                    if entry.get("response_body"):
                        body = str(entry.get("response_body", ""))
                        if any(
                            indicator in body.lower()
                            for indicator in [
                                "password",
                                "apikey",
                                "api_key",
                                "token",
                                "secret",
                                "private",
                                "credential",
                            ]
                        ):
                            result["vulnerability_found"] = True
                            result["vulnerability_type"] = (
                                "Information Disclosure in Response"
                            )
                            result["severity"] = "high"
                            result["details"] = {
                                "issue_type": "Information Disclosure",
                                "url": entry.get("url", ""),
                                "evidence": "Sensitive information found in response body",
                            }

                            logger.security(
                                f"Found Information Disclosure in response from {entry.get('url', '')}"
                            )

                # Clear traffic for next scan
                self.proxy.clear()

        return result
