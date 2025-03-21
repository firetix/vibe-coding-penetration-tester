from typing import Dict, Any
from playwright.sync_api import Page

from core.llm import LLMProvider
from core.scanner import Scanner
from agents.security.specialized_agent import SpecializedSecurityAgent
from utils.logger import get_logger


class AuthenticationAgent(SpecializedSecurityAgent):
    """Agent specializing in Authentication and Session Management testing."""
    
    def __init__(self, llm_provider: LLMProvider, scanner: Scanner):
        super().__init__("AuthenticationAgent", "auth_specialist", "auth", llm_provider, scanner)
    
    def _get_system_prompt(self) -> str:
        """Get the system prompt for authentication testing."""
        return """
        You are an Authentication Security specialist. Your job is to identify and exploit authentication and session management vulnerabilities in web applications.
        
        Focus on testing:
        1. Weak password policies and password enumeration
        2. Insecure authentication mechanisms
        3. Flawed session management
        4. Account lockout and timeout issues
        5. Multi-factor authentication bypasses
        6. Default or easily guessable credentials
        7. Remember me functionality vulnerabilities
        
        You have access to specialized authentication testing tools and browser interaction tools:
        
        AUTHENTICATION TOOLS:
        - test_password_policy: Test the password policy strength
        - check_session_security: Check session cookie security settings
        
        BROWSER INTERACTION TOOLS:
        - goto: Navigate to a URL
        - click: Click an element on the page
        - fill: Fill a form field with a value
        - submit: Submit a form
        - execute_js: Execute JavaScript on the page
        
        Common authentication vulnerabilities to look for:
        - Weak password requirements
        - Username enumeration via error messages
        - Predictable or insecure session identifiers
        - Missing session timeouts or session fixation issues
        - Authentication bypasses
        - Lack of brute force protection
        - Plain text password storage
        - SQL injection in login forms: Try payloads like: ' OR 1=1;--
        - Default credentials: Try admin/admin123, admin/password, etc.
        
        For OWASP Juice Shop specifically:
        - Try SQL injection with "' OR 1=1;--" in email field
        - Look for authentication-related information in the page source comments
        - Test for user enumeration in login error messages
        - Look for default/common credentials for administrator accounts
        - Check if email as password works
        """
    
    def _check_for_vulnerabilities(self, tool_name: str, tool_result: Dict[str, Any], 
                                   result: Dict[str, Any], page: Page, tool_call: Any) -> Dict[str, Any]:
        """Check for authentication vulnerabilities in tool results."""
        logger = get_logger()
        
        # Check for authentication issues reported by tools
        if tool_result.get("auth_issue_found", False):
            result["vulnerability_found"] = True
            result["vulnerability_type"] = "Authentication Vulnerability"
            result["severity"] = tool_result.get("severity", "high")
            result["details"] = tool_result
            
            logger.security(f"Found authentication vulnerability: {tool_result.get('issue_type', 'Unknown issue')}")
        
        # Check for weak password policies
        elif tool_name == "test_password_policy" and tool_result.get("weak_policy", False):
            result["vulnerability_found"] = True
            result["vulnerability_type"] = "Weak Password Policy"
            result["severity"] = "medium"
            result["details"] = {
                "issue_type": "Weak Password Policy",
                "url": page.url,
                "accepted_passwords": tool_result.get("accepted_passwords", []),
                "policy_requirements": tool_result.get("policy_requirements", {}),
                "evidence": "Application accepts weak passwords"
            }
            
            logger.security(f"Found weak password policy vulnerability")
        
        # Check for insecure session cookies
        elif tool_name == "check_session_security":
            if not tool_result.get("secure", True) or not tool_result.get("httponly", True):
                result["vulnerability_found"] = True
                result["vulnerability_type"] = "Insecure Session Management"
                result["severity"] = "high"
                result["details"] = {
                    "issue_type": "Insecure Session Cookies",
                    "cookies": tool_result.get("cookies", []),
                    "missing_httponly": not tool_result.get("httponly", False),
                    "missing_secure": not tool_result.get("secure", False),
                    "url": page.url,
                    "evidence": "Session cookies missing security attributes"
                }
                
                logger.security(f"Found insecure session cookie configuration")
        
        # Check for potential session management issues using browser tools
        elif tool_name in ["goto", "submit"]:
            # Check for session identifiers in URL
            current_url = page.url
            
            if any(param in current_url for param in ["jsessionid", "sessionid", "session=", "sid=", "auth="]):
                result["vulnerability_found"] = True
                result["vulnerability_type"] = "Session ID in URL"
                result["severity"] = "high"
                result["details"] = {
                    "issue_type": "Session Identifier in URL",
                    "url": current_url,
                    "evidence": "Session identifiers exposed in URL can lead to session hijacking"
                }
                
                logger.security(f"Found session ID exposed in URL")
            
            # Check for username enumeration via login errors
            if "login" in page.url.lower() and tool_name == "submit":
                # Get the page content and check for specific error messages
                html_content = page.content().lower()
                
                # Check for messages that confirm username exists
                enumeration_patterns = [
                    "invalid password", "incorrect password", "password doesn't match",
                    "password is incorrect", "wrong password"
                ]
                
                username_confirmed = any(pattern in html_content for pattern in enumeration_patterns)
                
                if username_confirmed:
                    result["vulnerability_found"] = True
                    result["vulnerability_type"] = "Username Enumeration"
                    result["severity"] = "medium"
                    result["details"] = {
                        "issue_type": "Username Enumeration",
                        "url": page.url,
                        "evidence": "Login error messages disclose whether a username exists"
                    }
                    
                    logger.security(f"Found username enumeration vulnerability")
                
                # Check for successful login with SQL injection
                if "welcome" in html_content or "dashboard" in html_content or "profile" in html_content or "account" in html_content:
                    # Try to identify if we used SQL injection for login
                    injection_indicators = [
                        "' OR 1=1", "' OR '1'='1", "OR 1=1;--", "admin'--", "' OR 1=1 --"
                    ]
                    
                    # Get the last few actions from memory to check if we used SQL injection
                    sqli_used = False
                    
                    for memory_item in self.memory[-5:]:
                        if any(indicator in str(memory_item).lower() for indicator in injection_indicators):
                            sqli_used = True
                            break
                    
                    if sqli_used:
                        result["vulnerability_found"] = True
                        result["vulnerability_type"] = "SQL Injection in Authentication"
                        result["severity"] = "critical"
                        result["details"] = {
                            "issue_type": "SQL Injection in Authentication",
                            "url": page.url,
                            "evidence": "Successfully logged in using SQL injection payload",
                            "technique": "SQL authentication bypass"
                        }
                        
                        logger.security(f"Found SQL Injection in Authentication vulnerability")
        
        # Check for missing account lockout
        elif tool_name == "fill" and tool_result.get("success", False):
            # Check if we're on a login page and trying a password
            is_password_field = False
            
            # Extract the selector and value
            selector = ""
            value = ""
            
            if hasattr(tool_call, 'function') and hasattr(tool_call.function, 'arguments'):
                selector = getattr(tool_call.function.arguments, 'selector', "")
                value = getattr(tool_call.function.arguments, 'value', "")
            else:
                selector = tool_call.get('function', {}).get('arguments', {}).get("selector", "")
                value = tool_call.get('function', {}).get('arguments', {}).get("value", "")
            
            # Check if we're filling a password field
            is_password_field = "password" in selector.lower()
            
            if is_password_field and hasattr(self, 'memory') and len(self.memory) > 10:
                # Count how many password attempts we've made
                password_attempts = 0
                
                for item in self.memory[-10:]:
                    if item.get("role") == "assistant" and "password" in str(item).lower():
                        password_attempts += 1
                
                # If we've made multiple password attempts without being locked out
                if password_attempts >= 5:
                    result["vulnerability_found"] = True
                    result["vulnerability_type"] = "Missing Account Lockout"
                    result["severity"] = "medium"
                    result["details"] = {
                        "issue_type": "Missing Account Lockout",
                        "url": page.url,
                        "login_attempts": password_attempts,
                        "evidence": "Multiple failed login attempts did not trigger account lockout"
                    }
                    
                    logger.security(f"Found missing account lockout vulnerability after {password_attempts} attempts")
            
            # Check if default/common credentials are being tried
            if is_password_field:
                common_credentials = [
                    "admin/admin123", "admin/password", "admin/admin",
                    "user/password", "customer/customer", "test/test"
                ]
                
                # Check if the entered value matches common passwords
                if value.lower() in ["admin123", "password", "admin", "test", "12345", "123456"]:
                    # Store this attempt for later verification
                    if not hasattr(self, 'common_credential_attempts'):
                        self.common_credential_attempts = []
                    
                    self.common_credential_attempts.append(value)
                    
                    # After submission, we'll check if login was successful
                    # This is handled in the submit tool check
        
        # Check for successful login with default credentials
        elif tool_name == "submit" and hasattr(self, 'common_credential_attempts') and len(self.common_credential_attempts) > 0:
            # Check if we're now logged in by looking for indicators
            html_content = page.content().lower()
            
            if "welcome" in html_content or "dashboard" in html_content or "profile" in html_content or "account" in html_content:
                result["vulnerability_found"] = True
                result["vulnerability_type"] = "Default/Common Credentials"
                result["severity"] = "critical"
                result["details"] = {
                    "issue_type": "Default/Common Credentials",
                    "url": page.url,
                    "credentials_used": self.common_credential_attempts[-1],
                    "evidence": "Successfully logged in using common/default credentials"
                }
                
                logger.security(f"Found default credentials vulnerability")
        
        # Check for client-side authentication bypass (using JavaScript execution)
        elif tool_name == "execute_js" and "login" in page.url.lower():
            script = ""
            if hasattr(tool_call, 'function') and hasattr(tool_call.function, 'arguments'):
                script = getattr(tool_call.function.arguments, 'js_code', "")
            else:
                script = tool_call.get('function', {}).get('arguments', {}).get("js_code", "")
            
            # Check if the script modifies authentication-related elements/variables
            auth_bypass_indicators = [
                "isLoggedIn", "authenticated", "userRole", "isAdmin", 
                "authToken", "localStorage.setItem('token'", "sessionStorage.setItem('auth'"
            ]
            
            if any(indicator in script for indicator in auth_bypass_indicators):
                result["vulnerability_found"] = True
                result["vulnerability_type"] = "Client-Side Authentication Bypass"
                result["severity"] = "high"
                result["details"] = {
                    "issue_type": "Client-Side Authentication Bypass",
                    "url": page.url,
                    "script": script,
                    "evidence": "Authentication bypass through client-side script manipulation"
                }
                
                logger.security(f"Found client-side authentication bypass vulnerability")
        
        return result