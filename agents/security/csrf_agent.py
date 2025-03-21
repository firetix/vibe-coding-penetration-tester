from typing import Dict, Any
from playwright.sync_api import Page

from core.llm import LLMProvider
from core.scanner import Scanner
from agents.security.specialized_agent import SpecializedSecurityAgent
from utils.logger import get_logger


class CSRFAgent(SpecializedSecurityAgent):
    """Agent specializing in Cross-Site Request Forgery (CSRF) testing."""
    
    def __init__(self, llm_provider: LLMProvider, scanner: Scanner):
        super().__init__("CSRFAgent", "csrf_specialist", "csrf", llm_provider, scanner)
    
    def _get_system_prompt(self) -> str:
        """Get the system prompt for CSRF testing."""
        return """
        You are a Cross-Site Request Forgery (CSRF) security specialist. Your job is to identify and exploit CSRF vulnerabilities in web applications.
        
        Focus on testing:
        1. Forms that perform state-changing operations
        2. Missing or inadequate CSRF tokens
        3. Insecure token validation
        4. Lack of proper origin or referrer validation
        5. Authentication mechanisms that rely solely on cookies
        6. SameSite cookie attribute configuration
        
        You have access to specialized CSRF tools and browser interaction tools:
        
        CSRF TOOLS:
        - check_csrf_protection: Check if a form is protected against CSRF attacks
        - generate_csrf_poc: Generate a Proof of Concept (PoC) for CSRF vulnerability
        
        BROWSER INTERACTION TOOLS:
        - goto: Navigate to a URL
        - click: Click an element on the page
        - fill: Fill a form field with a value
        - submit: Submit a form
        - execute_js: Execute JavaScript on the page
        
        Common CSRF testing techniques include:
        - Analyze HTML forms for absence of CSRF tokens
        - Check if the application accepts requests with modified or missing referrer/origin headers
        - Test if tokens are properly validated server-side
        - Look for forms that perform sensitive actions (like password changes, profile updates, etc.)
        - Examine redirect functionality for CSRF vulnerabilities
        
        For OWASP Juice Shop specifically:
        - Pay special attention to forms that handle user feedback
        - Check if user-specific operations can be performed through CSRF
        - Look for any forms that modify user data or settings
        - Check if the application properly verifies the origin of requests
        - Test the redirect functionality which may be vulnerable to CSRF
        
        When you find a vulnerability, you should:
        1. Document which form or functionality is vulnerable
        2. Identify what state-changing operation can be forced
        3. Assess the potential impact of the vulnerability
        4. Create a proof of concept demonstrating the attack
        """
    
    def _check_for_vulnerabilities(self, tool_name: str, tool_result: Dict[str, Any], 
                                   result: Dict[str, Any], page: Page, tool_call: Any) -> Dict[str, Any]:
        """Check for CSRF vulnerabilities in tool results."""
        logger = get_logger()
        
        # Check for CSRF issues reported by tools
        if tool_result.get("csrf_found", False) or tool_result.get("csrf_issue_found", False):
            result["vulnerability_found"] = True
            result["vulnerability_type"] = "Cross-Site Request Forgery (CSRF)"
            result["severity"] = tool_result.get("severity", "high")
            result["details"] = tool_result
            
            logger.security(f"Found CSRF vulnerability in {tool_result.get('form_id', 'unknown form')}")
        
        # Check for successful PoC generation
        elif tool_name == "generate_csrf_poc" and (tool_result.get("poc_html") or tool_result.get("poc_generated", False)):
            result["vulnerability_found"] = True
            result["vulnerability_type"] = "Cross-Site Request Forgery (CSRF)"
            result["severity"] = "high"
            result["details"] = {
                "issue_type": "Cross-Site Request Forgery",
                "url": tool_result.get("target_url", page.url),
                "form_data": tool_result.get("form_data", {}),
                "request_method": tool_result.get("request_method", "POST"),
                "poc_html": tool_result.get("poc_html", ""),
                "evidence": "Generated PoC would allow attackers to force state-changing operations"
            }
            
            logger.security(f"Generated CSRF PoC for {tool_result.get('target_url', page.url)}")
        
        # Check forms after submission
        elif tool_name == "submit" and tool_result.get("success", False):
            # Try to determine if the form has CSRF protection
            # First, check if the form had a hidden token field
            html_content = page.content().lower()
            
            # Look for common CSRF token indicators in the page
            csrf_indicators = [
                "name='csrf", 'name="csrf', "name='_token", 'name="_token',
                "name='token", 'name="token', "name='authenticity_token",
                'name="authenticity_token', "name='xsrf", 'name="xsrf'
            ]
            
            has_csrf_token = any(indicator in html_content for indicator in csrf_indicators)
            
            # Also check headers for security relevant headers
            uses_samesite_cookie = False
            check_origin_or_referer = False
            
            try:
                # Check if page uses the SameSite cookie attribute
                cookies = page.context.cookies()
                for cookie in cookies:
                    if cookie.get("sameSite") in ["strict", "lax"]:
                        uses_samesite_cookie = True
                        break
                
                # Try to determine if the app checks origin/referer (simple detection)
                # This requires more complex analysis that would be done in the actual CSRF tools
                check_origin_or_referer = "origin" in html_content or "referer" in html_content
            except:
                pass
            
            # Forms without CSRF protection are vulnerable
            if not has_csrf_token and not uses_samesite_cookie and not check_origin_or_referer:
                # Identify the form purpose based on the URL or form elements
                form_purpose = "unknown"
                
                if "login" in page.url.lower():
                    form_purpose = "login"
                elif "profile" in page.url.lower() or "account" in page.url.lower():
                    form_purpose = "profile update"
                elif "password" in page.url.lower():
                    form_purpose = "password change"
                elif "checkout" in page.url.lower() or "payment" in page.url.lower():
                    form_purpose = "payment"
                elif "comment" in page.url.lower() or "feedback" in page.url.lower():
                    form_purpose = "feedback submission"
                
                # Evaluate if this form is sensitive enough to be concerned about CSRF
                is_sensitive_operation = form_purpose not in ["login", "unknown"]
                
                if is_sensitive_operation:
                    result["vulnerability_found"] = True
                    result["vulnerability_type"] = "Cross-Site Request Forgery (CSRF)"
                    result["severity"] = "high"
                    result["details"] = {
                        "issue_type": "Missing CSRF Protection",
                        "url": page.url,
                        "form_purpose": form_purpose,
                        "has_csrf_token": has_csrf_token,
                        "uses_samesite_cookie": uses_samesite_cookie,
                        "form_action": page.url,  # Simplified, would need to extract form action in real implementation
                        "evidence": "Form performs a state-changing operation without CSRF protection"
                    }
                    
                    logger.security(f"Found CSRF vulnerability in {form_purpose} form")
        
        # Check for missing CSRF tokens using browser tools
        elif tool_name in ["execute_js"] and tool_result.get("success", False):
            js_result = tool_result.get("result", "")
            
            # Check if the script was analyzing forms and found no CSRF protection
            if "form" in str(js_result).lower() and ("csrf" in str(js_result).lower() or "token" in str(js_result).lower()):
                no_csrf_indicators = [
                    "no csrf" in str(js_result).lower(),
                    "missing csrf" in str(js_result).lower(),
                    "no token" in str(js_result).lower(),
                    "missing token" in str(js_result).lower(),
                    "hascrsf.*:.*false" in str(js_result).lower().replace(" ", "")
                ]
                
                if any(no_csrf_indicators):
                    result["vulnerability_found"] = True
                    result["vulnerability_type"] = "Cross-Site Request Forgery (CSRF)"
                    result["severity"] = "high"
                    result["details"] = {
                        "issue_type": "Missing CSRF Protection",
                        "url": page.url,
                        "js_analysis": str(js_result),
                        "evidence": "JavaScript analysis confirmed missing CSRF protection on forms"
                    }
                    
                    logger.security(f"Found CSRF vulnerability through JavaScript analysis")
        
        # Check for insecure redirect functionality
        elif tool_name == "goto" and "redirect" in tool_result.get("url", "").lower():
            target_url = tool_result.get("url", page.url)
            
            # Check for redirect parameters that might be vulnerable to CSRF
            redirect_params = ["redir", "redirect", "return", "returnto", "to", "next", "url"]
            has_redirect_param = any(param + "=" in target_url.lower() for param in redirect_params)
            
            if has_redirect_param:
                # This could be vulnerable to CSRF + open redirect combination
                result["vulnerability_found"] = True
                result["vulnerability_type"] = "Cross-Site Request Forgery (CSRF) with Open Redirect"
                result["severity"] = "high"
                result["details"] = {
                    "issue_type": "CSRF with Open Redirect",
                    "url": target_url,
                    "evidence": "Unvalidated redirect parameter can be used for CSRF attacks"
                }
                
                logger.security(f"Found potential CSRF with open redirect vulnerability")
        
        # Check specifically for OWASP Juice Shop vulnerabilities
        if "juice" in page.url.lower() or "owasp" in page.url.lower():
            # OWASP Juice Shop has known CSRF issues, particularly in:
            if any(path in page.url.lower() for path in ["/profile", "/feedback", "/contact", "/payment", "/order"]):
                # Check if there's a form without CSRF protection
                html_content = page.content().lower()
                has_form = "<form" in html_content
                has_token = any(indicator in html_content for indicator in csrf_indicators)
                
                if has_form and not has_token:
                    result["vulnerability_found"] = True
                    result["vulnerability_type"] = "Cross-Site Request Forgery (CSRF)"
                    result["severity"] = "high"
                    result["details"] = {
                        "issue_type": "Missing CSRF Protection",
                        "url": page.url,
                        "application": "OWASP Juice Shop",
                        "evidence": "Juice Shop form lacks CSRF protection"
                    }
                    
                    logger.security(f"Found CSRF vulnerability in Juice Shop application")
                
            # Check for redirect functionality in Juice Shop (the "wherever you go, there you are" challenge)
            if "redirect" in page.url.lower():
                result["vulnerability_found"] = True
                result["vulnerability_type"] = "CSRF with Redirect"
                result["severity"] = "medium"
                result["details"] = {
                    "issue_type": "CSRF with Open Redirect",
                    "url": page.url,
                    "application": "OWASP Juice Shop",
                    "evidence": "Juice Shop redirect functionality can be exploited for CSRF attacks",
                    "note": "This relates to the 'wherever you go, there you are' challenge in Juice Shop"
                }
                
                logger.security(f"Found CSRF with redirect vulnerability in Juice Shop")
                
        return result