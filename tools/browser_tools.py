import sys
import re
import json
import time
from io import StringIO
from typing import Dict, List, Any, Optional, Tuple, Union
from urllib.parse import urlparse
from playwright.sync_api import Page

from utils.logger import get_logger
from utils.network_utils import wait_for_network_idle, normalize_url

class BrowserTools:
    """
    Collection of tools for browser-based security testing.
    
    This class provides methods for interacting with web pages during security testing,
    including page navigation, element interaction, form manipulation, and JavaScript execution.
    It tracks security testing actions and ensures proper validation and error handling.
    """
    
    def __init__(self, debug: bool = False):
        """
        Initialize the browser tools.
        
        Args:
            debug: Whether to enable debug output
        """
        self.debug = debug
        self.logger = get_logger()
        
        # Security testing state tracking
        self.security_actions_performed = 0
        self.min_actions_required = 3  # Minimum security actions required before completion
        self.first_navigation = False
        
        # Store the current URL for relative URL resolution
        self.current_url = None
        
    def execute_js(self, page: Page, js_code: str) -> Any:
        """
        Execute JavaScript code on the page.
        
        Args:
            page: Playwright page object
            js_code: JavaScript code to execute
            
        Returns:
            Result of JavaScript evaluation
        """
        # Validate and fix common JavaScript issues
        js_code = self._validate_and_fix_js_code(js_code)
        
        try:
            # Count this as a security action (JS execution is often used for testing)
            self.security_actions_performed += 1
            self.logger.info(f"Executing JavaScript: {js_code[:50]}{'...' if len(js_code) > 50 else ''}", color="yellow")
            result = page.evaluate(js_code)
            return result
        except Exception as e:
            if "Illegal return statement" in str(e) and not js_code.strip().startswith("() =>"):
                # Try wrapping in an anonymous function
                wrapped_code = f"() => {{ {js_code} }}"
                if self.debug:
                    self.logger.debug(f"Retrying with wrapped JS code: {wrapped_code}")
                return page.evaluate(wrapped_code)
            
            self.logger.error(f"Error executing JavaScript: {str(e)}")
            raise
            
    def _validate_and_fix_js_code(self, js_code: str) -> str:
        """
        Validate and fix common JavaScript issues.
        
        Args:
            js_code: JavaScript code to validate and fix
            
        Returns:
            Fixed JavaScript code
        """
        # First, check for any nested tool calls and remove them
        # This prevents issues like execute_js(page, "execute_js(page, """)
        if re.search(r'(?:goto|click|fill|submit|execute_js|refresh|presskey)\s*\(', js_code):
            # We found what appears to be a nested tool call, clean it up
            if self.debug:
                self.logger.warning(f"Possible nested tool call detected in JS code: {js_code}")
            # Extract just the JavaScript part if possible, otherwise use a safe default
            js_code = "() => document.documentElement.innerHTML"
        
        # Ensure code doesn't contain unbalanced parentheses
        open_parens = js_code.count('(')
        close_parens = js_code.count(')')
        if open_parens != close_parens:
            if self.debug:
                self.logger.warning(f"Unbalanced parentheses in JS code: {js_code}")
            # Simplify to a safe default if the JS is likely malformed
            js_code = "() => document.documentElement.innerHTML"
        
        # Fix standalone return statements
        if js_code.strip().startswith('return '):
            js_code = f"() => {{ {js_code} }}"
        
        # Ensure async/await is properly handled
        if 'await ' in js_code and not js_code.strip().startswith('async'):
            if js_code.strip().startswith('() =>'):
                js_code = js_code.replace('() =>', 'async () =>')
            elif not js_code.strip().startswith('async () =>'):
                js_code = f"async () => {{ {js_code} }}"
        
        # Fix direct document.querySelector usage to ensure it's wrapped properly
        if 'document.querySelector' in js_code and not '() =>' in js_code:
            js_code = f"() => {{ {js_code} }}"
        
        # Remove standalone console.log statements without return values
        if 'console.log' in js_code and not 'return' in js_code:
            js_code = js_code.replace('console.log(', 'return console.log(')
            
        return js_code

    def click(self, page: Page, selector: str) -> str:
        """
        Click an element on the page.
        
        Args:
            page: Playwright page object
            selector: CSS or XPath selector for element to click
            
        Returns:
            Page HTML after click
        """
        self.logger.info(f"Clicking element: {selector}", color="cyan")
        try:
            page.click(selector, timeout=5000)
            # Count this as a security action (interaction with the page)
            self.security_actions_performed += 1
            # Wait for any resulting navigation or XHR to complete
            wait_for_network_idle(page)
            return page.content()
        except Exception as e:
            self.logger.error(f"Error clicking element '{selector}': {str(e)}")
            return f"Error: {str(e)}"

    def fill(self, page: Page, selector: str, value: str) -> str:
        """
        Fill a form field.
        
        Args:
            page: Playwright page object
            selector: CSS or XPath selector for input field
            value: Value to fill
            
        Returns:
            Page HTML after filling
        """
        self.logger.info(f"Filling form field '{selector}' with value: {value}", color="cyan")
        try:
            page.fill(selector, value, timeout=5000)
            # Count this as a security action (form interaction is common for testing)
            self.security_actions_performed += 1
            return page.content()
        except Exception as e:
            self.logger.error(f"Error filling form field '{selector}': {str(e)}")
            return f"Error: {str(e)}"

    def submit(self, page: Page, selector: str) -> str:
        """
        Submit a form by clicking an element.
        
        Args:
            page: Playwright page object
            selector: CSS or XPath selector for submit element
            
        Returns:
            Page HTML after submission
        """
        self.logger.info(f"Submitting form: {selector}", color="cyan")
        try:
            page.click(selector, timeout=5000)
            # Count this as a security action (form submission is critical for testing)
            self.security_actions_performed += 1
            # Wait for form submission to complete
            wait_for_network_idle(page)
            return page.content()
        except Exception as e:
            self.logger.error(f"Error submitting form '{selector}': {str(e)}")
            return f"Error: {str(e)}"

    def presskey(self, page: Page, key: str) -> str:
        """
        Press a keyboard key.
        
        Args:
            page: Playwright page object
            key: Key to press
            
        Returns:
            Page HTML after key press
        """
        self.logger.info(f"Pressing key: {key}", color="cyan")
        try:
            page.keyboard.press(key)
            # Count this as a security action
            self.security_actions_performed += 1
            return page.content()
        except Exception as e:
            self.logger.error(f"Error pressing key '{key}': {str(e)}")
            return f"Error: {str(e)}"

    def goto(self, page: Page, url: str) -> str:
        """
        Navigate to a URL.
        
        Args:
            page: Playwright page object
            url: URL to navigate to
            
        Returns:
            Page HTML after navigation
        """
        # Define an expanded URL mapping for common keywords
        URL_MAPPING = {
            "documentation": "/docs/",
            "docs": "/docs/",
            "doc": "/docs/",
            "api": "/api/",
            "swagger": "/swagger/",
            "api-docs": "/api-docs/",
            "home": "/",
            "login": "/login/",
            "admin": "/admin/"
        }
        
        # Clean up URL - remove any trailing natural language
        if url and ' ' in url:
            # Extract just the URL part before any natural language description
            url_match = re.match(r'([^"\']*?(?:\.html|\.php|\.aspx|\.js|\.css|\.json|\/)?)(?:\s|$)', url)
            if url_match:
                url = url_match.group(1)
            else:
                # If no clear endpoint, take everything before the first space
                url = url.split(' ')[0]
                
            if self.debug:
                self.logger.debug(f"Cleaned URL from natural language: '{url}'")
        
        # Handle keyword to URL mapping with proper sanitization
        if url and not url.startswith(('http://', 'https://', '/')):
            # Check for exact match in URL_MAPPING
            url_lower = url.lower().strip()
            if url_lower in URL_MAPPING:
                url = URL_MAPPING[url_lower]
                if self.debug:
                    self.logger.debug(f"URL mapping converted '{url_lower}' to path '{url}'")
            else:
                # For any other string that's not in our mapping, add leading slash
                url = '/' + url.lstrip('/')
        
        # Sanitize paths to prevent traversal attacks
        url = url.replace('../', '')
        
        # Fix relative URLs
        if url.startswith('/'):
            if hasattr(self, 'current_url') and self.current_url:
                # Extract base URL from current URL
                base_url = re.match(r'(https?://[^/]+)', self.current_url)
                if base_url:
                    url = base_url.group(1) + url
                else:
                    # Fallback - prepend the current domain if we can extract it
                    parsed = urlparse(self.current_url)
                    if parsed.netloc:
                        url = f"{parsed.scheme}://{parsed.netloc}{url}"
        
        # Store the current URL for future reference
        self.current_url = url
        
        # Only count as a security action if this isn't the initial navigation
        # or if it's navigating to a non-root path that might be more interesting for testing
        if self.first_navigation or '/' in url[8:]:
            self.security_actions_performed += 1
        else:
            # Mark that we've done the first navigation
            self.first_navigation = True
            
        self.logger.info(f"Navigating to: {url}", color="cyan")
        try:
            page.goto(url)
            # Wait for page to fully load
            wait_for_network_idle(page)
            return page.content()
        except Exception as e:
            # If navigation fails with the current URL, try adding /docs/ as fallback
            if "/docs/" not in url and "documentation" in url.lower():
                try:
                    # Extract base domain and add /docs/
                    parsed = urlparse(url)
                    fallback_url = f"{parsed.scheme}://{parsed.netloc}/docs/"
                    self.logger.warning(f"Primary navigation failed. Trying fallback to {fallback_url}")
                    page.goto(fallback_url)
                    return page.content()
                except Exception as e2:
                    # If fallback fails, report the original error
                    self.logger.error(f"Error navigating to {url}: {str(e)}")
                    self.logger.error(f"Fallback to {fallback_url} also failed: {str(e2)}")
                    return f"Error: {str(e)}"
            else:
                # Report the original error
                self.logger.error(f"Error navigating to {url}: {str(e)}")
                return f"Error: {str(e)}"

    def refresh(self, page: Page) -> str:
        """
        Refresh the current page.
        
        Args:
            page: Playwright page object
            
        Returns:
            Page HTML after refresh
        """
        self.logger.info("Refreshing page", color="cyan")
        try:
            page.reload()
            # Count this as a security action
            self.security_actions_performed += 1
            # Wait for refresh to complete
            wait_for_network_idle(page)
            return page.content()
        except Exception as e:
            self.logger.error(f"Error refreshing page: {str(e)}")
            return f"Error: {str(e)}"

    def python_interpreter(self, code: str) -> str:
        """
        Execute Python code and capture output.
        
        Args:
            code: Python code to execute
            
        Returns:
            Output from code execution
        """
        self.logger.info(f"Executing Python code: {code[:50]}{'...' if len(code) > 50 else ''}", color="yellow")
        output_buffer = StringIO()
        old_stdout = sys.stdout
        sys.stdout = output_buffer
        
        try:
            exec(code)
            output = output_buffer.getvalue()
            # Count this as a security action (code execution is important for testing)
            self.security_actions_performed += 1
            return output
        except Exception as e:
            error_message = f"Error executing Python code: {str(e)}"
            self.logger.error(error_message)
            return error_message
        finally:
            sys.stdout = old_stdout
            output_buffer.close()

    def get_user_input(self, prompt: str) -> str:
        """
        Get input from user.
        
        Args:
            prompt: Prompt to display to user
            
        Returns:
            Confirmation message
        """
        self.logger.info(f"Requesting user input: {prompt}", color="cyan")
        try:
            input(prompt)
            return "Input received"
        except:
            return "Input cancelled"

    def auth_needed(self) -> str:
        """
        Prompt for user authentication.
        
        Returns:
            Confirmation message
        """
        self.logger.info("Authentication needed. Please login and press enter to continue.", color="yellow")
        try:
            input("Press Enter when authentication is complete...")
            # Count this as a security action
            self.security_actions_performed += 1
            return "Authentication confirmed"
        except:
            return "Authentication cancelled"

    def complete(self) -> str:
        """
        Mark current task as complete with validation.
        
        Checks if sufficient security testing has been performed before allowing completion.
        
        Returns:
            Completion message or rejection message
        """
        if self.security_actions_performed < self.min_actions_required:
            # Not enough security testing was performed
            self.logger.warning(f"Completion rejected: Only {self.security_actions_performed}/{self.min_actions_required} security actions performed")
            return f"Completion rejected: Insufficient security testing performed ({self.security_actions_performed}/{self.min_actions_required} actions). Please continue testing with more actions before marking complete."
        
        # Reset action counter for next test plan
        self.logger.success(f"Security testing completed successfully with {self.security_actions_performed} actions")
        self.security_actions_performed = 0
        return "Completed"