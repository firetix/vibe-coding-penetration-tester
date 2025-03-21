import logging
import time
from typing import Dict, Any, Optional, Union
from playwright.sync_api import Page, TimeoutError

from utils.logger import get_logger
from utils.network_utils import wait_for_network_idle
from tools.browser_utils import BrowserUtils

class BrowserActions:
    def __init__(self, debug: bool = False):
        self.debug = debug
        self.logger = get_logger()
        self.utils = BrowserUtils(debug=debug)
        self.current_url = None
        self.actions_performed = 0
    
    def goto(self, page: Page, url: str) -> Dict[str, Any]:
        try:
            validated_url = self.utils.validate_url(url, self.current_url)
            
            self.logger.info(f"Navigating to: {validated_url}", color="blue")
            
            # Navigate to the URL with increased timeout and more robust error handling
            try:
                response = page.goto(validated_url, wait_until="networkidle", timeout=60000)
            except Exception as nav_error:
                self.logger.warning(f"Networkidle navigation failed: {str(nav_error)}, falling back to domcontentloaded")
                # If networkidle fails, try with domcontentloaded which is more reliable
                try:
                    response = page.goto(validated_url, wait_until="domcontentloaded", timeout=60000)
                except Exception as nav_error2:
                    self.logger.warning(f"Domcontentloaded navigation also failed: {str(nav_error2)}, trying no wait condition")
                    # Last resort - try with no wait condition
                    response = page.goto(validated_url, timeout=90000)
            
            # Store current URL for resolving relative URLs later
            self.current_url = page.url
            
            # Wait for network to be idle
            wait_for_network_idle(page)
            
            self.actions_performed += 1
            
            # Return result
            status_code = response.status if response else 0
            result = {
                "success": 200 <= status_code < 400,
                "url": page.url,
                "status": status_code
            }
            
            if result["success"]:
                self.logger.success(f"Successfully navigated to {page.url} (Status: {status_code})")
            else:
                self.logger.error(f"Navigation failed or returned error: {page.url} (Status: {status_code})")
                
            return result
            
        except Exception as e:
            self.logger.error(f"Error navigating to URL: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def click(self, page: Page, selector: str) -> Dict[str, Any]:
        try:
            selector = self.utils.validate_selector(selector)
            
            self.logger.info(f"Clicking element: {selector}", color="blue")
            
            # Wait for the element to be visible
            try:
                page.wait_for_selector(selector, state="visible", timeout=5000)
            except TimeoutError:
                self.logger.warning(f"Element not visible, but attempting to click anyway: {selector}")
            
            # Click the element
            page.click(selector)
            
            # Wait for network to be idle
            wait_for_network_idle(page)
            
            self.actions_performed += 1
            
            # Return result
            result = {
                "success": True,
                "selector": selector,
                "url": page.url
            }
            
            self.logger.success(f"Successfully clicked {selector}")
            return result
            
        except Exception as e:
            self.logger.error(f"Error clicking element: {str(e)}")
            return {"success": False, "selector": selector, "error": str(e)}
    
    def fill(self, page: Page, selector: str, value: str) -> Dict[str, Any]:
        try:
            selector = self.utils.validate_selector(selector)
            
            self.logger.info(f"Filling {selector} with value (length: {len(value)})", color="blue")
            
            # Wait for the element to be visible
            try:
                page.wait_for_selector(selector, state="visible", timeout=5000)
            except TimeoutError:
                self.logger.warning(f"Element not visible, but attempting to fill anyway: {selector}")
            
            # Clear the field first
            page.fill(selector, "")
            
            # Fill the field
            page.fill(selector, value)
            
            self.actions_performed += 1
            
            # Return result
            result = {
                "success": True,
                "selector": selector,
                "value_length": len(value)
            }
            
            self.logger.success(f"Successfully filled {selector}")
            return result
            
        except Exception as e:
            self.logger.error(f"Error filling element: {str(e)}")
            return {"success": False, "selector": selector, "error": str(e)}
    
    def submit(self, page: Page, selector: str = "form") -> Dict[str, Any]:
        try:
            selector = self.utils.validate_selector(selector)
            
            self.logger.info(f"Submitting form: {selector}", color="blue")
            
            # Get current URL before submission for comparison
            before_url = page.url
            
            # Try multiple submission methods for better compatibility
            try:
                # Method 1: Using the press Enter method
                page.press(selector, "Enter")
            except Exception as e1:
                try:
                    # Method 2: Using JS submit()
                    page.evaluate(f"document.querySelector('{selector}').submit()")
                except Exception as e2:
                    try:
                        # Method 3: Click the submit button
                        submit_selector = f"{selector} [type=submit]"
                        page.click(submit_selector)
                    except Exception as e3:
                        # All methods failed
                        raise Exception(f"All submission methods failed: {e1}; {e2}; {e3}")
            
            # Wait for navigation and network idle
            wait_for_network_idle(page)
            
            self.actions_performed += 1
            
            # Check if URL changed to detect successful submission
            url_changed = before_url != page.url
            
            # Return result
            result = {
                "success": True,
                "selector": selector,
                "url_changed": url_changed,
                "url": page.url
            }
            
            self.logger.success(f"Successfully submitted form. URL changed: {url_changed}")
            return result
            
        except Exception as e:
            self.logger.error(f"Error submitting form: {str(e)}")
            return {"success": False, "selector": selector, "error": str(e)}
    
    def execute_js(self, page: Page, js_code: str) -> Any:
        try:
            js_code = self.utils.validate_and_fix_js_code(js_code)
            
            self.logger.info(f"Executing JavaScript: {js_code[:50]}{'...' if len(js_code) > 50 else ''}", 
                           color="yellow")
            
            # Execute the JavaScript
            result = page.evaluate(js_code)
            
            self.actions_performed += 1
            
            # Format result for better readability
            if result is None:
                formatted_result = {"success": True, "result": None}
            elif isinstance(result, (dict, list)):
                formatted_result = {"success": True, "result": result}
            else:
                formatted_result = {"success": True, "result": str(result)}
            
            self.logger.success(f"JavaScript execution successful")
            return formatted_result
            
        except Exception as e:
            if "Illegal return statement" in str(e) and not js_code.strip().startswith("() =>"):
                # Try wrapping in an anonymous function
                wrapped_code = f"() => {{ {js_code} }}"
                return self.execute_js(page, wrapped_code)
            
            self.logger.error(f"Error executing JavaScript: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def refresh(self, page: Page) -> Dict[str, Any]:
        try:
            self.logger.info("Refreshing page", color="blue")
            
            # Refresh the page with increased timeout and error handling
            try:
                page.reload(wait_until="networkidle", timeout=60000)
            except Exception as e:
                self.logger.warning(f"Networkidle reload failed: {str(e)}, trying domcontentloaded")
                try:
                    page.reload(wait_until="domcontentloaded", timeout=60000)
                except Exception as e2:
                    self.logger.warning(f"Domcontentloaded reload also failed: {str(e2)}, using no wait condition")
                    page.reload(timeout=90000)
            
            # Wait for network to be idle
            wait_for_network_idle(page)
            
            self.actions_performed += 1
            
            # Return result
            result = {
                "success": True,
                "url": page.url
            }
            
            self.logger.success("Page refreshed successfully")
            return result
            
        except Exception as e:
            self.logger.error(f"Error refreshing page: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def presskey(self, page: Page, key: str) -> Dict[str, Any]:
        try:
            self.logger.info(f"Pressing key: {key}", color="blue")
            
            # Press the key
            page.keyboard.press(key)
            
            # Wait briefly for any resulting actions
            time.sleep(0.5)
            
            self.actions_performed += 1
            
            # Return result
            result = {
                "success": True,
                "key": key
            }
            
            self.logger.success(f"Successfully pressed key: {key}")
            return result
            
        except Exception as e:
            self.logger.error(f"Error pressing key: {str(e)}")
            return {"success": False, "key": key, "error": str(e)}
    
    def authenticate(self) -> str:
        self.logger.info("Authentication needed. Please login and press enter to continue.", 
                       color="yellow")
        try:
            input("Press Enter when authentication is complete...")
            self.actions_performed += 1
            return "Authentication confirmed"
        except:
            return "Authentication cancelled"