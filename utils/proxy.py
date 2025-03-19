from typing import List, Dict, Any, Tuple, Optional
from urllib.parse import urlparse
import json
import time
from playwright.sync_api import sync_playwright, Page, Browser, BrowserContext, Playwright

from utils.logger import get_logger

class WebProxy:
    """
    A web proxy that captures and analyzes HTTP traffic during security testing.
    
    This class creates a monitored browser session that intercepts and logs all 
    HTTP requests and responses, providing visibility into network traffic for
    security analysis.
    """

    def __init__(self, base_url: str = None, logger=None):
        """
        Initialize the web proxy with optional base URL.
        
        Args:
            base_url: The base URL for the security testing
            logger: Logger instance to use (will create one if not provided)
        """
        self.base_url = base_url
        self.logger = logger or get_logger()
        self.requests = []
        self.responses = []
        self.page = None
        self.browser = None
        self.context = None
        self.playwright = None
        
    def create_proxy(self, headless: bool = True) -> Tuple[Browser, BrowserContext, Page, Playwright]:
        """
        Create a new browser session with request/response interception.
        
        Args:
            headless: Whether to run the browser in headless mode
            
        Returns:
            Tuple of (browser, context, page, playwright) objects
        """
        self.playwright = sync_playwright().start()
        self.browser = self.playwright.chromium.launch(
            headless=headless,
            slow_mo=50  # Slow down operations for better visibility
        )
        
        self.context = self.browser.new_context(
            viewport={"width": 1280, "height": 800},
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
        )
        
        # Set up request interception
        self.context.on("request", lambda request: self._on_request(request))
        self.context.on("response", lambda response: self._on_response(response))
        
        # Create a new page
        self.page = self.context.new_page()
        
        return self.browser, self.context, self.page, self.playwright
    
    def _on_request(self, request) -> None:
        """
        Callback for intercepted requests.
        
        Args:
            request: The Playwright request object
        """
        try:
            # Skip non-http requests
            if not request.url.startswith(('http://', 'https://')):
                return
                
            # Extract basic request information
            request_data = {
                "method": request.method,
                "url": request.url,
                "resource_type": request.resource_type,
                "headers": request.headers,
                "timestamp": time.time(),
                "post_data": None
            }
            
            # Try to get POST data if applicable
            try:
                if request.method in ["POST", "PUT", "PATCH"] and request.post_data:
                    # Try to parse as JSON first
                    try:
                        request_data["post_data"] = json.loads(request.post_data)
                    except:
                        # If not JSON, store as raw text
                        request_data["post_data"] = request.post_data
            except:
                # POST data might not be accessible in some cases
                pass
                
            self.requests.append(request_data)
            
        except Exception as e:
            self.logger.error(f"Error intercepting request: {str(e)}")
    
    def _on_response(self, response) -> None:
        """
        Callback for intercepted responses.
        
        Args:
            response: The Playwright response object
        """
        try:
            # Skip non-http responses
            if not response.url.startswith(('http://', 'https://')):
                return
                
            # Extract basic response information
            response_data = {
                "url": response.url,
                "status": response.status,
                "status_text": response.status_text,
                "headers": response.headers,
                "timestamp": time.time(),
                "body": None
            }
            
            # Try to get response body for certain content types
            try:
                content_type = response.headers.get("content-type", "")
                if (any(ct in content_type.lower() for ct in ["json", "xml", "html", "text"]) and
                    response.status != 204):  # Skip No Content responses
                    body_text = response.text()
                    
                    # Try to parse as JSON if applicable
                    if "json" in content_type.lower():
                        try:
                            response_data["body"] = json.loads(body_text)
                        except:
                            response_data["body"] = body_text
                    else:
                        # Cap at 5000 chars to avoid memory issues
                        response_data["body"] = body_text[:5000] + ("..." if len(body_text) > 5000 else "")
            except:
                # Body might not be accessible or valid
                pass
                
            self.responses.append(response_data)
            
        except Exception as e:
            self.logger.error(f"Error intercepting response: {str(e)}")
    
    def clear(self) -> None:
        """Clear the stored requests and responses."""
        self.requests.clear()
        self.responses.clear()
        
    def get_traffic(self) -> List[Dict[str, Any]]:
        """
        Get the captured HTTP traffic in chronological order.
        
        Returns:
            List of traffic entries (requests and responses)
        """
        # Combine requests and responses based on URL
        traffic = []
        
        # Process requests first
        for req in self.requests:
            entry = {
                "type": "request",
                "method": req["method"],
                "url": req["url"],
                "resource_type": req["resource_type"],
                "headers": req["headers"],
                "timestamp": req["timestamp"],
                "post_data": req["post_data"],
                "status": None,
                "response_headers": None,
                "response_body": None
            }
            
            # Try to find matching response
            for resp in self.responses:
                if resp["url"] == req["url"]:
                    entry["status"] = resp["status"]
                    entry["response_headers"] = resp["headers"]
                    entry["response_body"] = resp["body"]
                    break
            
            traffic.append(entry)
        
        # Sort by timestamp
        traffic.sort(key=lambda x: x["timestamp"])
        return traffic
    
    def pretty_print_traffic(self) -> str:
        """
        Generate a human-readable summary of captured traffic.
        
        Returns:
            Formatted string representation of traffic
        """
        if not self.requests:
            return ""
            
        traffic = self.get_traffic()
        output = []
        
        output.append("HTTP Traffic Summary:")
        for entry in traffic:
            status_color = ""
            if entry["status"]:
                if 200 <= entry["status"] < 300:
                    status_str = f"HTTP {entry['status']} (Success)"
                elif 300 <= entry["status"] < 400:
                    status_str = f"HTTP {entry['status']} (Redirect)"
                elif 400 <= entry["status"] < 500:
                    status_str = f"HTTP {entry['status']} (Client Error)"
                elif 500 <= entry["status"] < 600:
                    status_str = f"HTTP {entry['status']} (Server Error)"
                else:
                    status_str = f"HTTP {entry['status']}"
            else:
                status_str = "No Response"
                
            # Basic request info
            output.append(f"{entry['method']} {entry['url']} {status_str}")
            
            # Show request headers (limit to important ones)
            important_req_headers = ["content-type", "authorization", "cookie", "x-csrf-token"]
            for header, value in entry["headers"].items():
                if header.lower() in important_req_headers:
                    output.append(f"  Request Header: {header}: {value}")
                    
            # Show POST data if present
            if entry["post_data"]:
                if isinstance(entry["post_data"], dict):
                    # Format JSON nicely
                    output.append("  Request Data (JSON):")
                    for key, value in entry["post_data"].items():
                        output.append(f"    {key}: {value}")
                else:
                    # Truncate if too long
                    post_data = str(entry["post_data"])
                    if len(post_data) > 500:
                        post_data = post_data[:500] + "..."
                    output.append(f"  Request Data: {post_data}")
                    
            # Show response info if available
            if entry["status"]:
                # Important response headers
                important_resp_headers = ["content-type", "set-cookie", "x-frame-options", "content-security-policy"]
                for header, value in entry.get("response_headers", {}).items():
                    if header.lower() in important_resp_headers:
                        output.append(f"  Response Header: {header}: {value}")
                        
                # Show response body if relevant
                if entry.get("response_body"):
                    body = entry["response_body"]
                    if isinstance(body, dict):
                        # Format JSON nicely but limit depth
                        output.append("  Response Data (JSON):")
                        for key, value in body.items():
                            output.append(f"    {key}: {str(value)[:100]}")
                    else:
                        # Truncate if too long
                        body_str = str(body)
                        if len(body_str) > 500:
                            body_str = body_str[:500] + "..."
                        output.append(f"  Response Body (excerpt): {body_str}")
            
            output.append("---")
            
        return "\n".join(output)
    
    def wait_for_network_idle(self, timeout: int = 5000) -> None:
        """
        Wait for network activity to complete.
        
        Args:
            timeout: Maximum time to wait in milliseconds
        """
        if self.page:
            try:
                self.page.wait_for_load_state("networkidle", timeout=timeout)
            except:
                # Timeout reached, continue anyway
                pass

def wait_for_network_idle(page: Page, timeout: int = 5000) -> None:
    """
    Wait for network activity to complete on a page.
    
    Args:
        page: The Playwright page to monitor
        timeout: Maximum time to wait in milliseconds
    """
    try:
        page.wait_for_load_state("networkidle", timeout=timeout)
    except:
        # Timeout reached, continue anyway
        pass