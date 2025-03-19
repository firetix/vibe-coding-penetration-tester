from typing import Dict, List, Any, Optional
from playwright.sync_api import sync_playwright, Page, Browser, BrowserContext
import re
import urllib.parse
from bs4 import BeautifulSoup

from utils.logger import get_logger
from core.scanner_context import scanner_context

class Scanner:
    """Handles browser interactions and page analysis."""
    
    def __init__(self, headless: bool = True, slow_mo: int = 50, timeout: int = 30000):
        self.headless = headless
        self.slow_mo = slow_mo
        self.timeout = timeout
        self.logger = get_logger()
        
        # Will be initialized in start()
        self.playwright = None
        self.browser = None
        self.context = None
    
    def start(self) -> None:
        """Initialize the Playwright browser."""
        self.playwright = sync_playwright().start()
        self.browser = self.playwright.chromium.launch(
            headless=self.headless,
            slow_mo=self.slow_mo
        )
        self.context = self.browser.new_context(
            viewport={"width": 1280, "height": 800},
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
        )
        
        # Set default timeout
        self.context.set_default_timeout(self.timeout)
        
        self.logger.info("Browser initialized successfully")
    
    def stop(self) -> None:
        """Close browser and clean up resources."""
        if self.context:
            self.context.close()
        if self.browser:
            self.browser.close()
        if self.playwright:
            self.playwright.stop()
        
        self.logger.info("Browser resources cleaned up")
    
    def load_page(self, url: str) -> Optional[Page]:
        """Load a page in the browser."""
        if not self.context:
            self.logger.error("Browser not initialized. Call start() first.")
            return None
        
        try:
            page = self.context.new_page()
            page.goto(url, wait_until="networkidle")
            self.logger.info(f"Loaded page: {url}")
            
            # Store the page in the global scanner context
            scanner_context.current_page = page
            
            return page
        except Exception as e:
            self.logger.error(f"Failed to load page {url}: {str(e)}")
            return None
    
    def extract_page_info(self, page: Page) -> Dict[str, Any]:
        """Extract detailed information about the page."""
        page_info = {
            "url": page.url,
            "title": page.title(),
            "html": page.content(),
            "links": [],
            "forms": [],
            "inputs": [],
            "scripts": [],
            "headers": {},
            "cookies": page.context.cookies(),
            "technologies": []
        }
        
        # Extract links
        links = page.evaluate("() => Array.from(document.querySelectorAll('a')).map(a => { return {href: a.href, text: a.textContent, id: a.id, class: a.className}})")
        page_info["links"] = links
        
        # Extract forms
        forms = page.evaluate("""() => {
            return Array.from(document.querySelectorAll('form')).map(form => {
                const inputs = Array.from(form.querySelectorAll('input, select, textarea')).map(input => {
                    return {
                        name: input.name,
                        id: input.id,
                        type: input.type || input.tagName.toLowerCase(),
                        value: input.value,
                        placeholder: input.placeholder
                    };
                });
                
                return {
                    id: form.id,
                    name: form.name,
                    action: form.action,
                    method: form.method,
                    inputs: inputs
                };
            });
        }""")
        page_info["forms"] = forms
        
        # Extract all inputs (including those outside forms)
        inputs = page.evaluate("() => Array.from(document.querySelectorAll('input, select, textarea')).map(input => { return {name: input.name, id: input.id, type: input.type || input.tagName.toLowerCase(), value: input.value}})")
        page_info["inputs"] = inputs
        
        # Extract scripts
        scripts = page.evaluate("() => Array.from(document.querySelectorAll('script[src]')).map(s => s.src)")
        page_info["scripts"] = scripts
        
        # Detect technologies (basic implementation)
        html = page_info["html"]
        if "jQuery" in html or "jquery" in html:
            page_info["technologies"].append("jQuery")
        if "react" in html or "React" in html:
            page_info["technologies"].append("React")
        if "angular" in html or "Angular" in html:
            page_info["technologies"].append("Angular")
        if "vue" in html or "Vue" in html:
            page_info["technologies"].append("Vue.js")
        if "wordpress" in html or "WordPress" in html:
            page_info["technologies"].append("WordPress")
        
        return page_info
    
    def intercept_network(self, page: Page, callback):
        """Set up network interception to monitor requests and responses."""
        page.on("request", lambda request: callback("request", request))
        page.on("response", lambda response: callback("response", response))
    
    def execute_javascript(self, page: Page, script: str) -> Any:
        """Execute JavaScript on the page and return the result."""
        try:
            result = page.evaluate(script)
            return result
        except Exception as e:
            self.logger.error(f"Error executing JavaScript: {str(e)}")
            return None
    
    def fill_form(self, page: Page, selector: str, value: str) -> bool:
        """Fill a form input field."""
        try:
            page.fill(selector, value)
            return True
        except Exception as e:
            self.logger.error(f"Error filling form field {selector}: {str(e)}")
            return False
    
    def click_element(self, page: Page, selector: str) -> bool:
        """Click an element on the page."""
        try:
            page.click(selector)
            return True
        except Exception as e:
            self.logger.error(f"Error clicking element {selector}: {str(e)}")
            return False
