from typing import Dict, Any, Optional
from playwright.sync_api import sync_playwright, Page
import time

from utils.logger import get_logger
from core.scanner_context import scanner_context


class Scanner:
    """Handles browser interactions and page analysis."""

    def __init__(self, headless: bool = True, slow_mo: int = 50, timeout: int = 90000):
        self.headless = headless
        self.slow_mo = slow_mo
        self.timeout = timeout
        self.logger = get_logger()

        # Will be initialized in start()
        self.playwright = None
        self.browser = None
        self.context = None

    def start(self) -> None:
        """Initialize the Playwright browser with enhanced configuration."""
        # List of modern user agents to rotate through if needed
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 Edg/117.0.2045.47",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
        ]

        # Use the first user agent by default
        selected_user_agent = user_agents[0]

        try:
            self.playwright = sync_playwright().start()

            # Launch browser with enhanced options
            browser_options = {
                "headless": self.headless,
                "slow_mo": self.slow_mo,
                # Disable web security features for testing purposes
                # Note: ignoreHTTPSErrors is not used at launch level in the Python API
                # Instead, it's passed at the context level as ignore_https_errors
                "args": [
                    "--disable-web-security",
                    "--disable-features=IsolateOrigins,site-per-process",
                    "--disable-site-isolation-trials",
                ],
            }

            self.browser = self.playwright.chromium.launch(**browser_options)

            # Create browser context with enhanced options
            context_options = {
                "viewport": {"width": 1280, "height": 800},
                "user_agent": selected_user_agent,
                "ignore_https_errors": True,
                # Emulate device characteristics
                "device_scale_factor": 1.0,
                "is_mobile": False,
                "has_touch": False,
                # Set geolocation permissions and locale
                "geolocation": {"latitude": 37.7749, "longitude": -122.4194},
                "permissions": ["geolocation"],
                "locale": "en-US",
                "timezone_id": "America/Los_Angeles",
            }

            self.context = self.browser.new_context(**context_options)

            # Set up more resilient timeouts
            self.context.set_default_timeout(self.timeout)
            self.context.set_default_navigation_timeout(self.timeout)

            # Add JavaScript helper functions to all pages
            self.context.add_init_script("""
            window.addEventListener('error', function(e) {
                console.error('JavaScript error intercepted:', e.message);
                return true;
            });
            """)

            self.logger.info("Browser initialized successfully with enhanced settings")
        except Exception as e:
            self.logger.error(f"Error initializing browser: {str(e)}")
            # Try to clean up any resources that might have been created
            self.stop()
            raise

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
        """Load a page in the browser with comprehensive error handling and retry logic."""
        if not self.context:
            self.logger.error("Browser not initialized. Call start() first.")
            return None

        # Normalize URL
        from utils.network_utils import normalize_url

        url = normalize_url(url)

        # Maximum number of retry attempts
        max_retries = 3
        retry_count = 0

        # We'll keep trying with different approaches
        while retry_count < max_retries:
            try:
                # Create a new page for each retry to avoid state issues
                page = self.context.new_page()

                # Add page error handling
                page.on(
                    "pageerror",
                    lambda err: self.logger.error(f"Page JavaScript error: {err}"),
                )
                page.on("crash", lambda: self.logger.error("Page crashed!"))
                page.on(
                    "requestfailed",
                    lambda request: self.logger.warning(
                        f"Request failed: {request.url}"
                    ),
                )

                # Configure page for maximum compatibility
                if retry_count > 0:
                    # On retries, try adjusting settings
                    self.logger.info(
                        f"Retry attempt {retry_count} with adjusted settings..."
                    )

                    # Disable JavaScript if this is a last resort attempt
                    if retry_count == max_retries - 1:
                        self.logger.warning(
                            "Attempting to load page with JavaScript disabled"
                        )
                        # For sync API we need to use a different approach to disable JavaScript
                        # We'll create a new context with JavaScript disabled if needed
                        try:
                            # Close this page
                            page.close()
                            # Create a new context with JS disabled
                            js_disabled_context = self.browser.new_context(
                                javaScriptEnabled=False
                            )
                            # Create a new page
                            page = js_disabled_context.new_page()
                            self.logger.info(
                                "Created new page with JavaScript disabled"
                            )
                        except Exception as js_err:
                            self.logger.error(
                                f"Failed to disable JavaScript: {str(js_err)}"
                            )

                # Attempt to navigate with progressively more lenient conditions
                navigation_methods = [
                    {"wait_until": "networkidle", "timeout": 60000},
                    {"wait_until": "domcontentloaded", "timeout": 60000},
                    {"wait_until": "commit", "timeout": 90000},
                    {"timeout": 120000},  # No wait condition at all
                ]

                # Select navigation method based on retry count
                nav_method = navigation_methods[
                    min(retry_count, len(navigation_methods) - 1)
                ]
                self.logger.info(f"Attempting navigation with settings: {nav_method}")

                # Try to navigate
                response = page.goto(url, **nav_method)

                # Check if we got a valid response
                if response:
                    status = response.status
                    self.logger.info(f"Page loaded with status code: {status}")

                    # Handle HTTP error codes
                    if isinstance(status, int) and status >= 400:
                        self.logger.warning(f"Received HTTP error status: {status}")
                        if retry_count < max_retries - 1:
                            retry_count += 1
                            continue

                    # Success! Store and return the page
                    self.logger.success(f"Successfully loaded page: {url}")
                    scanner_context.current_page = page
                    return page
                else:
                    self.logger.warning("Navigation completed but no response returned")
                    scanner_context.current_page = page
                    return page

            except Exception as e:
                self.logger.error(
                    f"Error during navigation attempt {retry_count}: {str(e)}"
                )
                if retry_count < max_retries - 1:
                    retry_count += 1
                    self.logger.info(
                        f"Retrying page load ({retry_count}/{max_retries})..."
                    )
                    # Add a brief delay before retry
                    time.sleep(2)
                else:
                    # Final attempt failed
                    self.logger.error(f"All page load attempts failed for {url}")
                    return None

        # If we got here, all retries failed
        self.logger.error(f"Failed to load page after {max_retries} attempts")
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
            "technologies": [],
        }

        # Extract links
        links = page.evaluate(
            "() => Array.from(document.querySelectorAll('a')).map(a => { return {href: a.href, text: a.textContent, id: a.id, class: a.className}})"
        )
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
        inputs = page.evaluate(
            "() => Array.from(document.querySelectorAll('input, select, textarea')).map(input => { return {name: input.name, id: input.id, type: input.type || input.tagName.toLowerCase(), value: input.value}})"
        )
        page_info["inputs"] = inputs

        # Extract scripts
        scripts = page.evaluate(
            "() => Array.from(document.querySelectorAll('script[src]')).map(s => s.src)"
        )
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
