import re
import logging
from urllib.parse import urlparse, urljoin
from typing import Optional, Dict, Any


class BrowserUtils:
    def __init__(self, debug: bool = False):
        self.logger = logging.getLogger("browser_tools")
        self.debug = debug

    def validate_url(self, url: str, base_url: Optional[str] = None) -> str:
        """Validate and normalize a URL, resolving relative URLs if a base URL is provided."""
        if not url:
            raise ValueError("URL cannot be empty")

        # Handle relative URLs
        if base_url and not bool(urlparse(url).netloc):
            url = urljoin(base_url, url)

        # Validate URL format
        parsed = urlparse(url)
        if not parsed.scheme:
            url = f"http://{url}"
            parsed = urlparse(url)

        if not parsed.netloc:
            raise ValueError(f"Invalid URL: {url}")

        return url

    def validate_selector(self, selector: str) -> str:
        """Validate CSS selector for common issues."""
        if not selector or not isinstance(selector, str):
            raise ValueError("Selector must be a non-empty string")

        # Clean common LLM mistakes in selectors
        selector = selector.strip()

        # Remove quotes around selectors
        if (selector.startswith('"') and selector.endswith('"')) or (
            selector.startswith("'") and selector.endswith("'")
        ):
            selector = selector[1:-1]

        # Handle XPath if specified explicitly
        if selector.startswith("xpath="):
            return selector

        # Remove any JavaScript execution attempt
        if "document." in selector or "window." in selector:
            raise ValueError(f"Invalid selector contains JavaScript: {selector}")

        return selector

    def validate_and_fix_js_code(self, js_code: str) -> str:
        """Validate and fix common JavaScript issues."""
        # Check for nested tool calls and remove them
        if re.search(
            r"(?:goto|click|fill|submit|execute_js|refresh|presskey)\s*\(", js_code
        ):
            if self.debug:
                self.logger.warning(f"Nested tool call detected in JS code: {js_code}")
            # Use safe default
            return "() => document.documentElement.innerHTML"

        # Check for balanced parentheses
        open_parens = js_code.count("(")
        close_parens = js_code.count(")")
        if open_parens != close_parens:
            if self.debug:
                self.logger.warning(f"Unbalanced parentheses in JS code: {js_code}")
            return "() => document.documentElement.innerHTML"

        # Fix standalone return statements
        if js_code.strip().startswith("return "):
            js_code = f"() => {{ {js_code} }}"

        # Fix missing semicolons in multi-line code
        if js_code.count("\n") > 0 and ";" not in js_code:
            lines = js_code.strip().split("\n")
            js_code = ";\n".join(lines) + ";"

        return js_code

    def extract_form_data(self, form_data: Any) -> Dict[str, str]:
        """Extract and validate form data from various input formats."""
        if not form_data:
            return {}

        if isinstance(form_data, dict):
            return form_data

        if isinstance(form_data, str):
            try:
                # Try to parse as JSON
                return eval(form_data)
            except:
                # Try to parse as key-value pairs
                pairs = {}
                for line in form_data.split("\n"):
                    if ":" in line:
                        key, value = line.split(":", 1)
                        pairs[key.strip()] = value.strip()
                return pairs

        return {}
