from typing import Dict, Any

from playwright.sync_api import Page
from utils.logger import get_logger
from tools.browser_utils import BrowserUtils
from tools.browser_actions import BrowserActions


class BrowserTools:
    """Collection of tools for browser-based security testing."""

    def __init__(self, debug: bool = False):
        self.debug = debug
        self.logger = get_logger()
        self.utils = BrowserUtils(debug=debug)
        self.actions = BrowserActions(debug=debug)
        self.min_actions_required = 3

    def goto(self, page: Page, url: str) -> Dict[str, Any]:
        """Navigate to a URL."""
        return self.actions.goto(page, url)

    def click(self, page: Page, selector: str) -> Dict[str, Any]:
        """Click an element on the page."""
        return self.actions.click(page, selector)

    def fill(self, page: Page, selector: str, value: str) -> Dict[str, Any]:
        """Fill a form field with a value."""
        return self.actions.fill(page, selector, value)

    def submit(self, page: Page, selector: str = "form") -> Dict[str, Any]:
        """Submit a form."""
        return self.actions.submit(page, selector)

    def execute_js(self, page: Page, js_code: str) -> Any:
        """Execute JavaScript code on the page."""
        return self.actions.execute_js(page, js_code)

    def refresh(self, page: Page) -> Dict[str, Any]:
        """Refresh the current page."""
        return self.actions.refresh(page)

    def presskey(self, page: Page, key: str) -> Dict[str, Any]:
        """Press a keyboard key."""
        return self.actions.presskey(page, key)

    def authenticate(self) -> str:
        """Prompt for user authentication."""
        return self.actions.authenticate()

    def complete(self) -> str:
        """Mark current task as complete with validation."""
        if self.actions.actions_performed < self.min_actions_required:
            self.logger.warning(
                f"Completion rejected: Only {self.actions.actions_performed}/{self.min_actions_required} "
                "security actions performed"
            )
            return (
                f"Completion rejected: Insufficient security testing performed "
                f"({self.actions.actions_performed}/{self.min_actions_required} actions). "
                "Please continue testing with more actions before marking complete."
            )

        self.logger.success(
            f"Security testing completed successfully with {self.actions.actions_performed} actions"
        )
        self.actions.actions_performed = 0
        return "Completed"
