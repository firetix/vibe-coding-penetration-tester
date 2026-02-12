from typing import Dict, Any

from tools.browser_tools_impl import fill as fill_impl
from core.scanner_context import scanner_context
from utils.logger import get_logger


def fill(selector: str, value: str) -> Dict[str, Any]:
    """
    Fill a form field with a value.

    Args:
        selector: CSS or XPath selector for the form field
        value: Value to fill in the field

    Returns:
        Result dictionary with action status
    """
    logger = get_logger()

    # Get the current page from the scanner context
    current_page = scanner_context.current_page

    # If no page is available, log an error
    if current_page is None:
        error_msg = (
            "No page object available. Please make sure the browser is initialized."
        )
        logger.error(error_msg)
        return {
            "action": "fill",
            "selector": selector,
            "value": value,
            "success": False,
            "error": error_msg,
        }

    return fill_impl(current_page, selector, value)
