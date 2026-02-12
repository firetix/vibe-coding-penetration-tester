from typing import Dict, Any

from tools.browser_tools_impl import refresh as refresh_impl
from core.scanner_context import scanner_context
from utils.logger import get_logger


def refresh() -> Dict[str, Any]:
    """
    Refresh the current page.

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
        return {"action": "refresh", "success": False, "error": error_msg}

    return refresh_impl(current_page)
