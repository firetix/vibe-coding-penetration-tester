from typing import Dict, Any

from tools.browser_tools_impl import submit as submit_impl
from core.scanner_context import scanner_context
from utils.logger import get_logger

def submit(selector: str) -> Dict[str, Any]:
    """
    Submit a form.
    
    Args:
        selector: CSS or XPath selector for the form or submit button
        
    Returns:
        Result dictionary with action status
    """
    logger = get_logger()
    
    # Get the current page from the scanner context
    current_page = scanner_context.current_page
    
    # If no page is available, log an error
    if current_page is None:
        error_msg = "No page object available. Please make sure the browser is initialized."
        logger.error(error_msg)
        return {
            "action": "submit",
            "selector": selector,
            "success": False,
            "error": error_msg
        }
    
    return submit_impl(current_page, selector)