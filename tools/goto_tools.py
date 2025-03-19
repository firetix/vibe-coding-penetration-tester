from typing import Dict, Any

from tools.browser_tools_impl import goto as goto_impl
from core.scanner_context import scanner_context
from utils.logger import get_logger

def goto(url: str) -> Dict[str, Any]:
    """
    Navigate to a URL.
    
    Args:
        url: URL to navigate to
        
    Returns:
        Result dictionary with page content
    """
    logger = get_logger()
    
    # Get the current page from the scanner context
    current_page = scanner_context.current_page
    
    # If no page is available, log an error
    if current_page is None:
        error_msg = "No page object available. Please make sure the browser is initialized."
        logger.error(error_msg)
        return {
            "action": "goto",
            "url": url,
            "success": False,
            "error": error_msg
        }
    
    return goto_impl(current_page, url)