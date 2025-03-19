from typing import Dict, Any

from tools.browser_tools_impl import execute_js as execute_js_impl
from core.scanner_context import scanner_context
from utils.logger import get_logger

def execute_js(js_code: str) -> Dict[str, Any]:
    """
    Execute JavaScript on the page.
    
    Args:
        js_code: JavaScript code to execute
        
    Returns:
        Result dictionary with JavaScript execution result
    """
    logger = get_logger()
    
    # Get the current page from the scanner context
    current_page = scanner_context.current_page
    
    # If no page is available, log an error
    if current_page is None:
        error_msg = "No page object available. Please make sure the browser is initialized."
        logger.error(error_msg)
        return {
            "action": "execute_js",
            "js_code": js_code,
            "success": False,
            "error": error_msg
        }
    
    return execute_js_impl(current_page, js_code)