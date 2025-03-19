from typing import Dict, Any

from tools.browser_tools_impl import presskey as presskey_impl
from core.scanner_context import scanner_context
from utils.logger import get_logger

def presskey(key: str) -> Dict[str, Any]:
    """
    Press a keyboard key.
    
    Args:
        key: Key to press (e.g., 'Enter', 'Tab')
        
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
            "action": "presskey",
            "key": key,
            "success": False,
            "error": error_msg
        }
    
    return presskey_impl(current_page, key)