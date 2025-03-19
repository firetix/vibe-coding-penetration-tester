from typing import Dict, List, Any, Optional, Union
import json
from playwright.sync_api import Page

from utils.logger import get_logger
from tools.browser_tools import BrowserTools

# Global browser tools instance
_browser_tools = None

def get_browser_tools(debug: bool = False) -> BrowserTools:
    """Get the global browser tools instance, initializing it if necessary."""
    global _browser_tools
    
    if _browser_tools is None:
        _browser_tools = BrowserTools(debug=debug)
    
    return _browser_tools

# Function implementations for browser interaction

def goto(page: Page, url: str) -> Dict[str, Any]:
    """
    Navigate to a URL.
    
    Args:
        page: Playwright page object
        url: URL to navigate to
        
    Returns:
        Result dictionary with page content
    """
    tools = get_browser_tools()
    result = tools.goto(page, url)
    
    return {
        "action": "goto",
        "url": url,
        "success": "Error" not in result,
        "content_length": len(result) if "Error" not in result else 0
    }

def click(page: Page, selector: str) -> Dict[str, Any]:
    """
    Click an element on the page.
    
    Args:
        page: Playwright page object
        selector: CSS or XPath selector for the element to click
        
    Returns:
        Result dictionary with action status
    """
    tools = get_browser_tools()
    result = tools.click(page, selector)
    
    return {
        "action": "click",
        "selector": selector,
        "success": "Error" not in result,
        "content_length": len(result) if "Error" not in result else 0
    }

def fill(page: Page, selector: str, value: str) -> Dict[str, Any]:
    """
    Fill a form field with a value.
    
    Args:
        page: Playwright page object
        selector: CSS or XPath selector for the form field
        value: Value to fill in the field
        
    Returns:
        Result dictionary with action status
    """
    tools = get_browser_tools()
    result = tools.fill(page, selector, value)
    
    return {
        "action": "fill",
        "selector": selector,
        "value": value,
        "success": "Error" not in result
    }

def submit(page: Page, selector: str) -> Dict[str, Any]:
    """
    Submit a form.
    
    Args:
        page: Playwright page object
        selector: CSS or XPath selector for the form or submit button
        
    Returns:
        Result dictionary with action status
    """
    tools = get_browser_tools()
    result = tools.submit(page, selector)
    
    return {
        "action": "submit",
        "selector": selector,
        "success": "Error" not in result,
        "content_length": len(result) if "Error" not in result else 0
    }

def execute_js(page: Page, js_code: str) -> Dict[str, Any]:
    """
    Execute JavaScript on the page.
    
    Args:
        page: Playwright page object
        js_code: JavaScript code to execute
        
    Returns:
        Result dictionary with JavaScript execution result
    """
    tools = get_browser_tools()
    
    try:
        result = tools.execute_js(page, js_code)
        
        # Convert result to a serializable format
        if isinstance(result, (dict, list, str, int, float, bool, type(None))):
            serialized_result = result
        else:
            # For non-serializable types, convert to string
            serialized_result = str(result)
            
        return {
            "action": "execute_js",
            "js_code": js_code,
            "success": True,
            "result": serialized_result
        }
    except Exception as e:
        return {
            "action": "execute_js",
            "js_code": js_code,
            "success": False,
            "error": str(e)
        }

def refresh(page: Page) -> Dict[str, Any]:
    """
    Refresh the current page.
    
    Args:
        page: Playwright page object
        
    Returns:
        Result dictionary with action status
    """
    tools = get_browser_tools()
    result = tools.refresh(page)
    
    return {
        "action": "refresh",
        "success": "Error" not in result,
        "url": page.url,
        "content_length": len(result) if "Error" not in result else 0
    }

def presskey(page: Page, key: str) -> Dict[str, Any]:
    """
    Press a keyboard key.
    
    Args:
        page: Playwright page object
        key: Key to press (e.g., 'Enter', 'Tab')
        
    Returns:
        Result dictionary with action status
    """
    tools = get_browser_tools()
    result = tools.presskey(page, key)
    
    return {
        "action": "presskey",
        "key": key,
        "success": "Error" not in result
    }

def auth_needed() -> Dict[str, Any]:
    """
    Signal that authentication is needed.
    
    Returns:
        Result dictionary with action status
    """
    tools = get_browser_tools()
    result = tools.auth_needed()
    
    return {
        "action": "auth_needed",
        "success": True,
        "message": result
    }

def complete() -> Dict[str, Any]:
    """
    Mark the current testing task as complete.
    
    Returns:
        Result dictionary with completion status
    """
    tools = get_browser_tools()
    result = tools.complete()
    
    is_complete = "Completed" in result
    
    return {
        "action": "complete",
        "success": is_complete,
        "message": result,
        "actions_performed": tools.security_actions_performed if not is_complete else 0
    }

def get_browser_interaction_tools() -> List[Dict[str, Any]]:
    """Get tool definitions for browser interaction."""
    logger = get_logger()
    
    # Define browser tool definitions
    tools = [
        {
            "type": "function",
            "function": {
                "name": "goto",
                "description": "Navigate to a URL",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "URL to navigate to"
                        }
                    },
                    "required": ["url"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "click",
                "description": "Click an element on the page",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "selector": {
                            "type": "string",
                            "description": "CSS or XPath selector for the element to click"
                        }
                    },
                    "required": ["selector"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "fill",
                "description": "Fill a form field with a value",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "selector": {
                            "type": "string",
                            "description": "CSS or XPath selector for the form field"
                        },
                        "value": {
                            "type": "string",
                            "description": "Value to fill in the field"
                        }
                    },
                    "required": ["selector", "value"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "submit",
                "description": "Submit a form",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "selector": {
                            "type": "string",
                            "description": "CSS or XPath selector for the form or submit button"
                        }
                    },
                    "required": ["selector"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "execute_js",
                "description": "Execute JavaScript on the page",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "js_code": {
                            "type": "string",
                            "description": "JavaScript code to execute"
                        }
                    },
                    "required": ["js_code"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "refresh",
                "description": "Refresh the current page",
                "parameters": {
                    "type": "object",
                    "properties": {}
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "presskey",
                "description": "Press a keyboard key",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "key": {
                            "type": "string",
                            "description": "Key to press (e.g., 'Enter', 'Tab')"
                        }
                    },
                    "required": ["key"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "auth_needed",
                "description": "Signal that authentication is needed",
                "parameters": {
                    "type": "object",
                    "properties": {}
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "complete",
                "description": "Mark the current testing task as complete",
                "parameters": {
                    "type": "object",
                    "properties": {}
                }
            }
        }
    ]
    
    return tools