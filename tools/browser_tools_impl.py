from typing import Dict, List, Any
from playwright.sync_api import Page

from tools.browser_tools import BrowserTools

# Global browser tools instance
_browser_tools = None

def get_browser_tools(debug: bool = False) -> BrowserTools:
    global _browser_tools
    if _browser_tools is None:
        _browser_tools = BrowserTools(debug=debug)
    return _browser_tools

# Function implementations for browser interaction
def goto(page: Page, url: str) -> Dict[str, Any]:
    """Navigate to a URL."""
    tools = get_browser_tools()
    result = tools.goto(page, url)
    
    return {
        "action": "goto",
        "url": url,
        "success": result.get("success", False),
        "status": result.get("status", 0)
    }

def click(page: Page, selector: str) -> Dict[str, Any]:
    """Click an element on the page."""
    tools = get_browser_tools()
    result = tools.click(page, selector)
    
    return {
        "action": "click",
        "selector": selector,
        "success": result.get("success", False)
    }

def fill(page: Page, selector: str, value: str) -> Dict[str, Any]:
    """Fill a form field with a value."""
    tools = get_browser_tools()
    result = tools.fill(page, selector, value)
    
    return {
        "action": "fill",
        "selector": selector,
        "success": result.get("success", False)
    }

def submit(page: Page, selector: str = "form") -> Dict[str, Any]:
    """Submit a form."""
    tools = get_browser_tools()
    result = tools.submit(page, selector)
    
    return {
        "action": "submit",
        "selector": selector,
        "success": result.get("success", False),
        "url_changed": result.get("url_changed", False)
    }

def execute_js(page: Page, js_code: str) -> Dict[str, Any]:
    """Execute JavaScript code on the page."""
    tools = get_browser_tools()
    result = tools.execute_js(page, js_code)
    
    return {
        "action": "execute_js",
        "success": result.get("success", False),
        "result": result.get("result")
    }

def refresh(page: Page) -> Dict[str, Any]:
    """Refresh the current page."""
    tools = get_browser_tools()
    result = tools.refresh(page)
    
    return {
        "action": "refresh",
        "success": result.get("success", False),
        "url": result.get("url")
    }

def presskey(page: Page, key: str) -> Dict[str, Any]:
    """Press a keyboard key."""
    tools = get_browser_tools()
    result = tools.presskey(page, key)
    
    return {
        "action": "presskey",
        "key": key,
        "success": result.get("success", False)
    }

def authenticate() -> Dict[str, Any]:
    """Prompt for user authentication."""
    tools = get_browser_tools()
    result = tools.authenticate()
    
    return {
        "action": "authenticate",
        "message": result
    }

def complete() -> Dict[str, Any]:
    """Mark current task as complete with validation."""
    tools = get_browser_tools()
    result = tools.complete()
    
    return {
        "action": "complete",
        "message": result,
        "success": result == "Completed"
    }

def get_browser_interaction_tools() -> List[Dict[str, Any]]:
    """Return the browser interaction tool definitions."""
    return [
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
                            "description": "CSS or XPath selector for the form to submit (default: 'form')"
                        }
                    }
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "execute_js",
                "description": "Execute JavaScript code on the page",
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
                            "description": "Key to press (e.g., 'Enter', 'Tab', 'Escape')"
                        }
                    },
                    "required": ["key"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "authenticate",
                "description": "Prompt for user authentication when needed",
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
                "description": "Mark current task as complete",
                "parameters": {
                    "type": "object",
                    "properties": {}
                }
            }
        }
    ]