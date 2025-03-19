from typing import Optional
from playwright.sync_api import Page

class ScannerContext:
    """
    Singleton class to hold global scanner context, including the current page object.
    This allows tools to access the current page without explicitly passing it as a parameter.
    """
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ScannerContext, cls).__new__(cls)
            cls._instance._current_page = None
        return cls._instance
    
    @property
    def current_page(self) -> Optional[Page]:
        """Get the current page."""
        return self._current_page
    
    @current_page.setter
    def current_page(self, page: Page) -> None:
        """Set the current page."""
        self._current_page = page
        
# Create a global instance
scanner_context = ScannerContext()