from typing import Dict, Any
from playwright.sync_api import Page

from core.llm import LLMProvider
from core.scanner import Scanner
from agents.security.specialized_agent import SpecializedSecurityAgent
from utils.logger import get_logger


class InsecureDesignAgent(SpecializedSecurityAgent):
    """Agent specializing in Insecure Design testing."""
    
    def __init__(self, llm_provider: LLMProvider, scanner: Scanner):
        super().__init__("InsecureDesignAgent", "design_specialist", 
                        "insecure_design", llm_provider, scanner)
    
    def _get_system_prompt(self) -> str:
        """Get the system prompt for insecure design testing."""
        return """
        You are an Insecure Design security specialist. Your job is to identify and report design flaws in web applications that lead to security vulnerabilities.
        
        Focus on testing:
        1. Business logic flaws in critical workflows
        2. Missing rate limiting or anti-automation mechanisms
        3. Insecure design patterns that enable abuse
        4. Inadequate data validation patterns
        5. Process flow vulnerabilities
        
        You have access to specialized insecure design testing tools and browser interaction tools:
        
        INSECURE DESIGN TOOLS:
        - identify_design_flaws: Identify potential insecure design patterns in the application
        - analyze_business_logic: Analyze business logic for security flaws
        
        BROWSER INTERACTION TOOLS:
        - goto: Navigate to a URL
        - click: Click an element on the page
        - fill: Fill a form field with a value
        - submit: Submit a form
        - execute_js: Execute JavaScript on the page
        
        Common insecure design issues to look for:
        - Missing authentication for critical functions
        - Lack of rate limiting on sensitive operations
        - Inadequate input validation
        - Insecure direct object references
        - Predictable resource locations
        - Race conditions in multi-step processes
        - Business logic that can be abused
        """
    
    def _check_for_vulnerabilities(self, tool_name: str, tool_result: Dict[str, Any], 
                                  result: Dict[str, Any], page: Page, tool_call: Any) -> Dict[str, Any]:
        """Check for insecure design vulnerabilities in tool results."""
        logger = get_logger()
        
        # Check for design flaws reported by tools
        if tool_result.get("design_issue_found", False):
            result["vulnerability_found"] = True
            result["vulnerability_type"] = "Insecure Design"
            result["severity"] = tool_result.get("severity", "medium")
            result["details"] = tool_result
            
            logger.security(f"Found Insecure Design issue: {', '.join(tool_result.get('issues', ['Unknown issue']))}")
        
        # Check for business logic flaws
        elif tool_result.get("logic_issue_found", False):
            result["vulnerability_found"] = True
            result["vulnerability_type"] = "Business Logic Flaw"
            result["severity"] = tool_result.get("severity", "high")
            result["details"] = tool_result
            
            logger.security(f"Found Business Logic Flaw in workflow: {tool_result.get('vulnerable_workflow', '')}")
        
        return result