from typing import Dict, Any
from playwright.sync_api import Page

from agents.agent_factory import BaseAgent
from core.llm import LLMProvider
from core.scanner import Scanner
from tools.browser_tools import BrowserTools
from tools.browser_tools_impl import get_browser_interaction_tools
from tools.security_tools import get_security_tools
from utils.logger import get_logger


class SpecializedSecurityAgent(BaseAgent):
    """Base class for specialized security testing agents."""

    def __init__(
        self,
        name: str,
        role: str,
        security_type: str,
        llm_provider: LLMProvider,
        scanner: Scanner,
    ):
        # Get security tools for this agent type
        security_tools = get_security_tools(security_type)

        # For access_control agent, also include specialized tools
        if security_type == "access_control":
            specialized_tools = get_security_tools("specialized")
            security_tools.extend(specialized_tools)

        browser_tools = get_browser_interaction_tools()
        tools = security_tools + browser_tools

        super().__init__(name, role, llm_provider, tools)
        self.scanner = scanner
        self.security_type = security_type
        self.browser_tools = BrowserTools(debug=True)

    def execute_task(
        self, task: Dict[str, Any], page: Page, page_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute a security testing task."""
        system_prompt = self._get_system_prompt()

        logger = get_logger()
        logger.highlight(
            f"{self.name} executing task: {task['type']} on {task['target']}"
        )

        input_data = self._create_input_data(task, page, page_info)
        response = self.think(input_data, system_prompt)

        result = {
            "task_type": task["type"],
            "target": task["target"],
            "vulnerability_found": False,
            "details": {},
            "actions_performed": [],
        }

        if response.get("tool_calls"):
            for tool_call in response["tool_calls"]:
                result = self._process_tool_call(tool_call, result, page)

        self._process_followup_response(response, result, page)

        return result

    def _get_system_prompt(self) -> str:
        """Override in subclasses to provide specialized system prompts."""
        return ""

    def _create_input_data(
        self, task: Dict[str, Any], page: Page, page_info: Dict[str, Any]
    ) -> Dict[str, str]:
        """Create the input data for the agent."""
        return {
            "content": f"Test for {self.security_type} vulnerabilities on: {page.url}\n\nTask details: {task}\n\nPage information: {page_info}"
        }

    def _process_tool_call(
        self, tool_call: Any, result: Dict[str, Any], page: Page
    ) -> Dict[str, Any]:
        """Process a tool call and update the result."""
        tool_name = self._get_tool_name(tool_call)

        self.logger.info(f"{self.name} using tool: {tool_name}", color="cyan")

        tool_result = self.execute_tool(tool_call)

        result["actions_performed"].append(
            {"tool": tool_name, "success": tool_result is not None}
        )

        if isinstance(tool_result, dict):
            result = self._check_for_vulnerabilities(
                tool_name, tool_result, result, page, tool_call
            )

        return result

    def _get_tool_name(self, tool_call: Any) -> str:
        """Extract the tool name from a tool call."""
        if hasattr(tool_call, "function") and hasattr(tool_call.function, "name"):
            return tool_call.function.name
        return tool_call.get("function", {}).get("name", "unknown_tool")

    def _check_for_vulnerabilities(
        self,
        tool_name: str,
        tool_result: Dict[str, Any],
        result: Dict[str, Any],
        page: Page,
        tool_call: Any,
    ) -> Dict[str, Any]:
        """Check for vulnerabilities in tool results. Override in subclasses."""
        return result

    def _process_followup_response(
        self, response: Dict[str, Any], result: Dict[str, Any], page: Page
    ) -> None:
        """Process the follow-up response for additional evidence. Override if needed."""
        pass
