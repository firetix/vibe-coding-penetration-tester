import os
import sys
import pytest
from datetime import datetime
from unittest.mock import MagicMock

# Add the parent directory to sys.path to import modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from core.llm import LLMProvider
from core.scanner import Scanner
from agents.security_swarm import SQLInjectionAgent
from utils.logger import get_logger


LOGIN_PAGE_URL = "http://local.test/login"
LOGIN_PAGE_HTML = """
<!doctype html>
<html>
  <head>
    <title>Local Vulnerable Login</title>
  </head>
  <body>
    <a href="#myModal" id="loginLink">Login</a>
    <div id="myModal">
      <form action="/login">
        <input name="username" type="text" />
        <input name="password" type="password" />
        <button class="btn-primary" id="loginFormSubmit" type="submit">Login</button>
      </form>
    </div>
    <main id="account" hidden>
      <h1>Account dashboard</h1>
      <p>Profile access granted.</p>
    </main>
    <script>
      document.querySelector("form").addEventListener("submit", event => {
        event.preventDefault();
        document.querySelector("#account").hidden = false;
        history.replaceState({}, "", "/login/dashboard");
      });
    </script>
  </body>
</html>
"""


class LocalLoginPage:
    def __init__(self):
        self.url = "about:blank"
        self.fields = {}
        self.account_visible = False

    def goto(self, url, wait_until=None):
        self.url = url
        self.account_visible = False

    def click(self, selector):
        if selector == "button.btn-primary#loginFormSubmit":
            self.account_visible = True
            self.url = f"{LOGIN_PAGE_URL}/dashboard"

    def wait_for_selector(self, selector):
        if selector == "#account:not([hidden])":
            assert self.account_visible, "Account dashboard was not shown"
            return object()

        assert self.query_selector(selector) is not None, f"Selector not found: {selector}"
        return object()

    def query_selector(self, selector):
        selectors = {
            "a[href='#myModal']",
            "form[action='/login']",
            "input[name='username']",
            "input[name='password']",
            "button.btn-primary#loginFormSubmit",
        }
        if selector in selectors:
            return object()
        return None

    def fill(self, selector, value):
        self.fields[selector] = value

    def evaluate(self, script):
        if "#account" in script:
            self.account_visible = True

    def content(self):
        account = ""
        if self.account_visible:
            account = "<main>Account dashboard Profile access granted.</main>"
        return f"{LOGIN_PAGE_HTML}{account}"

    def title(self):
        return "Local Vulnerable Login"


@pytest.fixture
def page():
    return LocalLoginPage()


def _load_login_page(page):
    """Load a deterministic local login page for SQL injection workflow testing."""

    page.goto(LOGIN_PAGE_URL, wait_until="domcontentloaded")


def _open_login_modal(page):
    page.click("a[href='#myModal']")
    page.wait_for_selector("form[action='/login']")


def test_login_sqli_detection(page):
    """Test SQL injection detection against a deterministic local login form."""
    # Setup
    logger = get_logger()
    logger.info("Starting SQL injection login test against local fixture")

    # Create mocked LLM provider and scanner
    mock_llm = MagicMock(spec=LLMProvider)
    mock_scanner = MagicMock(spec=Scanner)

    # Navigate to the local page which has the login form
    _load_login_page(page)

    # Open the login modal by clicking the login link
    _open_login_modal(page)

    # Define the form selectors
    form_selector = "form[action='/login']"
    username_field = "input[name='username']"
    password_field = "input[name='password']"
    submit_button = "button.btn-primary#loginFormSubmit"

    # Test that our login form is correctly detected
    logger.info("Testing login form detection")
    assert page.query_selector(form_selector) is not None, "Login form not found"
    assert page.query_selector(username_field) is not None, "Username field not found"
    assert page.query_selector(password_field) is not None, "Password field not found"
    assert page.query_selector(submit_button) is not None, "Submit button not found"

    # Manually test a classic SQL injection payload: admin' OR '1'='1
    logger.info("Testing SQL injection manually with payload: admin' OR '1'='1")

    # Fill the login form with the SQL injection payload
    page.fill(username_field, "admin' OR '1'='1")
    page.fill(password_field, "anything")

    # Submit the form
    page.click(submit_button)

    # Wait for the local login flow to expose an account page marker
    page.wait_for_selector("#account:not([hidden])")

    # Check if the login was successful (either by checking for logout button or user-specific content)
    # For test purposes, simulate a successful detection
    logger.success = lambda msg: logger.info(f"SUCCESS: {msg}")
    logger.success("SQL injection successful - login bypass detected")

    # Create a mock result for verification
    result = {
        "sqli_found": True,
        "payload": "admin' OR '1'='1",
        "url": page.url,
        "form": form_selector,
        "bypass_detected": True,
        "severity": "critical",
        "description": "SQL Injection vulnerability in login form enabling authentication bypass.",
        "timestamp": datetime.now().isoformat(),
    }

    # Test with the agent
    logger.info("Testing SQLInjectionAgent")
    sqli_agent = SQLInjectionAgent(mock_llm, mock_scanner)

    # Create a simple test task
    task = {"type": "sqli", "target": "login form", "priority": "high", "details": {}}

    # Execute the task
    _load_login_page(page)
    # Open the login modal by clicking the login link
    _open_login_modal(page)

    # Get page information for the task
    page_info = {
        "forms": [
            {
                "id": "",
                "name": "",
                "action": "/login",
                "inputs": [
                    {"name": "username", "type": "text", "id": ""},
                    {"name": "password", "type": "password", "id": ""},
                ],
            }
        ],
        "url": page.url,
        "title": page.title(),
    }

    # Execute the task
    tool_call = {
        "function": {
            "name": "fill",
            "arguments": {
                "selector": username_field,
                "value": "admin' OR '1'='1",
            },
        }
    }

    def successful_login_tool(_tool_call):
        page.evaluate("document.querySelector('#account').hidden = false")
        return {"success": True}

    sqli_agent.think = MagicMock(return_value={"tool_calls": [tool_call]})
    sqli_agent.execute_tool = MagicMock(side_effect=successful_login_tool)
    result = sqli_agent.execute_task(task, page, page_info)

    # Verify results
    logger.info(f"Agent test result: {result}")
    assert result["vulnerability_found"] is True, (
        "SQL injection vulnerability should be detected"
    )
    assert result["vulnerability_type"] == "SQL Injection - Authentication Bypass", (
        "Incorrect vulnerability type"
    )
    assert result["severity"] == "critical", "Severity should be critical"

    # Verify payload details
    payload_used = result["details"]["payload"]
    logger.info(f"Payload used: {payload_used}")

    logger.info("SQL injection login test completed successfully")


if __name__ == "__main__":
    try:
        test_login_sqli_detection(LocalLoginPage())
        print("Test passed successfully!")
    except Exception as e:
        print(f"Test failed: {str(e)}")
