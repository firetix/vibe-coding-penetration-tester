from typing import Dict, Any, Optional
from playwright.sync_api import Page
import re
from urllib.parse import unquote, parse_qs, urlparse

from core.llm import LLMProvider
from core.scanner import Scanner
from agents.security.specialized_agent import SpecializedSecurityAgent
from utils.logger import get_logger


class XSSAgent(SpecializedSecurityAgent):
    """Agent specializing in Cross-Site Scripting (XSS) testing with enhanced pattern-based detection."""

    def __init__(self, llm_provider: LLMProvider, scanner: Scanner):
        super().__init__("XSSAgent", "xss_specialist", "xss", llm_provider, scanner)
        self.logger = get_logger()

        # Enhanced XSS detection patterns
        self.xss_basic_patterns = [
            "<script>",
            "</script>",
            "onerror=",
            "onload=",
            "javascript:",
            "alert(",
            "<img",
            "<svg",
            "onmouseover=",
            "expression(",
            "document.cookie",
        ]

        # Context-specific XSS patterns
        self.context_patterns = {
            "html": [
                "<script>.*?</script>",
                "<img[^>]*onerror=",
                "<svg[^>]*onload=",
                '<iframe[^>]*src="?javascript:',
            ],
            "attribute": [
                '"[^"]*onerror=',
                '"[^"]*onload=',
                '"[^"]*javascript:',
                "'[^']*onerror=",
                "'[^']*onload=",
                "'[^']*javascript:",
            ],
            "javascript": [
                "eval\\(",
                "document\\.write\\(",
                '\\$(\\(|\\.|")',  # jQuery or similar expressions
            ],
            "url": ["javascript:", "data:text/html", "vbscript:"],
        }

        # XSS evasion techniques
        self.evasion_patterns = [
            # Case variations
            "(?i)script",
            # HTML encoding
            "&lt;script&gt;",
            # Double encoding
            "%253C(?:script|img|svg)",
            # Null bytes
            "script%00",
            # Unicode encoding
            "%u003C(?:script|img|svg)",
            # Nested tags
            "<<script",
            "<iframe<iframe",
        ]

        # DOM-based XSS sources and sinks
        self.dom_xss_sources = [
            "location",
            "referrer",
            "URL",
            "documentURI",
            "innerHTML",
            "outerHTML",
            "window.name",
            "history.pushState",
        ]

        self.dom_xss_sinks = [
            "eval",
            "setTimeout",
            "setInterval",
            "document.write",
            "innerHTML",
            "outerHTML",
            "setAttribute",
            "$",
            "jQuery",
        ]

    def _get_system_prompt(self) -> str:
        """Get the system prompt for XSS testing."""
        return """
        You are a Cross-Site Scripting (XSS) security specialist. Your job is to identify and exploit XSS vulnerabilities in web applications using pattern-based detection techniques.
        
        Focus on testing:
        1. Form inputs and URL parameters for script injection
        2. HTML context vs. attribute context vs. JavaScript context XSS
        3. Reflected XSS (input is immediately reflected on the page)
        4. Stored XSS (input is stored and displayed later)
        5. DOM-based XSS (input causes JavaScript execution via client-side code)
        6. Search fields, feedback forms, and user profile inputs
        7. Client-side validation bypass techniques
        8. XSS filter evasion techniques
        9. Content-Security-Policy (CSP) bypass methods
        10. Sanitization bypass patterns
        
        You have access to specialized XSS tools and browser interaction tools:
        
        XSS TOOLS:
        - generate_xss_payloads: Generate XSS payloads based on context
        - test_xss_payload: Test a Cross-Site Scripting (XSS) payload against a target
        
        BROWSER INTERACTION TOOLS:
        - goto: Navigate to a URL
        - click: Click an element on the page
        - fill: Fill a form field with a value
        - submit: Submit a form
        - execute_js: Execute JavaScript on the page
        
        XSS Pattern-Based Detection Strategy:
        1. Identify input points: URL parameters, form fields, headers, cookies
        2. Analyze context: Determine if input appears in HTML, attributes, JavaScript, or URL context
        3. Choose context-appropriate payloads using generate_xss_payloads tool
        4. Test sanitization bypass techniques if basic payloads fail
        5. Look for DOM-based XSS by analyzing JavaScript sources and sinks
        6. Test CSP bypass techniques if CSP is detected
        
        Common XSS evasion techniques:
        - Case variations: <ScRiPt>alert(1)</ScRiPt>
        - HTML encoding: &lt;script&gt;alert(1)&lt;/script&gt;
        - URL encoding: %3Cscript%3Ealert(1)%3C/script%3E
        - Double encoding: %253Cscript%253Ealert(1)%253C/script%253E
        - Null bytes: <scri%00pt>alert(1)</script>
        - Unicode encoding: <script\u0020alert(1);</script>
        - Nested tags: <<script>alert("XSS");//<</script>
        
        When you find a vulnerability, collect evidence:
        1. Document the payload used
        2. Track where it was injected
        3. Describe the observed effect
        4. Assess the severity based on impact
        5. Document the context in which the XSS was found
        6. Note any bypass techniques that were successful
        
        Focus on pattern-based detection, not application-specific knowledge, to make your testing more broadly applicable.
        """

    def _check_for_vulnerabilities(
        self,
        tool_name: str,
        tool_result: Dict[str, Any],
        result: Dict[str, Any],
        page: Page,
        tool_call: Any,
    ) -> Dict[str, Any]:
        """Enhanced pattern-based check for XSS vulnerabilities in tool results."""

        # Check for XSS reported by tools
        if tool_result.get("xss_found", False):
            result["vulnerability_found"] = True
            result["vulnerability_type"] = "Cross-Site Scripting (XSS)"
            result["severity"] = tool_result.get("severity", "high")
            result["details"] = tool_result

            self.logger.security(
                f"Found XSS vulnerability with payload: {tool_result.get('payload', 'unknown')}"
            )

        # Check for XSS in URL navigation using pattern-based detection
        elif tool_name == "goto" and tool_result.get("success", False):
            target_url = tool_result.get("url", page.url)

            # Check URL for potential XSS payloads
            xss_found = self._check_url_for_xss(target_url, page)

            if xss_found and isinstance(xss_found, dict):
                result["vulnerability_found"] = True
                result["vulnerability_type"] = "Reflected Cross-Site Scripting (XSS)"
                result["severity"] = "high"
                result["details"] = xss_found

                self.logger.security(
                    f"Found Reflected XSS vulnerability in URL parameter: {xss_found.get('payload', 'unknown')}"
                )

        # Check for DOM-based XSS in JavaScript execution
        elif tool_name == "execute_js" and tool_result.get("success", False):
            js_result = str(tool_result.get("result", ""))

            # Get the JS code from the tool call
            js_code = self._extract_js_code_from_tool_call(tool_call)

            # Look for DOM-based XSS vulnerabilities
            dom_xss = self._check_for_dom_xss(js_code, js_result, page)

            if dom_xss:
                result["vulnerability_found"] = True
                result["vulnerability_type"] = "DOM-based Cross-Site Scripting (XSS)"
                result["severity"] = "high"
                result["details"] = {
                    "issue_type": "DOM-based XSS",
                    "js_code": js_code,
                    "evidence": js_result,
                    "url": page.url,
                    "source": dom_xss.get("source"),
                    "sink": dom_xss.get("sink"),
                    "description": dom_xss.get(
                        "description", "DOM-based XSS vulnerability detected"
                    ),
                }

                self.logger.security(
                    f"Found DOM-based XSS vulnerability with source {dom_xss.get('source')} and sink {dom_xss.get('sink')}"
                )

        # Check for XSS in form submissions with pattern-based detection
        elif tool_name in ["fill", "submit"] and tool_result.get("success", False):
            # Extract the value that was submitted
            input_value = (
                self._extract_input_value_from_tool_call(tool_call)
                if tool_name == "fill"
                else ""
            )

            # Check if the input contains XSS payloads
            has_xss_input = any(
                pattern in input_value.lower() for pattern in self.xss_basic_patterns
            )

            if has_xss_input:
                # Check the page content after submission for reflected XSS
                reflection_details = self._check_for_reflected_content(
                    page, input_value
                )

                if reflection_details:
                    # Determine the type of XSS based on the context
                    xss_type = self._determine_xss_type(page.url)

                    result["vulnerability_found"] = True
                    result["vulnerability_type"] = (
                        f"{xss_type} Cross-Site Scripting (XSS)"
                    )
                    result["severity"] = "high"

                    # Determine injection point (form field selector)
                    selector = (
                        self._extract_selector_from_tool_call(tool_call)
                        if tool_name == "fill"
                        else ""
                    )

                    result["details"] = {
                        "issue_type": f"{xss_type} XSS",
                        "injection_point": selector,
                        "payload": input_value,
                        "url": page.url,
                        "evidence": reflection_details.get(
                            "evidence", "XSS payload reflected in page content"
                        ),
                        "context": reflection_details.get("context", "Unknown"),
                        "sanitization_bypass": reflection_details.get("bypass", False),
                    }

                    self.logger.security(
                        f"Found {xss_type} XSS vulnerability after form interaction"
                    )

            # Check for XSS sanitization bypass with nested tags
            if tool_name == "fill" and not result["vulnerability_found"]:
                bypass_result = self._check_for_sanitization_bypass(page, input_value)
                if bypass_result:
                    result["vulnerability_found"] = True
                    result["vulnerability_type"] = bypass_result.get(
                        "type",
                        "Stored Cross-Site Scripting (XSS) - Sanitization Bypass",
                    )
                    result["severity"] = "critical"
                    result["details"] = bypass_result

                    self.logger.security(
                        f"Found {bypass_result.get('type')} with payload: {bypass_result.get('payload', 'unknown')}"
                    )

        # Check for API-based XSS vulnerability (client-side validation bypass)
        if (
            not result["vulnerability_found"]
            and tool_name == "goto"
            and "/api/" in page.url.lower()
        ):
            api_xss = self._check_for_api_xss(page, tool_call)

            if api_xss:
                result["vulnerability_found"] = True
                result["vulnerability_type"] = (
                    "Stored Cross-Site Scripting (XSS) - Client-Side Validation Bypass"
                )
                result["severity"] = "high"
                result["details"] = api_xss

                self.logger.security(
                    "Found Stored XSS via API call (client-side validation bypass)"
                )

        return result

    def _check_url_for_xss(self, url: str, page: Page) -> Optional[Dict[str, Any]]:
        """Check URL for XSS vulnerabilities using pattern-based detection."""
        # Parse the URL to extract parameters
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)

        # Check each parameter for XSS payloads
        for param, values in query_params.items():
            for value in values:
                # Check for basic XSS patterns in the decoded value
                decoded_value = unquote(value)

                is_suspicious = False
                matched_pattern = None

                # Check for basic XSS patterns
                for pattern in self.xss_basic_patterns:
                    if pattern.lower() in decoded_value.lower():
                        is_suspicious = True
                        matched_pattern = pattern
                        break

                # Check for evasion techniques if basic patterns not found
                if not is_suspicious:
                    for pattern in self.evasion_patterns:
                        if re.search(pattern, decoded_value, re.IGNORECASE):
                            is_suspicious = True
                            matched_pattern = pattern
                            break

                if is_suspicious:
                    # Check if the payload was successfully reflected in the page
                    html_content = page.content().lower()

                    # Check if the script is actually executed
                    # by using a JavaScript check for alert() or XSS indicators
                    try:
                        script_executed = page.evaluate("""() => {
                            return window.__xss_triggered || 
                                   window.xssDetected || 
                                   document.title.includes('XSS') ||
                                   false;
                        }""")
                    except Exception:
                        script_executed = False

                    # Check for content reflection
                    payload_reflected = False
                    context = "Unknown"

                    # Check for HTML context reflection
                    for html_pattern in self.context_patterns["html"]:
                        if re.search(html_pattern, html_content, re.IGNORECASE):
                            payload_reflected = True
                            context = "HTML"
                            break

                    # Check for attribute context reflection
                    if not payload_reflected:
                        for attr_pattern in self.context_patterns["attribute"]:
                            if re.search(attr_pattern, html_content, re.IGNORECASE):
                                payload_reflected = True
                                context = "HTML Attribute"
                                break

                    # Check for JavaScript context reflection
                    if not payload_reflected:
                        for js_pattern in self.context_patterns["javascript"]:
                            if re.search(js_pattern, html_content, re.IGNORECASE):
                                payload_reflected = True
                                context = "JavaScript"
                                break

                    # Check for URL context reflection
                    if not payload_reflected:
                        for url_pattern in self.context_patterns["url"]:
                            if re.search(url_pattern, html_content, re.IGNORECASE):
                                payload_reflected = True
                                context = "URL"
                                break

                    # If we didn't find specific context patterns, check for basic reflection
                    if not payload_reflected and decoded_value.lower() in html_content:
                        payload_reflected = True
                        context = "Unknown"

                    if script_executed or payload_reflected:
                        return {
                            "issue_type": "Reflected XSS",
                            "injection_point": "URL parameter",
                            "parameter": param,
                            "payload": decoded_value,
                            "url": url,
                            "evidence": "XSS payload reflected in page content"
                            + (" and executed" if script_executed else ""),
                            "context": context,
                            "executed": script_executed,
                            "matched_pattern": matched_pattern,
                        }

        return None

    def _check_for_dom_xss(
        self, js_code: str, js_result: str, page: Page
    ) -> Optional[Dict[str, Any]]:
        """Check for DOM-based XSS vulnerabilities."""
        if not js_code:
            return None

        # Look for DOM XSS sources
        source_found = None
        for source in self.dom_xss_sources:
            if source in js_code:
                source_found = source
                break

        # Look for DOM XSS sinks
        sink_found = None
        for sink in self.dom_xss_sinks:
            if sink in js_code:
                sink_found = sink
                break

        # Check if result contains XSS indicators
        xss_indicators = ["alert(", "XSS", "injection", "script"]
        has_xss_result = any(indicator in js_result for indicator in xss_indicators)

        # If we found both a source and sink or have clear XSS evidence in result
        if (source_found and sink_found) or has_xss_result:
            # Try to verify DOM XSS by checking the page
            try:
                dom_xss_verified = page.evaluate("""() => {
                    // Check for common DOM XSS evidence
                    if (window.__xss_triggered || window.xssDetected) 
                        return true;
                    
                    // Look for suspicious DOM modifications
                    const scripts = document.querySelectorAll('script:not([src])');
                    for (const script of scripts) {
                        if (script.textContent.includes('alert(') || 
                            script.textContent.includes('XSS'))
                            return true;
                    }
                    
                    return false;
                }""")
            except Exception:
                dom_xss_verified = False

            description = "DOM-based XSS detected with "
            if source_found and sink_found:
                description += f"source '{source_found}' flowing to sink '{sink_found}'"
            else:
                description += "suspicious JavaScript execution"

            return {
                "source": source_found,
                "sink": sink_found,
                "verified": dom_xss_verified,
                "js_result": js_result,
                "description": description,
            }

        return None

    def _check_for_reflected_content(
        self, page: Page, input_value: str
    ) -> Optional[Dict[str, Any]]:
        """Check if an input value is reflected in the page content."""
        if not input_value:
            return None

        html_content = page.content().lower()
        input_lower = input_value.lower()

        # Check for direct reflection
        if input_lower in html_content:
            # Determine the context of the reflection
            context = self._determine_reflection_context(page, input_value)

            # Check if the reflection appears to bypass sanitization
            bypass = self._check_sanitization_bypass(html_content, input_value)

            return {
                "evidence": "XSS payload reflected in page content",
                "context": context,
                "bypass": bypass,
            }

        # Check for encoded/transformed reflection
        encoded_variations = [
            # HTML encoded
            input_value.replace("<", "&lt;").replace(">", "&gt;"),
            # URL encoded
            input_value.replace("<", "%3C").replace(">", "%3E"),
            # Partial encoding
            input_value.replace("<script>", "&lt;script&gt;"),
        ]

        for variation in encoded_variations:
            if variation.lower() in html_content:
                return {
                    "evidence": "XSS payload reflected in page content (encoded)",
                    "context": "Encoded content",
                    "bypass": False,
                }

        return None

    def _determine_reflection_context(self, page: Page, input_value: str) -> str:
        """Determine the context in which user input is reflected."""
        try:
            context_info = page.evaluate(
                """(input) => {
                const elements = [];
                // Create a tree walker to find all text nodes
                const walker = document.createTreeWalker(
                    document.body,
                    NodeFilter.SHOW_TEXT | NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_ATTRIBUTE,
                    null,
                    false
                );
                
                let node;
                let context = "Unknown";
                
                // Check for text node reflections (HTML context)
                while (node = walker.nextNode()) {
                    if (node.nodeType === Node.TEXT_NODE && node.nodeValue.includes(input)) {
                        const parent = node.parentNode.tagName.toLowerCase();
                        context = "HTML content in <" + parent + "> element";
                        break;
                    }
                    
                    // Check for attribute reflections
                    if (node.nodeType === Node.ELEMENT_NODE) {
                        for (const attr of node.attributes) {
                            if (attr.value.includes(input)) {
                                context = `${attr.name} attribute in <${node.tagName.toLowerCase()}> element`;
                                break;
                            }
                        }
                    }
                }
                
                // Check for JavaScript context (script tags or event handlers)
                const scripts = document.querySelectorAll('script:not([src])');
                for (const script of scripts) {
                    if (script.textContent.includes(input)) {
                        context = "JavaScript context in <script> tag";
                        break;
                    }
                }
                
                // Check for style context
                const styles = document.querySelectorAll('style');
                for (const style of styles) {
                    if (style.textContent.includes(input)) {
                        context = "CSS context in <style> tag";
                        break;
                    }
                }
                
                return context;
            }""",
                input_value,
            )

            return context_info
        except Exception:
            # Fallback to a simpler method if the evaluation fails
            html_content = page.content().lower()

            if f"<script>{input_value.lower()}" in html_content:
                return "JavaScript context in <script> tag"
            elif (
                f'="{input_value.lower()}' in html_content
                or f"='{input_value.lower()}" in html_content
            ):
                return "HTML attribute context"
            else:
                return "HTML content context"

    def _check_sanitization_bypass(self, html_content: str, input_value: str) -> bool:
        """Check if the input appears to bypass sanitization."""
        sanitization_bypass_indicators = [
            # Nested tags bypass
            "<<script>",
            # Null byte bypass
            "%00",
            # Encoded XSS
            "&lt;script&gt;",
        ]

        for indicator in sanitization_bypass_indicators:
            if indicator in input_value.lower() and indicator in html_content:
                return True

        return False

    def _check_for_sanitization_bypass(
        self, page: Page, input_value: str
    ) -> Optional[Dict[str, Any]]:
        """Check for successful XSS sanitization bypass techniques."""
        # Check for known bypass techniques
        nested_payload = "<<script>"
        null_bypass = "<script%00"
        case_variation = "<ScRiPt>"
        encoded_bypass = "%3Cscript%3E"

        has_bypass_attempt = any(
            bp in input_value
            for bp in [nested_payload, null_bypass, case_variation, encoded_bypass]
        )

        if not has_bypass_attempt:
            return None

        # For feedback forms, comments, or other potentially stored XSS targets
        is_feedback_form = any(
            keyword in page.url.lower()
            for keyword in ["feedback", "comment", "review", "message"]
        )

        if has_bypass_attempt and is_feedback_form:
            # Check if the bypass technique was successful
            html_content = page.content().lower()

            # Try to verify if the XSS was actually executed
            try:
                xss_executed = page.evaluate("""() => {
                    return window.__xss_triggered || window.xssDetected || false;
                }""")
            except Exception:
                xss_executed = False

            # Determine which bypass technique was used
            bypass_type = "Unknown"
            if nested_payload in input_value:
                bypass_type = "Nested Tags"
            elif null_bypass in input_value:
                bypass_type = "Null Byte Injection"
            elif case_variation in input_value:
                bypass_type = "Case Variation"
            elif encoded_bypass in input_value:
                bypass_type = "URL Encoding"

            # Check if the bypass payload is reflected in the HTML
            bypass_successful = False
            if nested_payload in input_value and "<script>" in html_content:
                bypass_successful = True
            elif null_bypass in input_value and "<script" in html_content:
                bypass_successful = True
            elif case_variation in input_value and "script" in html_content:
                bypass_successful = True
            elif encoded_bypass in input_value and "<script>" in html_content:
                bypass_successful = True

            if bypass_successful or xss_executed:
                return {
                    "type": f"Stored Cross-Site Scripting (XSS) - {bypass_type} Sanitization Bypass",
                    "issue_type": f"Stored XSS with {bypass_type} Sanitization Bypass",
                    "payload": input_value,
                    "url": page.url,
                    "evidence": f"{bypass_type} XSS payload bypasses server-side sanitization",
                    "executed": xss_executed,
                    "note": f"This vulnerability exploits a weakness in HTML sanitization that doesn't properly handle {bypass_type.lower()} techniques",
                }

        return None

    def _check_for_api_xss(
        self, page: Page, tool_call: Any
    ) -> Optional[Dict[str, Any]]:
        """Check for XSS vulnerabilities in API calls (client-side validation bypass)."""
        if "/api/" not in page.url.lower():
            return None

        # Respect explicit non-POST methods, but allow missing method metadata.
        request_method = self._extract_request_method_from_tool_call(tool_call)
        if request_method and request_method != "POST":
            return None

        # Extract the request body
        request_body = self._extract_request_body_from_tool_call(tool_call)

        if not request_body:
            return None

        # Check for XSS payloads in the request body
        has_xss_payload = False
        matched_pattern = None

        # Check basic patterns
        for pattern in self.xss_basic_patterns:
            if pattern.lower() in request_body.lower():
                has_xss_payload = True
                matched_pattern = pattern
                break

        # Check evasion techniques
        if not has_xss_payload:
            for pattern in self.evasion_patterns:
                if re.search(pattern, request_body, re.IGNORECASE):
                    has_xss_payload = True
                    matched_pattern = pattern
                    break

        if has_xss_payload:
            # Identify the specific API operation
            api_operation = (
                page.url.split("/api/")[-1] if "/api/" in page.url else "unknown"
            )

            return {
                "issue_type": "Stored XSS via API",
                "endpoint": page.url,
                "api_operation": api_operation,
                "payload": request_body,
                "matched_pattern": matched_pattern,
                "evidence": "XSS payload submitted directly to API, bypassing client-side validation",
            }

        return None

    def _determine_xss_type(self, url: str) -> str:
        """Determine if the XSS is likely Reflected or Stored based on the URL context."""
        # URLs containing these patterns are likely to store user input
        stored_patterns = [
            "feedback",
            "comment",
            "review",
            "post",
            "profile",
            "edit",
            "create",
            "write",
            "submit",
        ]

        # Check if URL matches any stored XSS patterns
        for pattern in stored_patterns:
            if pattern in url.lower():
                return "Stored"

        # Default to reflected XSS
        return "Reflected"

    def _extract_js_code_from_tool_call(self, tool_call: Any) -> str:
        """Extract JavaScript code from a tool call."""
        js_code = ""
        if hasattr(tool_call, "function") and hasattr(tool_call.function, "arguments"):
            js_code = getattr(tool_call.function.arguments, "js_code", "")
        else:
            js_code = (
                tool_call.get("function", {}).get("arguments", {}).get("js_code", "")
            )
        return js_code

    def _extract_input_value_from_tool_call(self, tool_call: Any) -> str:
        """Extract input value from a tool call."""
        input_value = ""
        if hasattr(tool_call, "function") and hasattr(tool_call.function, "arguments"):
            input_value = getattr(tool_call.function.arguments, "value", "")
        else:
            input_value = (
                tool_call.get("function", {}).get("arguments", {}).get("value", "")
            )
        return input_value

    def _extract_selector_from_tool_call(self, tool_call: Any) -> str:
        """Extract selector from a tool call."""
        selector = ""
        if hasattr(tool_call, "function") and hasattr(tool_call.function, "arguments"):
            selector = getattr(tool_call.function.arguments, "selector", "")
        else:
            selector = (
                tool_call.get("function", {}).get("arguments", {}).get("selector", "")
            )
        return selector

    def _extract_request_body_from_tool_call(self, tool_call: Any) -> str:
        """Extract request body from a tool call."""

        def _extract_from_dict(mapping: Dict[str, Any]) -> str:
            if not isinstance(mapping, dict):
                return ""
            if "body" in mapping and mapping.get("body") is not None:
                return str(mapping.get("body"))

            nested_args = mapping.get("arguments")
            if (
                isinstance(nested_args, dict)
                and "body" in nested_args
                and nested_args.get("body") is not None
            ):
                return str(nested_args.get("body"))

            for value in mapping.values():
                if isinstance(value, dict):
                    nested = _extract_from_dict(value)
                    if nested:
                        return nested
            return ""

        if isinstance(tool_call, dict):
            direct_body = _extract_from_dict(tool_call)
            if direct_body:
                return direct_body

        if hasattr(tool_call, "function") and hasattr(tool_call.function, "arguments"):
            arguments = tool_call.function.arguments
            if isinstance(arguments, dict):
                direct_body = _extract_from_dict(arguments)
                if direct_body:
                    return direct_body
            else:
                body_attr = getattr(arguments, "body", "")
                if isinstance(body_attr, str) and body_attr:
                    return body_attr

        if hasattr(tool_call, "get"):
            try:
                function_args = tool_call.get("function", {})
                if isinstance(function_args, dict):
                    direct_body = _extract_from_dict(function_args)
                    if direct_body:
                        return direct_body

                top_level_args = tool_call.get("arguments", {})
                if isinstance(top_level_args, dict):
                    direct_body = _extract_from_dict(top_level_args)
                    if direct_body:
                        return direct_body
            except Exception:
                return ""
        return ""

    def _extract_request_method_from_tool_call(self, tool_call: Any) -> str:
        """Extract HTTP request method from a tool call when available."""
        allowed_methods = {"GET", "POST", "PUT", "PATCH", "DELETE"}

        def _normalize(value: Any) -> str:
            if not isinstance(value, str):
                return ""
            normalized = value.strip().upper()
            return normalized if normalized in allowed_methods else ""

        method = ""
        if isinstance(tool_call, dict):
            method = _normalize(tool_call.get("method", ""))
            if method:
                return method

        if hasattr(tool_call, "function") and hasattr(tool_call.function, "arguments"):
            method = _normalize(getattr(tool_call.function.arguments, "method", ""))
            if method:
                return method

        if hasattr(tool_call, "get"):
            try:
                method = _normalize(tool_call.get("method", ""))
            except Exception:
                method = ""
        return method
