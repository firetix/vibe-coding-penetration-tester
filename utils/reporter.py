import os
import json
from datetime import datetime
from typing import Dict, List, Any
from urllib.parse import urlparse

from utils.logger import get_logger


class Reporter:
    """Handles the generation of security reports."""

    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        self.logger = get_logger()

        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)

    def generate_report(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Generate a comprehensive security report from the discovered vulnerabilities."""
        self.logger.info(
            f"Generating report for {len(vulnerabilities)} vulnerabilities in directory: {self.output_dir}"
        )

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Verify output directory exists (double-check)
        if not os.path.exists(self.output_dir):
            self.logger.warning(
                f"Output directory does not exist, creating: {self.output_dir}"
            )
            os.makedirs(self.output_dir, exist_ok=True)

        # Filter out vulnerabilities where vulnerability_found is False
        real_vulnerabilities = [
            vuln for vuln in vulnerabilities if vuln.get("vulnerability_found", True)
        ]

        # Debug info about filtering
        if len(real_vulnerabilities) < len(vulnerabilities):
            self.logger.info(
                f"Filtered out {len(vulnerabilities) - len(real_vulnerabilities)} false positives"
            )

        # Debug info for each vulnerability
        if real_vulnerabilities:
            self.logger.info("Vulnerabilities to report:")
            for i, vuln in enumerate(real_vulnerabilities, 1):
                self.logger.info(
                    f"  #{i}: {vuln.get('vulnerability_type', 'Unknown')} - {vuln.get('severity', 'Unknown')}"
                )
        else:
            self.logger.warning("No vulnerabilities to report - creating empty report")

        # Group vulnerabilities by type
        vuln_by_type = {}
        for vuln in real_vulnerabilities:
            vuln_type = vuln.get("vulnerability_type", "Unknown")
            if vuln_type not in vuln_by_type:
                vuln_by_type[vuln_type] = []
            vuln_by_type[vuln_type].append(vuln)

        # Count vulnerabilities by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        for vuln in real_vulnerabilities:
            severity = vuln.get("severity", "info").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1

        # Create report structure
        report = {
            "timestamp": timestamp,
            "summary": {
                "total_vulnerabilities": len(real_vulnerabilities),
                "severity_counts": severity_counts,
                "vulnerability_types": list(vuln_by_type.keys()),
            },
            "findings": [
                self._format_vulnerability(vuln) for vuln in real_vulnerabilities
            ],
        }

        # Save as JSON
        json_path = os.path.join(self.output_dir, "report.json")
        self.logger.info(f"Writing JSON report to: {json_path}")
        try:
            with open(json_path, "w") as f:
                json.dump(report, f, indent=2)
            self.logger.success(f"JSON report successfully written to {json_path}")
        except Exception as e:
            self.logger.error(f"Error writing JSON report: {str(e)}")
            import traceback

            self.logger.error(f"Traceback: {traceback.format_exc()}")

        # Generate markdown report
        md_path = os.path.join(self.output_dir, "report.md")
        self.logger.info(f"Writing Markdown report to: {md_path}")
        try:
            md_content = self._generate_markdown(report)
            with open(md_path, "w") as f:
                f.write(md_content)
            self.logger.success(f"Markdown report successfully written to {md_path}")
        except Exception as e:
            self.logger.error(f"Error writing Markdown report: {str(e)}")
            import traceback

            self.logger.error(f"Traceback: {traceback.format_exc()}")

        self.logger.info(f"Generated security report at {md_path}")
        return md_path

    def _format_vulnerability(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """Format a vulnerability for the report."""
        # Handle details field which might be a string or a dictionary
        details = vuln.get("details", {})
        if isinstance(details, str):
            details_dict = {"description": details}
        else:
            details_dict = details

        return {
            "title": self._generate_title(vuln),
            "type": vuln.get("type", vuln.get("vulnerability_type", "Unknown")),
            "severity": vuln.get("severity", "info"),
            "target": vuln.get("target", vuln.get("url", "")),
            "description": self._get_description(vuln),
            "impact": self._get_impact(vuln),
            "reproduction": details_dict.get("reproduction_steps", []),
            "evidence": details_dict.get("evidence", vuln.get("poc", "")),
            "exploitation_guide": self._get_exploitation_guide(vuln),
            "remediation": self._get_remediation(vuln),
            "references": self._get_references(vuln),
            "validated": vuln.get("validated", False),
            "validation_details": vuln.get("validation_details", {}),
        }

    def _generate_title(self, vuln: Dict[str, Any]) -> str:
        """Generate a descriptive title for the vulnerability."""
        vuln_type = vuln.get("vulnerability_type", "Security Issue")
        target = vuln.get("target", "")

        if target:
            parsed_target = urlparse(target)
            if parsed_target.netloc:
                target_short = parsed_target.netloc
            else:
                target_short = target[:40] + "..." if len(target) > 40 else target

            return f"{vuln_type} in {target_short}"
        else:
            return vuln_type

    def _get_description(self, vuln: Dict[str, Any]) -> str:
        """Get the vulnerability description or generate a default one."""
        if "details" in vuln and "description" in vuln["details"]:
            return vuln["details"]["description"]

        # Generate default description based on vulnerability type
        vuln_type = vuln.get("vulnerability_type", "").lower()

        if "xss" in vuln_type:
            return "Cross-Site Scripting (XSS) allows attackers to inject malicious scripts that execute in users' browsers, potentially leading to cookie theft, session hijacking, or phishing attacks."
        elif "sql" in vuln_type:
            return "SQL Injection vulnerabilities allow attackers to manipulate database queries, potentially exposing, modifying, or deleting sensitive data."
        elif "csrf" in vuln_type:
            return "Cross-Site Request Forgery (CSRF) forces authenticated users to execute unwanted actions on web applications they're currently authenticated to."
        elif "auth" in vuln_type or "session" in vuln_type:
            return "Authentication or session management vulnerabilities can allow attackers to impersonate legitimate users, bypass authentication controls, or hijack user sessions."
        else:
            return "A security vulnerability was identified that could potentially be exploited by attackers."

    def _get_impact(self, vuln: Dict[str, Any]) -> str:
        """Get the vulnerability impact or generate a default one based on severity."""
        if "details" in vuln and "impact" in vuln["details"]:
            return vuln["details"]["impact"]

        # Generate default impact based on severity
        severity = vuln.get("severity", "medium").lower()

        if severity == "critical":
            return "This vulnerability has a critical impact, potentially allowing full system compromise, unauthorized access to highly sensitive data, or complete application takeover."
        elif severity == "high":
            return "This vulnerability has a high impact, potentially allowing significant data exposure, partial application compromise, or unauthorized access to sensitive functionality."
        elif severity == "medium":
            return "This vulnerability has a moderate impact, potentially allowing limited data exposure or partial access to application functionality."
        elif severity == "low":
            return "This vulnerability has a low impact, with limited potential for data exposure or application compromise."
        else:
            return "The impact of this vulnerability is informational."

    def _get_remediation(self, vuln: Dict[str, Any]) -> str:
        """Get the vulnerability remediation guidance or generate a default one."""
        if "details" in vuln and "remediation" in vuln["details"]:
            return vuln["details"]["remediation"]

        # Generate default remediation based on vulnerability type
        vuln_type = vuln.get("vulnerability_type", "").lower()

        if "xss" in vuln_type:
            return "Implement proper input validation and output encoding. Use context-specific encoding for different parts of the HTML document, and consider implementing a Content Security Policy (CSP)."
        elif "sql" in vuln_type:
            return "Use parameterized queries or prepared statements instead of dynamically building SQL queries. Implement proper input validation and consider using an ORM framework."
        elif "csrf" in vuln_type:
            return "Implement anti-CSRF tokens for all state-changing operations. Consider using the SameSite cookie attribute and requiring re-authentication for sensitive actions."
        elif "auth" in vuln_type or "session" in vuln_type:
            return "Implement proper authentication controls including strong password policies, multi-factor authentication for sensitive functions, secure session management, and proper logout functionality."
        else:
            return "Review the vulnerable component and implement security best practices for that specific technology or framework."

    def _get_exploitation_guide(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a detailed exploitation guide for the vulnerability."""
        if "details" in vuln and "exploitation_guide" in vuln["details"]:
            return vuln["details"]["exploitation_guide"]

        # Default information
        result = {
            "summary": "This guide outlines the steps a malicious actor could take to exploit this vulnerability.",
            "prerequisites": [
                "Access to a web browser",
                "Basic knowledge of web technologies",
            ],
            "steps": [],
            "tools": [],
            "difficulty": "Medium",
            "detection_evasion": "This exploitation may be detected in security logs if monitoring is in place.",
        }

        # Generate specific exploitation steps based on vulnerability type
        vuln_type = vuln.get("vulnerability_type", "").lower()
        details = vuln.get("details", {})

        # Get evidence and payload if available
        evidence = details.get("evidence", "") if isinstance(details, dict) else ""
        payload = details.get("payload", "") if isinstance(details, dict) else ""
        target = vuln.get("target", "")

        if "xss" in vuln_type:
            result["summary"] = (
                "This Cross-Site Scripting vulnerability can be exploited to execute malicious JavaScript in victims' browsers."
            )
            result["tools"] = [
                "Web browser",
                "Browser Developer Tools",
                "BurpSuite (optional)",
            ]
            result["difficulty"] = "Low to Medium"

            xss_steps = [
                f"Navigate to the vulnerable page: {target}",
                "Identify the vulnerable input field or parameter",
            ]

            if payload:
                xss_steps.append(f"Insert the following XSS payload: `{payload}`")
            else:
                xss_steps.append(
                    "Insert a basic XSS payload such as: `<script>alert(document.cookie)</script>`"
                )

            xss_steps.extend(
                [
                    "Submit the form or request",
                    "Verify that the JavaScript executes in the browser",
                    "For a real attack, the payload would typically steal cookies, capture keystrokes, or perform actions on behalf of the victim",
                ]
            )

            result["steps"] = xss_steps

        elif "sql" in vuln_type:
            result["summary"] = (
                "This SQL Injection vulnerability can be exploited to extract data from the database or potentially gain further access to the system."
            )
            result["tools"] = [
                "Web browser",
                "Browser Developer Tools",
                "SQLmap (optional)",
                "BurpSuite (optional)",
            ]
            result["difficulty"] = "Medium"

            sqli_steps = [
                f"Navigate to the vulnerable page: {target}",
                "Identify the vulnerable input field or parameter",
            ]

            if payload:
                sqli_steps.append(
                    f"Use the following SQL Injection payload: `{payload}`"
                )
            else:
                sqli_steps.append(
                    "Use a basic SQL Injection payload such as: `' OR 1=1 --`"
                )

            sqli_steps.extend(
                [
                    "Submit the form or request",
                    "Observe the results to confirm successful injection",
                    "For database enumeration, try payloads like: `' UNION SELECT table_name,column_name FROM information_schema.columns --`",
                    "Extract specific data with targeted queries once database structure is known",
                ]
            )

            result["steps"] = sqli_steps

        elif "csrf" in vuln_type:
            result["summary"] = (
                "This Cross-Site Request Forgery vulnerability can be exploited to perform actions on behalf of authenticated users without their knowledge."
            )
            result["tools"] = [
                "Text editor",
                "Web hosting or local server",
                "Web browser",
            ]
            result["difficulty"] = "Medium"

            csrf_steps = [
                "Create a malicious HTML page that automatically submits a form to the vulnerable endpoint",
                f"The form should target: {target}",
                "Include all necessary parameters that the vulnerable form requires",
                "Host the malicious HTML page on a server or locally",
                "Trick the victim into visiting the malicious page while they're authenticated to the vulnerable site",
                "When the victim loads the page, the form will automatically submit, performing the action without their knowledge",
            ]

            result["steps"] = csrf_steps

        elif "auth" in vuln_type or "session" in vuln_type:
            result["summary"] = (
                "This authentication or session management vulnerability can be exploited to gain unauthorized access to user accounts."
            )
            result["tools"] = [
                "Web browser",
                "Browser Developer Tools",
                "BurpSuite (optional)",
            ]
            result["difficulty"] = "Medium to High"

            auth_steps = [
                f"Navigate to the vulnerable authentication page: {target}",
                "Identify the specific authentication weakness (weak passwords, session fixation, etc.)",
            ]

            if "password" in vuln_type.lower():
                auth_steps.extend(
                    [
                        "Attempt to use common passwords from a wordlist",
                        "Look for account lockout mechanisms and bypass methods",
                        "If successful, you will gain access to the account",
                    ]
                )
            elif "session" in vuln_type.lower():
                auth_steps.extend(
                    [
                        "Examine the session cookies using browser developer tools",
                        "Analyze the cookie pattern for predictability or other weaknesses",
                        "Attempt to manipulate the session identifier",
                        "If successful, you will gain access to another user's session",
                    ]
                )
            else:
                auth_steps.extend(
                    [
                        "Examine authentication mechanisms for bypass opportunities",
                        "Look for direct object references, authentication state bugs, or logic flaws",
                        "If successful, you will gain unauthorized access",
                    ]
                )

            result["steps"] = auth_steps

        elif "idor" in vuln_type:
            result["summary"] = (
                "This Insecure Direct Object Reference vulnerability can be exploited to access or modify data belonging to other users."
            )
            result["tools"] = [
                "Web browser",
                "Browser Developer Tools",
                "BurpSuite (optional)",
            ]
            result["difficulty"] = "Low to Medium"

            idor_steps = [
                f"Navigate to the vulnerable page: {target}",
                "Identify the object reference parameter in the URL or request (usually an ID number)",
                "Modify the parameter to reference another user's data (e.g., change id=123 to id=124)",
                "Submit the request with the modified parameter",
                "Verify that you can access data belonging to another user",
                "For a systematic approach, try sequential values, UUIDs, or other predictable patterns",
            ]

            result["steps"] = idor_steps

        else:
            # Generic exploitation steps for unknown vulnerability types
            result["steps"] = [
                f"Navigate to the vulnerable target: {target}",
                "Identify the input points or parameters that can be manipulated",
                "Craft appropriate payloads for the suspected vulnerability",
                "Submit the modified request and observe the response",
                "Look for signs of successful exploitation in the application response",
                "Refine the approach based on the observed results",
            ]

        # Add post-exploitation guidance
        result["post_exploitation"] = [
            "Document all findings and successful exploitation methods",
            "Consider the potential impact beyond the initial exploitation",
            "Assess what sensitive data or functionality could be accessed",
            "Determine if privilege escalation is possible from this entry point",
        ]

        return result

    def _get_references(self, vuln: Dict[str, Any]) -> List[str]:
        """Get references for the vulnerability or provide default ones."""
        if "details" in vuln and "references" in vuln["details"]:
            return vuln["details"]["references"]

        # Provide default references based on vulnerability type
        vuln_type = vuln.get("vulnerability_type", "").lower()

        if "xss" in vuln_type:
            return [
                "https://owasp.org/www-community/attacks/xss/",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                "https://portswigger.net/web-security/cross-site-scripting",
            ]
        elif "sql" in vuln_type:
            return [
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                "https://portswigger.net/web-security/sql-injection",
            ]
        elif "csrf" in vuln_type:
            return [
                "https://owasp.org/www-community/attacks/csrf",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
                "https://portswigger.net/web-security/csrf",
            ]
        elif "auth" in vuln_type or "session" in vuln_type:
            return [
                "https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication",
                "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
                "https://portswigger.net/web-security/authentication",
            ]
        elif "idor" in vuln_type:
            return [
                "https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control",
                "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html",
                "https://portswigger.net/web-security/access-control/idor",
            ]
        else:
            return [
                "https://owasp.org/www-project-top-ten/",
                "https://portswigger.net/web-security",
            ]

    def _generate_markdown(self, report: Dict[str, Any]) -> str:
        """Generate a markdown report from the report data structure."""
        timestamp = report["timestamp"]
        summary = report["summary"]
        findings = report["findings"]

        # Start with the report header
        md = "# Security Assessment Report\n\n"
        md += f"**Generated:** {timestamp}\n\n"

        # Add summary section
        md += "## Summary\n\n"
        md += f"**Total Vulnerabilities:** {summary['total_vulnerabilities']}\n\n"

        # Add severity breakdown
        md += "### Vulnerability Severity Breakdown\n\n"
        md += "| Severity | Count |\n|----------|-------|\n"
        for severity, count in summary["severity_counts"].items():
            md += f"| {severity.capitalize()} | {count} |\n"

        # Add vulnerability types
        if summary["vulnerability_types"]:
            md += "\n### Vulnerability Types\n\n"
            for vuln_type in summary["vulnerability_types"]:
                md += f"- {vuln_type}\n"

        # Add detailed findings
        md += "\n## Detailed Findings\n\n"

        # Sort findings by severity (critical to low)
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            findings,
            key=lambda x: severity_order.get(x.get("severity", "").lower(), 999),
        )

        # Add each finding
        for i, finding in enumerate(sorted_findings, 1):
            md += f"### {i}. {finding['title']}\n\n"
            md += f"**Severity:** {finding['severity'].capitalize()}  \n"
            md += f"**Type:** {finding['type']}  \n"
            if finding["target"]:
                md += f"**Target:** {finding['target']}  \n"
            md += f"**Validated:** {'Yes' if finding['validated'] else 'No'}  \n\n"

            md += f"#### Description\n\n{finding['description']}\n\n"
            md += f"#### Impact\n\n{finding['impact']}\n\n"

            if finding["reproduction"]:
                md += "#### Steps to Reproduce\n\n"
                if isinstance(finding["reproduction"], list):
                    for step_num, step in enumerate(finding["reproduction"], 1):
                        md += f"{step_num}. {step}\n"
                else:
                    md += finding["reproduction"] + "\n"
                md += "\n"

            if finding["evidence"]:
                md += f"#### Evidence\n\n```\n{finding['evidence']}\n```\n\n"

            # Add exploitation guide section
            if finding.get("exploitation_guide"):
                guide = finding["exploitation_guide"]
                md += "#### Exploitation Guide\n\n"

                if isinstance(guide, dict):
                    if guide.get("summary"):
                        md += f"**Summary:** {guide['summary']}\n\n"

                    if guide.get("difficulty"):
                        md += f"**Difficulty:** {guide['difficulty']}\n\n"

                    if guide.get("prerequisites"):
                        md += "**Prerequisites:**\n\n"
                        for prereq in guide["prerequisites"]:
                            md += f"- {prereq}\n"
                        md += "\n"

                    if guide.get("tools"):
                        md += "**Required Tools:**\n\n"
                        for tool in guide["tools"]:
                            md += f"- {tool}\n"
                        md += "\n"

                    if guide.get("steps"):
                        md += "**Detailed Exploitation Steps:**\n\n"
                        for step_num, step in enumerate(guide["steps"], 1):
                            md += f"{step_num}. {step}\n"
                        md += "\n"

                    if guide.get("post_exploitation"):
                        md += "**Post-Exploitation Actions:**\n\n"
                        for post_step in guide["post_exploitation"]:
                            md += f"- {post_step}\n"
                        md += "\n"

                    if guide.get("detection_evasion"):
                        md += f"**Detection Considerations:** {guide['detection_evasion']}\n\n"
                else:
                    # If it's just a string
                    md += guide + "\n\n"

            md += f"#### Remediation\n\n{finding['remediation']}\n\n"

            if finding["references"]:
                md += "#### References\n\n"
                for ref in finding["references"]:
                    md += f"- {ref}\n"
                md += "\n"

            md += "---\n\n"

        # Add footer
        md += "\n*Report generated by VibePenTester - Advanced AI Security Testing Agent*\n"

        return md
