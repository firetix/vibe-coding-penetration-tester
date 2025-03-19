import os
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
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
        self.logger.info(f"Generating report for {len(vulnerabilities)} vulnerabilities in directory: {self.output_dir}")
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Verify output directory exists (double-check)
        if not os.path.exists(self.output_dir):
            self.logger.warning(f"Output directory does not exist, creating: {self.output_dir}")
            os.makedirs(self.output_dir, exist_ok=True)
        
        # Filter out vulnerabilities where vulnerability_found is False
        real_vulnerabilities = [vuln for vuln in vulnerabilities if vuln.get("vulnerability_found", True)]
        
        # Debug info about filtering
        if len(real_vulnerabilities) < len(vulnerabilities):
            self.logger.info(f"Filtered out {len(vulnerabilities) - len(real_vulnerabilities)} false positives")
        
        # Debug info for each vulnerability
        if real_vulnerabilities:
            self.logger.info("Vulnerabilities to report:")
            for i, vuln in enumerate(real_vulnerabilities, 1):
                self.logger.info(f"  #{i}: {vuln.get('vulnerability_type', 'Unknown')} - {vuln.get('severity', 'Unknown')}")
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
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        
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
                "vulnerability_types": list(vuln_by_type.keys())
            },
            "findings": [self._format_vulnerability(vuln) for vuln in real_vulnerabilities]
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
            "remediation": self._get_remediation(vuln),
            "references": self._get_references(vuln),
            "validated": vuln.get("validated", False),
            "validation_details": vuln.get("validation_details", {})
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
            return f"A security vulnerability was identified that could potentially be exploited by attackers."
    
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
    
    def _get_references(self, vuln: Dict[str, Any]) -> List[str]:
        """Get references for the vulnerability or provide default ones."""
        if "details" in vuln and "references" in vuln["details"]:
            return vuln["details"]["references"]
        
        # Provide default references based on vulnerability type
        vuln_type = vuln.get("vulnerability_type", "").lower()
        
        if "xss" in vuln_type:
            return [
                "https://owasp.org/www-community/attacks/xss/",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
            ]
        elif "sql" in vuln_type:
            return [
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
            ]
        elif "csrf" in vuln_type:
            return [
                "https://owasp.org/www-community/attacks/csrf",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"
            ]
        elif "auth" in vuln_type or "session" in vuln_type:
            return [
                "https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication",
                "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"
            ]
        else:
            return [
                "https://owasp.org/www-project-top-ten/"
            ]
    
    def _generate_markdown(self, report: Dict[str, Any]) -> str:
        """Generate a markdown report from the report data structure."""
        timestamp = report["timestamp"]
        summary = report["summary"]
        findings = report["findings"]
        
        # Start with the report header
        md = f"# Security Assessment Report\n\n"
        md += f"**Generated:** {timestamp}\n\n"
        
        # Add summary section
        md += f"## Summary\n\n"
        md += f"**Total Vulnerabilities:** {summary['total_vulnerabilities']}\n\n"
        
        # Add severity breakdown
        md += f"### Vulnerability Severity Breakdown\n\n"
        md += f"| Severity | Count |\n|----------|-------|\n"
        for severity, count in summary["severity_counts"].items():
            md += f"| {severity.capitalize()} | {count} |\n"
        
        # Add vulnerability types
        if summary["vulnerability_types"]:
            md += f"\n### Vulnerability Types\n\n"
            for vuln_type in summary["vulnerability_types"]:
                md += f"- {vuln_type}\n"
        
        # Add detailed findings
        md += f"\n## Detailed Findings\n\n"
        
        # Sort findings by severity (critical to low)
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(findings, key=lambda x: severity_order.get(x.get("severity", "").lower(), 999))
        
        # Add each finding
        for i, finding in enumerate(sorted_findings, 1):
            md += f"### {i}. {finding['title']}\n\n"
            md += f"**Severity:** {finding['severity'].capitalize()}  \n"
            md += f"**Type:** {finding['type']}  \n"
            if finding['target']:
                md += f"**Target:** {finding['target']}  \n"
            md += f"**Validated:** {'Yes' if finding['validated'] else 'No'}  \n\n"
            
            md += f"#### Description\n\n{finding['description']}\n\n"
            md += f"#### Impact\n\n{finding['impact']}\n\n"
            
            if finding['reproduction']:
                md += f"#### Steps to Reproduce\n\n"
                if isinstance(finding['reproduction'], list):
                    for step_num, step in enumerate(finding['reproduction'], 1):
                        md += f"{step_num}. {step}\n"
                else:
                    md += finding['reproduction'] + "\n"
                md += "\n"
            
            if finding['evidence']:
                md += f"#### Evidence\n\n```\n{finding['evidence']}\n```\n\n"
            
            md += f"#### Remediation\n\n{finding['remediation']}\n\n"
            
            if finding['references']:
                md += f"#### References\n\n"
                for ref in finding['references']:
                    md += f"- {ref}\n"
                md += "\n"
            
            md += "---\n\n"
        
        # Add footer
        md += "\n*Report generated by VibePenTester - Advanced AI Security Testing Agent*\n"
        
        return md
