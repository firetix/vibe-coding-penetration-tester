import os
import json
import re
import logging
from datetime import datetime
from typing import Dict, List, Any


class ReportManager:
    def __init__(self, upload_folder: str):
        self.upload_folder = upload_folder
        self.logger = logging.getLogger("web_ui")
        self.sessions = {}
        self.ensure_report_directory()

    def ensure_report_directory(self) -> None:
        try:
            os.makedirs(self.upload_folder, exist_ok=True)
            self.logger.info(f"Ensured report directory exists: {self.upload_folder}")
        except Exception as e:
            self.logger.error(f"Failed to create report directory: {str(e)}")

    def get_report_directories(self) -> List[str]:
        if not os.path.exists(self.upload_folder):
            return []

        try:
            return [
                d
                for d in os.listdir(self.upload_folder)
                if os.path.isdir(os.path.join(self.upload_folder, d))
            ]
        except Exception as e:
            self.logger.error(f"Error listing report directories: {str(e)}")
            return []

    def get_report_list(self) -> List[Dict[str, Any]]:
        reports = []
        for report_dir in self.get_report_directories():
            try:
                report_info = self._parse_report_dir_name(report_dir)
                report_path = os.path.join(
                    self.upload_folder, report_dir, "report.json"
                )

                # Check if report exists directly in the directory
                if os.path.exists(report_path):
                    with open(report_path, "r") as f:
                        report_data = json.load(f)
                        vuln_count = len(report_data.get("findings", []))

                        reports.append(
                            {
                                "id": report_dir,
                                "url": report_info.get("url", "Unknown URL"),
                                "timestamp": report_info.get(
                                    "timestamp", "Unknown Date"
                                ),
                                "date": self._format_timestamp(
                                    report_info.get("timestamp")
                                ),
                                "vulnerabilities": vuln_count,
                            }
                        )
                else:
                    # Check if there's a subdirectory that might contain the report
                    dir_path = os.path.join(self.upload_folder, report_dir)
                    if os.path.exists(dir_path) and os.path.isdir(dir_path):
                        subdirs = [
                            d
                            for d in os.listdir(dir_path)
                            if os.path.isdir(os.path.join(dir_path, d))
                        ]

                        for subdir in subdirs:
                            nested_report_path = os.path.join(
                                dir_path, subdir, "report.json"
                            )
                            if os.path.exists(nested_report_path):
                                self.logger.info(
                                    f"Found report in nested directory: {nested_report_path}"
                                )

                                try:
                                    with open(nested_report_path, "r") as f:
                                        report_data = json.load(f)
                                        vuln_count = len(
                                            report_data.get("findings", [])
                                        )

                                        reports.append(
                                            {
                                                "id": report_dir,  # Still use the main directory as ID
                                                "url": report_info.get(
                                                    "url", "Unknown URL"
                                                ),
                                                "timestamp": report_info.get(
                                                    "timestamp", "Unknown Date"
                                                ),
                                                "date": self._format_timestamp(
                                                    report_info.get("timestamp")
                                                ),
                                                "vulnerabilities": vuln_count,
                                                "nested_dir": subdir,  # Track that this is in a nested directory
                                            }
                                        )
                                except Exception as nested_e:
                                    self.logger.error(
                                        f"Error parsing nested report {nested_report_path}: {str(nested_e)}"
                                    )
            except Exception as e:
                self.logger.error(f"Error parsing report {report_dir}: {str(e)}")

        # Sort by timestamp descending (newest first)
        return sorted(reports, key=lambda r: r.get("timestamp", ""), reverse=True)

    def get_report(self, report_id: str) -> Dict[str, Any]:
        report_path = os.path.join(self.upload_folder, report_id, "report.json")
        markdown_path = os.path.join(self.upload_folder, report_id, "report.md")

        # Handle nested directory structure
        if not os.path.exists(report_path):
            # Check if report_id directory exists at all
            if not os.path.exists(os.path.join(self.upload_folder, report_id)):
                return {"error": "Report not found"}

            # Check if there's a subdirectory that might contain the report
            subdirs = [
                d
                for d in os.listdir(os.path.join(self.upload_folder, report_id))
                if os.path.isdir(os.path.join(self.upload_folder, report_id, d))
            ]

            if subdirs:
                # Check for report in first subdirectory
                nested_report_path = os.path.join(
                    self.upload_folder, report_id, subdirs[0], "report.json"
                )
                nested_markdown_path = os.path.join(
                    self.upload_folder, report_id, subdirs[0], "report.md"
                )

                if os.path.exists(nested_report_path):
                    self.logger.info(
                        f"Found report in nested directory: {nested_report_path}"
                    )
                    report_path = nested_report_path
                    markdown_path = nested_markdown_path

        # If we still can't find the report, return an error
        if not os.path.exists(report_path):
            return {"error": "Report not found"}

        try:
            with open(report_path, "r") as f:
                report_data = json.load(f)

            # Add markdown content if available
            if os.path.exists(markdown_path):
                with open(markdown_path, "r") as f:
                    report_data["markdown"] = f.read()

            return report_data
        except Exception as e:
            self.logger.error(f"Error reading report {report_id}: {str(e)}")
            return {"error": f"Error reading report: {str(e)}"}

    def create_report_directory(self, url: str) -> str:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Sanitize the URL for filesystem use
        safe_url = self._sanitize_url(url)

        # Create a directory name that combines the URL and timestamp
        report_dir = f"{safe_url}_{timestamp}"
        report_path = os.path.join(self.upload_folder, report_dir)

        try:
            os.makedirs(report_path, exist_ok=True)
            return report_dir
        except Exception as e:
            self.logger.error(f"Error creating report directory: {str(e)}")
            return f"report_{timestamp}"  # Fallback

    def save_report(
        self, report_dir: str, report_data: Dict[str, Any]
    ) -> Dict[str, str]:
        report_path = os.path.join(self.upload_folder, report_dir)
        json_path = os.path.join(report_path, "report.json")
        markdown_path = os.path.join(report_path, "report.md")

        try:
            # Save JSON report
            with open(json_path, "w") as f:
                json.dump(report_data, f, indent=2)

            # Save markdown report if available
            if "markdown" in report_data:
                with open(markdown_path, "w") as f:
                    f.write(report_data["markdown"])

            return {
                "status": "success",
                "report_id": report_dir,
                "json_path": json_path,
                "markdown_path": markdown_path,
            }
        except Exception as e:
            self.logger.error(f"Error saving report: {str(e)}")
            return {"status": "error", "message": str(e)}

    def seed_deterministic_report(
        self, report_dir: str, url: str, scan_mode: str = "quick"
    ) -> Dict[str, str]:
        """Create deterministic report artifacts used by end-to-end tests."""
        report_data = {
            "status": "success",
            "url": url,
            "scan_mode": scan_mode,
            "generated_by": "seed_deterministic_report",
            "findings": [
                {
                    "name": "Reflected XSS",
                    "severity": "high",
                    "vulnerability_type": "Cross-Site Scripting (XSS)",
                    "target": url,
                    "details": {
                        "payload": "<script>alert(1)</script>",
                        "evidence": "Payload reflected in deterministic E2E fixture response",
                    },
                }
            ],
            "markdown": (
                "# Deterministic E2E Report\n\n"
                f"- Target: {url}\n"
                f"- Scan mode: {scan_mode}\n"
                "- Findings: 1\n"
            ),
        }
        return self.save_report(report_dir, report_data)

    def _sanitize_url(self, url: str) -> str:
        # Remove protocol
        url = re.sub(r"^https?://", "", url)

        # Handle fragments (anything after #) which commonly cause deeply nested folders
        url = url.split("#")[0]

        # Also remove query parameters (anything after ?)
        url = url.split("?")[0]

        # Replace all slashes, back slashes with underscores
        url = re.sub(r"[/\\]", "_", url)

        # Replace other invalid filename characters with underscores
        url = re.sub(r'[*?:"<>|]', "_", url)

        # Replace multiple underscores with a single one
        url = re.sub(r"_+", "_", url)

        # Limit length, but ensure we get the domain part
        domain_part = url.split("_")[0] if "_" in url else url

        if len(url) > 50:
            # Keep the domain and shorten the rest
            if len(domain_part) < 30:
                remaining_length = 50 - len(domain_part)
                url = domain_part + "_" + url[len(domain_part) + 1 :][:remaining_length]
            else:
                url = domain_part[:30] + "_" + url[len(domain_part) + 1 :][:20]

        return url

    def _parse_report_dir_name(self, dir_name: str) -> Dict[str, str]:
        # Expected format: sanitized_url_YYYYMMDD_HHMMSS
        parts = dir_name.split("_")

        # Extract timestamp from the end (last 15 characters should be YYYYMMDD_HHMMSS)
        timestamp_part = "_".join(parts[-2:]) if len(parts) >= 2 else ""

        # Everything before the timestamp is the URL part
        url_part = "_".join(parts[:-2]) if len(parts) >= 2 else dir_name

        # Restore protocol to URL for display
        if not url_part.startswith("http"):
            url_part = f"http://{url_part}"

        return {"url": url_part, "timestamp": timestamp_part}

    def _format_timestamp(self, timestamp_str: str) -> str:
        if not timestamp_str:
            return "Unknown Date"

        try:
            # Expected format: YYYYMMDD_HHMMSS
            dt = datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S")
            return dt.strftime("%b %d, %Y at %H:%M")
        except:
            return timestamp_str
