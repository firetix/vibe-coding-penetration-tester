import json
import logging
import os
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from utils.postgres_json import coerce_json_value


class PostgresReportManager:
    """Hybrid report manager: filesystem staging + Postgres persistence (Supabase-compatible)."""

    def __init__(self, db_url: str, upload_folder: str):
        self.db_url = db_url
        self.upload_folder = upload_folder
        self.logger = logging.getLogger("web_ui")
        self.ensure_report_directory()
        self._init_schema()

    def _connect(self):
        try:
            import psycopg  # type: ignore
            from psycopg.rows import dict_row  # type: ignore
        except Exception as exc:  # pragma: no cover - optional dependency
            raise RuntimeError(
                "PostgresReportManager requires psycopg. Install with: pip install 'psycopg[binary]'"
            ) from exc
        return psycopg.connect(self.db_url, row_factory=dict_row)

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS reports (
                    report_id TEXT PRIMARY KEY,
                    created_at DOUBLE PRECISION NOT NULL,
                    url TEXT,
                    timestamp_text TEXT,
                    report_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                    report_md TEXT
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_reports_created_at ON reports(created_at DESC)"
            )
            conn.commit()

    def ensure_report_directory(self) -> None:
        try:
            os.makedirs(self.upload_folder, exist_ok=True)
            self.logger.info(f"Ensured report directory exists: {self.upload_folder}")
        except Exception as e:
            self.logger.error(f"Failed to create report directory: {str(e)}")

    # --- Filesystem staging (kept for scanner subprocess output) ---

    def create_report_directory(self, url: str) -> str:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_url = self._sanitize_url(url)
        report_dir = f"{safe_url}_{timestamp}"
        report_path = os.path.join(self.upload_folder, report_dir)
        try:
            os.makedirs(report_path, exist_ok=True)
        except Exception as e:
            self.logger.error(f"Error creating report directory: {str(e)}")
        return report_dir

    def _sanitize_url(self, url: str) -> str:
        import re

        url = re.sub(r"^https?://", "", url)
        url = url.split("#")[0]
        url = url.split("?")[0]
        url = re.sub(r"[/\\\\]", "_", url)
        url = re.sub(r'[*?:\"<>|]', "_", url)
        url = re.sub(r"_+", "_", url)
        return url.strip("_") or "target"

    # --- Postgres persistence ---

    def _upsert_report(self, report_id: str, url: Optional[str], report_json: Dict[str, Any], report_md: Optional[str]) -> None:
        created_at = time.time()
        timestamp_text = None
        if isinstance(report_json, dict):
            timestamp_text = report_json.get("timestamp") or report_json.get("generated_at")

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO reports(report_id, created_at, url, timestamp_text, report_json, report_md)
                VALUES (%s, %s, %s, %s, %s::jsonb, %s)
                ON CONFLICT (report_id) DO UPDATE SET
                    url = COALESCE(EXCLUDED.url, reports.url),
                    timestamp_text = COALESCE(EXCLUDED.timestamp_text, reports.timestamp_text),
                    report_json = EXCLUDED.report_json,
                    report_md = COALESCE(EXCLUDED.report_md, reports.report_md),
                    created_at = GREATEST(reports.created_at, EXCLUDED.created_at)
                """,
                (
                    report_id,
                    created_at,
                    url,
                    timestamp_text,
                    json.dumps(report_json or {}),
                    report_md,
                ),
            )
            conn.commit()

    def ingest_report(self, report_id: str, url: Optional[str] = None) -> Dict[str, str]:
        """Read report artifacts from filesystem staging and persist into Postgres."""
        report_path = os.path.join(self.upload_folder, report_id, "report.json")
        markdown_path = os.path.join(self.upload_folder, report_id, "report.md")

        if not os.path.exists(report_path):
            return {"status": "error", "message": "report.json not found"}

        try:
            with open(report_path, "r") as f:
                report_json = json.load(f)
        except Exception as e:
            return {"status": "error", "message": f"failed to read report.json: {e}"}

        report_md = None
        if os.path.exists(markdown_path):
            try:
                with open(markdown_path, "r") as f:
                    report_md = f.read()
            except Exception:
                report_md = None

        self._upsert_report(report_id, url, report_json, report_md)
        return {"status": "success", "report_id": report_id}

    # --- API surface expected by routes ---

    def get_report_list(self) -> List[Dict[str, Any]]:
        reports: List[Dict[str, Any]] = []
        try:
            with self._connect() as conn:
                rows = conn.execute(
                    """
                    SELECT report_id, created_at, url, timestamp_text, report_json
                    FROM reports
                    ORDER BY created_at DESC
                    """
                ).fetchall()
        except Exception as e:
            self.logger.error(f"Error listing reports from Postgres: {e}")
            return reports

        for row in rows:
            report_id = row.get("report_id")
            report_json = coerce_json_value(row.get("report_json"), {}) or {}
            findings = report_json.get("findings") if isinstance(report_json, dict) else None
            vuln_count = len(findings) if isinstance(findings, list) else 0

            created_at = float(row.get("created_at") or 0)
            date_str = ""
            try:
                date_str = datetime.fromtimestamp(created_at).strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                date_str = ""

            reports.append(
                {
                    "id": report_id,
                    "url": row.get("url") or report_json.get("url") or "Unknown URL",
                    "timestamp": row.get("timestamp_text") or report_json.get("timestamp") or created_at,
                    "date": date_str,
                    "vulnerabilities": vuln_count,
                }
            )
        return reports

    def get_report(self, report_id: str) -> Dict[str, Any]:
        # Prefer Postgres.
        try:
            with self._connect() as conn:
                row = conn.execute(
                    """
                    SELECT report_json, report_md, url
                    FROM reports
                    WHERE report_id = %s
                    """,
                    (report_id,),
                ).fetchone()
        except Exception as e:
            self.logger.error(f"Error fetching report {report_id} from Postgres: {e}")
            row = None

        if row:
            report_json = coerce_json_value(row.get("report_json"), {}) or {}
            if not isinstance(report_json, dict):
                report_json = {"content": report_json}
            report_md = row.get("report_md")
            if report_md:
                report_json["markdown"] = report_md
            if row.get("url") and "url" not in report_json:
                report_json["url"] = row.get("url")
            return report_json

        # Fallback to filesystem for backwards compatibility.
        report_path = os.path.join(self.upload_folder, report_id, "report.json")
        markdown_path = os.path.join(self.upload_folder, report_id, "report.md")

        if not os.path.exists(report_path):
            return {"error": "Report not found"}

        try:
            with open(report_path, "r") as f:
                report_data = json.load(f)
            if os.path.exists(markdown_path):
                with open(markdown_path, "r") as f:
                    report_data["markdown"] = f.read()
            return report_data
        except Exception as e:
            self.logger.error(f"Error reading report {report_id}: {str(e)}")
            return {"error": f"Error reading report: {str(e)}"}

    def save_report(self, report_dir: str, report_data: Dict[str, Any]) -> Dict[str, str]:
        """Write report artifacts to filesystem staging and upsert into Postgres."""
        report_path = os.path.join(self.upload_folder, report_dir)
        json_path = os.path.join(report_path, "report.json")
        markdown_path = os.path.join(report_path, "report.md")

        try:
            os.makedirs(report_path, exist_ok=True)
            with open(json_path, "w") as f:
                json.dump(report_data, f, indent=2)

            md = None
            if "markdown" in report_data:
                md = str(report_data.get("markdown") or "")
                with open(markdown_path, "w") as f:
                    f.write(md)

            # Store a copy in Postgres (excluding markdown from the json file payload).
            report_json = dict(report_data)
            report_json.pop("markdown", None)
            self._upsert_report(report_dir, report_data.get("url"), report_json, md)

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

    def get_report_artifact_bytes(self, filename: str) -> Tuple[Optional[bytes], Optional[str]]:
        """
        Fetch known artifacts from Postgres for the /reports/<path:filename> route.
        Supports: <report_id>/report.json, <report_id>/report.md
        """
        parts = [p for p in filename.split("/") if p]
        if len(parts) < 2:
            return None, None
        report_id = parts[0]
        leaf = parts[-1]
        if leaf not in {"report.json", "report.md"}:
            return None, None

        report = self.get_report(report_id)
        if report.get("error") == "Report not found":
            return None, None

        if leaf == "report.md":
            md = report.get("markdown") or ""
            return str(md).encode("utf-8"), "text/markdown; charset=utf-8"

        # report.json should match the file artifact (exclude markdown).
        payload = dict(report)
        payload.pop("markdown", None)
        return json.dumps(payload, indent=2).encode("utf-8"), "application/json; charset=utf-8"
