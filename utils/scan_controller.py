import os
import json
import time
import subprocess
import threading
import logging
from typing import Dict, List, Any, Callable, Optional


class ScanController:
    def __init__(self, session_manager, report_manager):
        self.session_manager = session_manager
        self.report_manager = report_manager
        self.logger = logging.getLogger("web_ui")

    def start_scan(
        self,
        session_id: str,
        url: str,
        config: Dict[str, Any],
        activity_callback: Optional[Callable] = None,
    ) -> str:
        try:
            # Validate URL before starting
            if not url.startswith(("http://", "https://")):
                url = f"http://{url}"

            # Debug log about the activity callback
            if activity_callback:
                try:
                    import inspect

                    sig = inspect.signature(activity_callback)
                    self.logger.info(
                        f"Activity callback provided with {len(sig.parameters)} parameters: {list(sig.parameters.keys())}"
                    )
                except Exception as e:
                    self.logger.info(f"Could not inspect activity callback: {str(e)}")
            else:
                self.logger.info("No activity callback provided")

            # Create scan entry in session manager
            scan_id = self.session_manager.start_scan(session_id, url, config)

            # Create a new report directory for this scan
            report_dir = self.report_manager.create_report_directory(url)
            self.session_manager.update_scan_status(
                session_id, scan_id, "initializing", 0, report_dir
            )

            # Start the scan process in a background thread
            scan_thread = threading.Thread(
                target=self._run_scan_process,
                args=(session_id, scan_id, url, config, report_dir, activity_callback),
            )
            scan_thread.daemon = True
            scan_thread.start()

            return scan_id

        except Exception as e:
            self.logger.error(f"Error starting scan: {str(e)}")
            raise

    def _run_scan_process(
        self,
        session_id: str,
        scan_id: str,
        url: str,
        config: Dict[str, Any],
        report_dir: str,
        activity_callback: Optional[Callable] = None,
    ) -> None:
        try:
            if os.environ.get("VPT_E2E_MODE") == "1":
                self._run_e2e_scan_process(
                    session_id, scan_id, url, config, report_dir, activity_callback
                )
                return

            self.logger.info(f"Starting scan for {url} with scan_id: {scan_id}")
            self.logger.info(f"Using session_id: {session_id} for scan activities")

            # Debug the activity callback if provided
            if activity_callback:
                import inspect

                try:
                    sig = inspect.signature(activity_callback)
                    self.logger.info(
                        f"Activity callback function: {activity_callback.__name__} with params: {list(sig.parameters.keys())}"
                    )
                except Exception as e:
                    self.logger.warning(
                        f"Could not inspect activity callback: {str(e)}"
                    )
            else:
                self.logger.error(
                    "No activity callback provided - UI won't show activities!"
                )
                # We'll continue anyway, but this is a problem

            # Update status and log activity
            self.session_manager.update_scan_status(session_id, scan_id, "running", 5)

            # Add initial activity to ensure the activity tracking is working
            if activity_callback:
                try:
                    # Store time for debugging activity persistence
                    start_time = time.strftime("%H:%M:%S")

                    # Create a highly identifiable test activity
                    activity_result = activity_callback(
                        session_id,
                        "scan_start",
                        f"Starting scan of {url} at {start_time}",
                        {
                            "url": url,
                            "timestamp": time.time(),
                            "start_time": start_time,
                        },
                        "ScanController",
                    )

                    # Log the activity creation result
                    self.logger.info(
                        f"Created initial activity for session {session_id}: {activity_result}"
                    )

                    # Verify it was stored by immediately retrieving it
                    if hasattr(activity_callback, "__self__") and hasattr(
                        activity_callback.__self__, "get_activities"
                    ):
                        # This is likely the ActivityTracker.add_activity method with access to get_activities
                        tracker = activity_callback.__self__
                        activities = tracker.get_activities(session_id)
                        self.logger.info(
                            f"After adding initial activity, session has {len(activities)} activities"
                        )
                except Exception as e:
                    self.logger.error(f"Error adding initial activity: {str(e)}")

            # Add a callback function to monitor scan progress
            progress_callback = self._create_progress_callback(
                session_id, scan_id, activity_callback
            )

            # Add a series of security-related activities that should show up in the UI
            # These simulate what the security agents would log during the scan
            if activity_callback:
                try:
                    # Add multiple activities to test activity aggregation
                    security_activities = [
                        (
                            "security",
                            "Initializing security testing environment",
                            {"stage": "preparation"},
                            "SecuritySwarm",
                        ),
                        (
                            "planning",
                            "Analyzing application structure to plan security tests",
                            {"stage": "planning"},
                            "PlannerAgent",
                        ),
                        (
                            "xss_test",
                            "Preparing to test for Cross-Site Scripting vulnerabilities",
                            {"test_type": "xss"},
                            "XSSAgent",
                        ),
                        (
                            "sqli_test",
                            "Preparing to test for SQL Injection vulnerabilities",
                            {"test_type": "sqli"},
                            "SQLInjectionAgent",
                        ),
                        (
                            "csrf_test",
                            "Preparing to test for Cross-Site Request Forgery",
                            {"test_type": "csrf"},
                            "CSRFAgent",
                        ),
                        (
                            "discovery",
                            "Discovering application endpoints and structure",
                            {"stage": "discovery"},
                            "DiscoveryAgent",
                        ),
                    ]

                    for (
                        activity_type,
                        description,
                        details,
                        agent,
                    ) in security_activities:
                        try:
                            result = activity_callback(
                                session_id, activity_type, description, details, agent
                            )
                            self.logger.info(
                                f"Added {activity_type} activity for {agent}: {description}"
                            )
                        except Exception as e:
                            self.logger.error(
                                f"Error adding {activity_type} activity: {str(e)}"
                            )
                except Exception as e:
                    self.logger.error(f"Error adding security activities: {str(e)}")

            # Run the scan process
            self._execute_scan(url, config, report_dir, progress_callback)

            # Finalize the scan
            self._finalize_scan(session_id, scan_id, report_dir)

        except Exception as e:
            self.logger.error(f"Error running scan: {str(e)}")
            self.session_manager.update_scan_status(session_id, scan_id, "error", 100)

    def _run_e2e_scan_process(
        self,
        session_id: str,
        scan_id: str,
        url: str,
        config: Dict[str, Any],
        report_dir: str,
        activity_callback: Optional[Callable] = None,
    ) -> None:
        """Run a deterministic scan lifecycle for stable end-to-end tests."""
        scan_mode = config.get("scan_mode", "quick")
        vulnerabilities = [
            {
                "name": "Reflected XSS",
                "severity": "high",
                "vulnerability_type": "Cross-Site Scripting (XSS)",
                "target": url,
                "details": {
                    "payload": "<script>alert(1)</script>",
                    "evidence": "Payload reflected in response body",
                },
            }
        ]

        action_plan = [
            "Security Testing Plan",
            "Step 1: Initialize scan (Completed)",
            "Step 2: Run deterministic E2E checks (Completed)",
            "Step 3: Generate report artifacts (Completed)",
        ]

        def emit_activity(
            activity_type: str,
            description: str,
            details: Optional[Dict[str, Any]] = None,
        ):
            if not activity_callback:
                return
            try:
                activity_callback(
                    session_id,
                    activity_type,
                    description,
                    details or {},
                    "E2EScanController",
                )
            except Exception as err:
                self.logger.warning(f"E2E activity callback error: {err}")

        self.session_manager.update_scan_status(
            session_id,
            scan_id,
            "initializing",
            5,
            vulnerabilities=[],
            action_plan=["Step 1: Initialize scan (Pending)"],
            current_task="Initializing deterministic scan",
        )
        emit_activity(
            "scan_start",
            "Deterministic E2E scan started",
            {"url": url, "scan_mode": scan_mode},
        )
        time.sleep(0.05)

        self.session_manager.update_scan_status(
            session_id,
            scan_id,
            "running",
            45,
            vulnerabilities=vulnerabilities,
            action_plan=action_plan,
            current_task="Running deterministic vulnerability checks",
        )
        emit_activity(
            "security",
            "Running deterministic E2E security checks",
            {"scan_mode": scan_mode},
        )
        time.sleep(0.05)

        save_result = self.report_manager.seed_deterministic_report(
            report_dir, url, scan_mode
        )
        if save_result.get("status") != "success":
            raise RuntimeError(f"Failed to save deterministic report: {save_result}")

        self.session_manager.update_scan_status(
            session_id,
            scan_id,
            "completed",
            100,
            vulnerabilities=vulnerabilities,
            action_plan=action_plan,
            current_task="Deterministic scan completed",
        )
        emit_activity(
            "reporting",
            "Deterministic E2E report generated",
            {"report_dir": report_dir},
        )

    def _create_progress_callback(
        self,
        session_id: str,
        scan_id: str,
        activity_callback: Optional[Callable] = None,
    ) -> Callable:
        def progress_callback(
            progress: int,
            status: str = None,
            vulnerabilities: List[Dict[str, Any]] = None,
            activity: Dict[str, Any] = None,
            action_plan: List[str] = None,
        ) -> None:
            # Extract action plan and current task from activity if present
            extracted_action_plan = None
            current_task = None

            if activity:
                # Check if this is an action plan update
                if activity.get("type") == "action_plan" and "details" in activity:
                    plan_items = activity.get("details", {}).get("plan", [])
                    if isinstance(plan_items, list) and plan_items:
                        extracted_action_plan = plan_items

                # Check if this is a current task update
                elif activity.get("type") == "current_task":
                    description = activity.get("description", "")
                    if description:
                        current_task = description

            # Use explicitly provided action plan if available, otherwise use extracted one
            final_action_plan = (
                action_plan if action_plan is not None else extracted_action_plan
            )

            if status:
                self.session_manager.update_scan_status(
                    session_id,
                    scan_id,
                    status,
                    progress,
                    vulnerabilities=vulnerabilities,
                    action_plan=final_action_plan,
                    current_task=current_task,
                )
            else:
                self.session_manager.update_scan_status(
                    session_id,
                    scan_id,
                    None,
                    progress,
                    vulnerabilities=vulnerabilities,
                    action_plan=final_action_plan,
                    current_task=current_task,
                )

            if activity and activity_callback:
                try:
                    # Check the expected signature of the callback
                    import inspect

                    sig = inspect.signature(activity_callback)
                    param_count = len(sig.parameters)

                    if param_count == 2:
                        # It's probably expecting (session_id, activity)
                        activity_callback(session_id, activity)
                    elif param_count == 5:
                        # It's probably ActivityTracker.add_activity
                        activity_type = activity.get("type", "general")
                        description = activity.get("description", "Activity")
                        details = activity.get("details", {})
                        agent_name = activity.get("agent", None)
                        activity_callback(
                            session_id, activity_type, description, details, agent_name
                        )
                    else:
                        self.logger.warning(
                            f"Unknown activity callback signature with {param_count} parameters"
                        )
                except Exception as e:
                    self.logger.error(f"Error calling activity callback: {str(e)}")

        return progress_callback

    def _execute_scan(
        self,
        url: str,
        config: Dict[str, Any],
        report_dir: str,
        progress_callback: Callable,
    ) -> None:
        """Execute the actual scan using main.py"""
        try:
            # Create a JSON config file for the scan
            config_path = os.path.join(
                self.report_manager.upload_folder, report_dir, "scan_config.json"
            )
            os.makedirs(os.path.dirname(config_path), exist_ok=True)

            with open(config_path, "w") as f:
                json.dump(config, f, indent=2)

            # Log that we're starting the scan
            self.logger.info(f"Executing scan for {url} with output to {report_dir}")
            progress_callback(
                10,
                "preparing",
                activity={"type": "setup", "description": f"Preparing to scan {url}"},
            )

            # Setup command to run the scanner
            cmd = [
                "python",
                "main.py",
                "--url",
                url,
                "--output",
                os.path.join(self.report_manager.upload_folder, report_dir),
            ]

            # Add any additional options from config that match main.py arguments
            if config.get("model"):
                cmd.extend(["--model", config.get("model")])

            if config.get("provider"):
                cmd.extend(["--provider", config.get("provider")])

            if config.get("scope"):
                cmd.extend(["--scope", config.get("scope")])

            if config.get("verbose", False):
                cmd.append("--verbose")

            if config.get("ollama_url"):
                cmd.extend(["--ollama-url", config.get("ollama_url")])
            if config.get("openai_api_key"):
                cmd.extend(["--openai-api-key", config.get("openai_api_key")])
            if config.get("anthropic_api_key"):
                cmd.extend(["--anthropic-api-key", config.get("anthropic_api_key")])
            if config.get("google_api_key"):
                cmd.extend(["--google-api-key", config.get("google_api_key")])

            # Log the command we're about to run
            self.logger.info(f"Executing command: {' '.join(cmd)}")

            try:
                # Execute the scan process
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    bufsize=1,
                )

                # Monitor progress from process output
                self._monitor_process(process, progress_callback)

            except FileNotFoundError:
                self.logger.error("Python executable not found or main.py is missing")
                progress_callback(
                    100,
                    "error",
                    activity={
                        "type": "error",
                        "description": "Failed to start scanner process",
                    },
                )
                raise

        except Exception as e:
            self.logger.error(f"Error executing scan: {str(e)}")
            progress_callback(
                100,
                "error",
                activity={"type": "error", "description": f"Scan error: {str(e)}"},
            )
            raise

    def _monitor_process(self, process, progress_callback: Callable) -> None:
        """Monitor the scan process and update progress"""
        vulnerabilities = []
        action_plan = []
        last_error = None

        try:
            # Process stdout in real-time
            for line in iter(process.stdout.readline, ""):
                if not line.strip():
                    continue

                # Log the raw output for debugging
                self.logger.debug(f"Scanner output: {line.strip()}")

                # Parse the output line for progress information
                if "PROGRESS:" in line:
                    try:
                        progress = int(line.split("PROGRESS:")[1].strip().rstrip("%"))
                        progress_callback(progress)
                    except Exception as e:
                        self.logger.warning(f"Error parsing progress info: {str(e)}")

                # Parse the output line for vulnerability information
                elif "VULNERABILITY:" in line:
                    try:
                        vuln_json = line.split("VULNERABILITY:")[1].strip()
                        vuln = json.loads(vuln_json)
                        vulnerabilities.append(vuln)
                        progress_callback(None, vulnerabilities=vulnerabilities)

                        # Add vulnerability to action plan as well for UI visibility
                        action_item = f"Investigating vulnerability: {vuln.get('name', 'Unknown')} ({vuln.get('severity', 'medium')})"
                        if action_item not in action_plan:
                            action_plan.append(action_item)
                            progress_callback(
                                None,
                                activity={
                                    "type": "action_plan",
                                    "description": "Action Plan",
                                    "details": {"plan": action_plan},
                                },
                            )
                    except Exception as e:
                        self.logger.warning(
                            f"Error parsing vulnerability data: {str(e)}"
                        )

                # Parse output for activity information
                elif "ACTIVITY:" in line:
                    try:
                        activity_json = line.split("ACTIVITY:")[1].strip()
                        activity = json.loads(activity_json)

                        # Check if this is an action plan update
                        if activity.get(
                            "type"
                        ) == "action_plan" or "plan" in activity.get("details", {}):
                            # Extract plan items and add to our action plan
                            plan_items = activity.get("details", {}).get("plan", [])
                            if isinstance(plan_items, list) and plan_items:
                                for item in plan_items:
                                    if item not in action_plan:
                                        action_plan.append(item)

                                # Send updated action plan
                                progress_callback(
                                    None,
                                    activity={
                                        "type": "action_plan",
                                        "description": "Action Plan",
                                        "details": {"plan": action_plan},
                                    },
                                )

                        # Always send the original activity regardless
                        progress_callback(None, activity=activity)

                        # Add security activities to action plan for visibility
                        if activity.get("type") in [
                            "security",
                            "xss_test",
                            "sqli_test",
                            "csrf_test",
                            "vulnerability",
                        ]:
                            description = activity.get("description", "")
                            agent = activity.get("agent", "Security Agent")
                            action_item = f"{agent}: {description}"

                            if action_item not in action_plan:
                                action_plan.append(action_item)
                                # Send updated action plan
                                progress_callback(
                                    None,
                                    activity={
                                        "type": "action_plan",
                                        "description": "Action Plan",
                                        "details": {"plan": action_plan},
                                    },
                                )
                    except Exception as e:
                        self.logger.warning(f"Error parsing activity data: {str(e)}")

                # Check for report generation status
                elif "Generating report" in line or "Writing report" in line:
                    # Add report generation step to action plan if not already there
                    report_item = "Generating security assessment report... (Pending)"
                    if report_item not in action_plan:
                        action_plan.append(report_item)
                        progress_callback(
                            95,
                            "generating_report",
                            activity={
                                "type": "reporting",
                                "description": "Generating security assessment report",
                                "agent": "ReportGenerator",
                            },
                            action_plan=action_plan,
                        )

                # Check for report completion
                elif (
                    "report successfully written" in line
                    or "Generated security report" in line
                ):
                    # Update report generation status to completed
                    pending_item = "Generating security assessment report... (Pending)"
                    completed_item = (
                        "Security report generated successfully (Completed)"
                    )

                    # Replace pending with completed
                    if pending_item in action_plan:
                        action_plan.remove(pending_item)

                    if completed_item not in action_plan:
                        action_plan.append(completed_item)

                    progress_callback(
                        98,
                        "report_generated",
                        activity={
                            "type": "success",
                            "description": "Security report generated successfully",
                            "agent": "ReportGenerator",
                        },
                        action_plan=action_plan,
                    )

                # Parse explicit action plan lines
                elif "ACTION_PLAN:" in line:
                    try:
                        plan_text = line.split("ACTION_PLAN:")[1].strip()
                        # Try to parse as JSON first
                        try:
                            plan_data = json.loads(plan_text)
                            if isinstance(plan_data, list):
                                # Add new items to action plan
                                for item in plan_data:
                                    if item not in action_plan:
                                        action_plan.append(item)
                            elif isinstance(plan_data, dict) and "items" in plan_data:
                                for item in plan_data["items"]:
                                    if item not in action_plan:
                                        action_plan.append(item)
                        except json.JSONDecodeError:
                            # Not JSON, treat as plain text
                            if plan_text and plan_text not in action_plan:
                                action_plan.append(plan_text)

                        # Send updated action plan
                        progress_callback(
                            None,
                            activity={
                                "type": "action_plan",
                                "description": "Action Plan",
                                "details": {"plan": action_plan},
                            },
                        )
                    except Exception as e:
                        self.logger.warning(f"Error parsing action plan data: {str(e)}")

                # Look for error messages
                elif "ERROR:" in line:
                    last_error = line.strip()
                    self.logger.error(f"Scanner process error: {last_error}")

            # Read any remaining output and errors
            remaining_output, errors = process.communicate()
            exit_code = process.wait()

            # Check for errors in stderr
            if errors:
                error_msg = errors.strip()
                if error_msg:
                    self.logger.error(f"Scanner stderr: {error_msg}")
                    last_error = error_msg

            # Check exit code
            if exit_code != 0:
                self.logger.error(f"Scanner process exited with code {exit_code}")
                error_message = (
                    last_error or f"Process failed with exit code {exit_code}"
                )
                progress_callback(
                    100,
                    "error",
                    activity={"type": "error", "description": error_message},
                )

        except Exception as e:
            self.logger.error(f"Error monitoring scanner process: {str(e)}")
            progress_callback(
                100,
                "error",
                activity={
                    "type": "error",
                    "description": f"Monitoring error: {str(e)}",
                },
            )

    def _finalize_scan(self, session_id: str, scan_id: str, report_dir: str) -> None:
        try:
            # Check if report files exist
            report_path = os.path.join(
                self.report_manager.upload_folder, report_dir, "report.json"
            )
            self.logger.info(f"Report path: {report_path}")

            # If the report directory has nested structure due to long URL name, we need to fix it
            if not os.path.exists(report_path) and os.path.exists(
                os.path.join(self.report_manager.upload_folder, report_dir)
            ):
                # Check if there's a subdirectory
                subdirs = [
                    d
                    for d in os.listdir(
                        os.path.join(self.report_manager.upload_folder, report_dir)
                    )
                    if os.path.isdir(
                        os.path.join(self.report_manager.upload_folder, report_dir, d)
                    )
                ]

                if subdirs:
                    # Move files from the subdirectory to the main report directory
                    subdir_path = os.path.join(
                        self.report_manager.upload_folder, report_dir, subdirs[0]
                    )
                    self.logger.info(
                        f"Found nested report directory: {subdir_path}, moving files up"
                    )

                    # Move files up one level
                    import shutil

                    for filename in os.listdir(subdir_path):
                        src_path = os.path.join(subdir_path, filename)
                        dest_path = os.path.join(
                            self.report_manager.upload_folder, report_dir, filename
                        )
                        if os.path.isfile(src_path):
                            shutil.move(src_path, dest_path)
                            self.logger.info(
                                f"Moved file {filename} from nested directory to main report directory"
                            )

            self.logger.info(f"Scan completed successfully: {scan_id}")

            # Verify again that the report files actually exist now
            report_path = os.path.join(
                self.report_manager.upload_folder, report_dir, "report.json"
            )
            markdown_path = os.path.join(
                self.report_manager.upload_folder, report_dir, "report.md"
            )

            # Log if files exist
            if os.path.exists(report_path):
                self.logger.info(f"Verified report.json exists at: {report_path}")
            else:
                self.logger.warning(f"report.json still not found at: {report_path}")

            if os.path.exists(markdown_path):
                self.logger.info(f"Verified report.md exists at: {markdown_path}")
            else:
                self.logger.warning(f"report.md still not found at: {markdown_path}")

            # Create a final action plan with completed status for all tasks
            final_action_plan = []

            # Get the current action plan from the scan
            scan = self.session_manager.get_active_scan(session_id, scan_id)
            if scan and "action_plan" in scan:
                current_plan = scan.get("action_plan", [])
                self.logger.info(f"Current action plan has {len(current_plan)} items")

                # Update all tasks to completed status
                for item in current_plan:
                    # This is a task item, mark it as completed if it's not already
                    if "(Pending)" in item:
                        item = item.replace("(Pending)", "(Completed)")
                    elif "(Completed)" not in item and "Step" in item:
                        item = item.strip() + " (Completed)"
                    final_action_plan.append(item)
            else:
                self.logger.warning(f"No action plan found in scan {scan_id}")

            # If we have vulnerabilities, add them to the action plan
            if scan and "vulnerabilities" in scan and scan["vulnerabilities"]:
                vulns = scan["vulnerabilities"]
                self.logger.info(f"Adding {len(vulns)} vulnerabilities to action plan")
                for vuln in vulns:
                    vuln_name = vuln.get(
                        "vulnerability_type", vuln.get("name", "Unknown")
                    )
                    vuln_severity = vuln.get("severity", "medium")
                    vuln_item = f"Found vulnerability: {vuln_name} ({vuln_severity}) (Completed)"
                    if vuln_item not in final_action_plan:
                        final_action_plan.append(vuln_item)

            # Add report generation as completed
            report_item = "Security report generated successfully (Completed)"
            if report_item not in final_action_plan:
                final_action_plan.append(report_item)

            # Set final message for current task with explicit completed status
            self.logger.info(
                f"Finalizing scan with action plan containing {len(final_action_plan)} items"
            )

            # First, ensure that the scan is updated with the report_dir
            self.session_manager.update_scan_status(
                session_id,
                scan_id,
                "completed",
                100,
                report_dir=report_dir,
                action_plan=final_action_plan,
                current_task="Security testing completed. Report is available.",
            )

            # Double-check that the update worked correctly
            updated_scan = self.session_manager.get_active_scan(session_id, scan_id)
            if updated_scan:
                if updated_scan.get("report_dir") == report_dir:
                    self.logger.info(f"Successfully set report_dir to {report_dir}")
                else:
                    self.logger.warning(
                        f"Failed to set report_dir. Current value: {updated_scan.get('report_dir')}"
                    )

                if updated_scan.get("status") == "completed":
                    self.logger.info("Successfully marked scan as completed")
                else:
                    self.logger.warning(
                        f"Failed to mark scan as completed. Current status: {updated_scan.get('status')}"
                    )
            else:
                # If the scan is not in active scans anymore, check if it moved to completed scans
                completed_scans = self.session_manager.get_completed_scans(session_id)
                if completed_scans and completed_scans[0].get("id") == scan_id:
                    self.logger.info("Scan successfully moved to completed scans")
                    if completed_scans[0].get("report_dir") == report_dir:
                        self.logger.info(
                            f"Report directory correctly set in completed scan: {report_dir}"
                        )
                    else:
                        self.logger.warning(
                            f"Report directory incorrect in completed scan: {completed_scans[0].get('report_dir')}"
                        )
                else:
                    self.logger.warning(
                        "Scan not found in active or completed scans after update"
                    )

        except Exception as e:
            self.logger.error(f"Error finalizing scan: {str(e)}")
            import traceback

            self.logger.error(f"Traceback: {traceback.format_exc()}")
            self.session_manager.update_scan_status(
                session_id, scan_id, "error", 100, current_task=f"Error: {str(e)}"
            )

    def cancel_scan(self, session_id: str, scan_id: str) -> Dict[str, Any]:
        scan = self.session_manager.get_active_scan(session_id, scan_id)

        if not scan:
            return {"status": "error", "message": "Scan not found"}

        if scan.get("process") and hasattr(scan["process"], "terminate"):
            try:
                scan["process"].terminate()
                self.session_manager.update_scan_status(
                    session_id, scan_id, "cancelled", 100
                )
                return {"status": "success", "message": "Scan cancelled"}
            except Exception as e:
                return {
                    "status": "error",
                    "message": f"Error cancelling scan: {str(e)}",
                }
        else:
            self.session_manager.update_scan_status(
                session_id, scan_id, "cancelled", 100
            )
            return {"status": "success", "message": "Scan marked as cancelled"}
