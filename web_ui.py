#!/usr/bin/env python3

import os
import json
import subprocess
import time
import threading
import logging
import re
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_from_directory

# Setup logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('web_ui.log')
    ]
)
logger = logging.getLogger('web_ui')

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'reports')

# Store scan status
scan_status = {
    "is_running": False,
    "progress": 0,
    "current_task": "",
    "url": "",
    "report_path": "",
    "error": None,
    "agent_logs": [],
    "action_plan": [],
    "current_action": ""
}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def start_scan():
    global scan_status
    
    logger.info("Received scan request")
    
    # Check if a scan is already running
    if scan_status["is_running"]:
        logger.warning("Rejected scan request: A scan is already running")
        return jsonify({
            "status": "error",
            "message": "A scan is already running. Please wait for it to complete."
        }), 400
    
    # Get form data from the request
    url = request.form.get('url')
    model = request.form.get('model', 'gpt-4o')  # Default to gpt-4o if not specified
    provider = request.form.get('provider', 'openai')  # Default to openai if not specified
    
    logger.info(f"Requested scan for URL: {url} using {provider} model: {model}")
    
    if not url:
        logger.warning("Rejected scan request: No URL provided")
        return jsonify({
            "status": "error",
            "message": "No URL provided"
        }), 400
    
    # Reset scan status
    scan_status = {
        "is_running": True,
        "progress": 0,
        "current_task": "Initializing scan",
        "url": url,
        "model": model,
        "provider": provider,
        "report_path": "",
        "error": None,
        "agent_logs": [],
        "action_plan": ["Preparing Security Assessment for " + url],
        "current_action": "Initializing Security Agents"
    }
    logger.info(f"Scan status initialized for {url} with {provider} model: {model}")
    
    # Start scan in a background thread
    scan_thread = threading.Thread(target=run_scan, args=(url, model, provider))
    scan_thread.daemon = True
    scan_thread.start()
    logger.info(f"Scan thread started for {url}")
    
    return jsonify({
        "status": "success",
        "message": f"Scan started for {url} using {provider}:{model}"
    })

def run_scan(url, model="gpt-4o", provider="openai"):
    global scan_status
    
    logger.info(f"Starting scan process for {url} using {provider} model: {model}")
    
    try:
        # Generate a timestamp for the report directory
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        logger.debug(f"Generated timestamp: {timestamp}")
        
        # Update status
        scan_status["current_task"] = "Running scan"
        scan_status["progress"] = 10
        logger.debug("Updated scan status: 10% - Running scan")
        
        # Construct the command
        cmd = [
            "python", 
            "main.py",
            "--url", url,
            "--scope", "url",
            "--model", model,
            "--provider", provider
        ]
        logger.info(f"Constructed command: {' '.join(cmd)}")
        
        # Run the command
        logger.info("Starting subprocess")
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        logger.debug(f"Subprocess started with PID: {process.pid}")
        
        # Monitor output
        logger.info("Monitoring subprocess output")
        while True:
            output_line = process.stdout.readline()
            if output_line:
                logger.debug(f"Process output: {output_line.strip()}")
            
            if not output_line and process.poll() is not None:
                logger.debug(f"Process ended with return code: {process.returncode}")
                break
            
            # Add all output lines to agent logs (limit to last 100 entries)
            if output_line.strip():
                # Add timestamp to log entries
                log_entry = f"[{datetime.now().strftime('%H:%M:%S')}] {output_line.strip()}"
                scan_status["agent_logs"].append(log_entry)
                # Keep only the last 100 log entries
                if len(scan_status["agent_logs"]) > 100:
                    scan_status["agent_logs"] = scan_status["agent_logs"][-100:]
            
            # Update progress based on log messages
            if "Starting security testing" in output_line:
                scan_status["progress"] = 20
                scan_status["current_task"] = "Starting security testing"
                # Add to action plan if not already present
                if len(scan_status["action_plan"]) <= 1:
                    scan_status["action_plan"].append("Step 1: Target discovery and reconnaissance")
                logger.debug("Updated scan status: 20% - Starting security testing")
            elif "Executing xss task" in output_line or "XSS" in output_line:
                scan_status["progress"] = 40
                scan_status["current_task"] = "Testing for XSS vulnerabilities"
                scan_status["current_action"] = "XSS Testing"
                
                # Add to action plan if not already in the plan
                has_xss_step = False
                for step in scan_status["action_plan"]:
                    if "XSS" in step.upper():
                        has_xss_step = True
                        break
                
                if not has_xss_step:
                    scan_status["action_plan"].append("Step 2: Cross-Site Scripting (XSS) Vulnerability Testing")
                
                logger.debug("Updated scan status: 40% - Testing for XSS vulnerabilities")
            elif "Executing csrf task" in output_line or "CSRF" in output_line:
                scan_status["progress"] = 60
                scan_status["current_task"] = "Testing for CSRF vulnerabilities"
                scan_status["current_action"] = "CSRF Testing"
                
                # Add to action plan if not already in the plan
                has_csrf_step = False
                for step in scan_status["action_plan"]:
                    if "CSRF" in step.upper():
                        has_csrf_step = True
                        break
                
                if not has_csrf_step:
                    scan_status["action_plan"].append("Step 3: Cross-Site Request Forgery (CSRF) Vulnerability Testing")
                
                logger.debug("Updated scan status: 60% - Testing for CSRF vulnerabilities")
            elif "Executing auth task" in output_line or "auth" in output_line.lower() or "password" in output_line.lower():
                scan_status["progress"] = 80
                scan_status["current_task"] = "Testing authentication"
                scan_status["current_action"] = "Authentication Testing"
                
                # Add to action plan if not already in the plan
                has_auth_step = False
                for step in scan_status["action_plan"]:
                    if any(auth_term in step.lower() for auth_term in ["auth", "login", "password", "credential"]):
                        has_auth_step = True
                        break
                
                if not has_auth_step:
                    scan_status["action_plan"].append("Step 4: Authentication & Authorization Testing")
                
                logger.debug("Updated scan status: 80% - Testing authentication")
            elif "Security testing completed" in output_line or "report" in output_line.lower() or "generating" in output_line.lower():
                scan_status["progress"] = 90
                scan_status["current_task"] = "Generating report"
                scan_status["current_action"] = "Report Generation"
                
                # Add to action plan if not already in the plan
                has_report_step = False
                for step in scan_status["action_plan"]:
                    if "report" in step.lower():
                        has_report_step = True
                        break
                
                if not has_report_step:
                    scan_status["action_plan"].append("Step 5: Generating Security Assessment Report")
                
                logger.debug("Updated scan status: 90% - Generating report")
            
            # Extract security action plans and steps - broaden pattern matching
            # For action plans - match more patterns
            if any(plan_marker in output_line.upper() for plan_marker in 
                   ["ACTION PLAN", "SECURITY PLAN", "TESTING PLAN", "ATTACK PLAN", "SCAN PLAN", "PLANNER AGENT", "SECURITY TESTING PLAN"]):
                logger.debug(f"Found action plan marker in: {output_line}")
                if ":" in output_line:
                    plan_parts = output_line.split(":", 1)
                    if len(plan_parts) > 1:
                        plan_entry = plan_parts[1].strip()
                    else:
                        plan_entry = output_line.strip()
                else:
                    plan_entry = output_line.strip()
                
                # Initialize with this as the main plan
                scan_status["action_plan"] = [plan_entry]
                scan_status["current_action"] = "Planning Security Tests"
                logger.info(f"Created new action plan: {plan_entry}")
                
                # Add a badge to indicate this is from the planner agent
                scan_status["agent_logs"].append(f"[PLANNER] Created security testing plan for {scan_status['url']}")
                
                # Look for various patterns that indicate the security plan's tasks
                # First check for explicit mention of number of tasks - match both "tasks" and "task"
                tasks_match = re.search(r'with\s+(\d+)\s+tasks?', output_line, re.IGNORECASE)
                
                # First try to extract real task names if they're listed in the logs
                extracted_tasks = []
                
                # Look for task names in subsequent lines
                next_lines = []
                for _ in range(10):  # Check next 10 lines for possible tasks
                    next_line = process.stdout.readline()
                    if next_line:
                        next_lines.append(next_line.strip())
                        # Add to regular logs too
                        log_entry = f"[{datetime.now().strftime('%H:%M:%S')}] {next_line.strip()}"
                        scan_status["agent_logs"].append(log_entry)
                        
                        # Check if this line describes a task/step
                        task_line_match = re.search(r'(Step|Task)\s+(\d+)[:\.\)]\s*(.*)', next_line, re.IGNORECASE)
                        if task_line_match:
                            task_num = int(task_line_match.group(2))
                            task_desc = task_line_match.group(3).strip()
                            if task_desc:
                                while len(extracted_tasks) < task_num:
                                    extracted_tasks.append(None)  # Pad the list if needed
                                extracted_tasks.append(task_desc)
                                logger.info(f"Found task {task_num} description: {task_desc}")
                
                # If tasks were mentioned but not described, use default names with more descriptive text
                if tasks_match and not extracted_tasks:
                    num_tasks = int(tasks_match.group(1))
                    logger.info(f"Detected plan with {num_tasks} tasks but no descriptions found")
                    
                    # Default task descriptions
                    default_tasks = [
                        "Initial reconnaissance and target discovery",
                        "Surface crawling and endpoint enumeration",
                        "Cross-Site Scripting (XSS) vulnerability scanning",
                        "Cross-Site Request Forgery (CSRF) vulnerability detection", 
                        "Authentication security testing",
                        "SQL Injection vulnerability detection",
                        "Input validation and sanitization checks",
                        "Security header verification",
                        "Session management security analysis",
                        "Sensitive data exposure detection"
                    ]
                    
                    # Pre-populate action plan with placeholders using better descriptions
                    for i in range(1, num_tasks + 1):
                        if i <= len(default_tasks):
                            task_desc = default_tasks[i-1]
                        else:
                            task_desc = f"Security test {i}"
                            
                        task_name = f"Step {i}: {task_desc} (Pending)"
                        scan_status["action_plan"].append(task_name)
                        logger.info(f"Added placeholder for task {i}: {task_desc}")
                
                # If we found actual task descriptions, use those
                elif extracted_tasks:
                    for i, task_desc in enumerate(extracted_tasks, 1):
                        if task_desc:
                            task_name = f"Step {i}: {task_desc} (Pending)"
                            scan_status["action_plan"].append(task_name)
                            logger.info(f"Added placeholder with real description for task {i}: {task_desc}")
                
            # For steps - more flexible matching
            elif (("Step " in output_line or "STEP " in output_line or "Task " in output_line or output_line.strip().startswith("-") or 
                  output_line.strip().startswith("*") or output_line.strip().startswith("•") or
                  output_line.strip().startswith("#") or
                  (len(output_line.strip()) > 2 and output_line.strip()[0].isdigit() and output_line.strip()[1] in [".", ")", ":"]))
                  and len(output_line.strip()) > 5):
                
                # This looks like a step in an action plan
                step_entry = output_line.strip()
                
                # Check if this is updating a pending step
                step_match = re.search(r'Step\s+(\d+)', step_entry, re.IGNORECASE)
                task_match = re.search(r'Task\s+(\d+)', step_entry, re.IGNORECASE)
                step_num = None
                
                if step_match:
                    step_num = int(step_match.group(1))
                elif task_match:
                    step_num = int(task_match.group(1))
                
                if step_num is not None and len(scan_status["action_plan"]) > step_num:
                    # Build a pattern that will match a placeholder with this step number,
                    # but with any task description
                    placeholder_pattern = f"Step {step_num}:[^(]*\\(Pending\\)"
                    found_placeholder = False
                    
                    for i, plan_item in enumerate(scan_status["action_plan"]):
                        if re.search(placeholder_pattern, plan_item, re.IGNORECASE):
                            # Extract the description from the pending item if we want to preserve it
                            try:
                                pending_desc = re.search(f"Step {step_num}: (.*) \\(Pending\\)", plan_item, re.IGNORECASE).group(1)
                                
                                # If the current step has better description, use it
                                if ":" in step_entry:
                                    active_desc = step_entry.split(":", 1)[1].strip()
                                    # Use the best description (current or previous)
                                    better_desc = active_desc if len(active_desc) > 10 else pending_desc
                                    
                                    # Create a more informative step entry without the "pending" tag
                                    updated_step = f"Step {step_num}: {better_desc}"
                                else:
                                    # No good description in current log, use the one from placeholder
                                    updated_step = f"Step {step_num}: {pending_desc}"
                            except:
                                # If we can't extract, just use the current entry
                                updated_step = step_entry
                                
                            # Replace the placeholder with the actual step
                            logger.info(f"Replacing placeholder step {step_num} with actual step: {updated_step}")
                            scan_status["action_plan"][i] = updated_step
                            found_placeholder = True
                            break
                    
                    # If no placeholder was found, append as a new step
                    if not found_placeholder:
                        scan_status["action_plan"].append(step_entry)
                        logger.info(f"Added step to action plan: {step_entry}")
                else:
                    # No placeholder found or no step number, just append
                    scan_status["action_plan"].append(step_entry)
                    logger.info(f"Added step to action plan: {step_entry}")
                
                # Also use this as the current action if it's descriptive enough
                if len(step_entry) > 10:
                    if ":" in step_entry:
                        action_desc = step_entry.split(":", 1)[1].strip()
                        if action_desc:
                            scan_status["current_action"] = action_desc[:50] + ("..." if len(action_desc) > 50 else "")
                    else:
                        scan_status["current_action"] = step_entry[:50] + ("..." if len(step_entry) > 50 else "")
                
            # For vulnerabilities
            elif "Discovered vulnerability:" in output_line or "VULNERABILITY FOUND" in output_line.upper() or "FOUND VULNERABILITY" in output_line.upper():
                try:
                    if ":" in output_line:
                        vuln_info = output_line.split(":", 1)[1].strip()
                    else:
                        vuln_info = output_line.strip()
                    
                    scan_status["agent_logs"].append(f"[VULNERABILITY] {vuln_info}")
                    scan_status["current_action"] = f"Found: {vuln_info[:30]}..."
                    
                    # Don't add vulnerabilities to the action plan, only to logs
                    logger.info(f"Found vulnerability: {vuln_info}")
                except Exception as e:
                    logger.error(f"Error processing vulnerability line: {str(e)}")
                
            # Check for task execution in logs to update pending tasks
            elif any(task_marker in output_line.lower() for task_marker in ["executing", "testing", "scanning", "checking", "generating", "executing tool"]):
                # This might indicate a task is being executed
                task_types = ["sqli", "sql injection", "xss", "cross-site", "csrf", "request forgery",
                             "auth", "authentication", "session", "idor", "access control"]
                
                # Check which task type this might be
                matched_type = None
                for task_type in task_types:
                    if task_type.lower() in output_line.lower():
                        matched_type = task_type
                        break
                
                if matched_type:
                    # Try to find a pending task that matches this type
                    found = False
                    matched_index = -1
                    
                    # Go through all action plan items looking for pending ones
                    for i, plan_item in enumerate(scan_status["action_plan"]):
                        if "(Pending)" in plan_item and matched_type.lower() in plan_item.lower():
                            # Found a matching pending task
                            matched_index = i
                            found = True
                            break
                    
                    if found and matched_index >= 0:
                        # Update the pending task to remove the pending marker
                        current_task = scan_status["action_plan"][matched_index]
                        updated_task = current_task.replace("(Pending)", "").strip()
                        scan_status["action_plan"][matched_index] = updated_task
                        logger.info(f"Updated task from pending to active: {updated_task}")
                        
                        # Set as current action
                        task_desc = updated_task.split(": ", 1)[1] if ": " in updated_task else updated_task
                        scan_status["current_action"] = f"Executing: {task_desc[:30]}..."
            
            # Look for specific security plan markers in the logs
            elif "Creating security plan with" in output_line:
                # This is a clear indicator that a security plan was created
                # Extract the number of tasks if available
                tasks_count_match = re.search(r"Creating security plan with\s+(\d+)\s+tasks?", output_line)
                if tasks_count_match:
                    tasks_count = int(tasks_count_match.group(1))
                    logger.info(f"Detected security plan with {tasks_count} tasks")
                    
                    # If we don't already have a plan, create one
                    if len(scan_status["action_plan"]) == 0:
                        scan_status["action_plan"] = [f"Security Assessment Plan for {scan_status['url']}"]
                    
                    # Use default security tasks - will be replaced when actual tasks are found
                    default_security_tasks = [
                        "SQL Injection testing",
                        "Cross-Site Scripting (XSS) vulnerability scanning",
                        "Cross-Site Request Forgery (CSRF) protection check",
                        "Authentication & Authorization testing", 
                        "Session management security analysis",
                        "Access control verification",
                        "Security header verification",
                        "Input validation tests",
                        "Sensitive data exposure checks",
                        "Error handling & information leakage tests"
                    ]
                    
                    # Add tasks with pending status
                    for i in range(1, min(tasks_count + 1, len(default_security_tasks) + 1)):
                        # Check if we already have enough tasks
                        if i > len(scan_status["action_plan"]) - 1:  # -1 for the title
                            task_name = f"Step {i}: {default_security_tasks[i-1]} (Pending)"
                            scan_status["action_plan"].append(task_name)
                            logger.info(f"Added placeholder for security task {i}: {default_security_tasks[i-1]}")
            
            # Extract task details from logs - look for task arguments
            elif any(x in output_line.lower() for x in ["security plan", "planner", "security testing plan"]) or ("tasks" in output_line.lower() and ("type" in output_line.lower() and "target" in output_line.lower())):
                try:
                    # This looks like task information from the planner agent
                    logger.info("Found potential task details in logs from planner agent")
                    
                    # Add a planner agent log entry
                    if "security plan" in output_line.lower() or "planner" in output_line.lower():
                        scan_status["agent_logs"].append(f"[PLANNER] Processing security testing plan")
                    
                    # Look for task type and target patterns - match different formats
                    # Format 1: {'type': 'xxx', 'target': 'yyy', 'priority': 'zzz'}
                    # Format 2: type=xxx target=yyy
                    task_matches = []
                    
                    # Try specific patterns for the log format you provided
                    # Example: {"type":"sqli","target":"snippets.gtl?uid=cheddar","priority":"high"}
                    format0_matches = re.finditer(r'[{"]type[":]+"([^"]+)"[,:\s]+[":]?target[":]+"([^"]+)"', output_line)
                    for match in format0_matches:
                        task_matches.append(match)
                    
                    # Try the {'type': 'xxx', 'target': 'yyy'} format
                    if not task_matches:
                        format1_matches = re.finditer(r"[{']type['\"]?:\s*['\"]([^'\"]+)['\"],\s*['\"]?target['\"]?:\s*['\"]([^'\"]+)", output_line)
                        for match in format1_matches:
                            task_matches.append(match)
                    
                    # If nothing found, try the simpler 'type=xxx target=yyy' format
                    if not task_matches:
                        format2_matches = re.finditer(r"type\s*=\s*[\'\"]?([^\'\"}\s,]+)[\'\"]?[,\s]+target\s*=\s*[\'\"]?([^\'\"}\s,]+)", output_line)
                        for match in format2_matches:
                            task_matches.append(match)
                    
                    tasks_found = []
                    for match in task_matches:
                        try:
                            task_type = match.group(1)
                            task_target = match.group(2)
                            
                            # Clean up the values
                            task_type = task_type.strip("'\" ")
                            task_target = task_target.strip("'\" ")
                            
                            # Only add if we have valid values
                            if task_type and task_target:
                                tasks_found.append((task_type, task_target))
                        except Exception as e:
                            logger.error(f"Error extracting task match: {str(e)}")
                    
                    # If we found tasks, ensure they're represented in the action plan
                    if tasks_found:
                        logger.info(f"Extracted {len(tasks_found)} tasks from logs")
                        
                        # Make sure we have a basic action plan
                        if len(scan_status["action_plan"]) == 0:
                            scan_status["action_plan"] = [f"Security Assessment of {scan_status['url']}"]
                        
                        # For each task, either add it or update an existing one
                        for i, (task_type, task_target) in enumerate(tasks_found, 1):
                            task_desc = f"{task_type.upper()} testing on {task_target}"
                            
                            # Check if we already have a step with this info
                            step_exists = False
                            for plan_item in scan_status["action_plan"]:
                                if task_type.lower() in plan_item.lower() and task_target.lower() in plan_item.lower():
                                    step_exists = True
                                    break
                            
                            # If not, add it
                            if not step_exists:
                                # Find an appropriate step number - check the most recently added pending step
                                step_num = i
                                for j, plan_item in enumerate(scan_status["action_plan"]):
                                    if plan_item.lower().startswith("step "):
                                        step_match = re.search(r"Step\s+(\d+)", plan_item, re.IGNORECASE)
                                        if step_match:
                                            last_step = int(step_match.group(1))
                                            if last_step >= step_num:
                                                step_num = last_step + 1
                                
                                # Add the new step with pending status
                                new_step = f"Step {step_num}: {task_desc} (Pending)"
                                scan_status["action_plan"].append(new_step)
                                logger.info(f"Added new task from details: {new_step}")
                except Exception as e:
                    logger.error(f"Error processing task details: {str(e)}")
                    
            # Generate a default action plan if we have logs but no plan detected
            if len(scan_status["agent_logs"]) > 10 and len(scan_status["action_plan"]) == 0:
                logger.info("Generating default action plan based on scan progress")
                scan_status["action_plan"] = ["Security Assessment of " + scan_status["url"]]
                if scan_status["progress"] >= 20:
                    scan_status["action_plan"].append("Step 1: Initialize scanner and target discovery")
                if scan_status["progress"] >= 40:
                    scan_status["action_plan"].append("Step 2: Test for XSS vulnerabilities")
                if scan_status["progress"] >= 60:
                    scan_status["action_plan"].append("Step 3: Test for CSRF vulnerabilities")
                if scan_status["progress"] >= 80:
                    scan_status["action_plan"].append("Step 4: Test authentication mechanisms")
                if scan_status["progress"] >= 90:
                    scan_status["action_plan"].append("Step 5: Generate security report")
            elif "Report saved to" in output_line:
                # Extract and validate report path
                try:
                    report_path = output_line.split("Report saved to ")[1].strip()
                    logger.info(f"Found report path in output: {report_path}")
                    
                    # Check if this is an absolute path
                    if os.path.isabs(report_path):
                        # Convert to relative path from the project root
                        project_root = os.path.dirname(os.path.abspath(__file__))
                        if report_path.startswith(project_root):
                            report_path = os.path.relpath(report_path, project_root)
                            logger.debug(f"Converted to relative path: {report_path}")
                    
                    # Verify the path exists
                    if report_path.startswith('reports/'):
                        # Path is already relative to project root
                        full_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), report_path)
                    else:
                        # Try both as is and with 'reports/' prefix
                        full_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), report_path)
                        if not os.path.exists(full_path):
                            alt_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'reports', report_path)
                            if os.path.exists(alt_path):
                                full_path = alt_path
                                report_path = os.path.join('reports', report_path)
                                logger.debug(f"Adjusted path to: {report_path}")
                    
                    if os.path.exists(full_path):
                        logger.info(f"Verified report path exists: {full_path}")
                        # Check if this is a file or directory
                        if os.path.isdir(full_path):
                            # Check if report.md exists in this directory
                            report_file = os.path.join(full_path, "report.md")
                            if os.path.exists(report_file):
                                logger.info(f"Found report.md in {full_path}")
                                scan_status["report_path"] = report_path
                            else:
                                logger.warning(f"report.md not found in {full_path}")
                                scan_status["report_path"] = report_path  # Still use the path, will handle missing file error later
                        else:
                            # The path is a file
                            logger.warning(f"Report path is a file, not a directory: {full_path}")
                            # Use the directory containing the file
                            report_dir = os.path.dirname(full_path)
                            report_path = os.path.dirname(report_path)
                            logger.info(f"Using directory: {report_dir}")
                            scan_status["report_path"] = report_path
                    else:
                        logger.error(f"Report path does not exist: {full_path}")
                        # Still store the path, we'll try to find a report later
                        scan_status["report_path"] = report_path
                        
                    scan_status["progress"] = 100
                    scan_status["current_task"] = "Scan completed"
                    logger.debug("Updated scan status: 100% - Scan completed")
                except Exception as e:
                    logger.exception(f"Error processing report path: {str(e)}")
                    # Still try to extract the path even if validation fails
                    try:
                        report_path = output_line.split("Report saved to ")[1].strip()
                        scan_status["report_path"] = report_path
                    except:
                        logger.error("Failed to extract report path")
                    scan_status["progress"] = 100
                    scan_status["current_task"] = "Scan completed with path errors"
        
        # Get final process output
        stdout, stderr = process.communicate()
        if stderr:
            logger.warning(f"Process stderr: {stderr}")
        
        # Check if process failed
        if process.returncode != 0:
            logger.error(f"Process failed with return code {process.returncode}: {stderr}")
            scan_status["error"] = f"Scan failed: {stderr}"
            scan_status["current_task"] = "Scan failed"
            scan_status["progress"] = 100
        
        # If report path not found in logs, try to find it
        if not scan_status["report_path"]:
            logger.warning("Report path not found in process output, searching for most recent report")
            # Look for the most recently created report directory
            reports_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'reports')
            logger.debug(f"Searching for reports in: {reports_dir}")
            
            # Check if reports directory exists
            if not os.path.exists(reports_dir):
                logger.error(f"Reports directory does not exist: {reports_dir}")
                scan_status["error"] = f"Reports directory does not exist: {reports_dir}"
                return
                
            try:
                report_dirs = [d for d in os.listdir(reports_dir) if os.path.isdir(os.path.join(reports_dir, d))]
                logger.debug(f"Found report directories: {report_dirs}")
                
                if not report_dirs:
                    logger.error("No report directories found in reports folder")
                    scan_status["error"] = "No report directories found"
                    return
                    
                # Get all modification times for debugging
                mod_times = {d: os.path.getmtime(os.path.join(reports_dir, d)) for d in report_dirs}
                logger.debug(f"Directory modification times: {mod_times}")
                
                report_dirs.sort(key=lambda d: os.path.getmtime(os.path.join(reports_dir, d)), reverse=True)
                logger.debug(f"Sorted report directories: {report_dirs}")
                
                if report_dirs:
                    most_recent = report_dirs[0]
                    logger.info(f"Using most recent report directory: {most_recent}")
                    most_recent_path = os.path.join(reports_dir, most_recent)
                    
                    # Check if report.md exists in this directory
                    report_file = os.path.join(most_recent_path, "report.md")
                    if os.path.exists(report_file):
                        logger.info(f"Found report.md in {most_recent_path}")
                        scan_status["report_path"] = os.path.join('reports', most_recent)
                    else:
                        logger.error(f"report.md not found in {most_recent_path}")
                        # List all files in the directory for debugging
                        files = os.listdir(most_recent_path)
                        logger.debug(f"Files in directory: {files}")
                        scan_status["error"] = f"report.md not found in most recent report directory"
                else:
                    logger.error("No report directories found after sorting")
                    scan_status["error"] = "No report directories found"
            except Exception as e:
                logger.exception(f"Error finding report directory: {str(e)}")
                scan_status["error"] = f"Error finding report directory: {str(e)}"
                
    except Exception as e:
        logger.exception(f"Exception during scan: {str(e)}")
        scan_status["error"] = str(e)
        scan_status["current_task"] = "Scan failed"
        scan_status["progress"] = 100
    finally:
        # Ensure scan status is updated
        scan_status["is_running"] = False
        logger.info("Scan process completed, is_running set to False")

@app.route('/status')
def get_status():
    logger.debug(f"Status request received, current status: {scan_status}")
    return jsonify(scan_status)

@app.route('/report')
def get_report():
    logger.info("Report request received")
    
    if not scan_status["report_path"]:
        logger.warning("Report request rejected: No report available")
        return jsonify({
            "status": "error",
            "message": "No report available"
        }), 404
    
    # Handle report path resolution
    report_path = scan_status["report_path"]
    logger.debug(f"Raw report path: {report_path}")
    
    # Check if the path is absolute or relative
    if os.path.isabs(report_path):
        # Use absolute path directly
        if os.path.isdir(report_path):
            report_file = os.path.join(report_path, "report.md")
        else:
            # If it's a file path, use it directly
            report_file = report_path
    else:
        # Try different ways to resolve the path
        project_root = os.path.dirname(os.path.abspath(__file__))
        
        # First try: Direct join
        possible_path = os.path.join(project_root, report_path)
        
        # Second try: As a directory + report.md
        if os.path.isdir(possible_path):
            report_file = os.path.join(possible_path, "report.md")
        elif os.path.isdir(os.path.join(project_root, "reports", report_path)):
            # Third try: With reports/ prefix
            report_file = os.path.join(project_root, "reports", report_path, "report.md")
        elif "report.md" in report_path:
            # Fourth try: Path already includes report.md
            report_file = os.path.join(project_root, report_path)
        else:
            # If all else fails, assume it's in the reports directory
            report_file = os.path.join(project_root, report_path, "report.md")
    
    logger.info(f"Attempting to read report file: {report_file}")
    
    try:
        # Check if file exists
        if not os.path.exists(report_file):
            logger.error(f"Report file not found: {report_file}")
            
            # Try alternative: Check if the report file is in the parent directory
            alt_report_file = os.path.join(os.path.dirname(report_file), "report.md")
            if os.path.exists(alt_report_file):
                logger.info(f"Found alternative report file: {alt_report_file}")
                report_file = alt_report_file
            else:
                # List all files in the parent directory for debugging
                try:
                    parent_dir = os.path.dirname(report_file)
                    if os.path.exists(parent_dir) and os.path.isdir(parent_dir):
                        files = os.listdir(parent_dir)
                        logger.debug(f"Files in parent directory: {files}")
                except Exception as e:
                    logger.error(f"Could not list parent directory: {str(e)}")
                
                return jsonify({
                    "status": "error",
                    "message": f"Report file not found: {report_file}"
                }), 404
            
        # Read the file
        with open(report_file, 'r') as f:
            report_content = f.read()
            
        logger.info(f"Successfully read report file: {len(report_content)} characters")
        return jsonify({
            "status": "success",
            "content": report_content
        })
    except Exception as e:
        logger.exception(f"Error reading report file: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Error reading report: {str(e)}"
        }), 500

@app.route('/reports/<path:filename>')
def download_report(filename):
    logger.info(f"Download request for report file: {filename}")
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except Exception as e:
        logger.exception(f"Error serving report file: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Error serving report file: {str(e)}"
        }), 500

if __name__ == '__main__':
    # Create templates directory if it doesn't exist
    os.makedirs(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates'), exist_ok=True)
    # Use port 5050 to avoid conflicts with macOS AirPlay service on port 5000
    app.run(debug=True, host='0.0.0.0', port=5050)