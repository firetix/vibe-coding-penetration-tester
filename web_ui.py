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

# Setup logging - check if we're in a cloud environment like Vercel
import sys
import os

# Determine if we're running in Vercel or similar read-only environment
is_vercel = os.environ.get('VERCEL') == '1' or os.environ.get('VERCEL_ENV') is not None

# Configure appropriate logging handlers
log_handlers = [logging.StreamHandler()]
if not is_vercel:
    try:
        # Only add file handler in non-Vercel environment
        log_handlers.append(logging.FileHandler('web_ui.log'))
    except OSError as e:
        print(f"Warning: Could not create log file, continuing with stream logging only: {str(e)}", file=sys.stderr)

# Setup the logger
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=log_handlers
)
logger = logging.getLogger('web_ui')

# Log the environment we're running in
if is_vercel:
    logger.info("Running in Vercel environment, file logging disabled")

app = Flask(__name__)

# In Vercel, use /tmp for storing reports since the main directory is read-only
if is_vercel:
    app.config['UPLOAD_FOLDER'] = '/tmp/vibe_pen_tester_reports'
    logger.info(f"Using Vercel-compatible tmp directory for reports: {app.config['UPLOAD_FOLDER']}")
else:
    app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'reports')
    logger.info(f"Using standard directory for reports: {app.config['UPLOAD_FOLDER']}")

# Make sure reports directory exists
try:
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    logger.info(f"Successfully created reports directory: {app.config['UPLOAD_FOLDER']}")
except Exception as e:
    logger.error(f"Failed to create reports directory: {str(e)}")
    # Fall back to /tmp if we can't create the standard directory
    if not is_vercel:
        app.config['UPLOAD_FOLDER'] = '/tmp/vibe_pen_tester_reports'
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        logger.info(f"Using fallback tmp directory for reports: {app.config['UPLOAD_FOLDER']}")

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
    "current_action": "",
    "completed_tasks": []  # New field to track completed tasks by ID
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
    ollama_url = request.form.get('ollama_url', 'http://localhost:11434')  # Default Ollama URL
    
    # Get API keys from the form if provided
    openai_api_key = request.form.get('openai_api_key')
    anthropic_api_key = request.form.get('anthropic_api_key')
    
    logger.info(f"Requested scan for URL: {url} using {provider} model: {model}")
    if provider == "ollama":
        logger.info(f"Using Ollama server at: {ollama_url}")
    
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
        "ollama_url": ollama_url if provider == "ollama" else None,
        "report_path": "",
        "error": None,
        "agent_logs": [],
        "action_plan": [],
        "current_action": "Initializing Security Agents",
        "completed_tasks": []
    }
    logger.info(f"Scan status initialized for {url} with {provider} model: {model}")
    
    # Start scan in a background thread
    scan_thread = threading.Thread(
        target=run_scan, 
        args=(
            url, 
            model, 
            provider, 
            ollama_url if provider == "ollama" else None,
            openai_api_key,
            anthropic_api_key
        )
    )
    scan_thread.daemon = True
    scan_thread.start()
    logger.info(f"Scan thread started for {url}")
    
    return jsonify({
        "status": "success",
        "message": f"Scan started for {url} using {provider}:{model}"
    })

def run_scan(url, model="gpt-4o", provider="openai", ollama_url=None, openai_api_key=None, anthropic_api_key=None):
    global scan_status
    
    logger.info(f"Starting scan process for {url} using {provider} model: {model}")
    if provider == "ollama" and ollama_url:
        logger.info(f"Using Ollama server at: {ollama_url}")
    
    try:
        # Generate a timestamp for the report directory
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        logger.debug(f"Generated timestamp: {timestamp}")
        
        # Update status
        scan_status["current_task"] = "Running scan"
        scan_status["progress"] = 10
        logger.debug("Updated scan status: 10% - Running scan")
        
        # Define task IDs and their relationships
        task_mapping = {
            1: {"name": "Target discovery and reconnaissance", "keywords": ["target", "discovery", "reconnaissance", "scan initialization"]},
            2: {"name": "Surface crawling and endpoint enumeration", "keywords": ["crawl", "endpoint", "enumeration", "mapping"]},
            3: {"name": "Cross-Site Scripting (XSS) vulnerability scanning", "keywords": ["xss", "cross-site scripting"]},
            4: {"name": "Cross-Site Request Forgery (CSRF) vulnerability detection", "keywords": ["csrf", "cross-site request forgery"]},
            5: {"name": "Authentication security testing", "keywords": ["auth", "login", "password", "credential"]},
            6: {"name": "SQL Injection vulnerability detection", "keywords": ["sql", "injection", "sqli"]},
            7: {"name": "Input validation and sanitization checks", "keywords": ["input validation", "sanitization", "validate"]},
            8: {"name": "Security header verification", "keywords": ["security header", "header verification", "http header"]},
        }
        
        # Initialize the action plan with default tasks
        def initialize_action_plan():
            # Create header if not exists
            if len(scan_status["action_plan"]) == 0:
                scan_status["action_plan"] = [f"Preparing Security Assessment for {scan_status['url']}"]
                
            # Add all tasks to the action plan with pending status
            for task_id, task_info in task_mapping.items():
                # Check if this task already exists in the plan
                task_exists = False
                for item in scan_status["action_plan"]:
                    if task_info["name"].lower() in item.lower():
                        task_exists = True
                        break
                        
                if not task_exists:
                    # Add the task with the step number and pending status
                    scan_status["action_plan"].append(f"Step {task_id}: {task_info['name']} (Pending)")
                    logger.debug(f"Added task to action plan: Step {task_id}: {task_info['name']} (Pending)")
        
        # Create a function to check if a task already exists in the action plan
        def task_exists_in_plan(task_name):
            if not task_name:
                return False
            
            task_name_lower = task_name.lower()
            for item in scan_status["action_plan"]:
                if task_name_lower in item.lower():
                    return True
            return False
        
        # Create a function to clear duplicate tasks from the action plan
        def deduplicate_action_plan():
            # Skip if plan is empty or just has the title
            if len(scan_status["action_plan"]) <= 1:
                return
            
            # Keep track of seen task names to identify duplicates
            seen_tasks = set()
            unique_plan = [scan_status["action_plan"][0]]  # Keep the title
            
            for i, item in enumerate(scan_status["action_plan"]):
                # Skip the title item
                if i == 0:
                    continue
                    
                # Extract the core task name without status markers
                task_name = re.sub(r'\s*\((Pending|Completed)\)$', '', item)
                # Remove step number prefix if present
                if "Step " in task_name:
                    task_name = re.sub(r'^Step \d+:\s*', '', task_name)
                
                # Skip if we've seen this task before
                task_key = task_name.strip().lower()
                if task_key in seen_tasks:
                    logger.debug(f"Removing duplicate task: {item}")
                    continue
                    
                # Add to seen tasks and keep this item
                seen_tasks.add(task_key)
                unique_plan.append(item)
            
            # Update the plan if we removed any duplicates
            if len(unique_plan) < len(scan_status["action_plan"]):
                logger.info(f"Removed {len(scan_status['action_plan']) - len(unique_plan)} duplicate tasks from action plan")
                scan_status["action_plan"] = unique_plan
        
        # Initialize the action plan
        initialize_action_plan()
        
        # Function to mark a task as completed
        def mark_task_completed(task_id):
            if task_id not in scan_status["completed_tasks"]:
                logger.info(f"Marking task {task_id} as completed: {task_mapping.get(task_id, {}).get('name', 'Unknown task')}")
                scan_status["completed_tasks"].append(task_id)
                
                # Update action plan list with completion status
                for i, plan_item in enumerate(scan_status["action_plan"]):
                    # Skip the first item which is the main plan title
                    if i == 0:
                        continue
                        
                    task_name = task_mapping.get(task_id, {}).get('name', '')
                    # Check if this plan item corresponds to the completed task
                    if task_name and task_name.lower() in plan_item.lower():
                        # Remove any existing status markers
                        clean_item = re.sub(r'\s*\((Pending|Completed)\)$', '', plan_item)
                        # Add completed marker
                        scan_status["action_plan"][i] = f"{clean_item} (Completed)"
                        logger.debug(f"Updated action plan item {i} to mark as completed: {scan_status['action_plan'][i]}")
                        return  # Stop after the first match
        
        # Add a function to mark all tasks as completed at the end of the scan
        def mark_all_tasks_completed():
            logger.info("Marking all tasks as completed")
            for task_id in task_mapping.keys():
                if task_id not in scan_status["completed_tasks"]:
                    mark_task_completed(task_id)
            
            # Also iterate through all action plan items to ensure everything is marked
            for i, plan_item in enumerate(scan_status["action_plan"]):
                # Skip the first item which is the main plan title
                if i == 0:
                    continue
                    
                # If item has (Pending) status, change to completed
                if "(Pending)" in plan_item:
                    clean_item = re.sub(r'\s*\((Pending|Completed)\)$', '', plan_item)
                    scan_status["action_plan"][i] = f"{clean_item} (Completed)"
                    logger.debug(f"Force marked plan item {i} as completed: {scan_status['action_plan'][i]}")
        
        # Function to strip ANSI color codes from log messages
        def strip_ansi_codes(text):
            if not text:
                return text
            # Pattern to match ANSI escape sequences
            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
            return ansi_escape.sub('', text)
        
        # Set Ollama URL in environment if using Ollama provider
        if provider == "ollama" and ollama_url:
            os.environ["OLLAMA_BASE_URL"] = ollama_url
            logger.info(f"Using Ollama server at {ollama_url}")
        
        # Set API keys in environment if provided
        if provider == "openai" and openai_api_key:
            os.environ["OPENAI_API_KEY"] = openai_api_key
            logger.info("Using OpenAI API key from form input")
        
        if provider == "anthropic" and anthropic_api_key:
            os.environ["ANTHROPIC_API_KEY"] = anthropic_api_key
            logger.info("Using Anthropic API key from form input")
        
        # Prepare output directory based on sanitized URL and timestamp
        sanitized_url = re.sub(r'[^\w\-_]', '_', url.replace('://', '_'))
        output_dir = os.path.join(app.config['UPLOAD_FOLDER'], f"{sanitized_url}_{timestamp}")
        os.makedirs(output_dir, exist_ok=True)
        logger.debug(f"Created output directory: {output_dir}")
        
        # Add a placeholder for the report path
        scan_status["report_path"] = os.path.join(output_dir, "report.md")
        
        # Initialize and run the scan
        try:
            # Import here to avoid circular imports
            from core.coordinator import SwarmCoordinator
            from utils.config import load_config
            
            # Load configuration
            config = load_config()
            
            # Initialize the swarm coordinator
            coordinator = SwarmCoordinator(
                url=url,
                model=model,
                provider=provider,
                scope="url",  # Always use url scope in web UI
                output_dir=output_dir,
                config=config,
                openai_api_key=openai_api_key,
                anthropic_api_key=anthropic_api_key
            )
            
            # Run the scan and get results
            coordinator.run()
            
            # Scan completed, mark all tasks as completed
            scan_status["progress"] = 100
            scan_status["current_task"] = "Scan completed"
            # Run deduplication before marking tasks as completed
            deduplicate_action_plan()
            mark_all_tasks_completed()
            logger.info("All tasks marked as completed")

            # If report path not found, try to find it
            if not scan_status["report_path"]:
                logger.warning("Report path not found, searching for most recent report")
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

if __name__ == "__main__":
    # We already created the upload folder at the start
    # Just log that we're starting the server
    logger.info(f"Starting web server on port {int(os.environ.get('PORT', 5050))}")
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5050)), debug=not is_vercel)