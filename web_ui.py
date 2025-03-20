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

# Custom log handler to capture server logs for the UI
class UILogHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.logs = []
        # Keep track of recent duplicates to avoid duplication
        self.recent_messages = set()
        self.max_recent = 50
        
    def emit(self, record):
        try:
            msg = self.format(record)
            # Strip ANSI codes
            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
            msg = ansi_escape.sub('', msg)
            
            # Do not store DEBUG level logs to avoid flooding the UI
            if record.levelno >= logging.INFO:
                # Special handling for Agent Activity logs
                if "Agent Activity:" in msg:
                    # Clean up message first - remove common artifacts
                    msg = re.sub(r'\s*Activity\s*$', '', msg)  # Remove trailing 'Activity' text
                    msg = re.sub(r'\'}]\}.*?$', '', msg)     # Remove empty JSON artifacts
                    msg = re.sub(r'(\(Agent:\s*[^)]+\))\s*(\(Agent:.*?\))+', r'\1', msg) # Remove multiple agent refs
                
                    # Check if this is a duplicate of a recent message
                    # Create a checksum of the message to identify duplicates
                    # Extract real content if it's a duplicated agent activity log
                    if msg.count("INFO - Agent Activity:") > 1:
                        # Extract the actual message that follows the repeated log prefixes
                        clean_parts = re.split(r'INFO - Agent Activity: \[\w+\]\s*', msg)
                        # Find the last non-empty part, which should be the actual message
                        actual_message = next((part for part in reversed(clean_parts) if part.strip()), "")
                        
                        # If we found real content, use that as the message
                        if actual_message.strip():
                            # Clean the actual message further
                            actual_message = re.sub(r'\s*Activity\s*$', '', actual_message)
                            actual_message = re.sub(r'\'}]\}.*?$', '', actual_message)
                            actual_message = re.sub(r'(\(Agent:\s*[^)]+\))\s*(\(Agent:.*?\))+', r'\1', actual_message)
                            msg = f"INFO - Agent Activity: {actual_message.strip()}"
                    
                    # Simple duplicate check - only add if not a duplicate
                    # Compares only the content after "Agent Activity:"
                    message_checksum = msg.strip()[-50:]  # Use last 50 chars as fingerprint
                    if message_checksum in self.recent_messages:
                        # Skip this duplicate message
                        return 
                    
                    # Add to recent messages set for future duplicate detection
                    self.recent_messages.add(message_checksum)
                    # Keep the recent messages set at reasonable size
                    if len(self.recent_messages) > self.max_recent:
                        # Can't easily remove oldest in a set, so just clear and start over if too big
                        self.recent_messages.clear()
                
                # Add the log entry
                self.logs.append({
                    'time': time.strftime('%H:%M:%S'),
                    'level': record.levelname,
                    'message': msg
                })
                
                # Keep only the last 100 logs to avoid memory issues
                if len(self.logs) > 100:
                    self.logs = self.logs[-100:]
        except Exception:
            self.handleError(record)
    
    def get_logs(self):
        return self.logs
    
    def clear(self):
        self.logs = []
        self.recent_messages.clear()

# Agent Activity Tracker
class AgentActivityTracker:
    def __init__(self):
        self.activities = {}  # Keyed by session_id
        
    def add_activity(self, session_id, activity_type, description, details=None, agent_name=None):
        """Add an agent activity entry
        
        Args:
            session_id: The session ID this activity belongs to
            activity_type: Type of activity (test, discovery, analysis, etc.)
            description: Human-readable description
            details: Optional detailed information
            agent_name: Name of the agent performing the activity
        """
        if session_id not in self.activities:
            self.activities[session_id] = []
        
        # Clean up description - normalize and remove common artifacts
        description = description.strip()
        # Remove trailing 'Activity' text which is a common artifact
        description = re.sub(r'\s*Activity\s*$', '', description)
        # Remove empty JSON artifacts
        description = re.sub(r'\'}]\}.*?$', '', description)
        # Remove multiple duplicate agent references
        description = re.sub(r'(\(Agent:\s*[^)]+\))\s*(\(Agent:.*?\))+', r'\1', description)
        
        # Check for duplicate activity before adding
        # Use last 100 chars of description as a fingerprint to detect duplicates
        description_fingerprint = description[-100:] if len(description) > 100 else description
        
        # Check if this exact activity was recently added (prevent duplicates)
        recent_timeframe = 5.0  # seconds
        current_time = time.time()
        
        for existing in reversed(self.activities[session_id][-10:]):  # Check last 10 activities
            # Skip if more than 5 seconds old
            if current_time - existing.get('timestamp', 0) > recent_timeframe:
                continue
                
            # Check if same activity type
            if existing.get('type') != activity_type:
                continue
                
            # Check for similar description
            existing_desc = existing.get('description', '')
            existing_fingerprint = existing_desc[-100:] if len(existing_desc) > 100 else existing_desc
            
            # If agent name and description fingerprint match, it's a duplicate
            if existing_fingerprint == description_fingerprint and existing.get('agent') == agent_name:
                # Return the existing activity instead of creating a duplicate
                return existing
            
        # Create the activity entry
        activity = {
            'timestamp': time.time(),
            'time': time.strftime('%H:%M:%S'),
            'type': activity_type,
            'description': description,
            'agent': agent_name
        }
        
        if details:
            activity['details'] = details
            
        # Add the activity
        self.activities[session_id].append(activity)
        
        # Keep only the last 200 activities per session
        if len(self.activities[session_id]) > 200:
            self.activities[session_id] = self.activities[session_id][-200:]
            
        # Log to server logs too for debugging - but don't log if it contains Agent Activity already
        # This prevents the cascading duplication of log messages
        if "Agent Activity:" not in description:
            logging.info(f"Agent Activity: [{activity_type}] {description}" + 
                        (f" (Agent: {agent_name})" if agent_name else ""))
        
        return activity
        
    def get_activities(self, session_id):
        """Get all activities for a session"""
        return self.activities.get(session_id, [])
        
    def clear_activities(self, session_id):
        """Clear activities for a session"""
        if session_id in self.activities:
            self.activities[session_id] = []
            
    def parse_agent_message(self, session_id, message, agent_name=None):
        """Parse agent messages to detect and extract specific activities.
        This helps categorize logs into meaningful activities.
        
        Args:
            session_id: The session ID
            message: Log message to parse
            agent_name: Name of the agent (optional)
        """
        # Skip non-string messages
        if not isinstance(message, str):
            return None
            
        # Clean up the message
        message = message.strip()
        if not message:
            return None
            
        # Remove trailing 'Activity' text which is a common artifact
        message = re.sub(r'\s*Activity\s*$', '', message)
        
        # Remove empty JSON artifacts
        message = re.sub(r'\'}]\}.*?$', '', message)
        
        # Fix duplicated agent activity logs
        # Look for repeated "INFO - Agent Activity: [planning] INFO - Agent Activity: [planning]..." pattern
        duplicate_pattern = r'(INFO - Agent Activity: \[\w+\]\s*)+'
        if re.match(duplicate_pattern, message):
            # Extract the actual message that follows the repeated log prefixes
            clean_parts = re.split(r'INFO - Agent Activity: \[\w+\]\s*', message)
            # Find the last non-empty part, which should be the actual message
            actual_message = next((part for part in reversed(clean_parts) if part.strip()), "")
            
            # Try to extract agent name from the actual message
            agent_pattern = r'\(Agent:\s*([^)]+)\)'
            agent_matches = re.findall(agent_pattern, actual_message)
            if agent_matches and not agent_name:
                agent_name = agent_matches[0].strip()
                # Remove the agent marker from the message to avoid duplication
                actual_message = re.sub(r'\s*\(Agent:\s*[^)]+\)', '', actual_message).strip()
            
            # Use the cleaned actual message instead of the original
            if actual_message:
                message = actual_message
        
        # Common patterns for different activity types
        activity_patterns = [
            # XSS tests
            (r'testing.*XSS|cross-site scripting|Injecting.*script|DOM-based XSS', 'xss_test', 'XSS Testing'),
            (r'testing.*SQL injection|SQLi test|database injection|SQL vulnerability', 'sqli_test', 'SQL Injection Testing'),
            (r'testing.*CSRF|cross-site request forgery', 'csrf_test', 'CSRF Testing'),
            
            # Discovery patterns
            (r'crawling|mapping|enumerating|discovering endpoints', 'discovery', 'Discovery'),
            (r'analyzing.*form|identifying input fields', 'form_analysis', 'Form Analysis'),
            
            # Authentication tests
            (r'testing auth|password|credential|login|session|cookie', 'auth_test', 'Authentication Testing'),
            
            # Security headers and configuration
            (r'checking.*headers|security headers|content security policy|CSP', 'header_check', 'Security Header Check'),
            
            # General security tests
            (r'injection test|command injection|OS command|path traversal', 'injection_test', 'Injection Testing'),
            (r'scanning|vulnerability scan|security scan', 'scanning', 'Security Scanning'),
            
            # Report generation
            (r'generating.*report|summarizing|creating summary', 'reporting', 'Report Generation'),
            
            # Vulnerability found
            (r'found.*vulnerability|detected.*issue|security issue identified', 'vulnerability', 'Vulnerability Found'),
            
            # Agent actions and coordination
            (r'plan generation|security test plan|creating plan', 'planning', 'Test Planning'),
            (r'agent allocation|assigning tasks|task distribution', 'coordination', 'Agent Coordination'),
            
            # Catch-all for other messages
            (r'.*', 'agent_log', 'Agent Activity')
        ]
        
        # Try to match the message to a pattern
        for pattern, activity_type, type_name in activity_patterns:
            if re.search(pattern, message, re.IGNORECASE):
                return self.add_activity(session_id, activity_type, message, agent_name=agent_name)
                
        # Default case - add as generic agent log
        return self.add_activity(session_id, 'agent_log', message, agent_name=agent_name)

# Initialize the agent activity tracker
agent_activity_tracker = AgentActivityTracker()

# Create a UI log handler and add it to the root logger
ui_log_handler = UILogHandler()
ui_log_handler.setLevel(logging.INFO)
ui_log_handler.setFormatter(logging.Formatter('%(levelname)s - %(message)s'))
logging.getLogger().addHandler(ui_log_handler)

# Example agent activities to prepopulate for new users, so they get an idea of what they'll see
sample_agent_activities = [
    ('discovery', 'Initializing target discovery and reconnaissance', 'Discovery Agent'),
    ('discovery', 'Crawling target URL to map available endpoints', 'Discovery Agent'),
    ('discovery', 'Identifying forms and input fields for testing', 'Discovery Agent'),
    ('form_analysis', 'Analyzing login form for potential vulnerabilities', 'Security Agent'),
    ('xss_test', 'Testing form inputs for Cross-Site Scripting vulnerabilities', 'XSS Testing Agent'),
    ('sqli_test', 'Performing SQL Injection tests on input parameters', 'SQLi Testing Agent'),
    ('auth_test', 'Analyzing authentication mechanisms', 'Auth Testing Agent'),
    ('reporting', 'Aggregating security findings into report', 'Report Agent')
]

# Store scan statuses by session ID
scan_statuses = {}

# Path to the sessions file for persisting scan status
if is_vercel:
    # Use /tmp directory for Vercel's read-only filesystem
    SESSIONS_FILE = '/tmp/vibe_pen_tester_sessions.json'
    logger.info(f"Using Vercel-compatible tmp directory for sessions: {SESSIONS_FILE}")
else:
    SESSIONS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sessions.json')
    logger.info(f"Using standard directory for sessions: {SESSIONS_FILE}")

# Load persisted scan statuses from file
def load_scan_statuses():
    global scan_statuses
    try:
        if os.path.exists(SESSIONS_FILE):
            with open(SESSIONS_FILE, 'r') as f:
                persisted_statuses = json.load(f)
                
                # Filter out any expired or completed sessions older than 24 hours
                current_time = time.time()
                for session_id, status in persisted_statuses.items():
                    # Convert timestamp string to epoch time if needed
                    if isinstance(status.get('start_time'), str):
                        try:
                            # Try parsing ISO format
                            dt = datetime.fromisoformat(status['start_time'].replace('Z', '+00:00'))
                            status['start_time'] = dt.timestamp()
                        except (ValueError, TypeError):
                            status['start_time'] = current_time
                    
                    # If no start time, add current time
                    if not status.get('start_time'):
                        status['start_time'] = current_time
                
                # Only keep sessions from the last 24 hours
                valid_statuses = {
                    session_id: status for session_id, status in persisted_statuses.items()
                    if current_time - status.get('start_time', 0) < 86400  # 24 hours in seconds
                }
                
                # Update the global scan_statuses with the loaded data
                scan_statuses.update(valid_statuses)
                logger.info(f"Loaded {len(valid_statuses)} valid scan sessions from {SESSIONS_FILE}")
    except Exception as e:
        logger.error(f"Failed to load scan statuses from {SESSIONS_FILE}: {str(e)}")

# Save scan statuses to file
def save_scan_statuses():
    try:
        # Create a copy of scan_statuses without the large agent_logs to save space
        statuses_to_save = {}
        for session_id, status in scan_statuses.items():
            # Only persist the essential information needed for report retrieval
            status_copy = {
                "is_running": status.get("is_running", False),
                "progress": status.get("progress", 0),
                "current_task": status.get("current_task", ""),
                "url": status.get("url", ""),
                "report_path": status.get("report_path", ""),
                "session_id": session_id,
                "start_time": status.get("start_time", time.time()),
                "provider": status.get("provider", "openai"),
                "model": status.get("model", "gpt-4o"),
                "error": status.get("error", None)
            }
            statuses_to_save[session_id] = status_copy
        
        # Write to file
        with open(SESSIONS_FILE, 'w') as f:
            json.dump(statuses_to_save, f)
        logger.info(f"Saved {len(statuses_to_save)} scan sessions to {SESSIONS_FILE}")
    except Exception as e:
        logger.error(f"Failed to save scan statuses to {SESSIONS_FILE}: {str(e)}")

# Try to load previous sessions on startup
load_scan_statuses()

# Get a scan status for a session, creating a new one if needed
def get_scan_status(session_id=None):
    if not session_id:
        # For backward compatibility, return the first scan status or create a new default one
        if not scan_statuses:
            session_id = "default_session"
            scan_statuses[session_id] = {
                "is_running": False,
                "progress": 0,
                "current_task": "",
                "url": "",
                "report_path": "",
                "error": None,
                "agent_logs": [],  # This will be updated from ui_log_handler
                "action_plan": [],
                "current_action": "",
                "completed_tasks": [],  # Field to track completed tasks by ID
                "session_id": session_id,
                "start_time": time.time()
            }
        else:
            # Return the first available session
            session_id = next(iter(scan_statuses))
    
    # Create a new session if it doesn't exist
    if session_id not in scan_statuses:
        scan_statuses[session_id] = {
            "is_running": False,
            "progress": 0,
            "current_task": "",
            "url": "",
            "report_path": "",
            "error": None,
            "agent_logs": [],
            "action_plan": [],
            "current_action": "",
            "completed_tasks": [],
            "session_id": session_id,
            "start_time": time.time()
        }
    
    return scan_statuses[session_id]

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def start_scan():
    logger.info("Received scan request")
    
    # Get session ID from request or generate a new one
    session_id = request.form.get('session_id')
    if not session_id:
        session_id = f"session_{int(time.time())}_{hash(request.remote_addr)}"
        logger.info(f"Generated new session ID: {session_id}")
    
    # Get scan status for this session
    scan_status = get_scan_status(session_id)
    
    # Check if a scan is already running for this session
    if scan_status["is_running"]:
        logger.warning(f"Rejected scan request for session {session_id}: A scan is already running")
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
    
    logger.info(f"Requested scan for URL: {url} using {provider} model: {model} (session: {session_id})")
    if provider == "ollama":
        logger.info(f"Using Ollama server at: {ollama_url}")
    
    if not url:
        logger.warning("Rejected scan request: No URL provided")
        return jsonify({
            "status": "error",
            "message": "No URL provided"
        }), 400
    
    # Reset scan status for this session
    scan_status.update({
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
        "completed_tasks": [],
        "session_id": session_id,
        "start_time": time.time()
    })
    logger.info(f"Scan status initialized for {url} with {provider} model: {model} (session: {session_id})")
    
    # Save the updated scan statuses to persist them across restarts
    save_scan_statuses()
    
    # Start scan in a background thread
    scan_thread = threading.Thread(
        target=run_scan, 
        args=(
            url, 
            model, 
            provider, 
            ollama_url if provider == "ollama" else None,
            openai_api_key,
            anthropic_api_key,
            session_id  # Pass session_id to the run_scan function
        )
    )
    scan_thread.daemon = True
    scan_thread.start()
    logger.info(f"Scan thread started for {url} (session: {session_id})")
    
    return jsonify({
        "status": "success",
        "message": f"Scan started for {url} using {provider}:{model}",
        "session_id": session_id
    })

def run_scan(url, model="gpt-4o", provider="openai", ollama_url=None, openai_api_key=None, anthropic_api_key=None, session_id=None):
    # Get the scan status for this session
    scan_status = get_scan_status(session_id)
    
    logger.info(f"Starting scan process for {url} using {provider} model: {model} (session: {session_id})")
    if provider == "ollama" and ollama_url:
        logger.info(f"Using Ollama server at: {ollama_url}")
    
    try:
        # Generate a timestamp for the report directory
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        logger.debug(f"Generated timestamp: {timestamp}")
        
        # Update status
        scan_status["current_task"] = "Running scan"
        scan_status["progress"] = 10
        logger.debug(f"Updated scan status: 10% - Running scan (session: {session_id})")
        
        # Add initial agent activities
        agent_activity_tracker.add_activity(
            session_id,
            'initialization',
            f"Initializing security scan for {url}",
            agent_name="System"
        )
        
        agent_activity_tracker.add_activity(
            session_id,
            'planning',
            f"Generating security test plan for {url}",
            agent_name="Planner Agent"
        )
        
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
                # Skip the title/first item
                if i == 0:
                    continue
                    
                # Extract task description without status
                task_text = re.sub(r'\s*\((Pending|Completed)\)$', '', item).strip()
                # Remove step number prefix if present
                if "Step " in task_text:
                    task_text = re.sub(r'^Step \d+:\s*', '', task_text)
                
                # Skip if we've seen this task before
                task_key = task_text.strip().lower()
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
                task_name = task_mapping.get(task_id, {}).get('name', 'Unknown task')
                logger.info(f"Marking task {task_id} as completed: {task_name}")
                scan_status["completed_tasks"].append(task_id)
                
                # Add an agent activity for this task completion
                activity_types = {
                    1: "discovery",
                    2: "discovery",
                    3: "xss_test",
                    4: "csrf_test",
                    5: "auth_test",
                    6: "sqli_test",
                    7: "validation",
                    8: "header_check"
                }
                
                agent_names = {
                    1: "Discovery Agent",
                    2: "Crawler Agent",
                    3: "XSS Testing Agent",
                    4: "CSRF Testing Agent",
                    5: "Authentication Agent",
                    6: "SQLi Testing Agent",
                    7: "Input Validation Agent",
                    8: "Header Security Agent"
                }
                
                # Add an activity for this task completion
                agent_activity_tracker.add_activity(
                    session_id,
                    activity_types.get(task_id, "security"),
                    f"Completed: {task_name}",
                    agent_name=agent_names.get(task_id, "Security Agent")
                )
                
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
            
            # Add detailed logging for debugging
            logger.info("=== DEBUG START: Before coordinator.run() ===")
            logger.info(f"Current scan_status: {scan_status}")
            logger.info(f"Is Vercel environment: {is_vercel}")
            logger.info(f"Report path before run: {scan_status['report_path']}")
            logger.info(f"Output directory: {output_dir}")
            logger.info("=== DEBUG END ===")
            
            # Run the scan and get results
            try:
                coordinator.run()
                logger.info("Coordinator.run() completed successfully")
            except Exception as e:
                logger.error(f"Error during coordinator.run(): {str(e)}")
                import traceback
                logger.error(f"Traceback: {traceback.format_exc()}")
                raise
            
            # Add more detailed logging after coordinator run
            logger.info("=== DEBUG START: After coordinator.run() ===")
            logger.info(f"Updated scan_status: {scan_status}")
            
            # Check if report files were created
            report_md_path = os.path.join(output_dir, "report.md")
            report_json_path = os.path.join(output_dir, "report.json")
            logger.info(f"Checking for report.md at: {report_md_path}")
            logger.info(f"report.md exists: {os.path.exists(report_md_path)}")
            logger.info(f"report.json exists: {os.path.exists(report_json_path)}")
            
            # List all files in output directory
            try:
                files_in_output = os.listdir(output_dir)
                logger.info(f"Files in output directory: {files_in_output}")
            except Exception as e:
                logger.error(f"Error listing output directory: {str(e)}")
            
            logger.info("=== DEBUG END ===")
            
            # Scan completed, mark all tasks as completed
            scan_status["progress"] = 100
            scan_status["current_task"] = "Scan completed"
            # Run deduplication before marking tasks as completed
            deduplicate_action_plan()
            mark_all_tasks_completed()
            logger.info("All tasks marked as completed")
            
            # Add completion activities
            agent_activity_tracker.add_activity(
                session_id,
                'completion',
                f"All security tests completed for {url}",
                agent_name="Coordinator"
            )
            
            agent_activity_tracker.add_activity(
                session_id,
                'reporting',
                f"Generating security assessment report",
                agent_name="Report Agent"
            )
            
            # Save the completed status to persist it across restarts
            save_scan_statuses()

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
            
            # Save the error status to persist it across restarts
            save_scan_statuses()
        finally:
            # Ensure scan status is updated
            scan_status["is_running"] = False
            logger.info("Scan process completed, is_running set to False")
            
            # Save the final status to persist it across restarts
            save_scan_statuses()

    except Exception as e:
        logger.exception(f"Exception during scan: {str(e)}")
        scan_status["error"] = str(e)
        scan_status["current_task"] = "Scan failed"
        scan_status["progress"] = 100
        
        # Save the error status to persist it across restarts
        save_scan_statuses()
    finally:
        # Ensure scan status is updated
        scan_status["is_running"] = False
        logger.info("Scan process completed, is_running set to False")
        
        # Save the final status to persist it across restarts
        save_scan_statuses()

@app.route('/status')
def get_status():
    # Get session ID from query parameters
    session_id = request.args.get('session_id')
    
    # Get scan status for this session
    scan_status = get_scan_status(session_id)
    
    logger.debug(f"Status request received for session {session_id}, current status: {scan_status}")
    
    # Only add sample activities if explicitly requested via query parameter
    # This prevents sample activities from showing on page load
    add_samples = request.args.get('add_samples', 'false').lower() == 'true'
    
    # Check if we need to add sample activities for a new session
    if add_samples and session_id and not agent_activity_tracker.get_activities(session_id) and scan_status["is_running"]:
        # Add sample activities for demonstration purposes if this is a new session
        # Only do this for actual new scans that are running, and if we don't have real activities yet
        if not scan_status.get("_sample_activities_added"):
            scan_status["_sample_activities_added"] = True
            logger.info(f"Adding sample activities for session {session_id} (requested via add_samples=true)")
            
            # For demo purposes, add sample activities spaced out over time
            current_time = time.time()
            for i, (activity_type, description, agent_name) in enumerate(sample_agent_activities):
                # Simulate activities happening over the last few minutes
                activity_time = current_time - (len(sample_agent_activities) - i) * 15
                
                # Add the activity with a custom timestamp
                activity = {
                    'timestamp': activity_time,
                    'time': time.strftime('%H:%M:%S', time.localtime(activity_time)),
                    'type': activity_type,
                    'description': description,
                    'agent': agent_name
                }
                
                if session_id not in agent_activity_tracker.activities:
                    agent_activity_tracker.activities[session_id] = []
                
                agent_activity_tracker.activities[session_id].append(activity)
    
    # Get agent activities for this session - these are the security testing activities
    agent_activities = agent_activity_tracker.get_activities(session_id)
    
    # Get system logs - these are the web server logs
    system_logs = ui_log_handler.get_logs()
    
    # Parse any server logs that might contain agent activity information
    # This helps us extract agent activities from standard logging in existing code
    for log in system_logs:
        message = log.get('message', '')
        if message and isinstance(message, str):
            # Skip processing if it's a duplicated agent activity log 
            # (these will be handled by parse_agent_message)
            if message.startswith("INFO - Agent Activity:") and message.count("INFO - Agent Activity:") > 1:
                agent_activity_tracker.parse_agent_message(session_id, message, None)
                continue
                
            # Look for agent-related messages
            agent_patterns = [
                (r'\[Agent:?\s*([^\]]+)\]', r'\1'),            # [Agent: XSS] or [Agent XSS]
                (r'Agent ([^:]+):', r'\1'),                    # Agent XSS: 
                (r'([A-Za-z]+) Agent is', r'\1'),              # Security Agent is...
                (r'\(Agent:\s*([^)]+)\)', r'\1'),              # (Agent: Planner Agent)
                (r'Agent: ([A-Za-z][A-Za-z\s]+)(?:\)|\(|$)', r'\1')  # Agent: Security Agent) or (Agent: Activity)
            ]
            
            agent_name = None
            for pattern, group in agent_patterns:
                match = re.search(pattern, message)
                if match:
                    agent_name = match.group(1).strip()
                    break
                    
            # Look for specific activity types in the message
            if any(keyword in message.lower() for keyword in 
                  ['vulnerability', 'injection', 'security', 'scanning', 'crawling', 'xss', 'sql', 'csrf', 'planning']):
                agent_activity_tracker.parse_agent_message(session_id, message, agent_name)
    
    # Update the status with agent activities and system logs
    scan_status["agent_logs"] = agent_activities
    scan_status["system_logs"] = system_logs[:50]  # Limit to 50 items to reduce payload size
    
    # If scan is not running, append error message if there is one
    if not scan_status["is_running"] and scan_status["error"]:
        if not any(activity.get("description") == scan_status["error"] for activity in agent_activities):
            agent_activity_tracker.add_activity(
                session_id, 
                'error', 
                scan_status["error"], 
                agent_name="System"
            )
    
    # Add session_id to the response
    scan_status["session_id"] = session_id
    
    return jsonify(scan_status)

@app.route('/reset', methods=['POST'])
def reset_scan():
    """Reset scan status for a session to allow starting a new scan."""
    # Get session ID from form parameters
    session_id = request.form.get('session_id')
    
    logger.info(f"Reset request received for session {session_id}")
    
    if not session_id:
        return jsonify({
            "status": "error",
            "message": "No session ID provided"
        }), 400
    
    # Check if this session exists
    if session_id in scan_statuses:
        # Clear agent activities for this session
        agent_activity_tracker.clear_activities(session_id)
        
        # Reset the scan status to defaults
        scan_statuses[session_id] = {
            "is_running": False,
            "progress": 0,
            "current_task": "",
            "url": "",
            "report_path": "",
            "error": None,
            "agent_logs": [],
            "action_plan": [],
            "current_action": "",
            "completed_tasks": [],
            "session_id": session_id,
            "start_time": time.time()
        }
        
        # Save updated state
        save_scan_statuses()
        
        logger.info(f"Successfully reset scan status for session {session_id}")
        return jsonify({
            "status": "success",
            "message": f"Scan status reset for session {session_id}"
        })
    else:
        # If session doesn't exist, create a new empty one
        scan_status = get_scan_status(session_id)
        logger.info(f"Created new empty scan status for session {session_id}")
        return jsonify({
            "status": "success",
            "message": f"Created new scan status for session {session_id}"
        })

@app.route('/report')
def get_report():
    # Get session ID from query parameters
    session_id = request.args.get('session_id')
    
    # Get scan status for this session
    scan_status = get_scan_status(session_id)
    
    logger.info("==== REPORT DEBUG START ====")
    logger.info(f"Report request received for session {session_id}")
    logger.info(f"Current scan_status: {scan_status}")
    logger.info(f"Is Vercel environment: {is_vercel}")
    
    # Try to find any existing reports for this url if the session doesn't have a report path
    if not scan_status["report_path"] and scan_status["url"]:
        # Create a potential report directory name from the URL and look for it
        url = scan_status["url"]
        sanitized_url = re.sub(r'[^\w\-_]', '_', url.replace('://', '_'))
        
        # Find the most recent report directory for this URL
        possible_report_dirs = []
        
        try:
            # Check in the reports directory
            reports_dir = app.config['UPLOAD_FOLDER']
            if os.path.exists(reports_dir) and os.path.isdir(reports_dir):
                logger.info(f"Looking for reports matching URL: {url} in {reports_dir}")
                
                # Find all directories that match this URL pattern
                for item in os.listdir(reports_dir):
                    if sanitized_url in item and os.path.isdir(os.path.join(reports_dir, item)):
                        # Check if this directory has a report.md file
                        report_file = os.path.join(reports_dir, item, "report.md")
                        if os.path.exists(report_file):
                            possible_report_dirs.append((item, os.path.getmtime(os.path.join(reports_dir, item))))
                
                # Sort by modification time to get the most recent
                if possible_report_dirs:
                    possible_report_dirs.sort(key=lambda x: x[1], reverse=True)
                    most_recent_dir = possible_report_dirs[0][0]
                    logger.info(f"Found potential report directory for URL {url}: {most_recent_dir}")
                    
                    # Update the scan status with this report path
                    report_path = os.path.join(reports_dir, most_recent_dir, "report.md")
                    scan_status["report_path"] = report_path
                    logger.info(f"Updated scan status with report path: {report_path}")
                    
                    # Save the updated report path
                    save_scan_statuses()
        except Exception as e:
            logger.error(f"Error searching for report directories: {str(e)}")
    
    # If still no report path, return error
    if not scan_status["report_path"]:
        logger.warning(f"Report request rejected for session {session_id}: No report available")
        logger.info("==== REPORT DEBUG END ====")
        return jsonify({
            "status": "error",
            "message": "No report available",
            "session_id": session_id
        }), 404
    
    # Handle report path resolution
    report_path = scan_status["report_path"]
    logger.info(f"Raw report path: {report_path}")
    
    # In Vercel, confirm we're looking at the right directory
    if is_vercel:
        logger.info(f"Vercel report directory should be: {app.config['UPLOAD_FOLDER']}")
        try:
            tmp_files = os.listdir('/tmp')
            logger.info(f"Files in /tmp: {tmp_files}")
            
            if os.path.exists(app.config['UPLOAD_FOLDER']):
                report_folder_files = os.listdir(app.config['UPLOAD_FOLDER'])
                logger.info(f"Files in report folder: {report_folder_files}")
        except Exception as e:
            logger.error(f"Error listing directories: {str(e)}")
    
    # Special handling for Vercel environment
    if is_vercel:
        logger.info(f"Using special handling for Vercel report path resolution")
        
        # In Vercel, we need to look in the /tmp directory
        if os.path.isabs(report_path):
            # If it's already an absolute path to /tmp, use it directly
            if report_path.startswith('/tmp'):
                if os.path.isdir(report_path):
                    report_file = os.path.join(report_path, "report.md")
                else:
                    report_file = report_path
            else:
                # If it's an absolute path but not to /tmp, convert it
                base_name = os.path.basename(report_path)
                if os.path.isdir(report_path):
                    report_file = os.path.join(app.config['UPLOAD_FOLDER'], base_name, "report.md")
                else:
                    report_file = os.path.join(app.config['UPLOAD_FOLDER'], base_name)
        else:
            # Handle relative paths in Vercel
            if os.path.basename(report_path) == "report.md":
                # If it's just report.md, get the containing directory
                dir_path = os.path.dirname(report_path)
                if dir_path:
                    report_file = os.path.join(app.config['UPLOAD_FOLDER'], dir_path, "report.md")
                else:
                    report_file = os.path.join(app.config['UPLOAD_FOLDER'], "report.md")
            else:
                # Otherwise treat the path as a directory
                report_file = os.path.join(app.config['UPLOAD_FOLDER'], report_path, "report.md")
        
        logger.info(f"Resolved Vercel report file path: {report_file}")
    else:
        # Standard environment (not Vercel)
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
        logger.info("==== REPORT DEBUG END ====")
        
        # Return the report content
        response = {
            "status": "success",
            "content": report_content,
            "report_path": report_file,  # Include this for debugging
            "is_vercel": is_vercel,
            "session_id": session_id
        }
        
        # Log the response for debugging
        logger.info(f"Returning report with {len(report_content)} characters for session {session_id}")
        
        return jsonify(response)
    except Exception as e:
        logger.exception(f"Error reading report file: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Error reading report: {str(e)}",
            "session_id": session_id
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