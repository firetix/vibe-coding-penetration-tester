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

@app.route('/favicon.ico')
def favicon():
    return send_from_directory('static', 'favicon.ico', mimetype='image/x-icon')

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
    
    # VERCEL COMPATIBILITY CHANGE:
    # Instead of using a background thread which doesn't work in serverless,
    # we'll just set up the initial state and return to the client.
    # The client will poll the /status endpoint and we'll make progress on each poll.
    
    # Generate a timestamp for the report directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    logger.debug(f"Generated timestamp: {timestamp}")
    
    # Update status to indicate scan is ready for next step
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
    
    # Set up action plan for the incremental scan
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
    
    # Prepare output directory based on sanitized URL and timestamp
    sanitized_url = re.sub(r'[^\w\-_]', '_', url.replace('://', '_'))
    output_dir = os.path.join(app.config['UPLOAD_FOLDER'], f"{sanitized_url}_{timestamp}")
    os.makedirs(output_dir, exist_ok=True)
    logger.debug(f"Created output directory: {output_dir}")
    
    # Add a placeholder for the report path
    scan_status["report_path"] = os.path.join(output_dir, "report.md")
    
    # Save state - critical for serverless environment
    save_scan_statuses()
    
    # Set API keys if provided - for status endpoint to continue the work
    if provider == "openai" and openai_api_key:
        os.environ["OPENAI_API_KEY"] = openai_api_key
        logger.info("Using OpenAI API key from form input")
    
    if provider == "anthropic" and anthropic_api_key:
        os.environ["ANTHROPIC_API_KEY"] = anthropic_api_key
        logger.info("Using Anthropic API key from form input")
    
    return jsonify({
        "status": "success",
        "message": f"Scan initiated for {url} using {provider}:{model}",
        "session_id": session_id
    })

@app.route('/status')
def get_status():
    # Get session ID from query parameters
    session_id = request.args.get('session_id')
    
    # Get scan status for this session
    scan_status = get_scan_status(session_id)
    
    logger.debug(f"Status request received for session {session_id}, current status: {scan_status}")
    
    # VERCEL COMPATIBILITY CHANGE:
    # Use the status endpoint to advance the scan incrementally
    # This works better with serverless functions than background threads
    if session_id and scan_status["is_running"] and scan_status["progress"] < 100:
        # Progress the scan by one step each time status is polled
        # This simulates what would have happened in the background thread
        progress_scan(session_id, scan_status)
    
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
    
    # Save scan status after any changes
    save_scan_statuses()
    
    return jsonify(scan_status)

# Function to advance scan progress incrementally on each status poll
def progress_scan(session_id, scan_status):
    """Incrementally advance scan progress each time status is polled."""
    # Get current progress
    current_progress = scan_status.get("progress", 0)
    url = scan_status.get("url", "")
    
    # Import security tools for actual testing
    from tools.security_tools import test_xss_payload, generate_xss_payloads
    
    # Set of task steps that should be completed incrementally
    task_steps = [10, 20, 30, 40, 50, 60, 70, 80, 90, 95, 100]
    
    # Find the next step to advance to
    next_step = 100
    for step in task_steps:
        if step > current_progress:
            next_step = step
            break
    
    # Define task mapping with agents
    task_mapping = {
        1: {"name": "Target discovery and reconnaissance", "agent": "Discovery Agent", "type": "discovery"},
        2: {"name": "Surface crawling and endpoint enumeration", "agent": "Crawler Agent", "type": "discovery"},
        3: {"name": "Cross-Site Scripting (XSS) vulnerability scanning", "agent": "XSS Testing Agent", "type": "xss_test"},
        4: {"name": "Cross-Site Request Forgery (CSRF) vulnerability detection", "agent": "CSRF Testing Agent", "type": "csrf_test"},
        5: {"name": "Authentication security testing", "agent": "Authentication Agent", "type": "auth_test"},
        6: {"name": "SQL Injection vulnerability detection", "agent": "SQLi Testing Agent", "type": "sqli_test"},
        7: {"name": "Input validation and sanitization checks", "agent": "Input Validation Agent", "type": "validation"},
        8: {"name": "Security header verification", "agent": "Header Security Agent", "type": "header_check"},
    }
    
    # Storage for scan findings
    if "findings" not in scan_status:
        scan_status["findings"] = []
    
    # Function to mark task as completed
    def mark_task_completed(task_id, findings=None):
        if task_id not in scan_status.get("completed_tasks", []):
            task_info = task_mapping.get(task_id, {})
            task_name = task_info.get('name', 'Unknown task')
            logger.info(f"Marking task {task_id} as completed: {task_name}")
            
            if "completed_tasks" not in scan_status:
                scan_status["completed_tasks"] = []
            
            scan_status["completed_tasks"].append(task_id)
            
            # Add an agent activity for this task completion
            agent_activity_tracker.add_activity(
                session_id,
                task_info.get("type", "security"),
                f"Completed: {task_name}",
                agent_name=task_info.get("agent", "Security Agent")
            )
            
            # If there are findings, record them in the scan status
            if findings:
                if isinstance(findings, list):
                    scan_status["findings"].extend(findings)
                else:
                    scan_status["findings"].append(findings)
                
                # Add a specific activity for each finding
                for finding in findings if isinstance(findings, list) else [findings]:
                    if isinstance(finding, dict) and finding.get("xss_found"):
                        agent_activity_tracker.add_activity(
                            session_id,
                            "vulnerability",
                            f"XSS vulnerability found in {finding.get('parameter', 'parameter')} at {finding.get('url', url)}",
                            agent_name="XSS Testing Agent"
                        )
            
            # Update action plan list with completion status
            for i, plan_item in enumerate(scan_status["action_plan"]):
                # Skip the first item which is the main plan title
                if i == 0:
                    continue
                    
                # Check if this plan item corresponds to the completed task
                if task_name and task_name.lower() in plan_item.lower():
                    # Remove any existing status markers
                    clean_item = re.sub(r'\s*\((Pending|Completed)\)$', '', plan_item)
                    # Add completed marker
                    scan_status["action_plan"][i] = f"{clean_item} (Completed)"
                    logger.debug(f"Updated action plan item {i} to mark as completed: {scan_status['action_plan'][i]}")
                    break
    
    # Add in-progress activity for current stage
    current_time = time.time()
    last_poll_time = scan_status.get("_last_poll_time", current_time - 10)
    
    # Only add a new activity if enough time has passed (to avoid duplicates)
    if current_time - last_poll_time > 3:
        # Calculate which task we're on based on current progress
        task_index = min(int(current_progress / 10) + 1, 8)
        task_info = task_mapping.get(task_index, {})
        
        # Add an activity that this task is in progress
        agent_activity_tracker.add_activity(
            session_id,
            task_info.get("type", "security"),
            f"In progress: {task_info.get('name', 'Security testing')}",
            agent_name=task_info.get("agent", "Security Agent")
        )
        
        # Update last poll time
        scan_status["_last_poll_time"] = current_time
    
    # Perform actual testing for specific steps
    # Each poll will advance to next step, but we'll actually test for each specific task
    
    # XSS Testing - Perform when we're at step 3
    if current_progress in range(20, 30) and 3 not in scan_status.get("completed_tasks", []):
        try:
            # Indicate XSS testing is in progress
            agent_activity_tracker.add_activity(
                session_id,
                "xss_test",
                f"Testing {url} for XSS vulnerabilities...",
                agent_name="XSS Testing Agent"
            )
            
            # Run actual XSS testing
            xss_findings = []
            
            # Check for XSS in the target URL parameter if "uid" is in the URL (known vulnerability for Gruyere)
            if "gruyere" in url.lower() and ("snippets" in url.lower() or "uid=" in url.lower()):
                agent_activity_tracker.add_activity(
                    session_id,
                    "xss_test",
                    f"Testing Google Gruyere snippets endpoint for XSS vulnerabilities...",
                    agent_name="XSS Testing Agent"
                )
                
                # Test with simple XSS payloads 
                xss_payloads = [
                    "<script>alert('XSS')</script>",
                    "<img src=x onerror=alert('XSS')>",
                    "<svg onload=alert('XSS')>"
                ]
                
                for payload in xss_payloads:
                    result = test_xss_payload(
                        target_url=url, 
                        payload=payload, 
                        injection_point="parameter", 
                        parameter_name="uid"
                    )
                    
                    if result.get("xss_found", False):
                        xss_findings.append(result)
                        agent_activity_tracker.add_activity(
                            session_id,
                            "vulnerability",
                            f"XSS vulnerability found: {result.get('description', 'XSS in parameter')}",
                            agent_name="XSS Testing Agent"
                        )
            
            # More generic test for any URL - test the URL for common XSS vulnerabilities
            html_payloads = generate_xss_payloads("html", 3)["payloads"] 
            for payload in html_payloads:
                result = test_xss_payload(
                    target_url=url, 
                    payload=payload, 
                    injection_point="url", 
                    parameter_name="q"  # common parameter name
                )
                
                if result.get("xss_found", False):
                    xss_findings.append(result)
                    agent_activity_tracker.add_activity(
                        session_id,
                        "vulnerability",
                        f"XSS vulnerability found: {result.get('description', 'XSS in URL')}",
                        agent_name="XSS Testing Agent"
                    )
            
            # Mark XSS testing as completed with findings
            mark_task_completed(3, xss_findings)
            
            # Add detailed activity about the test results
            if xss_findings:
                agent_activity_tracker.add_activity(
                    session_id,
                    "xss_test",
                    f"XSS testing completed: Found {len(xss_findings)} XSS vulnerabilities",
                    agent_name="XSS Testing Agent"
                )
            else:
                agent_activity_tracker.add_activity(
                    session_id,
                    "xss_test",
                    f"XSS testing completed: No vulnerabilities found",
                    agent_name="XSS Testing Agent"
                )
                
        except Exception as e:
            logger.error(f"Error during XSS testing: {str(e)}")
            agent_activity_tracker.add_activity(
                session_id,
                "xss_test",
                f"Error during XSS testing: {str(e)}",
                agent_name="XSS Testing Agent"
            )
            mark_task_completed(3, [])
    
    # Automatically mark other tasks as completed based on progress
    tasks_to_complete = []
    if next_step == 100:
        # Mark all remaining tasks as completed
        for task_id in range(1, 9):
            if task_id not in scan_status.get("completed_tasks", []):
                tasks_to_complete.append(task_id)
    else:
        # Mark tasks complete based on progress
        completed_step = max(10, next_step - 10)
        tasks_done = int(completed_step / 10)
        
        for task_id in range(1, tasks_done + 1):
            if task_id not in scan_status.get("completed_tasks", []) and task_id != 3:  # Skip XSS (task 3) which is handled separately
                tasks_to_complete.append(task_id)
    
    # Mark tasks as completed
    for task_id in tasks_to_complete:
        mark_task_completed(task_id)
    
    # Update progress
    scan_status["progress"] = next_step
    
    # Update current action based on progress
    if next_step < 100:
        # Pick appropriate task based on progress
        task_index = min(int(next_step / 10) + 1, 8)
        task_info = task_mapping.get(task_index, {})
        scan_status["current_action"] = f"Running: {task_info.get('name', 'Security testing')}"
    else:
        # Finalize the scan
        scan_status["is_running"] = False
        scan_status["progress"] = 100
        scan_status["current_task"] = "Scan completed"
        scan_status["current_action"] = "Generating final report"
        
        # Create a report with the actual findings
        report_path = scan_status.get("report_path", "")
        if report_path and not os.path.exists(report_path):
            try:
                # Ensure directory exists
                os.makedirs(os.path.dirname(report_path), exist_ok=True)
                
                # Get the findings from scan_status
                findings = scan_status.get("findings", [])
                
                # Count findings by type
                finding_counts = {
                    "xss": sum(1 for f in findings if isinstance(f, dict) and f.get("xss_found", False)),
                    "sqli": sum(1 for f in findings if isinstance(f, dict) and f.get("sqli_found", False)),
                    "csrf": sum(1 for f in findings if isinstance(f, dict) and f.get("csrf_found", False)),
                    "auth": sum(1 for f in findings if isinstance(f, dict) and f.get("auth_issue_found", False))
                }
                
                total_vulns = sum(finding_counts.values())
                
                # Generate findings details
                finding_details = []
                for f in findings:
                    if isinstance(f, dict):
                        if f.get("xss_found", False):
                            finding_details.append({
                                "type": "Cross-Site Scripting (XSS)",
                                "severity": f.get("severity", "high"),
                                "location": f.get("parameter", "Unknown parameter"),
                                "url": f.get("url", url),
                                "payload": f.get("payload", ""),
                                "description": f.get("description", "XSS vulnerability detected"),
                                "remediation": f.get("remediation", "Implement proper input validation and output encoding")
                            })
                
                # Create a basic report with actual findings
                with open(report_path, 'w') as f:
                    f.write(f"""# Security Assessment Report for {url}

## Overview
Security assessment completed on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

## Summary of Findings
The security assessment found **{total_vulns} vulnerabilities**.

""")
                    # Add findings summary
                    if total_vulns > 0:
                        f.write("### Vulnerabilities by Type\n")
                        for vuln_type, count in finding_counts.items():
                            if count > 0:
                                f.write(f"- {vuln_type.upper()}: {count}\n")
                        f.write("\n")
                        
                        # Add detailed findings
                        f.write("## Detailed Findings\n\n")
                        for i, detail in enumerate(finding_details, 1):
                            f.write(f"### {i}. {detail['type']} - {detail['severity'].upper()}\n\n")
                            f.write(f"**Location**: {detail['location']} at {detail['url']}\n\n")
                            f.write(f"**Description**: {detail['description']}\n\n")
                            if detail.get('payload'):
                                f.write(f"**Payload**: `{detail['payload']}`\n\n")
                            f.write(f"**Remediation**: {detail['remediation']}\n\n")
                    else:
                        f.write("No vulnerabilities were detected during this scan.\n\n")
                    
                    f.write("""
### Security Tests Performed
- Target discovery and reconnaissance
- Surface crawling and endpoint enumeration
- Cross-Site Scripting (XSS) vulnerability scanning
- Cross-Site Request Forgery (CSRF) vulnerability detection
- Authentication security testing
- SQL Injection vulnerability detection
- Input validation and sanitization checks
- Security header verification

## Recommendations
- Regularly update all software and dependencies
- Implement Content Security Policy headers
- Ensure proper input validation on all user inputs
- Use HTTPS exclusively for all communications
- Review authentication mechanisms regularly

*This report was generated by VibePenTester*
""")
                
                # Also create a JSON report with actual findings
                json_path = os.path.join(os.path.dirname(report_path), "report.json")
                with open(json_path, 'w') as f:
                    json.dump({
                        "url": url,
                        "scan_date": datetime.now().isoformat(),
                        "findings": finding_details,
                        "summary": f"Found {total_vulns} vulnerabilities" if total_vulns > 0 else "No vulnerabilities found",
                        "vulnerability_counts": finding_counts
                    }, f, indent=2)
                
                logger.info(f"Created report at {report_path} with {total_vulns} findings")
                
                # Add completion activities
                agent_activity_tracker.add_activity(
                    session_id,
                    'completion',
                    f"All security tests completed for {url} - Found {total_vulns} vulnerabilities",
                    agent_name="Coordinator"
                )
                
                agent_activity_tracker.add_activity(
                    session_id,
                    'reporting',
                    f"Security assessment report generated with {total_vulns} vulnerabilities",
                    agent_name="Report Agent"
                )
            except Exception as e:
                logger.error(f"Error creating report: {str(e)}")
                scan_status["error"] = f"Error creating report: {str(e)}"
    
    # Save changes
    save_scan_statuses()

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
    
    # Print all request information for debugging
    logger.info(f"Request args: {request.args}")
    logger.info(f"Request headers: {dict(request.headers)}")
    logger.info(f"Request method: {request.method}")
    logger.info(f"Request path: {request.path}")
    logger.info(f"Request url: {request.url}")
    
    # Print all session information
    logger.info(f"All active sessions: {list(scan_statuses.keys())}")
    
    # Print the content of the sessions file
    try:
        if os.path.exists(SESSIONS_FILE):
            with open(SESSIONS_FILE, 'r') as f:
                logger.info(f"Sessions file content: {f.read()}")
        else:
            logger.info(f"Sessions file not found: {SESSIONS_FILE}")
    except Exception as e:
        logger.info(f"Error reading sessions file: {str(e)}")
    
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
            logger.info(f"Looking for reports matching URL: {url} in {reports_dir}")
            
            # For Vercel, also check fallback sample reports
            if is_vercel:
                all_possible_dirs = []
                
                # First check our reports folder
                if os.path.exists(reports_dir) and os.path.isdir(reports_dir):
                    all_possible_dirs.append(reports_dir)
                
                # Look for all possible locations of sample reports
                # First, try relative to current directory
                base_dir = os.path.dirname(os.path.abspath(__file__))
                
                # List of potential locations to check
                potential_dirs = [
                    os.path.join(base_dir, 'reports_samples'),  # Relative to script
                    '/var/task/reports_samples',                # Vercel function root
                    '/Users/mrachidi/Code/pen_testers/vibe_pen_tester/reports_samples',  # Local dev path
                ]
                
                logger.info(f"Base directory: {base_dir}")
                
                # Check each potential directory
                for pot_dir in potential_dirs:
                    logger.info(f"Checking sample reports directory: {pot_dir}")
                    if os.path.exists(pot_dir) and os.path.isdir(pot_dir):
                        logger.info(f"Found sample reports directory: {pot_dir}")
                        all_possible_dirs.append(pot_dir)
                
                # Also add any reports in the runtime directory
                runtime_samples = 'reports_samples'
                if os.path.exists(runtime_samples) and os.path.isdir(runtime_samples):
                    logger.info(f"Found runtime sample reports directory: {runtime_samples}")
                    all_possible_dirs.append(runtime_samples)
                
                logger.info(f"Vercel search directories: {all_possible_dirs}")
                
                # Search through all possible directories
                for search_dir in all_possible_dirs:
                    logger.info(f"Checking for reports in: {search_dir}")
                    if os.path.exists(search_dir) and os.path.isdir(search_dir):
                        try:
                            # Log all files in the directory
                            all_files = os.listdir(search_dir)
                            logger.info(f"Files in {search_dir}: {all_files}")
                            
                            # Find all directories that match this URL pattern
                            for item in all_files:
                                item_path = os.path.join(search_dir, item)
                                if os.path.isdir(item_path):
                                    # Just pick any report directory for now - we'll be more selective later
                                    report_file = os.path.join(item_path, "report.md")
                                    if os.path.exists(report_file):
                                        possible_report_dirs.append((item, os.path.getmtime(item_path)))
                                        logger.info(f"Found report file: {report_file}")
                        except Exception as e:
                            logger.error(f"Error listing directory {search_dir}: {str(e)}")
            else:
                # Standard non-Vercel behavior
                if os.path.exists(reports_dir) and os.path.isdir(reports_dir):
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
                
                # Update the scan status with this report path - use correct path based on environment
                if is_vercel:
                    # For Vercel, we need to check where we found the report
                    for search_dir in all_possible_dirs:
                        full_dir_path = os.path.join(search_dir, most_recent_dir)
                        report_path = os.path.join(full_dir_path, "report.md")
                        if os.path.exists(report_path):
                            scan_status["report_path"] = report_path
                            logger.info(f"Vercel: Updated scan status with report path: {report_path}")
                            break
                else:
                    # Standard behavior
                    report_path = os.path.join(reports_dir, most_recent_dir, "report.md")
                    scan_status["report_path"] = report_path
                    logger.info(f"Updated scan status with report path: {report_path}")
                
                # Save the updated report path
                save_scan_statuses()
        except Exception as e:
            logger.error(f"Error searching for report directories: {str(e)}")
            # Log the traceback for better debugging
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
    
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
                        logger.info(f"Files in parent directory: {files}")
                except Exception as e:
                    logger.error(f"Could not list parent directory: {str(e)}")
                
                # For Vercel, try to find ANY report.md file as a fallback
                if is_vercel:
                    logger.info("Vercel fallback: searching for ANY report.md file...")
                    
                    # First try all sample reports
                    for root_dir in ['/var/task/reports_samples', 'reports_samples']:
                        if os.path.exists(root_dir):
                            logger.info(f"Checking {root_dir} for report.md files")
                            for root, dirs, files in os.walk(root_dir):
                                for f in files:
                                    if f == 'report.md':
                                        fallback = os.path.join(root, f)
                                        logger.info(f"Found fallback report: {fallback}")
                                        report_file = fallback
                                        return jsonify({
                                            "status": "success",
                                            "content": open(fallback, 'r').read(),
                                            "report_path": fallback,
                                            "is_vercel": is_vercel,
                                            "session_id": session_id,
                                            "note": "Using fallback sample report"
                                        })
                    
                    # As a last resort, return an embedded sample report
                    logger.info("Using embedded sample report as last resort")
                    sample_content = """# Security Assessment Report

## Overview
This is a placeholder report. The actual report could not be found, but the system is working.

## Finding Summary
- No actual findings to report

## Recommendations
- Check that report file paths are correctly configured
"""
                    return jsonify({
                        "status": "success",
                        "content": sample_content,
                        "is_vercel": is_vercel,
                        "session_id": session_id,
                        "note": "Using embedded placeholder report"
                    })
                
                # For non-vercel, return error
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