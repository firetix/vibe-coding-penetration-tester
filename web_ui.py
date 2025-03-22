#!/usr/bin/env python3

import os
import json
import time
from functools import wraps
from flask import Flask, render_template, request, jsonify, send_from_directory, make_response, session
from flask_cors import CORS

from utils.logging_manager import LoggingManager
from utils.activity_tracker import ActivityTracker
from utils.report_manager import ReportManager
from utils.session_manager import SessionManager
from utils.scan_controller import ScanController

# Initialize logging
logging_manager = LoggingManager()
logger = logging_manager.get_logger()

# Initialize Flask app
app = Flask(__name__)

# Set a secret key for sessions
app.secret_key = os.environ.get('SECRET_KEY', 'vibe_pen_tester_secret_key')

# Enable CORS for all routes
CORS(app)

# Add global error handling
@app.errorhandler(Exception)
def handle_exception(e):
    logger.error(f"Unhandled exception: {str(e)}")
    if request.path.startswith('/api/') or request.headers.get('Accept') == 'application/json':
        return jsonify({'status': 'error', 'message': f'Internal server error: {str(e)}'}), 500
    return render_template('index.html'), 500

# Determine reports directory based on environment
is_vercel = os.environ.get('VERCEL') == '1' or os.environ.get('VERCEL_ENV') is not None
if is_vercel:
    app.config['UPLOAD_FOLDER'] = '/tmp/vibe_pen_tester_reports'
else:
    app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'reports')

# Initialize utilities
activity_tracker = ActivityTracker()
report_manager = ReportManager(app.config['UPLOAD_FOLDER'])
session_manager = SessionManager()
scan_controller = ScanController(session_manager, report_manager)

# Session maintenance - cleanup old sessions periodically
def cleanup_sessions():
    session_manager.cleanup_old_sessions(max_age_seconds=3600)  # 1 hour

# Helper decorator for auto-creating sessions
def auto_create_session(f):
    """Auto-create a session instead of returning 401 errors."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Log the original request details
        endpoint = request.path
        logger.debug(f"auto_create_session decorator called for endpoint: {endpoint}")
        
        # First, check for a Flask session cookie and use that as our primary session source
        if 'session_id' in session:
            logger.debug(f"Found session_id in Flask session cookie: {session['session_id']}")
            flask_session_id = session['session_id']
            is_valid = session_manager.check_session(flask_session_id)
            logger.debug(f"Is Flask session cookie {flask_session_id} valid? {is_valid}")
            
            if is_valid:
                # We have a valid session, ensure its being used for this request
                request_session_id = None
                
                # Check if the request also has a session_id
                if request.method == 'GET':
                    request_session_id = request.args.get('session_id')
                elif request.is_json and isinstance(request.json, dict):
                    request_session_id = request.json.get('session_id')
                elif request.form:
                    request_session_id = request.form.get('session_id')
                
                # If we have both, and they don't match, log this discrepancy
                if request_session_id and request_session_id != flask_session_id:
                    logger.warning(f"Session ID mismatch: Flask cookie has {flask_session_id} but request has {request_session_id}")
                    
                    # Priority: Use the Flask session unless the request session is valid
                    if session_manager.check_session(request_session_id):
                        logger.info(f"Both session IDs are valid, using request session: {request_session_id}")
                    else:
                        # Override any passed session with our cookie session
                        logger.info(f"Using Flask cookie session: {flask_session_id} instead of invalid request session")
                        
                        # Update request data with correct session
                        if request.method == 'GET':
                            request.args = {**request.args, 'session_id': flask_session_id}
                        elif request.is_json:
                            request._cached_json = {**request.json, 'session_id': flask_session_id}
        
        # For GET requests, check query parameters
        if request.method == 'GET':
            session_id = request.args.get('session_id')
            logger.debug(f"GET request with session_id: {session_id} to {endpoint}")
            
            if session_id:
                is_valid = session_manager.check_session(session_id)
                logger.debug(f"Is session {session_id} valid for GET request? {is_valid}")
                
                if not is_valid:
                    # Create a new session
                    new_session_id = session_manager.create_session()
                    logger.info(f"Created new session: {new_session_id} (replacing {session_id})")
                    # Replace the session_id in args
                    request.args = {**request.args, 'session_id': new_session_id}
                    logger.debug(f"Updated GET request args with new session_id: {new_session_id}")
                    # Store in Flask session cookie
                    session['session_id'] = new_session_id
            else:
                logger.debug(f"No session_id provided in GET request to {endpoint}")
                # Check if we have a Flask session we can use
                if 'session_id' in session and session_manager.check_session(session['session_id']):
                    request.args = {**request.args, 'session_id': session['session_id']}
                    logger.debug(f"Applied session from cookie: {session['session_id']}")
        
        # For JSON requests, check request body
        elif request.is_json:
            try:
                data = request.json
                logger.debug(f"JSON request to {endpoint} with data: {data if isinstance(data, dict) else 'non-dict data'}")
                
                if isinstance(data, dict) and 'session_id' in data:
                    session_id = data['session_id']
                    is_valid = session_manager.check_session(session_id)
                    logger.debug(f"Is session {session_id} valid for JSON request? {is_valid}")
                    
                    if not is_valid:
                        # Try to use Flask session if available before creating new one
                        if 'session_id' in session and session_manager.check_session(session['session_id']):
                            new_session_id = session['session_id']
                            logger.info(f"Using cookie session: {new_session_id} (replacing invalid {session_id})")
                        else:
                            new_session_id = session_manager.create_session()
                            logger.info(f"Created new session: {new_session_id} (replacing {session_id})")
                            # Store in Flask session
                            session['session_id'] = new_session_id
                            
                        # Update the request JSON data
                        request._cached_json = {**data, 'session_id': new_session_id}
                        logger.debug(f"Updated JSON request with new session_id: {new_session_id}")
                elif isinstance(data, dict) and 'session_id' not in data:
                    # No session in the request, try to use the cookie session if available
                    if 'session_id' in session and session_manager.check_session(session['session_id']):
                        request._cached_json = {**data, 'session_id': session['session_id']}
                        logger.debug(f"Added Flask cookie session {session['session_id']} to JSON request")
            except Exception as e:
                logger.warning(f"Error checking JSON for session: {str(e)}")
        
        # For form data, check form values
        elif request.form:
            session_id = request.form.get('session_id')
            logger.debug(f"Form request to {endpoint} with session_id: {session_id}")
            
            if session_id:
                is_valid = session_manager.check_session(session_id)
                logger.debug(f"Is session {session_id} valid for form request? {is_valid}")
                
                if not is_valid:
                    # Try to use Flask session if available
                    if 'session_id' in session and session_manager.check_session(session['session_id']):
                        logger.debug(f"Using Flask cookie session {session['session_id']} for form request")
                    else:
                        new_session_id = session_manager.create_session()
                        logger.info(f"Created new session for form: {new_session_id}")
                        session['session_id'] = new_session_id
            elif 'session_id' in session:
                # Form has no session but we have a cookie - log this
                logger.debug(f"Form has no session_id but cookie has {session['session_id']}")
        
        # Log all active sessions before handling the request
        active_sessions = session_manager.get_all_sessions()
        logger.debug(f"Active sessions before handling {endpoint}: {active_sessions}")
        
        # Call the original function
        return f(*args, **kwargs)
    return decorated_function

# Main routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/session/init', methods=['POST'])
def init_session():
    # Check if we already have a valid session in the cookie
    if 'session_id' in session and session_manager.check_session(session['session_id']):
        logger.debug(f"Found valid cookie session: {session['session_id']}, reusing it")
        return jsonify({'session_id': session['session_id'], 'restored': True})
    
    # Create and store a new session
    session_id = session_manager.create_session()
    session['session_id'] = session_id
    logger.debug(f"Created new cookie session: {session_id}")
    return jsonify({'session_id': session_id})

@app.route('/api/session/check', methods=['POST'])
def check_session():
    if not request.is_json:
        return jsonify({'status': 'error', 'message': 'Invalid JSON data'}), 400
        
    data = request.json
    if not isinstance(data, dict):
        return jsonify({'status': 'error', 'message': 'Invalid request format'}), 400
        
    session_id = data.get('session_id')
    if not session_id:
        # Create a new session if none provided
        session_id = session_manager.create_session()
        logger.info(f"Created new session for check_session endpoint: {session_id}")
        return jsonify({'status': 'valid', 'session_id': session_id})
    
    valid = session_manager.check_session(session_id)
    if not valid:
        # Create a new session if invalid
        session_id = session_manager.create_session()
        logger.info(f"Created new session for check_session endpoint (invalid session): {session_id}")
        return jsonify({'status': 'valid', 'session_id': session_id})
        
    return jsonify({'status': 'valid'})

# Scan routes
@app.route('/api/scan/start', methods=['POST'])
@auto_create_session
def start_scan():
    try:
        # Ensure we have valid JSON data
        if not request.is_json:
            return jsonify({'status': 'error', 'message': 'Invalid JSON data'}), 400
            
        data = request.json
        if not isinstance(data, dict):
            return jsonify({'status': 'error', 'message': 'Invalid request format'}), 400
            
        session_id = data.get('session_id')
        url = data.get('url')
        config = data.get('config', {})
        
        if not session_id:
            session_id = session_manager.create_session()
            logger.info(f"Created new session for start_scan: {session_id}")
            
        if not url:
            return jsonify({'status': 'error', 'message': 'Missing URL'}), 400
        
        # Start the scan
        scan_id = scan_controller.start_scan(
            session_id, url, config, 
            activity_callback=activity_tracker.add_activity
        )
        
        return jsonify({
            'status': 'success',
            'scan_id': scan_id,
            'message': f'Scan started for {url}'
        })
    except Exception as e:
        logger.error(f"Error starting scan: {str(e)}")
        return jsonify({
            'status': 'error', 
            'message': f'Internal error: {str(e)}'
        }), 500

@app.route('/api/scan/status', methods=['POST'])
@auto_create_session
def get_scan_status():
    try:
        if not request.is_json:
            return jsonify({'status': 'error', 'message': 'Invalid JSON data'}), 400
            
        data = request.json
        if not isinstance(data, dict):
            return jsonify({'status': 'error', 'message': 'Invalid request format'}), 400
            
        session_id = data.get('session_id')
        scan_id = data.get('scan_id')
        
        if not session_id:
            session_id = session_manager.create_session()
            logger.info(f"Created new session for get_scan_status: {session_id}")
            
        if not scan_id:
            return jsonify({'status': 'error', 'message': 'Missing scan ID'}), 400
        
        # Get active scan status
        scan = session_manager.get_active_scan(session_id, scan_id)
        
        if scan:
            return jsonify({
                'status': 'success',
                'scan': {
                    'id': scan_id,
                    'status': scan.get('status', 'unknown'),
                    'progress': scan.get('progress', 0),
                    'url': scan.get('url', ''),
                    'vulnerabilities': scan.get('vulnerabilities', []),
                    'report_dir': scan.get('report_dir')
                }
            })
        
        # Check completed scans
        completed_scans = session_manager.get_completed_scans(session_id)
        for completed in completed_scans:
            if completed.get('id') == scan_id:
                return jsonify({
                    'status': 'success',
                    'scan': {
                        'id': scan_id,
                        'status': completed.get('status', 'unknown'),
                        'progress': 100,
                        'url': completed.get('url', ''),
                        'vulnerabilities': completed.get('vulnerabilities', []),
                        'report_dir': completed.get('report_dir'),
                        'completed': True
                    }
                })
        
        return jsonify({'status': 'error', 'message': 'Scan not found'}), 404
    except Exception as e:
        logger.error(f"Error getting scan status: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Internal error: {str(e)}'}), 500

@app.route('/api/scan/cancel', methods=['POST'])
@auto_create_session
def cancel_scan():
    try:
        if not request.is_json:
            return jsonify({'status': 'error', 'message': 'Invalid JSON data'}), 400
            
        data = request.json
        if not isinstance(data, dict):
            return jsonify({'status': 'error', 'message': 'Invalid request format'}), 400
            
        session_id = data.get('session_id')
        scan_id = data.get('scan_id')
        
        if not session_id:
            session_id = session_manager.create_session()
            logger.info(f"Created new session for cancel_scan: {session_id}")
            
        if not scan_id:
            return jsonify({'status': 'error', 'message': 'Missing scan ID'}), 400
        
        result = scan_controller.cancel_scan(session_id, scan_id)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error cancelling scan: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Internal error: {str(e)}'}), 500

@app.route('/api/scan/list', methods=['POST'])
@auto_create_session
def list_scans():
    try:
        if not request.is_json:
            return jsonify({'status': 'error', 'message': 'Invalid JSON data'}), 400
            
        data = request.json
        if not isinstance(data, dict):
            return jsonify({'status': 'error', 'message': 'Invalid request format'}), 400
            
        session_id = data.get('session_id')
        
        if not session_id:
            session_id = session_manager.create_session()
            logger.info(f"Created new session for list_scans: {session_id}")
        
        active = session_manager.get_active_scans(session_id)
        completed = session_manager.get_completed_scans(session_id)
        
        return jsonify({
            'status': 'success',
            'active': active,
            'completed': completed
        })
    except Exception as e:
        logger.error(f"Error listing scans: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Internal error: {str(e)}'}), 500

# Activity routes
@app.route('/api/activity', methods=['POST'])
@auto_create_session
def get_activities():
    try:
        if not request.is_json:
            return jsonify({'status': 'error', 'message': 'Invalid JSON data'}), 400
            
        data = request.json
        if not isinstance(data, dict):
            return jsonify({'status': 'error', 'message': 'Invalid request format'}), 400
            
        session_id = data.get('session_id')
        
        if not session_id:
            session_id = session_manager.create_session()
            logger.info(f"Created new session for get_activities: {session_id}")
        
        activities = activity_tracker.get_activities(session_id)
        return jsonify({
            'status': 'success',
            'activities': activities
        })
    except Exception as e:
        logger.error(f"Error getting activities: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Internal error: {str(e)}'}), 500

# Log routes
@app.route('/api/logs', methods=['GET'])
def get_logs():
    logs = logging_manager.get_ui_logs()
    return jsonify({'logs': logs})

# Report routes
@app.route('/api/reports', methods=['GET'])
def get_reports():
    reports = report_manager.get_report_list()
    return jsonify({'reports': reports})

@app.route('/api/report/<report_id>', methods=['GET'])
def get_report(report_id):
    report = report_manager.get_report(report_id)
    return jsonify(report)

@app.route('/reports/<path:filename>')
def download_report(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Status endpoint for simple client checks
@app.route('/status', methods=['GET'])
@auto_create_session
def status_check():
    # Try multiple sources for session ID with priority:
    # 1. Flask session cookie - most reliable for continuity
    # 2. URL query parameter - might be stale but clients send it
    
    # Priority 1: Flask session cookie 
    flask_cookie_session_id = session.get('session_id')
    # Priority 2: URL query parameter
    query_session_id = request.args.get('session_id')
    
    # Log both sources for debugging
    logger.debug(f"Status request received - cookie session: {flask_cookie_session_id}, query param: {query_session_id}")
    
    # Decision logic for which session to use
    if flask_cookie_session_id and session_manager.check_session(flask_cookie_session_id):
        # Use the Flask cookie session as it's most reliable
        session_id = flask_cookie_session_id
        logger.debug(f"Using valid Flask cookie session: {session_id}")
        
        # If we also have a query param and it doesn't match, log the mismatch
        if query_session_id and query_session_id != session_id:
            logger.warning(f"Session ID mismatch in status request - cookie: {session_id}, query: {query_session_id}")
    elif query_session_id and session_manager.check_session(query_session_id):
        # Fall back to query parameter if valid
        session_id = query_session_id
        logger.debug(f"Using valid query param session: {session_id}")
        
        # Update the Flask cookie with this session ID for future continuity
        session['session_id'] = session_id
        logger.debug(f"Updated Flask cookie with session: {session_id}")
    else:
        # Create a new session if no valid session found
        session_id = session_manager.create_session()
        session['session_id'] = session_id
        logger.info(f"Created new session for status endpoint (no valid session found): {session_id}")
        return jsonify({
            'status': 'ok', 
            'server_status': 'running',
            'progress': 0,
            'current_task': 'Ready',
            'is_running': False,
            'session_id': session_id
        })
    
    # Log current active sessions for debugging
    active_sessions = session_manager.get_all_sessions()
    logger.debug(f"Current active sessions: {active_sessions}")
    logger.debug(f"Is session {session_id} valid: {session_manager.check_session(session_id)}")
    
    # Get any active scans for this session
    active_scans = session_manager.get_active_scans(session_id)
    is_scanning = len(active_scans) > 0
    
    if is_scanning and active_scans:
        # Get the most recent active scan
        scan = active_scans[0]
        
        # Log explicit debug info about this session id
        logger.info(f"Status request for active session {session_id} - scan in progress")
        logger.info(f"Active scan URL: {scan.get('url')}, progress: {scan.get('progress')}%")
        
        # Get activities for this session with explicit error checking
        try:
            activities = activity_tracker.get_activities(session_id)
            logger.debug(f"Retrieved {len(activities)} activities for session {session_id}")
            
            # Log the activities for debugging
            if activities:
                for i, activity in enumerate(activities):
                    logger.debug(f"Activity {i+1}: type={activity.get('type')}, agent={activity.get('agent')}, {activity.get('description')[:50]}...")
            else:
                logger.info(f"No activities found for session {session_id} - this might indicate a problem")
                
                # Try to check if there are activities for other sessions
                all_session_ids = list(activity_tracker.activities.keys())
                logger.info(f"Activity tracker has activities for these sessions: {all_session_ids}")
                
                # Add a test activity to see if the activity tracker is working
                try:
                    result = activity_tracker.add_activity(
                        session_id, 
                        "test", 
                        f"Test activity from status endpoint at {time.strftime('%H:%M:%S')}", 
                        {"test": True, "timestamp": time.time()}, 
                        "StatusEndpoint"
                    )
                    logger.info(f"Added test activity to session {session_id}: {result}")
                    
                    # Immediately try to retrieve it to verify
                    updated_activities = activity_tracker.get_activities(session_id)
                    logger.info(f"After adding test activity, now have {len(updated_activities)} activities")
                    activities = updated_activities  # Use these activities in the response
                except Exception as e:
                    logger.error(f"Failed to add test activity: {str(e)}")
        except Exception as e:
            logger.error(f"Error retrieving activities for session {session_id}: {str(e)}")
            activities = []  # Fallback to empty list
        
        # Extract action plan from activities or use the one stored in scan
        action_plan = scan.get('action_plan', [])
        current_agent_task = scan.get('current_task', "Security scanning in progress")
        
        # If no action plan is stored in scan, try to extract from activities
        if not action_plan:
            # Process activities to extract action plan
            for activity in activities:
                # Check for action plan activities
                if activity.get('type') == 'action_plan' and 'details' in activity:
                    plan_items = activity.get('details', {}).get('plan', [])
                    if isinstance(plan_items, list) and plan_items:
                        # Merge with existing action plan
                        for item in plan_items:
                            if item not in action_plan:
                                action_plan.append(item)
            
            # If no current task is set, try to determine from recent activities
            if not current_agent_task or current_agent_task == "Security scanning in progress":
                for activity in activities:
                    # Look at recent activities
                    if activity.get('timestamp', 0) > time.time() - 30:  # Within the last 30 seconds
                        agent_name = activity.get('agent', '')
                        description = activity.get('description', '')
                        
                        if agent_name and description:
                            current_agent_task = f"{agent_name}: {description}"
                            break
        
            # If still no action plan was found, create a basic one from security activities
            if not action_plan:
                security_activities = [a for a in activities if a.get('type') in ['security', 'xss_test', 'sqli_test', 'csrf_test', 'vulnerability']]
                for activity in security_activities:
                    agent = activity.get('agent', 'Security Agent')
                    description = activity.get('description', '')
                    if agent and description:
                        action_item = f"{agent}: {description}"
                        if action_item not in action_plan:
                            action_plan.append(action_item)
        
        # Ensure we have at least a title in the action plan
        if action_plan:
            # Check if first item is a title - if not, add one
            if not action_plan[0].startswith("Security Testing Plan"):
                action_plan.insert(0, f"Security Testing Plan for {scan.get('url', '')}")
        else:
            action_plan = [
                f"Security Testing Plan for {scan.get('url', '')}",
                "Initializing security testing environment",
                "Conducting automated security analysis",
                "Scanning for common web vulnerabilities"
            ]
            
        # Store the enhanced action plan back in scan for future use
        if 'action_plan' not in scan or scan['action_plan'] != action_plan:
            scan['action_plan'] = action_plan
        
        # Format the scan status in the way the UI expects
        response_data = {
            'status': 'ok',
            'progress': scan.get('progress', 0),
            'current_task': current_agent_task or scan.get('status', 'Running'),
            'is_running': True,
            'url': scan.get('url', ''),
            'scan_id': scan.get('id', ''),
            'agent_logs': activities,
            'action_plan': action_plan,
            'current_action': 'scanning',
            'vulnerabilities': scan.get('vulnerabilities', [])
        }
        
        # Log the response data size for debugging
        logger.debug(f"Sending response with {len(activities)} agent logs and {len(response_data.get('vulnerabilities', []))} vulnerabilities")
        
        logger.debug(f"Returning status response with {len(activities)} agent logs and {len(response_data.get('vulnerabilities', []))} vulns")
        return jsonify(response_data)
    else:
        # Get completed scans
        completed_scans = session_manager.get_completed_scans(session_id)
        
        if completed_scans:
            # Most recent completed scan
            scan = completed_scans[0]
            
            # Get activities for completed scan
            completed_activities = activity_tracker.get_activities(session_id)
            
            # Extract action plan from activities
            action_plan = []
            
            # Process activities to extract action plan
            for activity in completed_activities:
                # Check for action plan activities
                if activity.get('type') == 'action_plan' and 'details' in activity:
                    plan_items = activity.get('details', {}).get('plan', [])
                    if isinstance(plan_items, list) and plan_items:
                        # Merge with existing action plan
                        for item in plan_items:
                            if item not in action_plan:
                                action_plan.append(item)
            
            # If no action plan was found, create a basic one from security activities
            if not action_plan:
                security_activities = [a for a in completed_activities if a.get('type') in ['security', 'xss_test', 'sqli_test', 'csrf_test', 'vulnerability']]
                for activity in security_activities:
                    agent = activity.get('agent', 'Security Agent')
                    description = activity.get('description', '')
                    if agent and description:
                        action_item = f"{agent}: {description}"
                        if action_item not in action_plan:
                            action_plan.append(action_item)
            
            # Ensure we have at least a title in the action plan
            if action_plan:
                action_plan.insert(0, f"Security Testing Results for {scan.get('url', '')}")
            else:
                action_plan = [
                    f"Security Testing Results for {scan.get('url', '')}",
                    "Security scan completed",
                    "Report generated and available for review"
                ]
                
                # Add vulnerabilities to action plan if available
                if scan.get('vulnerabilities'):
                    for vuln in scan.get('vulnerabilities'):
                        action_plan.append(f"Found vulnerability: {vuln.get('name', 'Unknown')} ({vuln.get('severity', 'medium')})")
            
            # Use the stored current_task if available, otherwise use default
            current_task = scan.get('current_task', 'Security testing completed. Report is available.')
            
            return jsonify({
                'status': 'ok',
                'progress': 100,
                'current_task': current_task,
                'is_running': False,
                'url': scan.get('url', ''),
                'scan_id': scan.get('id', ''),
                'agent_logs': completed_activities,
                'action_plan': action_plan,
                'current_action': 'completed',
                'vulnerabilities': scan.get('vulnerabilities', []),
                'report_dir': scan.get('report_dir')
            })
        else:
            # No scans found
            return jsonify({
                'status': 'ok',
                'progress': 0,
                'current_task': 'Ready',
                'is_running': False,
                'url': '',
                'scan_id': '',
                'agent_logs': [],
                'action_plan': [],
                'current_action': 'ready'
            })

# Scan endpoint for starting a scan
@app.route('/scan', methods=['POST'])
def start_scan_compat():
    try:
        # Log all request details for debugging
        logger.info(f"Scan request received with content type: {request.content_type}")
        logger.info(f"Request form data: {request.form}")
        logger.info(f"Request method: {request.method}")
        logger.info(f"Request headers: {dict(request.headers)}")
        
        # Check content type and extract data accordingly
        if request.content_type and 'application/json' in request.content_type:
            # JSON data
            if not request.is_json:
                logger.error("Expected JSON data but couldn't parse it")
                return jsonify({'status': 'error', 'message': 'Invalid JSON format'}), 400
            data = request.json
            logger.info(f"Parsed JSON data: {data}")
        elif request.content_type and 'application/x-www-form-urlencoded' in request.content_type:
            # Form data
            data = request.form
            logger.info(f"Parsed form data: {data}")
        else:
            # Try to parse as form data anyway as fallback
            data = request.form or {}
            logger.info(f"Using fallback data: {data}")
        
        # Extract parameters
        session_id = data.get('session_id')
        url = data.get('url')
        
        logger.info(f"Extracted session_id: {session_id}, url: {url}")
        
        # Try to get config, which might be a nested JSON string
        config = {}
        config_str = data.get('config')
        if config_str:
            try:
                if isinstance(config_str, str):
                    config = json.loads(config_str)
                elif isinstance(config_str, dict):
                    config = config_str
                logger.info(f"Parsed config: {config}")
            except json.JSONDecodeError as json_err:
                # If not valid JSON, use as is
                logger.warning(f"Could not parse config as JSON: {json_err}")
                config = {'raw_config': config_str}
        
        # Special case: if nothing is found in data, fall back to query params
        if not session_id:
            session_id = request.args.get('session_id')
            logger.info(f"Using session_id from query params: {session_id}")
        
        if not url:
            url = request.args.get('url')
            logger.info(f"Using url from query params: {url}")
        
        # Validate required parameters
        if not session_id:
            logger.error("Missing session ID in request")
            return jsonify({'status': 'error', 'message': 'Missing session ID'}), 400
        
        if not url:
            logger.error("Missing URL in request")
            return jsonify({'status': 'error', 'message': 'Missing target URL'}), 400
        
        # Ensure URL has a scheme
        if not url.startswith(('http://', 'https://')):
            url = f"http://{url}"
            logger.info(f"Added http:// scheme to URL: {url}")
            
        # Get all active sessions before validation
        active_sessions_before = session_manager.get_all_sessions()
        logger.debug(f"Active sessions before validation: {active_sessions_before}")
        
        # Validate session
        is_valid_session = session_manager.check_session(session_id)
        logger.debug(f"Is session {session_id} valid? {is_valid_session}")
        
        if not is_valid_session:
            # If session doesn't exist, create a new one
            old_session_id = session_id
            session_id = session_manager.create_session()
            logger.info(f"Created new session: {session_id} (replacing invalid session: {old_session_id})")
        
        # Get all active sessions after validation
        active_sessions_after = session_manager.get_all_sessions()
        logger.debug(f"Active sessions after validation: {active_sessions_after}")
        
        # Debug the activity tracker state
        logger.debug(f"Activity tracker sessions: {list(activity_tracker.activities.keys())}")
        
        # Start the scan
        logger.info(f"Starting scan for URL {url} with session {session_id} and config {config}")
        scan_id = scan_controller.start_scan(
            session_id, url, config, 
            activity_callback=activity_tracker.add_activity
        )
        
        logger.info(f"Scan started successfully with scan_id: {scan_id}")
        return jsonify({
            'status': 'success',
            'scan_id': scan_id,
            'session_id': session_id,
            'message': f'Scan started for {url}'
        })
    except Exception as e:
        logger.error(f"Error starting scan: {str(e)}")
        logger.exception("Full stack trace:")
        return jsonify({'status': 'error', 'message': f'Internal error: {str(e)}'}), 500

# Report endpoint for getting scan report
@app.route('/report', methods=['GET'])
def get_report_compat():
    try:
        session_id = request.args.get('session_id')
        
        if not session_id:
            # Create a new session if none provided
            session_id = session_manager.create_session()
            logger.info(f"Created new session for report endpoint (no session ID): {session_id}")
            return jsonify({'status': 'error', 'message': 'No session - created new one', 'session_id': session_id}), 200
        
        # Get most recent scan for this session
        completed_scans = session_manager.get_completed_scans(session_id)
        active_scans = session_manager.get_active_scans(session_id)
        
        if not completed_scans:
            if active_scans:
                # There are active scans but no completed scans
                active_scan = active_scans[0]
                return jsonify({
                    'status': 'in_progress',
                    'message': 'Scan is in progress',
                    'scan_id': active_scan.get('id', ''),
                    'progress': active_scan.get('progress', 0),
                    'url': active_scan.get('url', '')
                }), 202  # 202 Accepted status code indicates the request is being processed
            else:
                # No scans at all
                return jsonify({'status': 'error', 'message': 'No completed scans found'}), 404
        
        latest_scan = completed_scans[0]
        report_dir = latest_scan.get('report_dir')
        
        if not report_dir:
            return jsonify({'status': 'error', 'message': 'No report available'}), 404
        
        report = report_manager.get_report(report_dir)
        return jsonify(report)
        
    except Exception as e:
        logger.error(f"Error getting report: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Internal error: {str(e)}'}), 500

# Reset endpoint
@app.route('/reset', methods=['POST'])
def reset_session():
    try:
        # Check content type and extract data accordingly
        logger.debug(f"Reset request content type: {request.content_type}")
        logger.debug(f"Reset request data: {request.form or request.data}")
        
        # Handle different request formats
        if request.content_type and 'application/json' in request.content_type:
            if request.is_json:
                data = request.json
            else:
                data = {}
        elif request.content_type and 'application/x-www-form-urlencoded' in request.content_type:
            data = request.form
        elif request.content_type and 'multipart/form-data' in request.content_type:
            data = request.form
        else:
            # Try to get data from any available source
            data = request.form or {}
        
        # Extract session ID from form data or query string
        session_id = data.get('session_id') or request.args.get('session_id')
        
        if not session_id:
            return jsonify({'status': 'success', 'message': 'No session to reset'}), 200
        
        # Even if session is invalid, return success since the goal is to reset
        if not session_manager.check_session(session_id):
            return jsonify({'status': 'success', 'message': 'No active session found'}), 200
        
        # Cancel any active scans
        active_scans = session_manager.get_active_scans(session_id)
        for scan in active_scans:
            scan_id = scan.get('id')
            if scan_id:
                scan_controller.cancel_scan(session_id, scan_id)
        
        # Clear activities
        activity_tracker.clear_activities(session_id)
        
        logger.info(f"Session reset successful for session {session_id}")
        return jsonify({
            'status': 'success',
            'message': 'Session reset successful'
        })
    except Exception as e:
        logger.error(f"Error resetting session: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Internal error: {str(e)}'}), 500

# Add compatibility endpoint for client-side state management
@app.route('/api/state', methods=['GET', 'POST'])
def api_state():
    try:
        session_id = request.args.get('session_id')
        if request.method == 'POST' and request.is_json:
            session_id = request.json.get('session_id', session_id)
            
        if not session_id:
            return jsonify({
                'status': 'ok', 
                'server_status': 'running',
                'state': None
            })
        
        valid = session_manager.check_session(session_id)
        
        if not valid:
            # Create a new session instead of returning invalid state
            session_id = session_manager.create_session()
            logger.info(f"Created new session for API state endpoint: {session_id}")
            valid = True
        
        # Get active scans
        active_scans = session_manager.get_active_scans(session_id)
        completed_scans = session_manager.get_completed_scans(session_id)
        is_scanning = len(active_scans) > 0
        
        # Get most recent scan if available
        current_scan = None
        if active_scans:
            current_scan = active_scans[0]
        elif completed_scans:
            current_scan = completed_scans[0]
            
        return jsonify({
            'status': 'ok',
            'server_status': 'running',
            'state': {
                'session_id': session_id,
                'is_scanning': is_scanning,
                'current_scan': current_scan
            }
        })
    except Exception as e:
        logger.error(f"Error in state endpoint: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

# Handle 404 errors with JSON response instead of HTML
@app.errorhandler(404)
def not_found(e):
    if request.path.startswith('/api/') or request.headers.get('Accept') == 'application/json':
        return jsonify({'status': 'error', 'message': 'Endpoint not found'}), 404
    return render_template('index.html'), 404

# Static routes
@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory('static', filename)

@app.route('/favicon.ico')
def favicon():
    return send_from_directory('static', 'favicon.ico')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5050)))