"""Scan management routes."""

from flask import Blueprint, g
import logging

from web_api.helpers.request_parser import parse_request, get_json_param, normalize_url
from web_api.helpers.response_formatter import success_response, error_response
from web_api.middleware.session_validator import validate_session
from web_api.middleware.error_handler import handle_errors

logger = logging.getLogger('web_api')

def register_routes(app, session_manager, scan_controller, activity_tracker):
    """Register scan routes with the Flask app."""
    
    bp = Blueprint('scan', __name__, url_prefix='/api/scan')
    
    @bp.route('/start', methods=['POST'])
    @handle_errors
    @validate_session(session_manager)
    def start_scan():
        """Start a new scan with the provided URL and configuration."""
        session_id = g.session_id
        data = parse_request()
        url = data.get('url')
        config = get_json_param(data, 'config', default={})
        
        if not url:
            return error_response('Missing target URL', 400)
        
        # Normalize URL to ensure it has a scheme
        url = normalize_url(url)
        
        # Create an adapter for the activity tracker callback
        def activity_adapter(session_id, activity):
            activity_type = activity.get('type', 'general')
            description = activity.get('description', 'Activity')
            details = activity.get('details', {})
            agent_name = activity.get('agent', None)
            return activity_tracker.add_activity(session_id, activity_type, description, details, agent_name)
            
        # Start the scan
        scan_id = scan_controller.start_scan(
            session_id, url, config, 
            activity_callback=activity_adapter
        )
        
        return success_response(
            message=f'Scan started for {url}',
            data={'scan_id': scan_id}
        )
    
    @bp.route('/status', methods=['POST'])
    @handle_errors
    @validate_session(session_manager)
    def get_scan_status():
        """Get the status of a specific scan."""
        session_id = g.session_id
        data = parse_request()
        scan_id = data.get('scan_id')
        
        if not scan_id:
            return error_response('Missing scan ID', 400)
        
        # Get active scan status
        scan = session_manager.get_active_scan(session_id, scan_id)
        
        if scan:
            return success_response(data={
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
                return success_response(data={
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
        
        return error_response('Scan not found', 404)
    
    @bp.route('/cancel', methods=['POST'])
    @handle_errors
    @validate_session(session_manager)
    def cancel_scan():
        """Cancel an active scan."""
        session_id = g.session_id
        data = parse_request()
        scan_id = data.get('scan_id')
        
        if not scan_id:
            return error_response('Missing scan ID', 400)
        
        result = scan_controller.cancel_scan(session_id, scan_id)
        return success_response(data=result)
    
    @bp.route('/list', methods=['POST'])
    @handle_errors
    @validate_session(session_manager)
    def list_scans():
        """List all scans for a session."""
        session_id = g.session_id
        
        active = session_manager.get_active_scans(session_id)
        completed = session_manager.get_completed_scans(session_id)
        
        return success_response(data={
            'active': active,
            'completed': completed
        })
    
    # Legacy route handler that works more flexibly
    @app.route('/scan', methods=['POST'])
    @handle_errors
    def start_scan_compat():
        """Legacy endpoint for starting a scan that accepts various formats."""
        data = parse_request()
        
        # Log all request details for debugging
        logger.info(f"Scan request received with data: {data}")
        
        session_id = data.get('session_id')
        url = data.get('url')
        
        # Try to get config, which might be a nested JSON string
        config = get_json_param(data, 'config', default={})
        
        # Validate required parameters
        if not session_id:
            return error_response('Missing session ID', 400)
        
        if not url:
            return error_response('Missing target URL', 400)
        
        # Ensure URL has a scheme
        url = normalize_url(url)
            
        # Validate session
        if not session_manager.check_session(session_id):
            # If session doesn't exist, create a new one
            session_id = session_manager.create_session()
            logger.info(f"Created new session: {session_id}")
        
        # Start the scan
        logger.info(f"Starting scan for URL {url} with session {session_id} and config {config}")
        
        # Create an adapter for the activity tracker callback
        def activity_adapter(session_id, activity):
            activity_type = activity.get('type', 'general')
            description = activity.get('description', 'Activity')
            details = activity.get('details', {})
            agent_name = activity.get('agent', None)
            return activity_tracker.add_activity(session_id, activity_type, description, details, agent_name)
            
        scan_id = scan_controller.start_scan(
            session_id, url, config, 
            activity_callback=activity_adapter
        )
        
        logger.info(f"Scan started successfully with scan_id: {scan_id}")
        return success_response(
            message=f'Scan started for {url}',
            data={
                'scan_id': scan_id,
                'session_id': session_id
            }
        )
    
    app.register_blueprint(bp)