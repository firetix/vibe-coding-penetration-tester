"""Status routes for monitoring application state."""

from flask import Blueprint, request
import logging

from web_api.helpers.response_formatter import success_response, error_response, scan_status_response
from web_api.middleware.error_handler import handle_errors

logger = logging.getLogger('web_api')

def register_routes(app, session_manager, activity_tracker):
    """Register status routes with the Flask app."""
    
    bp = Blueprint('status', __name__)
    
    @bp.route('/status', methods=['GET'])
    @handle_errors
    def status_check():
        """Check the current status of the application or a specific session."""
        session_id = request.args.get('session_id')
        
        if not session_id:
            return scan_status_response(
                is_running=False,
                activities=[]
            )
        
        valid = session_manager.check_session(session_id)
        
        if not valid:
            return success_response(data={
                'status': 'error',
                'message': 'Invalid session',
                'progress': 0,
                'current_task': 'Session expired',
                'is_running': False
            })
        
        # Get any active scans for this session
        active_scans = session_manager.get_active_scans(session_id)
        is_scanning = len(active_scans) > 0
        
        if is_scanning and active_scans:
            # Get the most recent active scan
            scan = active_scans[0]
            
            # Get activities for this session
            activities = activity_tracker.get_activities(session_id)
            
            # Format the scan status
            return scan_status_response(
                scan=scan,
                activities=activities,
                is_running=True
            )
        else:
            # Get completed scans
            completed_scans = session_manager.get_completed_scans(session_id)
            
            if completed_scans:
                # Most recent completed scan
                scan = completed_scans[0]
                
                return scan_status_response(
                    scan=scan,
                    activities=activity_tracker.get_activities(session_id),
                    is_running=False
                )
            else:
                # No scans found
                return scan_status_response(
                    is_running=False,
                    activities=[]
                )
    
    # Log routes
    @bp.route('/api/logs', methods=['GET'])
    @handle_errors
    def get_logs():
        """Get UI logs."""
        from utils.logging_manager import LoggingManager
        logs = LoggingManager().get_ui_logs()
        return success_response(data={'logs': logs})
    
    app.register_blueprint(bp)