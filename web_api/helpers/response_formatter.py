from flask import jsonify
import logging

logger = logging.getLogger('web_api')

def success_response(message=None, data=None, status_code=200):
    """Format a standardized success response."""
    response = {'status': 'success'}
    
    if message:
        response['message'] = message
        
    if data:
        response.update(data)
        
    return jsonify(response), status_code

def error_response(message, status_code=400, error_details=None):
    """Format a standardized error response."""
    response = {
        'status': 'error',
        'message': message
    }
    
    if error_details:
        response['details'] = error_details
        
    return jsonify(response), status_code

def scan_status_response(scan=None, activities=None, session_id=None, is_running=False):
    """Format a scan status response based on current scan state."""
    if not scan:
        return jsonify({
            'status': 'ok',
            'progress': 0,
            'current_task': 'Ready',
            'is_running': False,
            'agent_logs': activities or [],
            'action_plan': [],
            'current_action': 'ready',
            'report_available': False
        })
        
    # A report is available if a scan is completed and has a report_dir
    report_available = not is_running and scan.get('report_dir') is not None
    
    return jsonify({
        'status': 'ok',
        'progress': scan.get('progress', 0),
        'current_task': scan.get('status', 'Running'),
        'is_running': is_running,
        'url': scan.get('url', ''),
        'scan_id': scan.get('id', ''),
        'agent_logs': activities or [],
        'action_plan': [],
        'current_action': 'scanning' if is_running else 'completed',
        'vulnerabilities': scan.get('vulnerabilities', []),
        'report_dir': scan.get('report_dir') if not is_running else None,
        'report_available': report_available
    })