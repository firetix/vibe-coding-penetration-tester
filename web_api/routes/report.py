"""Report generation and retrieval routes."""

from flask import Blueprint, send_from_directory, g
import logging

from web_api.helpers.response_formatter import success_response, error_response
from web_api.middleware.session_validator import validate_session
from web_api.middleware.error_handler import handle_errors

logger = logging.getLogger('web_api')

def register_routes(app, session_manager, report_manager):
    """Register report routes with the Flask app."""
    
    bp = Blueprint('report', __name__, url_prefix='/api')
    
    @bp.route('/reports', methods=['GET'])
    @handle_errors
    def get_reports():
        """Get a list of all available reports."""
        reports = report_manager.get_report_list()
        return success_response(data={'reports': reports})
    
    @bp.route('/report/<report_id>', methods=['GET'])
    @handle_errors
    def get_report(report_id):
        """Get a specific report by ID."""
        report = report_manager.get_report(report_id)
        return success_response(data=report)
    
    # Legacy report endpoint
    @app.route('/report', methods=['GET'])
    @handle_errors
    @validate_session(session_manager, auto_create=True, fallback_to_args=True, required=False)
    def get_report_compat():
        """Get the latest report for a session (legacy endpoint)."""
        session_id = g.session_id
        logger.info(f"Processing report request for session: {session_id}")
        
        # Get most recent scan for this session
        completed_scans = session_manager.get_completed_scans(session_id)
        active_scans = session_manager.get_active_scans(session_id)
        
        if not completed_scans:
            if active_scans:
                # There are active scans but no completed scans
                active_scan = active_scans[0]
                logger.info(f"Report requested but scan is still in progress: {active_scan.get('id', '')}")
                return success_response(
                    message='Scan is in progress',
                    data={
                        'status': 'in_progress',
                        'scan_id': active_scan.get('id', ''),
                        'progress': active_scan.get('progress', 0),
                        'url': active_scan.get('url', '')
                    },
                    status_code=202  # 202 Accepted status code indicates the request is being processed
                )
            else:
                # No scans at all
                logger.info(f"No completed scans found for session: {session_id}")
                return error_response('No completed scans found', 404)
        
        latest_scan = completed_scans[0]
        report_dir = latest_scan.get('report_dir')
        
        if not report_dir:
            logger.info(f"Completed scan has no report_dir: {latest_scan.get('id', '')}")
            # Return a specific response to indicate report is being generated
            return success_response(
                message='Report is being generated',
                data={
                    'status': 'generating',
                    'scan_id': latest_scan.get('id', ''),
                    'progress': latest_scan.get('progress', 100),
                    'url': latest_scan.get('url', '')
                },
                status_code=202  # 202 Accepted status code indicates the report is being processed
            )
        
        try:
            report = report_manager.get_report(report_dir)
            if not report or not report.get('content'):
                logger.warning(f"Empty report content for report_dir: {report_dir}")
                return success_response(
                    message='Report is being generated',
                    data={
                        'status': 'generating',
                        'scan_id': latest_scan.get('id', ''),
                        'progress': latest_scan.get('progress', 100),
                        'url': latest_scan.get('url', '')
                    },
                    status_code=202  # Report exists but has no content yet
                )
            return success_response(data=report)
        except Exception as e:
            logger.error(f"Error retrieving report from {report_dir}: {str(e)}")
            return success_response(
                message='Report generation error',
                data={
                    'status': 'error',
                    'error': str(e),
                    'scan_id': latest_scan.get('id', '')
                },
                status_code=202  # Still return 202 to allow retry
            )
    
    # Serve report files
    @app.route('/reports/<path:filename>')
    def download_report(filename):
        """Download a report file."""
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    
    app.register_blueprint(bp)