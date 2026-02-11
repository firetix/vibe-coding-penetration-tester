"""Status routes for monitoring application state."""

import logging
from flask import Blueprint, request, g

from web_api.helpers.response_formatter import success_response, scan_status_response
from web_api.middleware.error_handler import handle_errors
from utils.entitlements import is_hosted_mode

logger = logging.getLogger('web_api')


def register_routes(app, session_manager, activity_tracker, billing_store=None):
    """Register status routes with the Flask app."""

    bp = Blueprint('status', __name__)

    @bp.route('/status', methods=['GET'])
    @handle_errors
    def status_check():
        """Check the current status of the application or a specific session."""
        session_id = request.args.get('session_id')
        account_id = getattr(g, "account_id", None)

        entitlements = None
        paywall_state = None
        if is_hosted_mode() and billing_store is not None and account_id:
            entitlements = billing_store.get_entitlements(account_id)
            paywall_state = {
                "is_hosted": True,
                "requires_payment_for_next_scan": entitlements.get("free_scans_remaining", 0) <= 0
                and not entitlements.get("pro_active")
                and entitlements.get("deep_scan_credits", 0) <= 0,
            }

        if not session_id:
            return scan_status_response(
                is_running=False,
                activities=[],
                entitlements=entitlements,
                paywall_state=paywall_state,
            )

        valid = session_manager.check_session(session_id)

        if not valid:
            return success_response(data={
                'status': 'error',
                'message': 'Invalid session',
                'progress': 0,
                'current_task': 'Session expired',
                'is_running': False,
                'entitlements': entitlements,
                'paywall_state': paywall_state,
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
                is_running=True,
                entitlements=entitlements,
                paywall_state=paywall_state,
            )

        # Get completed scans
        completed_scans = session_manager.get_completed_scans(session_id)

        if completed_scans:
            # Most recent completed scan
            scan = completed_scans[0]

            return scan_status_response(
                scan=scan,
                activities=activity_tracker.get_activities(session_id),
                is_running=False,
                entitlements=entitlements,
                paywall_state=paywall_state,
            )

        # No scans found
        return scan_status_response(
            is_running=False,
            activities=[],
            entitlements=entitlements,
            paywall_state=paywall_state,
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
