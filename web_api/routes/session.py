"""Session management routes."""

from flask import Blueprint, g
import logging

from web_api.helpers.request_parser import parse_request
from web_api.helpers.response_formatter import success_response, error_response
from web_api.middleware.session_validator import validate_session
from web_api.middleware.error_handler import handle_errors

logger = logging.getLogger("web_api")


def register_routes(app, session_manager, activity_tracker, scan_controller):
    """Register session routes with the Flask app."""

    bp = Blueprint("session", __name__, url_prefix="/api/session")

    @bp.route("/init", methods=["POST"])
    @handle_errors
    def init_session():
        """Initialize a new session."""
        data = parse_request()
        client_id = data.get("client_id")
        if client_id and session_manager.check_session(client_id):
            return success_response(data={"session_id": client_id, "restored": True})

        session_id = session_manager.create_session()
        return success_response(data={"session_id": session_id, "restored": False})

    @bp.route("/check", methods=["POST"])
    @handle_errors
    def check_session():
        """Check if a session is valid."""
        data = parse_request()
        session_id = data.get("session_id")

        if not session_id:
            return error_response("No session ID provided", 400)

        valid = session_manager.check_session(session_id)
        return success_response(data={"status": "valid" if valid else "invalid"})

    @bp.route("/reset", methods=["POST"])
    @handle_errors
    @validate_session(session_manager, fallback_to_args=True)
    def reset_session():
        """Reset a session by canceling active scans and clearing activities."""
        session_id = g.session_id

        # Cancel any active scans
        active_scans = session_manager.get_active_scans(session_id)
        for scan in active_scans:
            scan_id = scan.get("id")
            if scan_id:
                scan_controller.cancel_scan(session_id, scan_id)

        # Clear activities
        activity_tracker.clear_activities(session_id)

        logger.info(f"Session reset successful for session {session_id}")
        return success_response("Session reset successful")

    @bp.route("/state", methods=["GET", "POST"])
    @handle_errors
    def api_state():
        """Get the current state of a session."""
        data = parse_request()
        session_id = data.get("session_id")

        if not session_id:
            return success_response(data={"server_status": "running", "state": None})

        valid = session_manager.check_session(session_id)

        if valid:
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

            return success_response(
                data={
                    "server_status": "running",
                    "state": {
                        "session_id": session_id,
                        "is_scanning": is_scanning,
                        "current_scan": current_scan,
                    },
                }
            )
        else:
            return success_response(
                data={
                    "server_status": "running",
                    "state": {"session_id": session_id, "valid": False},
                }
            )

    # Legacy routes for compatibility
    app.route("/reset", methods=["POST"])(reset_session)
    app.route("/api/state", methods=["GET", "POST"])(api_state)

    app.register_blueprint(bp)
