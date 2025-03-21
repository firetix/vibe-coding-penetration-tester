"""Activity tracking routes."""

from flask import Blueprint, g
import logging

from web_api.helpers.response_formatter import success_response
from web_api.middleware.session_validator import validate_session
from web_api.middleware.error_handler import handle_errors

logger = logging.getLogger('web_api')

def register_routes(app, session_manager, activity_tracker):
    """Register activity routes with the Flask app."""
    
    bp = Blueprint('activity', __name__, url_prefix='/api/activity')
    
    @bp.route('', methods=['POST'])
    @handle_errors
    @validate_session(session_manager)
    def get_activities():
        """Get all activities for a session."""
        session_id = g.session_id
        
        activities = activity_tracker.get_activities(session_id)
        return success_response(data={'activities': activities})
    
    app.register_blueprint(bp)