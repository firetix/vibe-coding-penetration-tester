"""Static file serving routes."""

from flask import Blueprint, render_template, send_from_directory
import logging

from web_api.middleware.error_handler import handle_errors

logger = logging.getLogger('web_api')

def register_routes(app):
    """Register static file routes with the Flask app."""
    
    bp = Blueprint('static', __name__)
    
    @bp.route('/')
    @handle_errors
    def index():
        """Serve the main application page."""
        return render_template('index.html')
    
    @bp.route('/static/<path:filename>')
    @handle_errors
    def serve_static(filename):
        """Serve static files."""
        return send_from_directory('static', filename)
    
    @bp.route('/favicon.ico')
    @handle_errors
    def favicon():
        """Serve the favicon."""
        return send_from_directory('static', 'favicon.ico')
    
    app.register_blueprint(bp)