"""Web API for the Vibe penetration testing tool."""

import os
import logging
from flask import Flask
import time

# Try to import CORS, but don't fail if it's not available
try:
    from flask_cors import CORS
    has_cors = True
except ImportError:
    has_cors = False
    print("WARNING: flask_cors is not installed. CORS support will be disabled.")
    print("To enable CORS, install flask_cors: pip install flask_cors")

from utils.logging_manager import LoggingManager
from utils.activity_tracker import ActivityTracker
from utils.report_manager import ReportManager
from utils.session_manager import SessionManager
from utils.scan_controller import ScanController

from web_api.middleware.error_handler import register_error_handlers
from web_api.routes import (
    session, scan, activity, report, status, static
)

def create_app():
    """Create and configure the Flask application."""
    # Initialize logging
    logging_manager = LoggingManager()
    logger = logging_manager.get_logger()
    
    # Initialize Flask app
    app = Flask(__name__, 
                static_folder='../static',
                template_folder='../templates')
    
    # Enable CORS for all routes if available
    if has_cors:
        CORS(app)
    else:
        # Basic CORS implementation if flask_cors is not available
        @app.after_request
        def add_cors_headers(response):
            response.headers.add('Access-Control-Allow-Origin', '*')
            response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
            response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
            return response
    
    # Determine reports directory based on environment
    is_vercel = os.environ.get('VERCEL') == '1' or os.environ.get('VERCEL_ENV') is not None
    if is_vercel:
        app.config['UPLOAD_FOLDER'] = '/tmp/vibe_pen_tester_reports'
    else:
        app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'reports')
    
    # Register error handlers
    register_error_handlers(app)
    
    # Initialize utilities
    activity_tracker = ActivityTracker()
    report_manager = ReportManager(app.config['UPLOAD_FOLDER'])
    session_manager = SessionManager()
    scan_controller = ScanController(session_manager, report_manager)
    
    # Register route handlers
    session.register_routes(app, session_manager, activity_tracker, scan_controller)
    scan.register_routes(app, session_manager, scan_controller, activity_tracker)
    activity.register_routes(app, session_manager, activity_tracker)
    report.register_routes(app, session_manager, report_manager)
    status.register_routes(app, session_manager, activity_tracker)
    static.register_routes(app)
    
    # Start session cleanup in the background
    import threading
    
    def cleanup_thread():
        """Periodically clean up old sessions."""
        while True:
            session_manager.cleanup_old_sessions(max_age_seconds=3600)  # 1 hour
            time.sleep(3600)  # Run every hour
    
    # Start the cleanup thread
    thread = threading.Thread(target=cleanup_thread)
    thread.daemon = True
    thread.start()
    
    # Alternative method for Flask 2.0+
    with app.app_context():
        # Run cleanup once at startup
        session_manager.cleanup_old_sessions(max_age_seconds=3600)
    
    return app