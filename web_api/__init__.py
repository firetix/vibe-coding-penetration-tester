"""Web API for the Vibe penetration testing tool."""

import os
import logging
import uuid
from flask import Flask, g, request
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
from utils.billing_store import BillingStore
from utils.entitlements import is_hosted_mode

from web_api.middleware.error_handler import register_error_handlers
from web_api.routes import session, scan, activity, report, status, static, billing, scans


def create_app():
    """Create and configure the Flask application."""
    # Initialize logging
    logging_manager = LoggingManager()
    logger = logging_manager.get_logger()

    # Initialize Flask app
    app = Flask(__name__, static_folder="../static", template_folder="../templates")

    # Enable CORS for all routes if available
    if has_cors:
        CORS(app)
    else:
        # Basic CORS implementation if flask_cors is not available
        @app.after_request
        def add_cors_headers(response):
            response.headers.add("Access-Control-Allow-Origin", "*")
            response.headers.add(
                "Access-Control-Allow-Headers", "Content-Type,Authorization"
            )
            response.headers.add(
                "Access-Control-Allow-Methods", "GET,PUT,POST,DELETE,OPTIONS"
            )
            return response

    # Determine reports directory based on environment
    is_vercel = (
        os.environ.get("VERCEL") == "1" or os.environ.get("VERCEL_ENV") is not None
    )
    if is_vercel:
        app.config["UPLOAD_FOLDER"] = "/tmp/vibe_pen_tester_reports"
    else:
        app.config["UPLOAD_FOLDER"] = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports"
        )

    # Register error handlers
    register_error_handlers(app)

    # Initialize utilities
    activity_tracker = ActivityTracker()
    report_manager = ReportManager(app.config["UPLOAD_FOLDER"])
    session_manager = SessionManager()
    scan_controller = ScanController(session_manager, report_manager)
    if is_vercel:
        default_db_path = "/tmp/vpt.db"
    else:
        default_db_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "data",
            "vpt.db",
        )
    db_path = os.environ.get("VPT_BILLING_DB_PATH", default_db_path)
    billing_store = BillingStore(db_path=db_path)

    @app.before_request
    def attach_account_identity():
        account_id = request.cookies.get("vpt_account_id")
        if not account_id:
            account_id = str(uuid.uuid4())
            g._set_account_cookie = True
        else:
            g._set_account_cookie = False
        g.account_id = account_id
        billing_store.ensure_account(account_id)

    @app.after_request
    def persist_account_identity(response):
        if getattr(g, "_set_account_cookie", False):
            response.set_cookie(
                "vpt_account_id",
                g.account_id,
                max_age=60 * 60 * 24 * 365,
                httponly=True,
                samesite="Lax",
            )
        return response

    # Register route handlers
    session.register_routes(app, session_manager, activity_tracker, scan_controller)
    scan.register_routes(
        app,
        session_manager,
        scan_controller,
        activity_tracker,
        billing_store=billing_store,
    )
    activity.register_routes(app, session_manager, activity_tracker)
    report.register_routes(app, session_manager, report_manager)
    status.register_routes(
        app, session_manager, activity_tracker, billing_store=billing_store
    )
    billing.register_routes(app, billing_store)
    scans.register_routes(app)
    static.register_routes(app)

    # Run database migrations for the new app store (non-blocking on failure)
    try:
        from web_api.store.migrator import run_migrations

        run_migrations()
    except Exception as _mig_err:
        logger.warning("App DB migration skipped: %s", _mig_err)

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
