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
from utils.supabase_auth import maybe_get_supabase_user
from utils.entitlements import is_hosted_mode

from web_api.middleware.error_handler import register_error_handlers
from web_api.routes import (
    session,
    scan,
    activity,
    report,
    status,
    static,
    billing,
    v1_scans,
)


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
    app_db_url = (
        os.environ.get("VPT_APP_DB_URL")
        or os.environ.get("SUPABASE_DATABASE_URL")
        or os.environ.get("VPT_BILLING_DB_URL")
    )
    if app_db_url and app_db_url.startswith(("postgres://", "postgresql://")):
        from utils.activity_tracker_postgres import PostgresActivityTracker
        from utils.report_manager_postgres import PostgresReportManager
        from utils.saas_store import PostgresSaaSStore
        from utils.session_manager_postgres import PostgresSessionManager

        activity_tracker = PostgresActivityTracker(app_db_url)
        report_manager = PostgresReportManager(app_db_url, app.config["UPLOAD_FOLDER"])
        session_manager = PostgresSessionManager(app_db_url)
        saas_store = PostgresSaaSStore(app_db_url)
    else:
        from utils.saas_store import InMemorySaaSStore

        activity_tracker = ActivityTracker()
        report_manager = ReportManager(app.config["UPLOAD_FOLDER"])
        session_manager = SessionManager()
        saas_store = InMemorySaaSStore()

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
    # Prefer explicit billing DB configuration to avoid surprising behavior when
    # developers have unrelated DATABASE_URL env vars set.
    billing_db_url = (
        os.environ.get("VPT_BILLING_DB_URL")
        or os.environ.get("VPT_APP_DB_URL")
        or os.environ.get("SUPABASE_DATABASE_URL")
    )
    if billing_db_url and billing_db_url.startswith(("postgres://", "postgresql://")):
        from utils.billing_store_postgres import PostgresBillingStore

        billing_store = PostgresBillingStore(db_url=billing_db_url)
    else:
        billing_store = BillingStore(db_path=db_path)

    @app.before_request
    def attach_account_identity():
        supabase_user = maybe_get_supabase_user(request.headers.get("Authorization"))
        if supabase_user:
            account_id = str(supabase_user.get("sub"))
            g.supabase_user = supabase_user
            g._set_account_cookie = False
        else:
            account_id = request.cookies.get("vpt_account_id")
            if not account_id:
                account_id = str(uuid.uuid4())
                g._set_account_cookie = True
            else:
                g._set_account_cookie = False
        g.account_id = account_id
        # Ensure entitlement rows exist for both SQLite and Postgres stores before
        # checkout completion paths attempt credit/pro updates.
        try:
            billing_store.ensure_account(account_id)
        except Exception as exc:
            logger.warning(f"Failed to ensure billing account {account_id}: {exc}")

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
    v1_scans.register_routes(
        app,
        saas_store,
        session_manager,
        scan_controller,
        activity_tracker,
        report_manager,
        billing_store=billing_store,
    )
    status.register_routes(
        app, session_manager, activity_tracker, billing_store=billing_store
    )
    billing.register_routes(app, billing_store)
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
