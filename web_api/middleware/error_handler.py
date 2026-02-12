import logging
from functools import wraps
from flask import request, render_template

from web_api.helpers.response_formatter import error_response

logger = logging.getLogger("web_api")


def handle_errors(f):
    """Middleware for consistent API error handling."""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            logger.error(f"Error in {f.__name__}: {str(e)}")

            # Different error message based on environment
            if logger.getEffectiveLevel() <= logging.DEBUG:
                # In debug mode, include the full error message
                return error_response(f"Internal server error: {str(e)}", 500)
            else:
                # In production, show a generic message
                return error_response("Internal server error", 500)

    return decorated_function


def register_error_handlers(app):
    """Register global error handlers for the Flask app."""

    @app.errorhandler(404)
    def not_found(e):
        if (
            request.path.startswith("/api/")
            or request.headers.get("Accept") == "application/json"
        ):
            return error_response("Endpoint not found", 404)
        return render_template("index.html"), 404

    @app.errorhandler(500)
    def server_error(e):
        if (
            request.path.startswith("/api/")
            or request.headers.get("Accept") == "application/json"
        ):
            return error_response("Internal server error", 500)
        return render_template("index.html"), 500
