"""New /api/scans endpoints for the Next.js app.

These routes use Supabase JWT auth and persist to the Postgres/SQLite store.
They coexist with the legacy /api/scan/* routes.
"""

import logging

from flask import Blueprint, g, jsonify, request

from web_api.helpers.response_formatter import error_response
from web_api.middleware.error_handler import handle_errors
from web_api.middleware.supabase_auth import require_supabase_auth
from web_api.store import scan_store

logger = logging.getLogger("web_api.routes.scans")

bp = Blueprint("scans_v2", __name__, url_prefix="/api/scans")


@bp.route("", methods=["POST"])
@handle_errors
@require_supabase_auth
def create_scan():
    """Create a new scan."""
    user = g.internal_user
    data = request.get_json(silent=True) or {}

    target_url = data.get("target_url")
    if not target_url:
        return error_response("Missing target_url", 400)

    scan_mode = data.get("scan_mode", "quick")

    scan = scan_store.create_scan(
        user_id=user["id"],
        target_url=target_url,
        scan_mode=scan_mode,
    )

    # Record a creation event
    scan_store.add_scan_event(scan["id"], "created", {"scan_mode": scan_mode})

    return jsonify({"status": "success", "scan": scan}), 201


@bp.route("", methods=["GET"])
@handle_errors
@require_supabase_auth
def list_scans():
    """List scans for the authenticated user."""
    user = g.internal_user
    items = scan_store.list_scans(user_id=user["id"])
    return jsonify({"status": "success", "scans": items})


@bp.route("/<scan_id>", methods=["GET"])
@handle_errors
@require_supabase_auth
def get_scan(scan_id):
    """Get a single scan by ID."""
    user = g.internal_user
    scan = scan_store.get_scan(scan_id, user_id=user["id"])
    if scan is None:
        return error_response("Scan not found", 404)
    return jsonify({"status": "success", "scan": scan})


@bp.route("/<scan_id>/events", methods=["GET"])
@handle_errors
@require_supabase_auth
def get_scan_events(scan_id):
    """Get event stream for a scan."""
    user = g.internal_user
    events = scan_store.list_scan_events(scan_id, user_id=user["id"])
    if not events and scan_store.get_scan(scan_id, user_id=user["id"]) is None:
        return error_response("Scan not found", 404)
    return jsonify({"status": "success", "events": events})


def register_routes(app):
    """Register the scans blueprint with the Flask app."""
    app.register_blueprint(bp)
