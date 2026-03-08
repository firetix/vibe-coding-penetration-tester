"""New /api/scans endpoints for the Next.js app.

These routes use Supabase JWT auth and persist to the Postgres/SQLite store.
They coexist with the legacy /api/scan/* routes.
"""

import json
import logging
import os
import time

from flask import Blueprint, Response, g, jsonify, request, stream_with_context

from web_api.helpers.response_formatter import error_response
from web_api.middleware.error_handler import handle_errors
from web_api.middleware.supabase_auth import require_supabase_auth, verify_token
from web_api.store import scan_store

logger = logging.getLogger("web_api.routes.scans")

bp = Blueprint("scans_v2", __name__, url_prefix="/api/scans")

_SSE_POLL_INTERVAL_SECONDS = max(
    float(os.environ.get("VPT_SSE_POLL_INTERVAL_SECONDS", "1.0")), 0.1
)
_SSE_HEARTBEAT_SECONDS = max(
    float(os.environ.get("VPT_SSE_HEARTBEAT_SECONDS", "15")), 1.0
)
_SSE_MAX_EVENTS_PER_POLL = max(
    int(os.environ.get("VPT_SSE_MAX_EVENTS_PER_POLL", "100")), 1
)


def _to_non_negative_int(value, default: int = 0) -> int:
    try:
        return max(int(value), 0)
    except (TypeError, ValueError):
        return default


def _resolve_stream_user():
    """Resolve user for SSE, allowing token via query string for EventSource."""
    if not os.environ.get("SUPABASE_URL") and not os.environ.get("SUPABASE_JWT_SECRET"):
        return (
            None,
            error_response(
                "Authentication service not configured. Set SUPABASE_URL or SUPABASE_JWT_SECRET.",
                503,
            ),
        )

    auth_header = request.headers.get("Authorization", "")
    access_token = ""

    if auth_header.startswith("Bearer "):
        access_token = auth_header[7:].strip()

    # Browser EventSource cannot set Authorization headers, so we allow
    # a token in the query string as an MVP transport mechanism.
    if not access_token:
        access_token = request.args.get("access_token", "").strip()

    if not access_token:
        return None, error_response("Missing access token", 401)

    payload = verify_token(access_token)
    if payload is None:
        return None, error_response("Invalid or expired token", 401)

    sub = payload.get("sub")
    if not sub:
        return None, error_response("Token missing subject claim", 401)

    from web_api.store.user_store import get_or_create_user

    user = get_or_create_user(sub, email=payload.get("email"))
    return user, None


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

    # Record starter events so realtime streams have immediate data.
    scan_store.add_scan_event(scan["id"], "created", {"scan_mode": scan_mode})
    scan_store.add_scan_event(
        scan["id"],
        "status.pending",
        {"message": "Scan accepted and queued"},
    )

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


@bp.route("/<scan_id>/events", methods=["POST"])
@handle_errors
@require_supabase_auth
def append_scan_event(scan_id):
    """Append an event to a scan so realtime UI can be tested before workers."""
    user = g.internal_user
    scan = scan_store.get_scan(scan_id, user_id=user["id"])
    if scan is None:
        return error_response("Scan not found", 404)

    data = request.get_json(silent=True) or {}
    event_type = data.get("event_type")
    event_data = data.get("data")

    if not isinstance(event_type, str) or not event_type.strip():
        return error_response("Missing event_type", 400)

    if event_data is not None and not isinstance(event_data, dict):
        return error_response("data must be an object", 400)

    event = scan_store.add_scan_event(
        scan_id=scan_id,
        event_type=event_type.strip(),
        data=event_data,
    )
    return jsonify({"status": "success", "event": event}), 201


@bp.route("/<scan_id>/events/stream", methods=["GET"])
@handle_errors
def stream_scan_events(scan_id):
    """Server-Sent Events stream for scan events."""
    user, auth_error = _resolve_stream_user()
    if auth_error:
        return auth_error

    if scan_store.get_scan(scan_id, user_id=user["id"]) is None:
        return error_response("Scan not found", 404)

    raw_last_event_id = request.headers.get("Last-Event-ID") or request.args.get(
        "last_event_id"
    )
    last_event_id = _to_non_negative_int(raw_last_event_id)

    def event_stream():
        nonlocal last_event_id
        last_heartbeat = 0.0

        connected_payload = json.dumps({"scan_id": scan_id, "status": "connected"})
        yield "event: connected\n"
        yield f"data: {connected_payload}\n\n"

        try:
            while True:
                events = scan_store.list_scan_events_since(
                    scan_id=scan_id,
                    user_id=user["id"],
                    last_event_id=last_event_id,
                    limit=_SSE_MAX_EVENTS_PER_POLL,
                )

                if events:
                    for event in events:
                        event_id = _to_non_negative_int(event.get("id"), last_event_id)
                        if event_id > last_event_id:
                            last_event_id = event_id

                        payload = json.dumps(event, separators=(",", ":"))
                        yield f"id: {event_id}\n"
                        yield "event: scan_event\n"
                        yield f"data: {payload}\n\n"

                    last_heartbeat = time.monotonic()
                    continue

                now = time.monotonic()
                if (now - last_heartbeat) >= _SSE_HEARTBEAT_SECONDS:
                    yield ": heartbeat\n\n"
                    last_heartbeat = now

                time.sleep(_SSE_POLL_INTERVAL_SECONDS)
        except GeneratorExit:
            logger.info("SSE stream closed for scan_id=%s", scan_id)

    response = Response(stream_with_context(event_stream()), mimetype="text/event-stream")
    response.headers["Cache-Control"] = "no-cache"
    response.headers["Connection"] = "keep-alive"
    response.headers["X-Accel-Buffering"] = "no"
    return response


def register_routes(app):
    """Register the scans blueprint with the Flask app."""
    app.register_blueprint(bp)
