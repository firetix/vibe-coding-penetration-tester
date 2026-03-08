"""Versioned SaaS scan endpoints with authenticated org ownership checks."""

import logging
from functools import wraps

from flask import Blueprint, g, jsonify, request

from web_api.helpers.request_parser import parse_request, get_json_param, normalize_url
from web_api.helpers.response_formatter import success_response, error_response
from web_api.middleware.error_handler import handle_errors
from utils.entitlements import (
    check_scan_rate_limits,
    extract_client_ip,
    is_hosted_mode,
    is_valid_target_for_hosted,
    parse_scan_mode,
    payment_required_payload,
)


logger = logging.getLogger("web_api")


def _coerce_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return False


def register_routes(
    app,
    saas_store,
    session_manager,
    scan_controller,
    activity_tracker,
    report_manager,
    billing_store=None,
):
    """Register authenticated v1 scan endpoints."""

    bp = Blueprint("v1_scans", __name__, url_prefix="/api/v1/scans")

    def _require_auth(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            supabase_user = getattr(g, "supabase_user", None)
            if not supabase_user or not supabase_user.get("sub"):
                return error_response("Authentication required", 401)
            return f(*args, **kwargs)

        return wrapped

    def _make_checkout_url(scan_mode: str) -> str:
        return f"{request.host_url.rstrip('/')}/billing/checkout?scan_mode={scan_mode}"

    def _enforce_hosted_policy(data, url: str, scan_mode: str):
        if not is_hosted_mode() or billing_store is None:
            return None

        account_id = getattr(g, "account_id", None)
        if not account_id:
            return error_response("Missing account identity", 400)

        authorization_confirmed = _coerce_bool(data.get("authorization_confirmed"))
        if not authorization_confirmed:
            return error_response(
                "Authorization confirmation is required for hosted scans", 400
            )

        target_ok, target_reason = is_valid_target_for_hosted(url)
        if not target_ok:
            return error_response(target_reason or "Target is blocked in hosted mode", 400)

        ip_address = extract_client_ip(
            request.remote_addr,
            request.headers.get("X-Forwarded-For"),
        )
        rate_ok, rate_reason = check_scan_rate_limits(
            billing_store, account_id, ip_address
        )
        if not rate_ok:
            return error_response(rate_reason or "Rate limit exceeded", 429)

        ent_check = billing_store.try_consume_entitlement_for_scan(account_id, scan_mode)
        if not ent_check["allowed"]:
            payload = payment_required_payload(
                ent_check["entitlements"], _make_checkout_url(scan_mode)
            )
            return jsonify(payload), 402

        g.pending_entitlement_consume = ent_check["consume"]
        g.pending_usage_event_ip = ip_address
        g.entitlements = ent_check["entitlements"]
        return None

    def _finalize_entitlement_consumption():
        if not is_hosted_mode() or billing_store is None:
            return

        account_id = getattr(g, "account_id", None)
        if not account_id:
            return

        usage_ip = getattr(g, "pending_usage_event_ip", None)
        if usage_ip:
            try:
                billing_store.record_usage_event(account_id, usage_ip, "scan_start")
                g.pending_usage_event_ip = None
            except Exception:
                logger.exception(
                    "Failed to record scan usage event for account %s", account_id
                )
        g.pending_entitlement_consume = None

    def _rollback_entitlement_consumption():
        if not is_hosted_mode() or billing_store is None:
            return

        consume_kind = getattr(g, "pending_entitlement_consume", None)
        account_id = getattr(g, "account_id", None)
        if not consume_kind or not account_id:
            return

        try:
            billing_store.refund_consumption(account_id, consume_kind)
            g.entitlements = billing_store.get_entitlements(account_id)
            g.pending_entitlement_consume = None
        except Exception:
            logger.exception(
                "Failed to refund entitlement after v1 scan start failure for account %s",
                account_id,
            )

    def _resolve_scan_status(session_id: str, legacy_scan_id: str):
        scan = session_manager.get_active_scan(session_id, legacy_scan_id)
        if scan:
            return {
                "status": scan.get("status", "running"),
                "progress": scan.get("progress", 0),
                "current_task": scan.get("current_task", scan.get("status", "running")),
                "is_running": True,
                "url": scan.get("url", ""),
                "report_available": False,
                "report_dir": None,
                "vulnerabilities": scan.get("vulnerabilities", []),
                "session_id": session_id,
                "legacy_scan_id": legacy_scan_id,
                "agent_logs": activity_tracker.get_activities(session_id),
            }

        completed_scans = session_manager.get_completed_scans(session_id)
        for completed in completed_scans:
            if completed.get("id") != legacy_scan_id:
                continue
            report_dir = completed.get("report_dir")
            return {
                "status": completed.get("status", "completed"),
                "progress": completed.get("progress", 100),
                "current_task": completed.get("current_task", completed.get("status", "completed")),
                "is_running": False,
                "url": completed.get("url", ""),
                "report_available": bool(report_dir),
                "report_dir": report_dir,
                "vulnerabilities": completed.get("vulnerabilities", []),
                "session_id": session_id,
                "legacy_scan_id": legacy_scan_id,
                "agent_logs": activity_tracker.get_activities(session_id),
            }
        return None

    @bp.route("", methods=["POST"])
    @handle_errors
    @_require_auth
    def create_scan():
        data = parse_request()
        url = normalize_url(data.get("url"))
        if not url:
            return error_response("Missing target URL", 400)

        config = get_json_param(data, "config", default={}) or {}
        scan_mode = parse_scan_mode(data.get("scan_mode") or config.get("scan_mode"))
        config["scan_mode"] = scan_mode

        policy_response = _enforce_hosted_policy(data, url, scan_mode)
        if policy_response is not None:
            return policy_response

        supabase_user = g.supabase_user
        user_id = str(supabase_user["sub"])
        user_ctx = saas_store.ensure_user_org(user_id, supabase_user.get("email"))

        # Versioned API scan identifier maps to existing session/scan runtime state.
        session_id = session_manager.create_session()

        def activity_adapter(session_id, activity):
            activity_type = activity.get("type", "general")
            description = activity.get("description", "Activity")
            details = activity.get("details", {})
            agent_name = activity.get("agent", None)
            return activity_tracker.add_activity(
                session_id, activity_type, description, details, agent_name
            )

        try:
            legacy_scan_id = scan_controller.start_scan(
                session_id, url, config, activity_callback=activity_adapter
            )
            v1_scan_id = saas_store.create_scan(
                org_id=user_ctx["org_id"],
                created_by_user_id=user_id,
                target_url=url,
                mode=scan_mode,
                session_id=session_id,
                legacy_scan_id=legacy_scan_id,
            )
        except Exception:
            _rollback_entitlement_consumption()
            raise
        _finalize_entitlement_consumption()

        response_data = {
            "scan": {
                "id": v1_scan_id,
                "status": "queued",
                "target_url": url,
                "mode": scan_mode,
                "created_by_user_id": user_id,
                "org_id": user_ctx["org_id"],
            }
        }
        if getattr(g, "entitlements", None):
            response_data["entitlements"] = g.entitlements
        return success_response(data=response_data, status_code=201)

    @bp.route("/<scan_id>", methods=["GET"])
    @handle_errors
    @_require_auth
    def get_scan(scan_id):
        user_id = str(g.supabase_user["sub"])
        record = saas_store.get_scan_for_user(scan_id, user_id)
        if not record:
            return error_response("Scan not found", 404)

        status_payload = _resolve_scan_status(record["session_id"], record["legacy_scan_id"])
        if not status_payload:
            return error_response("Scan not found", 404)

        return success_response(
            data={
                "scan": {
                    "id": scan_id,
                    "org_id": record["org_id"],
                    "created_by_user_id": record["created_by_user_id"],
                    "target_url": record["target_url"],
                    "mode": record["mode"],
                    **status_payload,
                }
            }
        )

    @bp.route("/<scan_id>/report", methods=["GET"])
    @handle_errors
    @_require_auth
    def get_scan_report(scan_id):
        user_id = str(g.supabase_user["sub"])
        record = saas_store.get_scan_for_user(scan_id, user_id)
        if not record:
            return error_response("Scan not found", 404)

        status_payload = _resolve_scan_status(record["session_id"], record["legacy_scan_id"])
        if not status_payload:
            return error_response("Scan not found", 404)
        if status_payload["is_running"]:
            return success_response(
                message="Scan is in progress",
                data={
                    "scan_id": scan_id,
                    "status": "in_progress",
                    "progress": status_payload["progress"],
                },
                status_code=202,
            )
        if not status_payload["report_dir"]:
            return success_response(
                message="Report is being generated",
                data={
                    "scan_id": scan_id,
                    "status": "generating",
                    "progress": status_payload["progress"],
                },
                status_code=202,
            )

        report = report_manager.get_report(status_payload["report_dir"])
        if isinstance(report, dict) and report.get("error") == "Report not found":
            return error_response("Report not found", 404)

        return success_response(
            data={
                "scan_id": scan_id,
                "report": report,
            }
        )

    app.register_blueprint(bp)
