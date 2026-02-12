"""Scan management routes."""

import logging

from flask import Blueprint, g, jsonify, request

from web_api.helpers.request_parser import parse_request, get_json_param, normalize_url
from web_api.helpers.response_formatter import success_response, error_response
from web_api.middleware.session_validator import validate_session
from web_api.middleware.error_handler import handle_errors
from utils.entitlements import (
    check_scan_rate_limits,
    extract_client_ip,
    is_hosted_mode,
    is_valid_target_for_hosted,
    parse_scan_mode,
    payment_required_payload,
)

logger = logging.getLogger('web_api')


def _coerce_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return False


def register_routes(app, session_manager, scan_controller, activity_tracker, billing_store=None):
    """Register scan routes with the Flask app."""

    bp = Blueprint('scan', __name__, url_prefix='/api/scan')

    def _make_checkout_url(scan_mode: str) -> str:
        return f"{request.host_url.rstrip('/')}/billing/checkout?scan_mode={scan_mode}"

    def _enforce_hosted_policy(data, url: str, scan_mode: str):
        if not is_hosted_mode() or billing_store is None:
            return None

        account_id = getattr(g, "account_id", None)
        if not account_id:
            return error_response("Missing account identity", 400)

        # Hosted abuse controls
        authorization_confirmed = _coerce_bool(data.get("authorization_confirmed"))
        if not authorization_confirmed:
            return error_response("Authorization confirmation is required for hosted scans", 400)

        target_ok, target_reason = is_valid_target_for_hosted(url)
        if not target_ok:
            return error_response(target_reason or "Target is blocked in hosted mode", 400)

        ip_address = extract_client_ip(
            request.remote_addr,
            request.headers.get("X-Forwarded-For"),
        )
        rate_ok, rate_reason = check_scan_rate_limits(billing_store, account_id, ip_address)
        if not rate_ok:
            return error_response(rate_reason or "Rate limit exceeded", 429)

        ent_check = billing_store.try_consume_entitlement_for_scan(account_id, scan_mode)
        if not ent_check["allowed"]:
            checkout_url = _make_checkout_url(scan_mode)
            payload = payment_required_payload(ent_check["entitlements"], checkout_url)
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
                logger.exception("Failed to record scan usage event for account %s", account_id)
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
            logger.exception("Failed to refund entitlement after scan start failure for account %s", account_id)

    @bp.route('/start', methods=['POST'])
    @handle_errors
    @validate_session(session_manager)
    def start_scan():
        """Start a new scan with the provided URL and configuration."""
        session_id = g.session_id
        data = parse_request()
        url = data.get('url')
        config = get_json_param(data, 'config', default={}) or {}

        if not url:
            return error_response('Missing target URL', 400)

        # Normalize URL to ensure it has a scheme
        url = normalize_url(url)
        scan_mode = parse_scan_mode(data.get("scan_mode") or config.get("scan_mode"))
        config["scan_mode"] = scan_mode

        policy_response = _enforce_hosted_policy(data, url, scan_mode)
        if policy_response is not None:
            return policy_response

        # Create an adapter for the activity tracker callback
        def activity_adapter(session_id, activity):
            activity_type = activity.get('type', 'general')
            description = activity.get('description', 'Activity')
            details = activity.get('details', {})
            agent_name = activity.get('agent', None)
            return activity_tracker.add_activity(session_id, activity_type, description, details, agent_name)

        # Start the scan
        try:
            scan_id = scan_controller.start_scan(
                session_id, url, config,
                activity_callback=activity_adapter
            )
        except Exception:
            _rollback_entitlement_consumption()
            raise
        _finalize_entitlement_consumption()

        response_data = {
            'scan_id': scan_id,
            'scan_mode': scan_mode,
        }
        if getattr(g, "entitlements", None):
            response_data["entitlements"] = g.entitlements

        return success_response(
            message=f'Scan started for {url}',
            data=response_data
        )

    @bp.route('/status', methods=['POST'])
    @handle_errors
    @validate_session(session_manager)
    def get_scan_status():
        """Get the status of a specific scan."""
        session_id = g.session_id
        data = parse_request()
        scan_id = data.get('scan_id')

        if not scan_id:
            return error_response('Missing scan ID', 400)

        # Get active scan status
        scan = session_manager.get_active_scan(session_id, scan_id)

        if scan:
            payload = {
                'scan': {
                    'id': scan_id,
                    'status': scan.get('status', 'unknown'),
                    'progress': scan.get('progress', 0),
                    'url': scan.get('url', ''),
                    'vulnerabilities': scan.get('vulnerabilities', []),
                    'report_dir': scan.get('report_dir')
                }
            }
            return success_response(data=payload)

        # Check completed scans
        completed_scans = session_manager.get_completed_scans(session_id)
        for completed in completed_scans:
            if completed.get('id') == scan_id:
                return success_response(data={
                    'scan': {
                        'id': scan_id,
                        'status': completed.get('status', 'unknown'),
                        'progress': 100,
                        'url': completed.get('url', ''),
                        'vulnerabilities': completed.get('vulnerabilities', []),
                        'report_dir': completed.get('report_dir'),
                        'completed': True
                    }
                })

        return error_response('Scan not found', 404)

    @bp.route('/cancel', methods=['POST'])
    @handle_errors
    @validate_session(session_manager)
    def cancel_scan():
        """Cancel an active scan."""
        session_id = g.session_id
        data = parse_request()
        scan_id = data.get('scan_id')

        if not scan_id:
            return error_response('Missing scan ID', 400)

        result = scan_controller.cancel_scan(session_id, scan_id)
        return success_response(data=result)

    @bp.route('/list', methods=['POST'])
    @handle_errors
    @validate_session(session_manager)
    def list_scans():
        """List all scans for a session."""
        session_id = g.session_id

        active = session_manager.get_active_scans(session_id)
        completed = session_manager.get_completed_scans(session_id)

        return success_response(data={
            'active': active,
            'completed': completed
        })

    # Legacy route handler that works more flexibly
    @app.route('/scan', methods=['POST'])
    @handle_errors
    def start_scan_compat():
        """Legacy endpoint for starting a scan that accepts various formats."""
        data = parse_request()

        # Log all request details for debugging
        logger.info(f"Scan request received with data: {data}")

        session_id = data.get('session_id')
        url = data.get('url')

        # Try to get config, which might be a nested JSON string
        config = get_json_param(data, 'config', default={}) or {}

        # Validate required parameters
        if not session_id:
            return error_response('Missing session ID', 400)

        if not url:
            return error_response('Missing target URL', 400)

        # Ensure URL has a scheme
        url = normalize_url(url)

        scan_mode = parse_scan_mode(data.get("scan_mode") or config.get("scan_mode"))
        config["scan_mode"] = scan_mode

        # Validate session
        if not session_manager.check_session(session_id):
            # If session doesn't exist, create a new one
            session_id = session_manager.create_session()
            logger.info(f"Created new session: {session_id}")

        policy_response = _enforce_hosted_policy(data, url, scan_mode)
        if policy_response is not None:
            return policy_response

        # Start the scan
        logger.info(f"Starting scan for URL {url} with session {session_id} and config {config}")

        # Create an adapter for the activity tracker callback
        def activity_adapter(session_id, activity):
            activity_type = activity.get('type', 'general')
            description = activity.get('description', 'Activity')
            details = activity.get('details', {})
            agent_name = activity.get('agent', None)
            return activity_tracker.add_activity(session_id, activity_type, description, details, agent_name)

        try:
            scan_id = scan_controller.start_scan(
                session_id, url, config,
                activity_callback=activity_adapter
            )
        except Exception:
            _rollback_entitlement_consumption()
            raise
        _finalize_entitlement_consumption()

        logger.info(f"Scan started successfully with scan_id: {scan_id}")
        response_data = {
            'scan_id': scan_id,
            'session_id': session_id,
            'scan_mode': scan_mode,
        }
        if getattr(g, "entitlements", None):
            response_data["entitlements"] = g.entitlements

        return success_response(
            message=f'Scan started for {url}',
            data=response_data
        )

    app.register_blueprint(bp)
