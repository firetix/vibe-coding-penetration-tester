"""Billing and entitlement routes."""

import os
import uuid
from typing import Any, Dict

from flask import Blueprint, g, request

from web_api.helpers.request_parser import parse_request
from web_api.helpers.response_formatter import error_response, success_response
from web_api.middleware.error_handler import handle_errors
from utils.entitlements import (
    parse_scan_mode,
)

try:
    import stripe  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    stripe = None


def _line_item_for_mode(scan_mode: str) -> Dict[str, Any]:
    # Stripe price ids are optional; fallback to inline test prices when not provided.
    if scan_mode == "solutions":
        price_id = os.environ.get("STRIPE_PRICE_CREDIT_PACK")
        if price_id:
            return {"price": price_id, "quantity": 1}
        return {
            "price_data": {
                "currency": "usd",
                "unit_amount": 2900,
                "product_data": {"name": "Vibe Pen Tester - Solutions Pack"},
            },
            "quantity": 1,
        }

    if scan_mode == "deep":
        price_id = os.environ.get("STRIPE_PRICE_CREDIT_PACK")
        if price_id:
            return {"price": price_id, "quantity": 1}
        return {
            "price_data": {
                "currency": "usd",
                "unit_amount": 900,
                "product_data": {"name": "Vibe Pen Tester - Deep Scan Credit"},
            },
            "quantity": 1,
        }

    # quick mode post-free default goes to pro for simplicity.
    price_id = os.environ.get("STRIPE_PRICE_PRO_MONTHLY")
    if price_id:
        return {"price": price_id, "quantity": 1}
    return {
        "price_data": {
            "currency": "usd",
            "unit_amount": 1900,
            "recurring": {"interval": "month"},
            "product_data": {"name": "Vibe Pen Tester - Pro Monthly"},
        },
        "quantity": 1,
    }


def _mock_checkout_url(checkout_session_id: str) -> str:
    return f"{request.host_url.rstrip('/')}/mock-checkout/{checkout_session_id}"


def _allow_unverified_webhooks() -> bool:
    return os.environ.get("VPT_ALLOW_UNVERIFIED_WEBHOOKS") == "1"


def register_routes(app, billing_store):
    """Register billing and entitlement routes."""
    bp = Blueprint("billing", __name__, url_prefix="/api")

    @bp.route("/entitlements", methods=["GET"])
    @handle_errors
    def get_entitlements():
        account_id = getattr(g, "account_id", None)
        if not account_id:
            return error_response("Missing account identity", 400)

        ent = billing_store.get_entitlements(account_id)
        return success_response(data={"entitlements": ent})

    @bp.route("/billing/checkout", methods=["POST"])
    @handle_errors
    def create_checkout():
        account_id = getattr(g, "account_id", None)
        if not account_id:
            return error_response("Missing account identity", 400)

        data = parse_request()
        scan_mode = parse_scan_mode(data.get("scan_mode", "deep"))
        checkout_session_id = f"cs_{uuid.uuid4().hex}"

        checkout_url = _mock_checkout_url(checkout_session_id)
        amount = 0
        currency = "usd"
        price_id = None

        stripe_secret_key = os.environ.get("STRIPE_SECRET_KEY")
        if stripe and stripe_secret_key:
            try:
                stripe.api_key = stripe_secret_key
                success_url = data.get("success_url") or f"{request.host_url.rstrip('/')}/?checkout=success"
                cancel_url = data.get("cancel_url") or f"{request.host_url.rstrip('/')}/?checkout=cancel"
                line_item = _line_item_for_mode(scan_mode)
                session = stripe.checkout.Session.create(
                    mode="payment" if scan_mode in {"deep", "solutions"} else "subscription",
                    line_items=[line_item],
                    success_url=success_url,
                    cancel_url=cancel_url,
                    metadata={
                        "account_id": account_id,
                        "scan_mode": scan_mode,
                    },
                )
                checkout_session_id = session.id
                checkout_url = session.url
                amount = getattr(session, "amount_total", 0) or 0
                currency = getattr(session, "currency", "usd") or "usd"
                price_id = os.environ.get("STRIPE_PRICE_CREDIT_PACK") if scan_mode in {"deep", "solutions"} else os.environ.get("STRIPE_PRICE_PRO_MONTHLY")
            except Exception:
                # fall back to mock checkout if Stripe call fails
                pass

        billing_store.create_checkout_session(
            checkout_session_id=checkout_session_id,
            account_id=account_id,
            scan_mode=scan_mode,
            price_id=price_id,
            amount=amount,
            currency=currency,
        )

        return success_response(
            data={
                "checkout_url": checkout_url,
                "checkout_session_id": checkout_session_id,
                "scan_mode": scan_mode,
            }
        )

    @bp.route("/billing/webhook", methods=["POST"])
    @handle_errors
    def billing_webhook():
        payload = request.get_data(as_text=False)
        sig_header = request.headers.get("Stripe-Signature")
        webhook_secret = os.environ.get("STRIPE_WEBHOOK_SECRET")

        if _allow_unverified_webhooks():
            event = request.get_json(silent=True) or {}
        else:
            if not stripe or not webhook_secret:
                return error_response("Webhook verification is not configured", 400)
            if not sig_header:
                return error_response("Missing webhook signature", 400)
            try:
                event = stripe.Webhook.construct_event(payload=payload, sig_header=sig_header, secret=webhook_secret)
            except Exception:
                return error_response("Invalid webhook signature", 400)

        event_type = event.get("type")
        data_object = (event.get("data") or {}).get("object", {})
        checkout_session_id = data_object.get("id") or event.get("checkout_session_id")

        if event_type != "checkout.session.completed" or not checkout_session_id:
            return success_response(message="Webhook ignored")

        checkout = billing_store.mark_checkout_completed(checkout_session_id)
        if not checkout:
            return error_response("Unknown checkout session", 404)
        if not checkout.get("just_completed", False):
            return success_response(message="Webhook already processed")

        account_id = checkout["account_id"]
        scan_mode = checkout["scan_mode"]

        # Grant entitlement idempotently by checking for existing completion status in checkout row.
        # mark_checkout_completed already short-circuits repeated updates.
        if scan_mode == "solutions":
            billing_store.add_credits(account_id, credits=10)
        elif scan_mode == "deep":
            billing_store.add_credits(account_id, credits=5)
        else:
            billing_store.activate_pro(account_id, days=30)

        billing_store.record_payment(
            account_id=account_id,
            checkout_session_id=checkout_session_id,
            status="completed",
            amount=checkout.get("amount"),
            currency=checkout.get("currency") or "usd",
            payment_intent_id=data_object.get("payment_intent"),
        )

        return success_response(message="Webhook processed")

    app.register_blueprint(bp)
