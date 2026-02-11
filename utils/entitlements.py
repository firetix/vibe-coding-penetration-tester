import ipaddress
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

from utils.billing_store import BillingStore


ALLOWED_SCAN_MODES = {"quick", "deep", "solutions"}


def is_hosted_mode() -> bool:
    """Hosted SaaS mode toggle. OSS/self-host should keep unrestricted behavior by default."""
    return os.environ.get("VPT_HOSTED_MODE", "0") == "1"


def parse_scan_mode(value: Optional[str]) -> str:
    mode = (value or "quick").strip().lower()
    if mode not in ALLOWED_SCAN_MODES:
        return "quick"
    return mode


def generate_account_id() -> str:
    return str(uuid.uuid4())


def is_valid_target_for_hosted(url: str) -> Tuple[bool, Optional[str]]:
    """Block localhost/private/internal targets in hosted mode."""
    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").strip().lower()
        if not hostname:
            return False, "Invalid target URL"

        if hostname in {"localhost", "127.0.0.1", "::1"} or hostname.endswith(".local"):
            return False, "Localhost and local domains are blocked in hosted mode"

        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
                return False, "Private/internal IP targets are blocked in hosted mode"
        except ValueError:
            # Hostname is not an IP, allow domain names.
            pass

        return True, None
    except Exception:
        return False, "Invalid target URL"


def is_pro_active(pro_until: Optional[str]) -> bool:
    if not pro_until:
        return False
    try:
        return datetime.fromisoformat(pro_until).replace(tzinfo=timezone.utc) > datetime.now(timezone.utc)
    except Exception:
        return False


def evaluate_entitlement_for_scan(
    store: BillingStore,
    account_id: str,
    scan_mode: str,
) -> Dict[str, Any]:
    """
    Policy:
    - exactly one free quick scan
    - after free scan, any mode requires credits or pro
    - deep/solutions always require credits/pro unless pro active
    """
    ent = store.get_entitlements(account_id)

    if ent["pro_active"]:
        return {"allowed": True, "reason": None, "consume": None, "entitlements": ent}

    if scan_mode == "quick" and ent["free_scans_remaining"] > 0:
        return {"allowed": True, "reason": None, "consume": "free", "entitlements": ent}

    if ent["deep_scan_credits"] > 0:
        return {"allowed": True, "reason": None, "consume": "credit", "entitlements": ent}

    return {
        "allowed": False,
        "reason": "Payment required for additional scans",
        "consume": None,
        "entitlements": ent,
    }


def consume_entitlement(store: BillingStore, account_id: str, consume: Optional[str]) -> Dict[str, Any]:
    if consume == "free":
        store.decrement_free_scan(account_id)
    elif consume == "credit":
        store.decrement_credit(account_id)
    return store.get_entitlements(account_id)


def check_scan_rate_limits(store: BillingStore, account_id: str, ip: str) -> Tuple[bool, Optional[str]]:
    # Conservative defaults for hosted mode.
    account_events = store.count_recent_events_by_account(account_id, "scan_start", window_seconds=60)
    ip_events = store.count_recent_events_by_ip(ip, "scan_start", window_seconds=60)

    if account_events >= 5:
        return False, "Rate limit exceeded for this account"
    if ip_events >= 20:
        return False, "Rate limit exceeded for this IP"
    return True, None


def payment_required_payload(entitlements: Dict[str, Any], checkout_url: str) -> Dict[str, Any]:
    return {
        "status": "payment_required",
        "paywall_required": True,
        "checkout_url": checkout_url,
        "entitlements": entitlements,
    }
