import ipaddress
import os
import uuid
import socket
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


def _is_blocked_ip(ip) -> bool:
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _parse_ip_candidate(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    candidate = value.strip()
    if not candidate or candidate.lower() == "unknown":
        return None

    if candidate.startswith("[") and "]" in candidate:
        candidate = candidate[1 : candidate.index("]")]
    if "%" in candidate:
        candidate = candidate.split("%", 1)[0]

    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        # Handle IPv4 addresses that may include port suffixes.
        if ":" in candidate and candidate.count(":") == 1:
            host, _, _port = candidate.partition(":")
            try:
                return str(ipaddress.ip_address(host))
            except ValueError:
                return None
        return None


def should_trust_proxy_headers() -> bool:
    return os.environ.get("VPT_TRUST_PROXY_HEADERS", "0") == "1"


def extract_client_ip(
    remote_addr: Optional[str],
    x_forwarded_for: Optional[str],
    trust_proxy_headers: Optional[bool] = None,
) -> str:
    trust_proxy = (
        should_trust_proxy_headers()
        if trust_proxy_headers is None
        else trust_proxy_headers
    )

    if trust_proxy and x_forwarded_for:
        first_hop = x_forwarded_for.split(",", 1)[0].strip()
        parsed = _parse_ip_candidate(first_hop)
        if parsed:
            return parsed

    parsed_remote = _parse_ip_candidate(remote_addr)
    return parsed_remote or ""


def _hostname_resolves_to_blocked_ip(hostname: str) -> Tuple[bool, Optional[str]]:
    try:
        addr_info = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        # If DNS resolution is unavailable, do not hard-fail valid public hostnames.
        return False, None
    except Exception:
        return False, None

    resolved_ips = set()
    for info in addr_info:
        address = info[4][0]
        try:
            resolved_ips.add(ipaddress.ip_address(address))
        except ValueError:
            continue

    for ip in resolved_ips:
        if _is_blocked_ip(ip):
            return (
                True,
                "Target resolves to a private/internal IP address in hosted mode",
            )

    return False, None


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
            if _is_blocked_ip(ip):
                return False, "Private/internal IP targets are blocked in hosted mode"
        except ValueError:
            blocked, reason = _hostname_resolves_to_blocked_ip(hostname)
            if blocked:
                return False, reason

        return True, None
    except Exception:
        return False, "Invalid target URL"


def is_pro_active(pro_until: Optional[str]) -> bool:
    if not pro_until:
        return False
    try:
        return datetime.fromisoformat(pro_until).replace(
            tzinfo=timezone.utc
        ) > datetime.now(timezone.utc)
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
        return {
            "allowed": True,
            "reason": None,
            "consume": "credit",
            "entitlements": ent,
        }

    return {
        "allowed": False,
        "reason": "Payment required for additional scans",
        "consume": None,
        "entitlements": ent,
    }


def consume_entitlement(
    store: BillingStore, account_id: str, consume: Optional[str]
) -> Dict[str, Any]:
    if consume == "free":
        store.decrement_free_scan(account_id)
    elif consume == "credit":
        store.decrement_credit(account_id)
    return store.get_entitlements(account_id)


def check_scan_rate_limits(
    store: BillingStore, account_id: str, ip: str
) -> Tuple[bool, Optional[str]]:
    # Conservative defaults for hosted mode.
    account_events = store.count_recent_events_by_account(
        account_id, "scan_start", window_seconds=60
    )
    ip_events = store.count_recent_events_by_ip(ip, "scan_start", window_seconds=60)

    if account_events >= 5:
        return False, "Rate limit exceeded for this account"
    if ip_events >= 20:
        return False, "Rate limit exceeded for this IP"
    return True, None


def payment_required_payload(
    entitlements: Dict[str, Any], checkout_url: str
) -> Dict[str, Any]:
    return {
        "status": "payment_required",
        "paywall_required": True,
        "checkout_url": checkout_url,
        "entitlements": entitlements,
    }
