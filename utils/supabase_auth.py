import logging
import os
from typing import Any, Dict, Optional


logger = logging.getLogger(__name__)


class SupabaseAuthError(Exception):
    pass


def supabase_auth_enabled() -> bool:
    """Enable Supabase auth integration when a JWT secret is configured."""
    return bool(os.environ.get("SUPABASE_JWT_SECRET"))


def extract_bearer_token(auth_header: Optional[str]) -> Optional[str]:
    if not auth_header:
        return None
    value = auth_header.strip()
    if not value:
        return None
    if " " not in value:
        return None
    scheme, token = value.split(" ", 1)
    if scheme.strip().lower() != "bearer":
        return None
    token = token.strip()
    return token or None


def _expected_issuer() -> Optional[str]:
    explicit = os.environ.get("SUPABASE_JWT_ISS")
    if explicit:
        return explicit
    supabase_url = os.environ.get("SUPABASE_URL")
    if not supabase_url:
        return None
    return supabase_url.rstrip("/") + "/auth/v1"


def verify_supabase_jwt(token: str) -> Dict[str, Any]:
    secret = os.environ.get("SUPABASE_JWT_SECRET")
    if not secret:
        raise SupabaseAuthError("SUPABASE_JWT_SECRET is not set")

    alg = os.environ.get("SUPABASE_JWT_ALG", "HS256").strip() or "HS256"
    aud = os.environ.get("SUPABASE_JWT_AUD")

    try:
        import jwt  # type: ignore
    except Exception as exc:  # pragma: no cover - optional dependency
        raise SupabaseAuthError(
            "Supabase JWT verification requires PyJWT. Install with: pip install PyJWT"
        ) from exc

    options = {"verify_aud": bool(aud)}
    kwargs = {}
    if aud:
        kwargs["audience"] = aud

    try:
        payload = jwt.decode(
            token,
            secret,
            algorithms=[alg],
            options=options,
            **kwargs,
        )
    except Exception as exc:
        raise SupabaseAuthError("Invalid Supabase access token") from exc

    expected_iss = _expected_issuer()
    if expected_iss and payload.get("iss") != expected_iss:
        raise SupabaseAuthError("Invalid token issuer")

    return payload


def maybe_get_supabase_user(auth_header: Optional[str]) -> Optional[Dict[str, Any]]:
    if not supabase_auth_enabled():
        return None
    token = extract_bearer_token(auth_header)
    if not token:
        return None
    try:
        payload = verify_supabase_jwt(token)
    except SupabaseAuthError as exc:
        logger.warning("Supabase auth token rejected: %s", exc)
        return None

    if not payload.get("sub"):
        logger.warning("Supabase auth token missing 'sub' claim")
        return None
    return payload

