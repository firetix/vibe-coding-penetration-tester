"""Supabase JWT verification middleware.

Verifies Bearer tokens using Supabase JWKS (kid-based key lookup).
Gracefully degrades when Supabase env vars are not configured – protected
endpoints return a clear 503 error instead of crashing the app.

Required env vars:
  SUPABASE_URL          – e.g. https://<project>.supabase.co
  SUPABASE_JWT_SECRET   – (optional) fallback HMAC secret for local dev
"""

import os
import logging
import time
from functools import wraps

import jwt
from flask import g, request

from web_api.helpers.response_formatter import error_response

logger = logging.getLogger("web_api.middleware.supabase_auth")

# --- JWKS cache ---------------------------------------------------------------

_jwks_cache: dict | None = None
_jwks_fetched_at: float = 0
_JWKS_TTL = 3600  # re-fetch keys every hour


def _supabase_url() -> str | None:
    return os.environ.get("SUPABASE_URL")


def _jwks_uri() -> str | None:
    base = _supabase_url()
    if not base:
        return None
    return f"{base.rstrip('/')}/auth/v1/.well-known/jwks.json"


def _fetch_jwks() -> dict | None:
    """Fetch JWKS from Supabase. Returns None on failure."""
    global _jwks_cache, _jwks_fetched_at

    if _jwks_cache and (time.time() - _jwks_fetched_at) < _JWKS_TTL:
        return _jwks_cache

    uri = _jwks_uri()
    if not uri:
        return None

    try:
        import requests as _requests

        resp = _requests.get(uri, timeout=5)
        resp.raise_for_status()
        _jwks_cache = resp.json()
        _jwks_fetched_at = time.time()
        logger.info("Fetched JWKS from %s (%d keys)", uri, len(_jwks_cache.get("keys", [])))
        return _jwks_cache
    except Exception:
        logger.warning("Failed to fetch JWKS from %s", uri, exc_info=True)
        return _jwks_cache  # return stale cache if available


def _get_signing_key(token: str):
    """Resolve the signing key for a JWT using JWKS kid lookup."""
    jwks_data = _fetch_jwks()
    if jwks_data:
        try:
            from jwt.api_jwk import PyJWKSet

            keyset = PyJWKSet.from_dict(jwks_data)
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")
            if kid:
                for key in keyset.keys:
                    if key.key_id == kid:
                        return key.key
            # If no kid match, try first key
            if keyset.keys:
                return keyset.keys[0].key
        except Exception:
            logger.warning("JWKS key resolution failed, falling back to secret", exc_info=True)

    # Fallback: use SUPABASE_JWT_SECRET (HMAC)
    secret = os.environ.get("SUPABASE_JWT_SECRET")
    if secret:
        return secret

    return None


# --- Token verification -------------------------------------------------------


def verify_token(token: str) -> dict | None:
    """Verify a Supabase JWT and return its decoded payload, or None."""
    key = _get_signing_key(token)
    if key is None:
        logger.error("No signing key available for JWT verification")
        return None

    audience = os.environ.get("SUPABASE_JWT_AUDIENCE", "authenticated")
    algorithms = ["RS256", "HS256"]

    try:
        payload = jwt.decode(
            token,
            key,
            algorithms=algorithms,
            audience=audience,
            options={
                "verify_exp": True,
                "verify_aud": bool(audience),
            },
        )
        return payload
    except jwt.ExpiredSignatureError:
        logger.info("JWT expired")
        return None
    except jwt.InvalidAudienceError:
        logger.info("JWT audience mismatch")
        return None
    except jwt.PyJWTError as exc:
        logger.info("JWT verification failed: %s", exc)
        return None


# --- Flask decorator -----------------------------------------------------------


def require_supabase_auth(f):
    """Decorator: require a valid Supabase JWT in the Authorization header.

    On success, sets:
      g.supabase_user_id  – the 'sub' claim (Supabase user UUID)
      g.jwt_payload       – full decoded token payload
      g.internal_user     – internal user record (after mapping)
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        # Check if Supabase auth is configured
        if not _supabase_url() and not os.environ.get("SUPABASE_JWT_SECRET"):
            return error_response(
                "Authentication service not configured. Set SUPABASE_URL or SUPABASE_JWT_SECRET.",
                503,
            )

        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return error_response("Missing or invalid Authorization header", 401)

        token = auth_header[7:]
        payload = verify_token(token)
        if payload is None:
            return error_response("Invalid or expired token", 401)

        sub = payload.get("sub")
        if not sub:
            return error_response("Token missing subject claim", 401)

        g.supabase_user_id = sub
        g.jwt_payload = payload

        # Map to internal user (lazy import to avoid circular deps)
        from web_api.store.user_store import get_or_create_user

        email = payload.get("email")
        g.internal_user = get_or_create_user(sub, email=email)

        return f(*args, **kwargs)

    return decorated
