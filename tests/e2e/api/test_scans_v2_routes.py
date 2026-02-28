"""Tests for the new /api/scans endpoints (v2).

Uses Flask test client with monkeypatched auth to avoid needing real
Supabase credentials.
"""

import json
import os
import sys
import time
from unittest.mock import patch

import pytest

# Ensure project root is on path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FAKE_SUB = "supabase-user-uuid-1234"
_FAKE_EMAIL = "test@example.com"


def _make_fake_payload(sub=_FAKE_SUB, email=_FAKE_EMAIL):
    return {
        "sub": sub,
        "email": email,
        "aud": "authenticated",
        "exp": int(time.time()) + 3600,
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def app(tmp_path):
    """Create a fresh Flask app with an isolated SQLite DB."""
    db_path = str(tmp_path / "test_app.db")
    env_overrides = {
        "DATABASE_URL": f"sqlite:///{db_path}",
        "SUPABASE_JWT_SECRET": "test-secret-at-least-32-chars-long!!",
        "SUPABASE_JWT_AUDIENCE": "authenticated",
    }
    with patch.dict(os.environ, env_overrides):
        # Reset cached engine so each test gets a fresh DB
        import web_api.store.db as db_mod

        db_mod._engine = None

        from web_api import create_app

        application = create_app()
        application.config["TESTING"] = True
        yield application

        db_mod._engine = None


@pytest.fixture()
def client(app):
    return app.test_client()


def _auth_header(payload=None):
    """Build an Authorization header with a real HS256 JWT signed by the test secret."""
    import jwt as pyjwt

    payload = payload or _make_fake_payload()
    token = pyjwt.encode(payload, "test-secret-at-least-32-chars-long!!", algorithm="HS256")
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Auth tests
# ---------------------------------------------------------------------------


class TestAuth:
    def test_missing_auth_returns_401(self, client):
        resp = client.get("/api/scans")
        assert resp.status_code == 401

    def test_invalid_token_returns_401(self, client):
        resp = client.get(
            "/api/scans", headers={"Authorization": "Bearer bad.token.here"}
        )
        assert resp.status_code == 401

    def test_expired_token_returns_401(self, client):
        payload = _make_fake_payload()
        payload["exp"] = int(time.time()) - 10  # expired
        resp = client.get("/api/scans", headers=_auth_header(payload))
        assert resp.status_code == 401

    def test_no_supabase_config_returns_503(self, client):
        """If neither SUPABASE_URL nor SUPABASE_JWT_SECRET is set, return 503."""
        with patch.dict(
            os.environ,
            {"SUPABASE_URL": "", "SUPABASE_JWT_SECRET": ""},
            clear=False,
        ):
            # Need to remove the keys entirely
            env = os.environ.copy()
            env.pop("SUPABASE_URL", None)
            env.pop("SUPABASE_JWT_SECRET", None)
            with patch.dict(os.environ, env, clear=True):
                resp = client.get(
                    "/api/scans", headers={"Authorization": "Bearer some.token"}
                )
                assert resp.status_code == 503


# ---------------------------------------------------------------------------
# CRUD tests
# ---------------------------------------------------------------------------


class TestCreateScan:
    def test_create_scan_success(self, client):
        resp = client.post(
            "/api/scans",
            json={"target_url": "https://example.com", "scan_mode": "quick"},
            headers=_auth_header(),
        )
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["status"] == "success"
        scan = data["scan"]
        assert scan["target_url"] == "https://example.com"
        assert scan["scan_mode"] == "quick"
        assert scan["status"] == "pending"
        assert "id" in scan

    def test_create_scan_missing_url_returns_400(self, client):
        resp = client.post(
            "/api/scans",
            json={"scan_mode": "quick"},
            headers=_auth_header(),
        )
        assert resp.status_code == 400

    def test_create_scan_default_mode(self, client):
        resp = client.post(
            "/api/scans",
            json={"target_url": "https://example.com"},
            headers=_auth_header(),
        )
        assert resp.status_code == 201
        assert resp.get_json()["scan"]["scan_mode"] == "quick"


class TestListScans:
    def test_list_empty(self, client):
        resp = client.get("/api/scans", headers=_auth_header())
        assert resp.status_code == 200
        assert resp.get_json()["scans"] == []

    def test_list_after_create(self, client):
        client.post(
            "/api/scans",
            json={"target_url": "https://a.com"},
            headers=_auth_header(),
        )
        client.post(
            "/api/scans",
            json={"target_url": "https://b.com"},
            headers=_auth_header(),
        )
        resp = client.get("/api/scans", headers=_auth_header())
        data = resp.get_json()
        assert len(data["scans"]) == 2

    def test_scans_scoped_to_user(self, client):
        """Different supabase user IDs should not see each other's scans."""
        headers_a = _auth_header(_make_fake_payload(sub="user-a"))
        headers_b = _auth_header(_make_fake_payload(sub="user-b"))

        client.post(
            "/api/scans",
            json={"target_url": "https://a.com"},
            headers=headers_a,
        )
        client.post(
            "/api/scans",
            json={"target_url": "https://b.com"},
            headers=headers_b,
        )

        resp_a = client.get("/api/scans", headers=headers_a)
        resp_b = client.get("/api/scans", headers=headers_b)
        assert len(resp_a.get_json()["scans"]) == 1
        assert len(resp_b.get_json()["scans"]) == 1
        assert resp_a.get_json()["scans"][0]["target_url"] == "https://a.com"
        assert resp_b.get_json()["scans"][0]["target_url"] == "https://b.com"


class TestGetScan:
    def test_get_existing_scan(self, client):
        create = client.post(
            "/api/scans",
            json={"target_url": "https://example.com"},
            headers=_auth_header(),
        )
        scan_id = create.get_json()["scan"]["id"]

        resp = client.get(f"/api/scans/{scan_id}", headers=_auth_header())
        assert resp.status_code == 200
        assert resp.get_json()["scan"]["id"] == scan_id

    def test_get_nonexistent_scan_returns_404(self, client):
        resp = client.get("/api/scans/does-not-exist", headers=_auth_header())
        assert resp.status_code == 404


class TestScanEvents:
    def test_events_after_create(self, client):
        create = client.post(
            "/api/scans",
            json={"target_url": "https://example.com", "scan_mode": "deep"},
            headers=_auth_header(),
        )
        scan_id = create.get_json()["scan"]["id"]

        resp = client.get(f"/api/scans/{scan_id}/events", headers=_auth_header())
        assert resp.status_code == 200
        events = resp.get_json()["events"]
        assert len(events) >= 1
        assert events[0]["event_type"] == "created"
        assert events[0]["data"]["scan_mode"] == "deep"

    def test_events_nonexistent_scan_returns_404(self, client):
        resp = client.get(
            "/api/scans/does-not-exist/events", headers=_auth_header()
        )
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Legacy route coexistence
# ---------------------------------------------------------------------------


class TestLegacyCoexistence:
    def test_old_scan_routes_still_exist(self, client):
        """The old /api/scan/start endpoint should still be reachable."""
        resp = client.post("/api/scan/start", json={})
        # Should get 400 (missing session/url), not 404
        assert resp.status_code == 400
