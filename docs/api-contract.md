# API Contract – /api/scans (v2)

All endpoints require a valid Supabase JWT in the `Authorization` header.

## Authentication

```
Authorization: Bearer <supabase_access_token>
```

The token is verified server-side against Supabase JWKS. The `sub` claim is
mapped to an internal user record automatically.

If Supabase environment variables (`SUPABASE_URL` or `SUPABASE_JWT_SECRET`)
are not configured, protected endpoints return **503 Service Unavailable**.

---

## Endpoints

### POST /api/scans

Create a new scan.

**Request:**
```json
{
  "target_url": "https://example.com",
  "scan_mode": "quick"
}
```

| Field        | Type   | Required | Notes                                |
|-------------|--------|----------|--------------------------------------|
| target_url  | string | yes      | URL to scan                          |
| scan_mode   | string | no       | `quick` (default), `deep`, `solutions` |

**Response (201):**
```json
{
  "status": "success",
  "scan": {
    "id": "a1b2c3d4-...",
    "user_id": 1,
    "target_url": "https://example.com",
    "scan_mode": "quick",
    "status": "pending",
    "created_at": "2026-02-28T12:00:00",
    "updated_at": "2026-02-28T12:00:00"
  }
}
```

---

### GET /api/scans

List all scans for the authenticated user (most recent first).

**Request:** No body. Auth header only.

**Response (200):**
```json
{
  "status": "success",
  "scans": [
    {
      "id": "a1b2c3d4-...",
      "user_id": 1,
      "target_url": "https://example.com",
      "scan_mode": "quick",
      "status": "pending",
      "created_at": "2026-02-28T12:00:00",
      "updated_at": "2026-02-28T12:00:00"
    }
  ]
}
```

---

### GET /api/scans/{id}

Get a single scan by ID. Returns 404 if the scan does not exist or does not
belong to the authenticated user.

**Response (200):**
```json
{
  "status": "success",
  "scan": {
    "id": "a1b2c3d4-...",
    "user_id": 1,
    "target_url": "https://example.com",
    "scan_mode": "deep",
    "status": "running",
    "created_at": "2026-02-28T12:00:00",
    "updated_at": "2026-02-28T12:05:00"
  }
}
```

---

### GET /api/scans/{id}/events

Get the event stream for a scan. Events are ordered chronologically (oldest
first). Returns 404 if the scan does not exist or does not belong to the
authenticated user.

**Response (200):**
```json
{
  "status": "success",
  "events": [
    {
      "id": 1,
      "scan_id": "a1b2c3d4-...",
      "event_type": "created",
      "data": {"scan_mode": "quick"},
      "created_at": "2026-02-28T12:00:00"
    },
    {
      "id": 2,
      "scan_id": "a1b2c3d4-...",
      "event_type": "progress",
      "data": {"percent": 25, "message": "Crawling target..."},
      "created_at": "2026-02-28T12:01:00"
    }
  ]
}
```

---

## Error Responses

All errors follow a consistent shape:

```json
{
  "status": "error",
  "message": "Human-readable description"
}
```

| Status Code | Meaning                                    |
|------------|--------------------------------------------|
| 400        | Bad request (missing fields, etc.)         |
| 401        | Missing/invalid/expired JWT                |
| 404        | Scan not found or not owned by user        |
| 500        | Internal server error                      |
| 503        | Auth service not configured (missing env)  |

---

## Environment Variables

| Variable               | Required | Description                              |
|-----------------------|----------|------------------------------------------|
| DATABASE_URL          | no       | Postgres connection string. Falls back to SQLite `data/vpt_app.db` |
| SUPABASE_URL          | yes*     | Supabase project URL for JWKS fetch      |
| SUPABASE_JWT_SECRET   | yes*     | Fallback HMAC secret for local dev       |
| SUPABASE_JWT_AUDIENCE | no       | Expected `aud` claim (default: `authenticated`) |

\* At least one of `SUPABASE_URL` or `SUPABASE_JWT_SECRET` must be set for auth to work.
