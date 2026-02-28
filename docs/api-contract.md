# API Contract – /api/scans (v2)

All endpoints require a valid Supabase JWT in the `Authorization` header.

For browser `EventSource` clients, `GET /api/scans/{id}/events/stream` also
accepts `access_token` as a query parameter because native EventSource cannot
set custom headers.

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

### POST /api/scans/{id}/events

Append a scan event manually (useful for MVP realtime testing before workers
are wired in).

**Request:**
```json
{
  "event_type": "progress",
  "data": {
    "percent": 42,
    "message": "Crawling target"
  }
}
```

| Field      | Type   | Required | Notes |
|------------|--------|----------|-------|
| event_type | string | yes      | Event name/label |
| data       | object | no       | JSON payload attached to event |

**Response (201):**
```json
{
  "status": "success",
  "event": {
    "id": 3,
    "scan_id": "a1b2c3d4-...",
    "event_type": "progress",
    "data": {"percent": 42, "message": "Crawling target"},
    "created_at": "2026-02-28T12:02:00"
  }
}
```

---

### GET /api/scans/{id}/events/stream

Open a Server-Sent Events (SSE) stream for realtime updates.

Auth options:
- `Authorization: Bearer <token>` header (recommended for non-browser clients)
- `?access_token=<token>` query param (required for browser EventSource)

Optional resume controls:
- `Last-Event-ID` request header
- `last_event_id` query param

**SSE event types:**
- `connected` – initial handshake event
- `scan_event` – each row from `scan_events`
- `: heartbeat` comment frames keep the connection warm

**Example (EventSource):**
```ts
const source = new EventSource(
  `${API_BASE_URL}/api/scans/${scanId}/events/stream?access_token=${token}`,
);

source.addEventListener("scan_event", (event) => {
  const payload = JSON.parse(event.data);
  console.log(payload.event_type, payload.data);
});
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
| VPT_CORS_ALLOW_ORIGINS | no      | Comma-separated CORS allowlist (e.g. `https://app.example.com,https://*.vercel.app`) |
| VPT_FRONTEND_ORIGIN   | no       | Optional single frontend origin to allow |
| VPT_SSE_POLL_INTERVAL_SECONDS | no | SSE poll cadence in seconds (default: `1.0`) |
| VPT_SSE_HEARTBEAT_SECONDS | no   | SSE heartbeat interval in seconds (default: `15`) |
| VPT_SSE_MAX_EVENTS_PER_POLL | no | Max events emitted per poll iteration (default: `100`) |

\* At least one of `SUPABASE_URL` or `SUPABASE_JWT_SECRET` must be set for auth to work.

---

## Local Backend Run Notes

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Configure environment (example):
   ```bash
   export DATABASE_URL="postgresql://postgres:postgres@localhost:5432/vpt"
   export SUPABASE_URL="https://<your-project-ref>.supabase.co"
   export SUPABASE_JWT_AUDIENCE="authenticated"
   # Optional local fallback for HS256 tokens:
   # export SUPABASE_JWT_SECRET="your-local-dev-secret"
   ```
3. Start the API:
   ```bash
   python3 web_api/main.py
   ```

Migrations for `users`, `scans`, `scan_events`, and `findings` run automatically on app startup via `web_api.store.migrator.run_migrations()`.

