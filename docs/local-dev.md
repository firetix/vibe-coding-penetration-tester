# Local Development (Backend + `vibehack-web`)

This guide runs the Flask API on **:5000** and the Next.js frontend on **:3000** for local end-to-end smoke testing.

## Prerequisites

- Python 3.11+ (or compatible with this repo)
- Node.js + npm (project currently works with Node 22 in this environment)
- Backend deps installed:
  - `python3 -m venv .venv`
  - `source .venv/bin/activate`
  - `pip install -r requirements.txt`
- Frontend deps installed:
  - `cd vibehack-web && npm install`

---

## 1) Start backend on `:5000`

From repo root:

```bash
cd /home/mrachidi/.openclaw/workspace/projects/vibe-pentester

PORT=5000 \
DATABASE_URL='sqlite:///data/vpt_app.db' \
SUPABASE_JWT_SECRET='local-dev-secret-at-least-32-chars-long' \
SUPABASE_JWT_AUDIENCE='authenticated' \
VPT_CORS_ALLOW_ORIGINS='http://localhost:3000' \
.venv/bin/python run_web.py
```

Backend health check:

```bash
curl -sS http://localhost:5000/status
```

Expected: JSON with `"status": "ok"`.

### Backend env vars (local)

- `PORT=5000`
- `DATABASE_URL=sqlite:///data/vpt_app.db`
- `SUPABASE_JWT_SECRET=local-dev-secret-at-least-32-chars-long`
- `SUPABASE_JWT_AUDIENCE=authenticated`
- `VPT_CORS_ALLOW_ORIGINS=http://localhost:3000`

Optional when using **real Supabase** verification via JWKS:

- `SUPABASE_URL=https://<your-project>.supabase.co`

---

## 2) Start frontend (`vibehack-web`) on `:3000`

From repo root:

```bash
cd /home/mrachidi/.openclaw/workspace/projects/vibe-pentester/vibehack-web

NEXT_PUBLIC_SUPABASE_URL='https://example.supabase.co' \
NEXT_PUBLIC_SUPABASE_ANON_KEY='dummy-anon-key-for-local-render' \
NEXT_PUBLIC_API_BASE_URL='http://localhost:5000' \
PORT=3000 \
npm run dev -- --port 3000
```

### Frontend env vars

- `NEXT_PUBLIC_SUPABASE_URL`
- `NEXT_PUBLIC_SUPABASE_ANON_KEY`
- `NEXT_PUBLIC_API_BASE_URL=http://localhost:5000`
- `PORT=3000`

> You can use **dummy Supabase URL/key** to render pages.
>
> **Important:** real login/signup requires real Supabase project credentials.

---

## 3) Auth testing: real Supabase vs local fallback

### Option A — Real Supabase auth (recommended for true login flow)

Use real values for:

- Backend: `SUPABASE_URL`
- Frontend: `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_ANON_KEY`

Then open:

- `http://localhost:3000/login`
- `http://localhost:3000/app/scans`

### Option B — Local fallback auth with `SUPABASE_JWT_SECRET`

If you do not have real Supabase keys, backend can validate HS256 JWTs with `SUPABASE_JWT_SECRET`.
Generate a local token:

```bash
cd /home/mrachidi/.openclaw/workspace/projects/vibe-pentester

TOKEN=$(
  .venv/bin/python - <<'PY'
import jwt, time
secret = 'local-dev-secret-at-least-32-chars-long'
payload = {
  'sub': '00000000-0000-4000-8000-000000000001',
  'aud': 'authenticated',
  'email': 'local-dev@example.com',
  'role': 'authenticated',
  'iat': int(time.time()),
  'exp': int(time.time()) + 3600,
}
print(jwt.encode(payload, secret, algorithm='HS256'))
PY
)

echo "$TOKEN"
```

Use this token in API curl requests.

---

## 4) API smoke-test curl commands (create scan, append event, SSE)

Assumes `TOKEN` is exported as above.

### Create scan

```bash
CREATE_RESPONSE=$(curl -sS -X POST http://localhost:5000/api/scans \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"target_url":"https://example.com","scan_mode":"quick"}')

echo "$CREATE_RESPONSE"
```

Extract `scan_id` (without `jq`):

```bash
echo "$CREATE_RESPONSE" > /tmp/vpt-create.json
SCAN_ID=$(python3 - <<'PY'
import json
with open('/tmp/vpt-create.json') as f:
  print(json.load(f)['scan']['id'])
PY
)

echo "$SCAN_ID"
```

### Append event

```bash
curl -sS -X POST "http://localhost:5000/api/scans/$SCAN_ID/events" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"event_type":"status.running","data":{"progress":10,"message":"Local smoke event"}}'
```

### Stream SSE

```bash
curl -sS -N "http://localhost:5000/api/scans/$SCAN_ID/events/stream?access_token=$TOKEN"
```

You should see:

- `event: connected`
- one or more `event: scan_event` messages (including your appended event)

---

## 5) Troubleshooting

### CORS errors in browser

- Ensure backend has:
  - `VPT_CORS_ALLOW_ORIGINS='http://localhost:3000'`
- Restart backend after env changes.

### Port already in use (`5000` or `3000`)

```bash
ss -ltnp | grep ':5000\|:3000'
```

Kill stale processes if needed.

### `/app/scans` redirects to `/login`

This is expected when unauthenticated (middleware protection on `/app/*`).

### Login fails with dummy Supabase values

Expected. Dummy values allow page rendering only. Use real Supabase project URL + anon key for actual login/signup.

### API returns `401 Invalid or expired token`

- Regenerate `TOKEN` (it may be expired)
- Ensure token claims include:
  - `sub`
  - `aud=authenticated`
- Ensure backend secret matches token signing secret.

### API returns `503 Authentication service not configured`

Set at least one of:

- `SUPABASE_URL` (real Supabase JWKS path), or
- `SUPABASE_JWT_SECRET` (local fallback)
