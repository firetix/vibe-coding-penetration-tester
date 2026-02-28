# E2E Test Plan — Next.js Frontend + Flask API (`vibe-pentester`)

## Scope

This plan covers end-to-end validation for local development with:

- Frontend: `http://localhost:3000` (`vibehack-web`)
- Backend: `http://localhost:5000` (`run_web.py` API)
- Auth model: Supabase JWT verification, with optional local fallback via `SUPABASE_JWT_SECRET`

It includes:

1. Happy path tests
2. Auth tests (real Supabase vs local JWT-secret fallback)
3. API tests (curl)
4. SSE live update tests
5. Automation vs manual testing split

---

## Test Preconditions

- Backend is up on `:5000`
- Frontend is up on `:3000`
- CORS includes frontend origin (`VPT_CORS_ALLOW_ORIGINS=http://localhost:3000`)
- For real auth flow, valid Supabase project vars are configured

---

## Executed UI Smoke + Screenshot Evidence

Harness script:

- `vibehack-web/scripts/e2e-screenshot-harness.mjs`

Run command:

```bash
cd vibehack-web
npm run e2e:screenshots
```

Captured pages:

1. `GET /login`
2. `GET /app/scans` (unauthenticated redirect expected to `/login?redirectedFrom=%2Fapp%2Fscans`)
3. `GET /`

Screenshot outputs:

- `reports/e2e_screenshots/01-login-page.png`
- `reports/e2e_screenshots/02-app-scans-redirected-to-login.png`
- `reports/e2e_screenshots/03-home-page.png`

Observed result from run:

- `/login` loaded (`200`)
- `/app/scans` redirected to `/login?redirectedFrom=%2Fapp%2Fscans` (`200`)
- `/` loaded (`200`)

---

## Happy Path Test Cases

## 1) User authentication + app access (real Supabase)

- Navigate to `/login`
- Sign in with valid credentials
- Expect redirect to `/app` (or original redirected route)
- Navigate to `/app/scans`
- Expect:
  - scan form visible
  - existing scans list visible
  - no auth error banner

## 2) Create scan + list scan

- From `/app/scans`, submit valid target URL + mode
- Expect success toast/message (`Scan submitted successfully.`)
- Expect scan to appear in recent scans list

## 3) Open scan details + live updates

- Open `/app/scans/[id]` from list
- Expect existing events load
- While page open, append event via API
- Expect new event appears without page refresh (SSE)

---

## Auth Test Matrix (Supabase Real vs Local Fallback)

## A) Real Supabase auth

Use:

- Backend: `SUPABASE_URL=https://<project>.supabase.co`
- Frontend: `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_ANON_KEY`

Tests:

1. Signup (optional) and login succeeds
2. Invalid password shows login error
3. Unauthenticated route guard redirects `/app/*` to `/login`
4. Authenticated user can access `/app/scans`
5. Logout invalidates app access and returns to login flow

## B) Local fallback auth (`SUPABASE_JWT_SECRET`)

Use:

- Backend: `SUPABASE_JWT_SECRET=<local-secret>`
- Optional backend audience: `SUPABASE_JWT_AUDIENCE=authenticated`

Notes:

- Frontend login UI can render with dummy public Supabase vars, but real browser login will not succeed without real Supabase credentials.
- Local fallback is best validated via API JWT generation + curl tests.

Tests:

1. Valid locally signed HS256 token accepted by `/api/scans*`
2. Missing token -> `401`
3. Invalid/expired token -> `401`
4. No `SUPABASE_URL` and no `SUPABASE_JWT_SECRET` -> `503`
5. Token with missing `sub` claim -> `401`

---

## API E2E Tests (curl)

## 0) Generate local fallback token

```bash
TOKEN=$(
  python3 - <<'PY'
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
```

## 1) Create scan

```bash
CREATE_RESPONSE=$(curl -sS -X POST http://localhost:5000/api/scans \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"target_url":"https://example.com","scan_mode":"quick"}')

echo "$CREATE_RESPONSE"
```

## 2) List scans

```bash
curl -sS -H "Authorization: Bearer $TOKEN" \
  http://localhost:5000/api/scans
```

## 3) Get scan id + fetch details

```bash
echo "$CREATE_RESPONSE" > /tmp/vpt-create.json
SCAN_ID=$(python3 - <<'PY'
import json
with open('/tmp/vpt-create.json') as f:
  print(json.load(f)['scan']['id'])
PY
)

curl -sS -H "Authorization: Bearer $TOKEN" \
  "http://localhost:5000/api/scans/$SCAN_ID"
```

## 4) Append event

```bash
curl -sS -X POST "http://localhost:5000/api/scans/$SCAN_ID/events" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"event_type":"status.running","data":{"progress":10,"message":"Local smoke event"}}'
```

## 5) List events

```bash
curl -sS -H "Authorization: Bearer $TOKEN" \
  "http://localhost:5000/api/scans/$SCAN_ID/events"
```

---

## SSE Live Updates Test

## Option A — Terminal verification with curl

1. Start stream in terminal A:

```bash
curl -sS -N "http://localhost:5000/api/scans/$SCAN_ID/events/stream?access_token=$TOKEN"
```

2. In terminal B, append event:

```bash
curl -sS -X POST "http://localhost:5000/api/scans/$SCAN_ID/events" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"event_type":"status.progress","data":{"progress":42,"message":"SSE smoke"}}'
```

3. Expect in terminal A:

- `event: connected`
- `event: scan_event` records including appended event payload
- periodic `: heartbeat`

## Option B — Browser verification

- Open `/app/scans/[id]`
- Append events from API
- Expect UI event timeline/list updates live without full refresh

---

## What to Automate vs Manual

## Automate (CI-friendly)

1. **Frontend unauthenticated routing smoke**
   - `/login` loads
   - `/app/scans` redirects to `/login`
   - `/` loads
2. **API contract smoke**
   - `create/list/get/events` with local JWT fallback
3. **SSE transport smoke**
   - stream connects, receives connected + appended events
4. **Negative auth API checks**
   - missing/invalid token -> `401`
   - missing backend auth config -> `503`

## Manual / staging validation

1. **Real Supabase browser auth**
   - signup/login/logout UX with real Supabase project
2. **Cross-browser visual QA**
   - layout/spacing/theme checks and accessibility spot checks
3. **Long-running scan lifecycle UX**
   - progress semantics and user messaging over time
4. **Billing/hosted mode integration**
   - external provider callbacks and entitlement behavior

---

## Suggested Automation Cadence

- On every PR: routing smoke + API smoke + SSE smoke
- Nightly: extended auth + scan scenario matrix (including user isolation)
- Before release: manual Supabase + visual QA checklist
