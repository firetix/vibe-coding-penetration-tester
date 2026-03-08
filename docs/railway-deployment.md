# VibePenTester Railway Deployment Runbook (Backend)

**Scope:** M1 DevOps baseline for **Vercel frontend + Railway backend**  
**Backlog alignment:** `_bmad-output/planning-artifacts/execution-backlog-vibepentester-m1-m4-2026-02-28-v2.md` (M1-S1, M1-S6)

---

## 1) Current state (what exists today)

Reviewed artifacts/code:
- `VERCEL_DEPLOYMENT.md`
- `docs/vercel_deployment_fix.md`
- `web_api/` and `utils/` backend structure

Current backend reality in this repo:
- Flask API/UI app (`wsgi.py`, `run_web.py`, `web_api/*`)
- Billing/entitlements persistence is currently SQLite (`utils/billing_store.py`)
- Session/report persistence is currently filesystem-based
- Postgres-backed worker loop is available at `web_api.worker` (simulated processing, no Redis required)

This runbook sets up Railway so M1 can ship with clear infra boundaries, while keeping compatibility with current code and enabling Postgres-backed queue execution.

---

## 2) Target service topology on Railway

Create **two Railway projects**:
- `vpt-staging`
- `vpt-production`

In each project, define services:

1. **Postgres** (managed Railway PostgreSQL)
2. **API service** (`vpt-api`) — deploys this repo
3. **Worker service** (`vpt-worker`) — same repo, separate start command (`python -m web_api.worker`)

> Optional: add **Redis** only if you later introduce non-Postgres queue patterns.

---

## 3) Step-by-step Railway setup

### Step 1 — Create staging/prod projects
1. In Railway, create project `vpt-staging`.
2. Duplicate process for `vpt-production`.
3. Keep env values separated by environment (no shared prod secrets in staging).

### Step 2 — Provision Postgres service
1. Add Railway **PostgreSQL** service in each project.
2. Keep backups enabled.
3. Copy connection reference for app services as `DATABASE_URL`.

### Step 3 — (Optional) Provision Redis service
1. Add Railway **Redis** service only if you need it for future features.
2. Current worker design does **not** require `REDIS_URL`.

### Step 4 — Deploy API service (`vpt-api`)
1. Add service from this GitHub repo.
2. Runtime/build: Nixpacks default (Python).
3. Start command: use `Procfile` (`web`) from repo.
4. Health check path: `/status`.
5. Attach a persistent volume mounted at `/data` (important for current filesystem-based persistence).
6. Set API environment variables from the matrix below.

### Step 5 — Configure worker service (`vpt-worker`)
1. Add second service from same repo.
2. Disable external/public domain for worker.
3. Set shared env vars + worker env vars from matrix below.
4. Set worker start command:
   - `python -m web_api.worker`
5. Validate worker logs show scan claiming and progress event inserts.

---

## 4) Copy/paste environment variable matrix

A repo-ready template is committed at: **`.env.railway.example`**

### 4.1 Shared vars (API + Worker)

```bash
VPT_ENV=production
VPT_HOSTED_MODE=1
VPT_TRUST_PROXY_HEADERS=1
VPT_ENABLE_MOCK_CHECKOUT=0
VPT_ALLOW_UNVERIFIED_WEBHOOKS=0

OPENAI_API_KEY=
ANTHROPIC_API_KEY=
GOOGLE_API_KEY=

DATABASE_URL=${{Postgres.DATABASE_URL}}

SUPABASE_URL=
SUPABASE_ANON_KEY=
SUPABASE_JWT_SECRET=
SUPABASE_SERVICE_ROLE_KEY=
```

### 4.2 API service vars

```bash
PORT=8080
WEB_CONCURRENCY=2
WEB_THREADS=4
WEB_TIMEOUT=180

STRIPE_SECRET_KEY=
STRIPE_WEBHOOK_SECRET=
STRIPE_PRICE_PRO_MONTHLY=
STRIPE_PRICE_CREDIT_PACK=

# Current code compatibility (durable file paths on Railway volume)
VPT_BILLING_DB_PATH=/data/vpt.db
VPT_SESSION_FILE=/data/sessions.json
VPT_UPLOAD_FOLDER=/data/reports
```

### 4.3 Worker service vars

```bash
# Same shared vars as API, plus worker tuning knobs
WORKER_POLL_INTERVAL_SECONDS=3
WORKER_STEP_INTERVAL_SECONDS=1
WORKER_SIMULATED_STEPS=4
WORKER_RECONNECT_DELAY_SECONDS=5
WORKER_LOG_LEVEL=INFO
WORKER_RUN_ONCE=0
```

---

## 5) Minimal operational checklist (M1)

### Health checks
- API liveness:
  - `GET /status` returns HTTP 200 and JSON with `status: "ok"`
- Smoke check after deploy:
  - initialize session (`POST /api/session/init`)
  - start deterministic scan in staging with `VPT_E2E_MODE=1`

### Logging/observability
- Use Railway logs for API and worker streams.
- Ensure error-level logs for scan failures are visible in API logs.
- Add alert routing for:
  - API service down/restart loop
  - Worker crash loop (when worker enabled)

### Migrations/data management
- **Current state:** no Postgres migration framework is active in this repo yet.
- M1 compatibility mode uses `/data` mounted volume with:
  - `VPT_BILLING_DB_PATH=/data/vpt.db`
  - `VPT_SESSION_FILE=/data/sessions.json`
  - `VPT_UPLOAD_FOLDER=/data/reports`
- When Postgres schema is introduced (M2/M3), add migration command to deploy pipeline (e.g. Alembic `upgrade head`).

### Rollback
1. Roll back to previous Railway deployment release for `vpt-api`.
2. Revert recently changed env vars if incident is configuration-driven.
3. Confirm `/status` health and a basic scan/session flow.
4. If data regression occurred, restore Postgres backup (and verify app compatibility before re-promote).

---

## 6) Vercel frontend env var changes (required for split architecture)

For Vercel-hosted frontend, add/update:

```bash
NEXT_PUBLIC_API_BASE_URL=https://<your-railway-api-domain>
API_BASE_URL=https://<your-railway-api-domain>

NEXT_PUBLIC_SUPABASE_URL=
NEXT_PUBLIC_SUPABASE_ANON_KEY=

NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=
```

Notes:
- `NEXT_PUBLIC_API_BASE_URL` is the browser-side base URL used by frontend fetch calls.
- `API_BASE_URL` is server-side (SSR/route handlers) base URL.
- Keep backend-only secrets **off Vercel** (`STRIPE_SECRET_KEY`, webhook secrets, DB URLs).
- Existing CI preview automation secret (`VERCEL_AUTOMATION_BYPASS_SECRET`) remains useful for preview E2E.

---

## 7) Gaps to close in next milestones

- Wire Postgres as the backend system of record in app code (currently SQLite/file based for billing/session/report compatibility paths).
- Replace simulated worker execution with real scanner orchestration logic.
- Add formal migration tooling and pre-deploy migration step.
