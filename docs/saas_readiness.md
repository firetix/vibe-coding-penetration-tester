# SaaS Readiness (Supabase Auth + DB)

This repo is close to “demo SaaS”, but not yet safe/reliable to charge money without tightening identity, persistence, and worker isolation.

This document assumes you want:
- Supabase for auth + Postgres database
- Vercel for web UI
- A separate containerized worker runtime for scanning (Playwright-heavy)

## What You Already Have (Good SaaS Hooks)
- Hosted-mode toggle: `VPT_HOSTED_MODE=1`.
- A paywall/entitlements model with:
  - `/api/entitlements`
  - `/api/billing/checkout`
  - `/api/billing/webhook`
- Abuse controls in hosted mode:
  - Explicit authorization confirmation (`authorization_confirmed`)
  - Localhost/private IP blocking (`utils.entitlements.is_valid_target_for_hosted`)
  - Rate limiting via usage events (`utils.entitlements.check_scan_rate_limits`)
- Deterministic end-to-end mode (`VPT_E2E_MODE=1`) for stable CI.

## Critical Gaps Before Charging Money
- Identity is currently cookie-based (`vpt_account_id`) by default, so users are not “real”.
  - Cookies are not a durable, tamper-resistant user identity boundary for SaaS.
- Persistence is still local:
  - sessions/scan state is in-memory + `sessions.json`
  - reports are on local disk (`reports/` or `/tmp`)
  - billing/entitlements are SQLite by default (`data/vpt.db` or `/tmp/vpt.db`)
- Multi-instance safety:
  - With multiple web instances, you can get split-brain scan state and inconsistent rate limits.
- Scanning runtime fit:
  - Playwright + long-running scans are not a good fit for pure serverless request/response platforms.
- Security/compliance gaps:
  - SSRF hardening needs DNS rebinding + redirect-chain re-validation (policy must run in both API and worker).
  - No retention/deletion policies for scan artifacts (reports can contain sensitive data).

## Changes Implemented In This Repo (Supabase-Ready)

### 1) Supabase Auth (JWT) Support
If `SUPABASE_JWT_SECRET` is set, the backend accepts Supabase access tokens:
- Header: `Authorization: Bearer <access_token>`
- Identity mapping: `account_id = JWT.sub`

This is implemented in:
- `utils/supabase_auth.py`
- `web_api/__init__.py` (sets `g.account_id` from Supabase JWT when present)
- `web_ui.py` (legacy app, same behavior)

Notes:
- Cookie identity still works as a fallback for OSS/local usage.
- You can later enforce auth in hosted mode by returning `401` when the token is missing/invalid (policy choice).

### 2) Supabase Postgres For Billing/Entitlements
Billing/entitlements can now be backed by Supabase Postgres instead of SQLite.

Implemented in:
- `utils/billing_store_postgres.py` (`PostgresBillingStore`, same method contract as SQLite store)
- `web_api/__init__.py` and `web_ui.py` select Postgres when a Postgres URL is provided

Enable by setting one of:
- `VPT_BILLING_DB_URL=postgresql://...`
- `VPT_APP_DB_URL=postgresql://...` (fallback when `VPT_BILLING_DB_URL` is unset)
- `SUPABASE_DATABASE_URL=postgresql://...`

If none are set, the app falls back to SQLite `VPT_BILLING_DB_PATH`.

### 3) Supabase Postgres For Sessions/Scans/Reports (Reliability)
Scan state and reports no longer have to live in `sessions.json` and local `reports/` directories.

Implemented in:
- `utils/session_manager_postgres.py` (`PostgresSessionManager`)
- `utils/activity_tracker_postgres.py` (`PostgresActivityTracker`)
- `utils/report_manager_postgres.py` (`PostgresReportManager`)
- Wired into `web_api/__init__.py` and `web_ui.py` when a Postgres URL is configured

Enable by setting one of:
- `VPT_APP_DB_URL=postgresql://...`
- `SUPABASE_DATABASE_URL=postgresql://...`

Behavior:
- The scanner still uses local disk as a *staging* directory for subprocess output, but the finalized report is ingested into Postgres for durability (`ScanController` calls `report_manager.ingest_report(...)` when supported).
- The `/reports/<report_id>/report.json` and `/reports/<report_id>/report.md` routes fall back to serving these artifacts from Postgres when the local file is not present.

### 4) Authenticated v1 Scan API (User/Org Ownership)
Implemented endpoints:
- `POST /api/v1/scans` (auth required)
- `GET /api/v1/scans/<id>` (auth required)
- `GET /api/v1/scans/<id>/report` (auth required)

Behavior:
- Requires a valid Supabase Bearer token (`g.supabase_user` must be present).
- Auto-provisions a personal org on first authenticated request (`users/orgs/memberships`).
- Persists scan ownership mapping in `saas_scans` and enforces org-based access checks.
- Reuses the existing scan engine/session state under the hood while establishing SaaS authorization boundaries.

## Recommended Supabase-Backed Architecture

### Web (Vercel)
- Hosts the UI (static + server-rendered pages if desired).
- Uses Supabase JS client for:
  - email/password
  - magic link
  - OAuth (Google/GitHub)
- Calls backend API with `Authorization: Bearer <access_token>`.
- Recommended env vars on web tier:
  - `SUPABASE_URL`
  - `SUPABASE_PUBLISHABLE_KEY`

### API (Flask Web API)
Keep the current Flask API for now, but treat it as the “control plane”:
- Validate Supabase JWT for authenticated endpoints
- Create scan jobs (do not execute scans inline)
- Report scan status
- Serve reports or signed URLs
- Handle billing webhooks (Stripe)

### Worker (Containerized)
Run scans in a separate worker pool:
- Pull jobs from a queue
- Execute Playwright + scan engine
- Write progress/events to Postgres
- Upload artifacts to object storage

This is required for reliability and to avoid request timeouts on Vercel/serverless.

### Storage
- Database: Supabase Postgres
- Queue/rate limiting: Redis (or Supabase queue equivalent, but Redis is simplest)
- Artifacts: Supabase Storage (or S3-compatible object store)

## Decision-Complete Data Model (Supabase)
Supabase provides `auth.users`. You should add your own tables for SaaS behavior.

Suggested tables:
- `profiles`: `user_id (pk -> auth.users.id)`, `email`, `created_at`
- `orgs`: `id`, `name`, `created_at`
- `memberships`: `user_id`, `org_id`, `role`
- `entitlements`: `org_id (pk)`, `free_scans_remaining`, `credits`, `pro_until`, `updated_at`
- `scans`: `id`, `org_id`, `created_by_user_id`, `target_url`, `mode`, `status`, `progress`, `created_at`, `started_at`, `finished_at`
- `scan_events`: `id`, `scan_id`, `ts`, `type`, `payload`
- `artifacts`: `id`, `scan_id`, `kind`, `storage_key`, `content_type`, `size_bytes`
- `billing_customers`: `org_id (pk)`, `stripe_customer_id`
- `checkout_sessions`: `id`, `org_id`, `stripe_session_id`, `mode`, `status`, `amount`, `currency`, `created_at`
- `usage_events`: `id`, `org_id`, `ip`, `event_type`, `ts`

RLS policy recommendation:
- Default-deny.
- Allow members to `SELECT` scans/events for their org.
- Writes come from the worker and billing webhook using the Supabase service role key (server-side only).

## Public API Shape (SaaS API)
Keep the existing endpoints for backwards compatibility, but add stable v1 endpoints that are explicitly auth-bound:
- `POST /api/v1/scans` create scan (Supabase auth required)
- `GET /api/v1/scans/<id>` status/progress/logs (Supabase auth required)
- `GET /api/v1/scans/<id>/report` report JSON/markdown or signed URL (Supabase auth required)
- `POST /api/v1/billing/checkout` checkout (Supabase auth required)
- `POST /api/v1/billing/webhook` Stripe webhook (signature + idempotency required)

Compatibility layer:
- Keep `/scan`, `/status`, `/report` for the existing UI, but treat `session_id` as UI convenience only.

## Security/Abuse Controls (Must-Haves)
- Re-check target policy inside worker:
  - resolve DNS at execution time (block private)
  - re-validate every redirect hop
  - cap redirects
- Lock down worker networking:
  - block cloud metadata IPs
  - restrict outbound ports to `80/443` where possible
- Move rate limiting counters to Redis for correctness across instances.
- Add artifact retention + deletion (per org, per scan) and audit logging.
