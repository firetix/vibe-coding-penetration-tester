# Project Context — VibePenTester

Last updated: 2026-03-05

Use this file as the **first read** before making implementation changes.

## 1) Product + Architecture Snapshot
- Product: AI-assisted web application security scanner
- Frontend: **Next.js** app in `vibehack-web/` (deployed on **Vercel**)
- Backend API: **Flask** app in `web_api/` + entrypoints `run_web.py` / `wsgi.py` (deployed on **Railway**)
- Async workers/queue: Redis-backed worker model (Temporal deferred)
- Auth: **Supabase Auth** JWTs verified by API middleware
- DB: **Railway Postgres** with SQL migrations under `web_api/store/migrations/`
- Realtime: SSE stream for scan events (`/api/scans/{id}/events/stream`)

## 2) Non-Negotiable Implementation Rules
1. Keep deployment split intact: Vercel frontend, Railway API/workers.
2. Do not bypass JWT verification on protected scan endpoints.
3. Preserve org/user data boundaries; never allow cross-tenant reads/writes.
4. Maintain API contract compatibility for scans endpoints unless contract update is intentional and documented.
5. Prefer additive DB migrations; avoid destructive schema changes in-place.
6. Preserve SSE reconnect/resume behavior (`last_event_id` semantics).

## 3) High-Value Repo Map
- `vibehack-web/` — frontend app
  - `app/(auth)` login/signup routes
  - `app/app/scans` scan list + detail live view
  - `lib/api.ts` typed API client + SSE URL builder
  - `lib/env.ts` required public env validation
- `web_api/` — backend modules
  - `routes/scans.py` scan CRUD/events/stream
  - `middleware/supabase_auth.py` JWT verification
  - `store/migrations/*.sql` schema migrations
- `docs/` — operating docs + API contract
- `_bmad-output/` — planning/solutioning artifacts (PRD, UX, architecture)

## 4) Local Dev Commands
### Backend
- Install: `pip install -r requirements.txt`
- Run API: `python run_web.py`
- Health check: `curl http://localhost:5000/health`

### Frontend
- Install: `cd vibehack-web && npm install`
- Dev server: `npm run dev`
- Build: `npm run build`
- Lint: `npm run lint`
- Type check: `npm run typecheck`
- Unit tests: `npm test`
- E2E (Playwright): `npm run test:e2e`

## 5) Environment Variables (Critical)
### Frontend (`vibehack-web`)
- `NEXT_PUBLIC_SUPABASE_URL`
- `NEXT_PUBLIC_SUPABASE_ANON_KEY`
- `NEXT_PUBLIC_API_BASE_URL`

### Backend (`web_api`)
- `DATABASE_URL`
- `JWT_SECRET` and/or Supabase JWKS-related env
- `FLASK_ENV`, `DEBUG` (non-prod only)
- Queue/Redis/billing envs as configured in deployment

## 6) API Contract Pointers
Primary reference: `docs/api-contract.md`

Critical endpoints currently used by frontend:
- `POST /api/scans`
- `GET /api/scans`
- `GET /api/scans/{id}`
- `GET /api/scans/{id}/events`
- `POST /api/scans/{id}/events`
- `GET /api/scans/{id}/events/stream`

If you change response shape or auth behavior, update:
- backend route handlers,
- frontend `vibehack-web/lib/api.ts` normalizers,
- contract docs,
- tests.

## 7) Coding Guardrails for Agents
- Prefer minimal-scope edits; avoid unrelated refactors.
- Keep naming style consistent within touched module.
- Add/update tests when behavior changes.
- Document significant API/DB changes in `docs/`.
- For security-sensitive changes, include risk notes and rollback approach.

## 8) Planning Artifacts to Respect
- PRD v3: `_bmad-output/planning-artifacts/prd-consolidated-2026-03-05-v3.md`
- Architecture: `_bmad-output/solutioning/architecture-2026-03-05.md`
- UX Design: `_bmad-output/design/ux-design-2026-03-05.md`

If code decisions conflict with these artifacts, align code or open a decision update.




---

## Maintenance Notes
- Refresh this file whenever API contracts, auth model, deployment topology, or migration strategy changes.
- Keep this document concise and implementation-oriented for agent consumption.
