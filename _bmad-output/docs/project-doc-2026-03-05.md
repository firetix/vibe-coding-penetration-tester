---
date: 2026-03-05
project: VibePenTester
type: project-documentation
status: complete
---

# VibePenTester — Project Documentation (Current State)

## 1) Project Summary
VibePenTester is a security-focused SaaS product with a split architecture:
- **Frontend:** Next.js app (`vibehack-web`) intended for Vercel deployment
- **Backend:** Flask API (`web_api`) with scan/event routes
- **Data:** PostgreSQL + migrations
- **Realtime:** SSE stream for scan progress/events
- **Queue:** Redis-backed async processing model

Primary value flow: user signs in, starts scan, monitors live updates, reviews findings, exports reports.

## 2) Runtime Topology
### Web plane
- Next.js frontend in `vibehack-web/`
- Protected app routes via middleware auth checks
- API base URL configured through `NEXT_PUBLIC_API_BASE_URL`

### API plane
- Flask app entrypoints: `run_web.py`, `wsgi.py`
- Route modules under `web_api/routes`
- Auth middleware in `web_api/middleware/supabase_auth.py`

### Data + events
- Relational persistence via SQL migrations in `web_api/store/migrations/`
- Scan event model supports list/publish/stream behavior
- SSE endpoint powers live scan view

### External services
- Supabase Auth for identity/JWT
- Stripe (billing contract per planning artifacts)
- Railway (backend/db/worker target)
- Vercel (frontend target)

## 3) Repository Topology (Important Paths)
- `vibehack-web/` — frontend app, UX flows, API client
- `web_api/` — backend services, routes, middleware, data access
- `docs/` — API contract, deployment and local-dev notes
- `_bmad-output/` — planning + solutioning outputs (PRD/UX/Architecture)
- `.github/workflows/` — CI and scheduled E2E workflows

## 4) Local Development
### Backend
```bash
pip install -r requirements.txt
python run_web.py
# API health
curl http://localhost:5000/health
```

### Frontend
```bash
cd vibehack-web
npm install
npm run dev
npm run lint
npm run typecheck
npm test
npm run test:e2e
```

### Integration notes
- Frontend requires valid public envs for Supabase + API base URL.
- Backend auth-protected routes require valid bearer tokens.
- SSE testing should cover reconnect + resume behavior.

## 5) Deployment Notes
### Intended target model
- **Vercel:** frontend delivery
- **Railway:** API + workers + Postgres + Redis

### Legacy/transition artifacts present
- Root `vercel.json` and historical deployment docs indicate prior backend-on-Vercel patterns.
- Current planning artifacts lock split-plane deployment; implementation should align to that direction.

### Environment configuration
Frontend critical:
- `NEXT_PUBLIC_SUPABASE_URL`
- `NEXT_PUBLIC_SUPABASE_ANON_KEY`
- `NEXT_PUBLIC_API_BASE_URL`

Backend critical:
- `DATABASE_URL`
- JWT/Supabase verification env variables
- Queue/cache env settings (Redis)
- Billing webhook/signing envs (Stripe)

## 6) Engineering Guardrails
1. Keep authz boundaries strict and org-safe.
2. Do not break scans API contract without coordinated updates.
3. Preserve migration discipline (versioned SQL, forward-safe changes).
4. Maintain SSE UX reliability (state clarity, reconnect behavior).
5. Keep docs synchronized when changing environment or deployment assumptions.

## 7) Key Documentation References
- `README.md`
- `docs/local-dev.md`
- `docs/api-contract.md`
- `docs/web_api_refactoring.md`
- `_bmad-output/planning-artifacts/prd-consolidated-2026-03-05-v3.md`
- `_bmad-output/solutioning/architecture-2026-03-05.md`
- `_bmad-output/design/ux-design-2026-03-05.md`
- `project-context.md`

## 8) Known Open Areas
- Final entitlement schema + quota semantics in code vs PRD v3 contract
- Worker orchestration hardening and escalation criteria for Temporal
- Consolidation of legacy deployment docs to avoid frontend/backend hosting ambiguity
