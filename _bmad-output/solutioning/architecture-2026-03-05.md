---
date: 2026-03-05
product: VibePenTester
document: architecture
source_prd: _bmad-output/planning-artifacts/prd-consolidated-2026-03-05-v3.md
status: draft-final
---

# VibePenTester Architecture (MVP)

## 1. Purpose
Define implementation architecture for MVP consistent with locked product decisions:
- Frontend on Vercel
- API/workers on Railway
- Supabase Auth
- Railway Postgres
- SSE for realtime
- Redis queue now, Temporal later

## 2. System Context
### Actors
- End users (developers, startup teams)
- API consumers (automation/CI)
- Internal worker processes
- Billing provider (Stripe)
- Auth provider (Supabase)

### High-level components
1. **Web App (Vercel)** — Next.js UI, auth session handling, scan UX
2. **API Service (Railway)** — Flask modular API, authorization, scan lifecycle, billing hooks
3. **Worker Service (Railway)** — async scan execution against queue jobs
4. **Postgres (Railway)** — durable source of truth
5. **Redis (Railway)** — queue broker + short-lived stream support as needed
6. **Object Storage (S3-compatible)** — report artifact storage
7. **Supabase** — identity and JWT issuance/verification keys
8. **Stripe** — checkout + webhook events

## 3. Deployment Topology
### Plane split
- **Vercel:**
  - `vibehack-web` Next.js frontend
  - Public routes (`/`, `/login`, `/signup`, `/app/*`)
- **Railway:**
  - API container (`run_web.py` / `wsgi.py`)
  - Worker container(s)
  - Postgres + Redis managed services

### Network & trust boundaries
- Browser ↔ Vercel via HTTPS
- Vercel frontend ↔ Railway API via HTTPS (`NEXT_PUBLIC_API_BASE_URL`)
- API ↔ Postgres/Redis over private Railway networking where possible
- API verifies Supabase JWTs against JWKS/secret configuration
- Stripe webhook endpoint accepts only signed requests in non-test mode

---

## 4. Architecture Decision Records (ADRs)

## ADR-001 — Vercel ↔ Railway split
**Status:** Accepted (MVP)

**Decision**
- Deploy UI to Vercel for frontend velocity + edge/static benefits.
- Deploy API and workers to Railway for long-running processes and simpler background orchestration.

**Rationale**
- Frontend and backend have different scaling/runtime profiles.
- Vercel is optimized for Next.js delivery; Railway is better for persistent Python workers.
- Keeps developer ergonomics high while avoiding serverless limits for scanner execution.

**Consequences**
- Must maintain strict CORS and redirect origin policies.
- Requires coordinated CI/CD across two deploy planes.
- Requires centralized observability across Vercel + Railway logs.

## ADR-002 — Supabase Auth + JWT verification
**Status:** Accepted (MVP)

**Decision**
- Supabase is identity provider.
- Backend protected routes require Bearer JWT; verification via Supabase JWKS with optional local HS256 fallback for development.

**Rationale**
- Fast path to secure identity/session primitives.
- Existing backend middleware already supports this model.

**Consequences**
- Token audience/expiry handling must be consistent across frontend and API.
- SSE transport supports query token for EventSource browser constraints.
- Auth outage modes must fail safely (reject protected access).

## ADR-003 — Postgres schema + migrations
**Status:** Accepted (MVP)

**Decision**
- Railway Postgres is source of truth.
- Migration runner (`web_api/store/migrator.py`) applies ordered SQL migrations at startup.
- Baseline tables include: `users`, `scans`, `scan_events`, `findings` with indexed access patterns.

**Rationale**
- Durable relational model with predictable query semantics and transactional behavior.
- Supports tenant isolation and auditability growth path.

**Consequences**
- Migration discipline required (forward-only, tested in staging first).
- Schema extensions for billing/audit should remain versioned and additive.
- Restore drills must be part of operational readiness.

## ADR-004 — SSE streaming for live scan view
**Status:** Accepted (MVP)

**Decision**
- Use SSE endpoint (`/api/scans/{id}/events/stream`) for one-way live updates.
- Support reconnect and resume via `Last-Event-ID` / `last_event_id`.
- Maintain polling fallback for constrained clients.

**Rationale**
- Lower complexity than websocket infrastructure for current one-way needs.
- Existing endpoint contract and frontend support already present.

**Consequences**
- Event taxonomy and ordering guarantees must remain stable.
- Keep heartbeat frames to sustain long-lived connections.
- Need backpressure and max-events-per-poll guardrails.

## ADR-005 — Queue/worker plan: Redis now, Temporal later
**Status:** Accepted (MVP with trigger gate)

**Decision**
- Run scan jobs through Redis-backed queue and worker services.
- Defer Temporal adoption until objective complexity/operability thresholds are crossed.

**Temporal trigger thresholds**
1. >= 15% of jobs need multi-step compensation logic,
2. >= 10% of jobs exceed 15 minutes with manual intervention,
3. recurrent orchestration-state incidents over 2 consecutive releases.

**Rationale**
- Current workflow complexity does not justify orchestration overhead now.
- Preserves delivery speed for MVP.

**Consequences**
- Job idempotency, retries, and DLQ policies become non-negotiable in MVP.
- Migration memo required before any Temporal rollout.

---

## 5. Data & API Contract
### Core API (scans v2)
- `POST /api/scans`
- `GET /api/scans`
- `GET /api/scans/{id}`
- `GET /api/scans/{id}/events`
- `POST /api/scans/{id}/events`
- `GET /api/scans/{id}/events/stream`

Reference: `docs/api-contract.md`

### Data model baseline
- `users` mapped by `supabase_user_id`
- `scans` lifecycle records
- `scan_events` ordered event stream
- `findings` vulnerability records

Planned near-term expansion:
- subscriptions/entitlements/audit-log tables normalized under same DB

## 6. Security Architecture (MVP minimum)
### Least privilege
- Separate service credentials for API and workers
- DB roles scoped to required tables/operations
- Avoid shared admin credentials for runtime services

### Secrets management
- All production secrets stored in platform-managed secret stores (Vercel + Railway)
- No secrets in repo or client bundle
- Rotate critical secrets on <= 90-day cadence

### Auditability
Capture at minimum:
- auth failures/successes (security-relevant)
- entitlement checks and denials
- billing webhook processing outcomes
- report export actions
- privileged/admin operations

Retention target: >= 180 days searchable by actor/action/resource/time.

### Abuse controls
- Validate scan target authorization posture
- Enforce protections against private-network and loopback abuse
- Apply rate limits on scan-creation and auth-sensitive endpoints

## 7. Observability & Reliability
- Structured logs across API and worker services
- Correlation id propagated from request to worker events
- Metrics: queue depth, job failure rate, SSE disconnect/reconnect rate, webhook latency
- Alerts for: auth failures spike, webhook failures, queue backlog saturation, DB connectivity incidents

## 8. Delivery Notes
### Implementation sequence
1. Harden deployment split and env contract
2. Finalize auth/JWT + org-scoped authorization checks
3. Stabilize scan/job lifecycle + SSE behavior
4. Lock billing/entitlement contract and audit flows
5. Run staging failure drills (webhook failure, worker crash, DB failover recovery)

### Open architecture questions
1. Object storage provider and retention/cost policy (owner: engineering)
2. Railway region strategy for latency/data residency (owner: engineering)
3. Exact entitlement schema evolution path (owner: PM + engineering)



---

## Workflow Completion Marker
- create-architecture workflow completed (8/8).
- Finalized for implementation handoff.
