---
version: v3
product: VibePenTester
date: 2026-03-05
classification:
  domain: cybersecurity-saas
  projectType: web_app
inputDocuments:
  - _bmad-output/planning-artifacts/prd-consolidated-vibepentester-2026-02-28-v2.md
  - _bmad-output/planning-artifacts/validate-prd-2026-03-05.md
  - PRD-REDESIGN.md
  - docs/api-contract.md
status: implementation-ready
---

# VibePenTester — Consolidated PRD v3

## 1) Executive Summary
VibePenTester is an AI-assisted web application security product that helps developers and startup teams identify actionable vulnerabilities quickly, with clear evidence and remediation guidance.

**MVP objective:** reliably convert users from first scan to paid usage while maintaining technical trust (accurate findings, clear reports, stable scan execution).

### Locked decisions (MVP)
- **Pro plan:** **$19/month**
- **Auth:** **Supabase Auth**
- **Deployment:** **Frontend on Vercel**, **API + workers on Railway**
- **Database:** **Railway Postgres**
- **Realtime:** **SSE (with polling fallback)**
- **Orchestration:** **Redis queue + workers now**, evaluate Temporal later

## 2) Success Criteria
### Product outcomes
1. Activation (signup → first completed scan): **>= 60%**
2. Time to first meaningful finding: **< 5 minutes**
3. 7-day remediation action rate on findings: **>= 50%**
4. False-positive rate (sampled verification): **< 15%**

### Business outcomes
1. Visitor → free signup conversion: **>= 8% by month 3**
2. Free → paid conversion: **>= 5% by month 3**
3. MRR targets: **$3K (M3), $10K (M6), $50K (M12)**
4. Monthly paid churn: **< 5% by month 6**

### Reliability outcomes
1. Non-scan API p95 latency: **< 400ms**
2. SSE event freshness in UI: **<= 2s** (p95)
3. Service availability: **99.5% MVP**

## 3) Product Scope
### In scope (MVP)
- Marketing landing page and pricing flow
- Login/signup and protected application routes
- Scan creation, status tracking, cancellation, history
- Live scan detail stream via SSE
- Findings and downloadable reports
- Billing and entitlement enforcement for Free/Pro
- Org-safe access control and audit trail for key actions

### Out of scope (MVP)
- Enterprise SSO/SAML
- Broad plugin marketplace
- Full compliance automation packs
- On-prem enterprise deployment
- Real-time collaborative editing/control features

## 4) Users & Journeys
### Personas
- **Dev Danny (indie builder):** needs fast confidence before launch
- **Startup Sarah (engineering lead):** needs repeatable security checks and audit-ready artifacts
- **Security Sam (AppSec/ops):** needs signal-rich triage across projects

### Primary journeys
1. **First scan → first fix**: signup, run scan, review evidence, apply remediation, re-scan
2. **Release gate**: run scan before deploy, enforce severity policy, export report
3. **Operational continuity**: monitor in-progress scans, recover from failures, preserve history
4. **API-triggered scan**: trigger scan programmatically and consume structured output

## 5) Pricing & Entitlement Contract (MVP)
| Plan | Price | Limits | Included | Enforcement |
|---|---:|---|---|---|
| Free | $0 | 3 scans/month, quick mode only | Basic findings view | Block on limit reached with upgrade CTA |
| Pro | $19/mo | Unlimited quick scans, deep + solutions enabled | PDF export, extended history, priority queue tier | Entitlement checked before scan start |

### Billing behavior requirements
- Monthly usage window resets at UTC month boundary
- When entitlement is exceeded, scan creation returns paywall response (HTTP 402-style business response with checkout path)
- Successful billing webhook updates entitlement state within **<= 60s**
- Billing and entitlement events are recorded in audit logs

## 6) Functional Requirements
- **FR-01 Identity:** A visitor can create an account and authenticate using Supabase-managed credentials.
- **FR-02 Session Access:** An authenticated user can access protected `/app/*` routes and an unauthenticated user is redirected to login.
- **FR-03 Workspace Context:** A signed-in user can operate in an organization/workspace context scoped to their membership.
- **FR-04 Target Registration:** A user can create projects and register valid scan targets.
- **FR-05 Scan Creation:** A user can start a scan with selected mode and receive a persistent scan identifier.
- **FR-06 Scan Tracking:** A user can view scan status transitions and timeline events for each scan.
- **FR-07 Live Updates:** A user can receive live scan updates through SSE and resume from last received event id.
- **FR-08 Scan Control:** A user can cancel an eligible running scan.
- **FR-09 Findings:** A user can review findings with severity, evidence, and reproduction context.
- **FR-10 Reports:** A user can download generated report artifacts for completed scans.
- **FR-11 Plan Visibility:** A user can view current plan, entitlement state, and usage.
- **FR-12 Entitlement Enforcement:** The system can prevent scan start when plan limits are exceeded and provide upgrade path.
- **FR-13 API Access:** An authenticated API consumer can create/list/get scans and retrieve scan events.
- **FR-14 Tenant Isolation:** A user can only read/write data that belongs to their organization.
- **FR-15 Auditability:** The system can record security, billing, and authorization-relevant actions in a queryable audit log.

## 7) Non-Functional Requirements
- **NFR-01 API latency:** p95 for non-scan API endpoints is **< 400ms** at MVP target load.
- **NFR-02 Realtime freshness:** p95 delay from event creation to UI receipt is **<= 2s**.
- **NFR-03 Availability:** API + SSE service monthly uptime is **>= 99.5%**.
- **NFR-04 Auth correctness:** 100% of protected endpoints reject missing/invalid JWTs.
- **NFR-05 Isolation:** 0 known cross-tenant read/write violations in automated policy tests.
- **NFR-06 Durability:** scan state survives process restart with no loss of terminal state.
- **NFR-07 Secrets hygiene:** production secrets are stored in managed secret stores and rotated at least every **90 days**.
- **NFR-08 Audit retention:** audit logs are retained for **>= 180 days** and searchable by actor, action, and target.
- **NFR-09 Backups:** Postgres backup policy provides daily restore point and tested restore runbook.

## 8) Architecture Guardrails (Normative)
### ADR-A: Deployment Split
- Frontend web app is deployed on **Vercel**.
- API and workers are deployed on **Railway**.
- Data services: **Railway Postgres** + Redis queue backend.
- Cross-plane security controls include strict CORS allowlist and explicit frontend origin config.

### ADR-B: Authentication & Authorization
- Supabase JWTs are required for protected API routes.
- JWT verification supports JWKS/secret fallback for local development.
- Authorization checks are org-scoped and enforced on data access boundaries.

### ADR-C: Persistence & Migration Policy
- Postgres is source of truth for users, scans, events, findings, billing, entitlements, and audit metadata.
- Migrations are forward-only and run on startup in controlled environments.
- Schema changes must include migration tests and rollback/runbook notes.

### ADR-D: Realtime Contract (SSE)
- Canonical stream endpoint supports reconnect and `last_event_id` resume.
- Minimum event taxonomy: `connected`, `scan_event`, heartbeat comments.
- Client fallback to polling is required when SSE is unavailable.

### ADR-E: Queue/Worker Evolution
- MVP execution uses Redis-backed queue and worker services.
- Temporal is adopted only when trigger thresholds are met:
  1. >= 15% of jobs require multi-step compensation/recovery,
  2. >= 10% of jobs exceed 15 minutes with manual intervention,
  3. on-call burden shows recurring orchestration-state incidents over 2 consecutive releases.

## 9) Security & Compliance Baseline
- Least privilege for all service credentials and role-scoped database access
- Secrets never committed to repo; all production credentials sourced from managed env secrets
- Audit events required for: auth failures, entitlement checks, plan changes, report exports, admin actions
- Abuse controls enforce target authorization checks and private-network protections
- Incident runbooks exist for auth outages, queue failures, and billing webhook failures

## 10) UX Scope for MVP Pages
Required UX coverage in MVP implementation:
- Landing page (`/`)
- Login and signup (`/login`, `/signup`)
- Scans list (`/app/scans`)
- Scan detail with live stream (`/app/scans/[id]`)
- Reports and billing views in app shell

## 11) Traceability Matrix (Condensed)
| Journey | Primary FRs |
|---|---|
| First scan → first fix | FR-01, FR-04, FR-05, FR-06, FR-09, FR-10 |
| Release gate | FR-05, FR-06, FR-09, FR-10, FR-13 |
| Operational continuity | FR-06, FR-07, FR-08, FR-15 |
| API-triggered scan | FR-05, FR-06, FR-07, FR-13 |

## 12) Delivery Milestones
- **M1:** Landing + deployment baseline + observability
- **M2:** Supabase auth + app shell + workspace mapping
- **M3:** Scan UX + API contracts + persistence hardening
- **M4:** SSE + billing enforcement + reports + launch readiness

## 13) Risks & Mitigations
1. **False positives reduce trust** → evidence-first findings and confidence scoring
2. **Billing entitlement edge cases** → atomic entitlement operations + webhook replay safety
3. **Queue instability under load** → bounded retries, DLQ policy, worker observability
4. **Platform concentration risk** → backup portability and documented migration paths
5. **Auth policy regressions** → JWT contract tests + org-isolation tests in CI

## 14) Open Questions (with owner/date)
1. Final Pro retention duration and exact deep/solutions quota behavior — **Owner:** PM, **Due:** 2026-03-12
2. Initial Railway region/data residency statement for customer-facing docs — **Owner:** Engineering, **Due:** 2026-03-12
3. Public packaging exposure for Team/Business at launch (visible vs waitlist) — **Owner:** GTM, **Due:** 2026-03-15

## 15) Launch Go/No-Go Gates
- End-to-end scan lifecycle stable in staging and beta cohort
- Billing-to-entitlement propagation verified under success/failure paths
- SSE live updates stable with reconnect and resume behavior
- Security baseline checks (least privilege, secrets, audit events) completed
- Funnel instrumentation available for landing, signup, first scan, and upgrade



---

## Edit Workflow Completion Marker
- edit-prd workflow completed (4/4).
- Source guidance incorporated from `_bmad-output/planning-artifacts/validate-prd-2026-03-05.md`.
