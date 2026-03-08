# HTTP Endpoints

This repository exposes **two** Flask applications:

- `web_api.create_app()` (production app factory used by `run_web.py`, `wsgi.py`, Vercel)
- `web_ui.app` (legacy monolith used by `python web_ui.py`)

The route inventories below can be regenerated with:

```bash
python3 scripts/list_routes.py --app both --format markdown
python3 scripts/update_route_snapshots.py
```

## Route Inventory (Auto-Generated)

## `web_api` routes (29)

| Methods | Path | Endpoint |
|---|---|---|
| `GET` | `/` | `static.index` |
| `POST` | `/api/activity` | `activity.get_activities` |
| `POST` | `/api/billing/checkout` | `billing.create_checkout` |
| `POST` | `/api/billing/webhook` | `billing.billing_webhook` |
| `GET` | `/api/entitlements` | `billing.get_entitlements` |
| `GET` | `/api/logs` | `status.get_logs` |
| `GET` | `/api/report/<report_id>` | `report.get_report` |
| `GET` | `/api/reports` | `report.get_reports` |
| `POST` | `/api/scan/cancel` | `scan.cancel_scan` |
| `POST` | `/api/scan/list` | `scan.list_scans` |
| `POST` | `/api/scan/start` | `scan.start_scan` |
| `POST` | `/api/scan/status` | `scan.get_scan_status` |
| `POST` | `/api/session/check` | `session.check_session` |
| `POST` | `/api/session/init` | `session.init_session` |
| `POST` | `/api/session/reset` | `session.reset_session` |
| `GET, POST` | `/api/session/state` | `session.api_state` |
| `GET, POST` | `/api/state` | `api_state` |
| `POST` | `/api/v1/scans` | `v1_scans.create_scan` |
| `GET` | `/api/v1/scans/<scan_id>` | `v1_scans.get_scan` |
| `GET` | `/api/v1/scans/<scan_id>/report` | `v1_scans.get_scan_report` |
| `GET` | `/billing/checkout` | `browser_checkout` |
| `GET` | `/favicon.ico` | `static.favicon` |
| `GET` | `/mock-checkout/<checkout_session_id>` | `mock_checkout` |
| `GET` | `/report` | `get_report_compat` |
| `GET` | `/reports/<path:filename>` | `download_report` |
| `POST` | `/reset` | `reset_session` |
| `POST` | `/scan` | `start_scan_compat` |
| `GET` | `/static/<path:filename>` | `static.serve_static` |
| `GET` | `/status` | `status.status_check` |

## `web_ui` routes (24)

| Methods | Path | Endpoint |
|---|---|---|
| `GET` | `/` | `index` |
| `POST` | `/api/activity` | `get_activities` |
| `POST` | `/api/billing/checkout` | `billing_checkout` |
| `POST` | `/api/billing/webhook` | `billing_webhook` |
| `GET` | `/api/entitlements` | `get_entitlements` |
| `GET` | `/api/logs` | `get_logs` |
| `GET` | `/api/report/<report_id>` | `get_report` |
| `GET` | `/api/reports` | `get_reports` |
| `POST` | `/api/scan/cancel` | `cancel_scan` |
| `POST` | `/api/scan/list` | `list_scans` |
| `POST` | `/api/scan/start` | `start_scan` |
| `POST` | `/api/scan/status` | `get_scan_status` |
| `POST` | `/api/session/check` | `check_session` |
| `POST` | `/api/session/init` | `init_session` |
| `GET, POST` | `/api/state` | `api_state` |
| `GET` | `/billing/checkout` | `browser_checkout` |
| `GET` | `/favicon.ico` | `favicon` |
| `GET` | `/mock-checkout/<checkout_session_id>` | `mock_checkout` |
| `GET` | `/report` | `get_report_compat` |
| `GET` | `/reports/<path:filename>` | `download_report` |
| `POST` | `/reset` | `reset_session` |
| `POST` | `/scan` | `start_scan_compat` |
| `GET` | `/static/<path:filename>` | `serve_static` |
| `GET` | `/status` | `status_check` |

## Behavioral Notes

### Session vs Account Identity
- `session_id` is used to track scan progress and activity logs (stored by `SessionManager`).
- Hosted-mode billing uses a separate cookie-backed `account_id`:
  - `web_api` uses `g.account_id` (cookie `vpt_account_id`)
  - `web_ui` uses `request._vpt_account_id` (cookie `vpt_account_id`)
- Supabase auth integration (optional):
  - If `SUPABASE_JWT_SECRET` is set and requests include `Authorization: Bearer <access_token>`,
    then `account_id` is derived from the JWT `sub` claim (no account cookie is set).

### Hosted Mode
Hosted mode is enabled with `VPT_HOSTED_MODE=1`.

In hosted mode, starting scans via:
- `POST /api/scan/start`
- `POST /scan` (compat)

enforces:
- `authorization_confirmed` truthy
- Target policy (blocks localhost/private IPs via `utils.entitlements.is_valid_target_for_hosted`)
- Rate limiting (`utils.entitlements.check_scan_rate_limits`)
- Paywall/entitlements (`BillingStore.try_consume_entitlement_for_scan`)

### Authenticated v1 SaaS API
- `POST /api/v1/scans`
- `GET /api/v1/scans/<scan_id>`
- `GET /api/v1/scans/<scan_id>/report`

These endpoints require Supabase Bearer auth and do **not** fall back to cookie identity:
- Requests must include `Authorization: Bearer <access_token>`.
- Access is scoped by org membership (scan ownership enforced via `users/orgs/memberships/saas_scans`).

### Report Availability
- The UI should use `/status?session_id=...` and check `report_available` before calling `/report?session_id=...`.
- `GET /api/reports` and `GET /api/report/<report_id>` access reports by report directory ID.
- Optional Supabase Postgres persistence:
  - If `VPT_APP_DB_URL` or `SUPABASE_DATABASE_URL` is set to a Postgres URL, scan state, activity logs, and reports are persisted in Postgres.
  - `/reports/<report_id>/report.json` and `/reports/<report_id>/report.md` will serve from Postgres if the local file is missing.

## Example Requests (Local)

Assume `BASE_URL=http://127.0.0.1:5050`.

### Init Session
```bash
curl -sS -X POST "$BASE_URL/api/session/init" \\
  -H 'Content-Type: application/json' \\
  -d '{"client_id":"docs"}'
```

### Start Scan (Hosted Mode)
```bash
curl -sS -X POST "$BASE_URL/api/scan/start" \\
  -H 'Content-Type: application/json' \\
  -d '{"session_id":"<session_id>","url":"https://example.com","scan_mode":"quick","authorization_confirmed":true}'
```

### Poll Status
```bash
curl -sS "$BASE_URL/status?session_id=<session_id>"
```

### Fetch Legacy Report
```bash
curl -sS "$BASE_URL/report?session_id=<session_id>"
```

### List Reports and Fetch by ID
```bash
curl -sS "$BASE_URL/api/reports"
curl -sS "$BASE_URL/api/report/<report_id>"
```

### Billing Checkout (Mock Checkout Available in `VPT_E2E_MODE=1`)
```bash
curl -sS -X POST "$BASE_URL/api/billing/checkout" \\
  -H 'Content-Type: application/json' \\
  -d '{"scan_mode":"deep"}'
```

### Create v1 Scan (Auth Required)
```bash
curl -sS -X POST "$BASE_URL/api/v1/scans" \\
  -H "Authorization: Bearer $SUPABASE_ACCESS_TOKEN" \\
  -H 'Content-Type: application/json' \\
  -d '{"url":"https://example.com","scan_mode":"quick","authorization_confirmed":true}'
```

### Poll v1 Scan Status (Auth Required)
```bash
curl -sS "$BASE_URL/api/v1/scans/<scan_id>" \\
  -H "Authorization: Bearer $SUPABASE_ACCESS_TOKEN"
```

### Fetch v1 Report (Auth Required)
```bash
curl -sS "$BASE_URL/api/v1/scans/<scan_id>/report" \\
  -H "Authorization: Bearer $SUPABASE_ACCESS_TOKEN"
```
