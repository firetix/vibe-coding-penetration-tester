# Learned

## Learned Entries

### abuse-controls-client-ip-extraction-ignores-x-fo-c4324bd4
- summary: Abuse controls: client IP extraction ignores X-Forwarded-For unless VPT_TRUST_PROXY_HEADERS=1; hosted target validation resolves DNS to block hosts resolving to private/loopback IPs; paywalled attempts keep returning 402 (usage events recorded only after successful scan start).
- confidence: 0.60
- domain: environment
- first_seen: 2026-02-13
- last_seen: 2026-02-13
- evidence: "Abuse controls: client IP extraction ignores X-Forwarded-For unless VPT_TRUST_PROXY_HEADERS=1; hosted target validation resolves DNS to block hosts resolving to private/loopback IPs; paywalled attempts keep returning 402 (usage events recorded only after successful scan start)."

### added-hosted-mode-billing-paywall-with-stripe-ro-a38311db
- summary: Added hosted-mode billing/paywall with Stripe routes, SQLite BillingStore, entitlements, and deterministic E2E mode.
- confidence: 0.50
- domain: environment
- first_seen: 2026-02-13
- last_seen: 2026-02-13
- evidence: "Added hosted-mode billing/paywall with Stripe routes, SQLite BillingStore, entitlements, and deterministic E2E mode."

### branch-codex-full-e2e-billing-paywall-pr-7-all-r-c7bc7266
- summary: Branch codex/full-e2e-billing-paywall, PR #7; all review threads addressed; latest commit b2cf029.
- confidence: 0.50
- domain: environment
- first_seen: 2026-02-13
- last_seen: 2026-02-13
- evidence: "Branch codex/full-e2e-billing-paywall, PR #7; all review threads addressed; latest commit b2cf029."

### developer-workflow-note-on-this-machine-use-pyth-b238af04
- summary: Developer workflow note: on this machine use python3 -m pytest (pytest/python not on PATH).
- confidence: 0.60
- domain: environment
- first_seen: 2026-02-13
- last_seen: 2026-02-13
- evidence: "Developer workflow note: on this machine use python3 -m pytest (pytest/python not on PATH)."

### entitlement-consumption-is-now-atomic-billingsto-b1080a51
- summary: Entitlement consumption is now atomic: BillingStore.try_consume_entitlement_for_scan performs decision+decrement under lock/conditional SQL; refund_consumption restores entitlement on scan startup failure.
- confidence: 0.50
- domain: environment
- first_seen: 2026-02-13
- last_seen: 2026-02-13
- evidence: "Entitlement consumption is now atomic: BillingStore.try_consume_entitlement_for_scan performs decision+decrement under lock/conditional SQL; refund_consumption restores entitlement on scan startup failure."

### frontend-fix-prevent-requestsubmit-microtask-loo-801c69ad
- summary: Frontend fix: prevent requestSubmit microtask loop when session init returns success without session_id by generating fallback session id and resetting cached init promise on failure.
- confidence: 0.50
- domain: workflow
- first_seen: 2026-02-13
- last_seen: 2026-02-13
- evidence: "Frontend fix: prevent requestSubmit microtask loop when session init returns success without session_id by generating fallback session id and resetting cached init promise on failure."

### key-env-vars-vpt-e2e-mode-1-for-deterministic-sc-abb9afc5
- summary: Key env vars: VPT_E2E_MODE=1 for deterministic scans in tests; VPT_HOSTED_MODE=1 to enable hosted safeguards; VPT_ALLOW_UNVERIFIED_WEBHOOKS=1 only for test webhook bypass; VPT_ENABLE_MOCK_CHECKOUT=0 disables mock checkout endpoints/URLs in hosted mode.
- confidence: 0.55
- domain: environment
- first_seen: 2026-02-13
- last_seen: 2026-02-13
- evidence: "Key env vars: VPT_E2E_MODE=1 for deterministic scans in tests; VPT_HOSTED_MODE=1 to enable hosted safeguards; VPT_ALLOW_UNVERIFIED_WEBHOOKS=1 only for test webhook bypass; VPT_ENABLE_MOCK_CHECKOUT=0 disables mock checkout endpoints/URLs in hosted mode."

### security-hardening-web-api-scan-paywall-now-retu-2aca8697
- summary: Security hardening: web_api scan paywall now returns /billing/checkout redirect (not /mock-checkout) to avoid free bypass; mock-checkout is gated/disabled by default in hosted mode; webhook verification rejects unsigned payloads unless explicit test mode.
- confidence: 0.60
- domain: environment
- first_seen: 2026-02-13
- last_seen: 2026-02-13
- evidence: "Security hardening: web_api scan paywall now returns /billing/checkout redirect (not /mock-checkout) to avoid free bypass; mock-checkout is gated/disabled by default in hosted mode; webhook verification rejects unsigned payloads unless explicit test mode."

### vibe-pen-tester-firetix-vibe-coding-penetration--732bf80e
- summary: Vibe Pen Tester (firetix/vibe-coding-penetration-tester) session learnings: Implemented and hardened full E2E coverage for Flask web_api + legacy web_ui compat + frontend smoke.
- confidence: 0.50
- domain: environment
- first_seen: 2026-02-13
- last_seen: 2026-02-13
- evidence: "Vibe Pen Tester (firetix/vibe-coding-penetration-tester) session learnings: Implemented and hardened full E2E coverage for Flask web_api + legacy web_ui compat + frontend smoke."

## Needs Review
