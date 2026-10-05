# Alpha validation record

## Current alpha: 2.0.0a2

Observed on 2026-10-05 UTC, 2026-10-04 Pacific.

| Check | Observed result | Limit |
| --- | --- | --- |
| Runner suite | 130 passed locally | Includes prior regression tests and new Supabase controls |
| Real local Supabase | Eight expected outcomes verified | Auth, PostgREST, and PostgreSQL 17; disposable data |
| Public key compatibility | Legacy anon and publishable keys passed | Local Supabase CLI 2.95.4 |
| Leak cases | Disabled RLS and an extra permissive policy failed with exit 1 | Configured private row and canary |
| Invalid controls | Blocked owner, invalid session, and swapped sessions returned exit 2 | No passing result with incomplete evidence |
| Restored policy | Same contract passed with exit 0 | Reads only |
| FastAPI regression | Broken failed; fixed passed | Existing generic contract remains supported |
| Packaging | Wheel and source archive built; clean wheel executed outside checkout | No registry publication |
| Product page | Desktop and mobile inspected; tabs, copy, overflow, and script checks passed | Replays saved real Supabase results |
| Static checks | Ruff, workflow syntax, changed Markdown links, and whitespace checks passed | See pull request for remote results |

The Supabase workflow is now included in pull request checks.
The [demand review](../research/developer-demand.md) records developer requests and competing tools.
Those sources do not establish retained users or willingness to pay.

## Previous alpha: 2.0.0a1

Date: 2026-10-04 Pacific time, 2026-10-05 UTC.
Package: `vibe-pentest` version `2.0.0a1`.

| Check | Observed result | Limit |
| --- | --- | --- |
| Runner suite, Python 3.11 | 95 passed | Local macOS execution |
| Runner suite, Python 3.14 | 95 passed | Local macOS execution |
| Existing unit and API suites | 163 passed | No live model or external scan |
| FastAPI fixture | Broken version failed; fixed version passed | Synthetic local data |
| MCP client | Initialize, list, run, structured result passed | Real standard-input/output connection; graphical clients not tested |
| Concurrent MCP calls | Busy result returned; describe remained available | One running suite at a time |
| Credentials | Missing, duplicate, swapped, wrong-tenant, and expired values rejected or inconclusive | Provider-specific token renewal is external |
| Mid-run token expiry | Authenticated `401` produced error | Added after independent review |
| Denial bodies | HTML, duplicate keys, malformed JSON, and nonfinite numbers produced errors | Added after independent review; empty denial bodies remain supported |
| Transport | Redirect, proxy, compression, and body-limit tests passed | No hosted SSRF protection claim |
| Reports | Secret, body, target, and canary exclusion passed | Actor and case labels are operator-controlled |
| Packaging | Wheel and source archive built | Registry publication not performed |
| Clean installation | Dependency-free wheel ran outside the checkout | macOS with Python 3.11 |
| Landing page | Desktop and mobile inspected; tabs and copy fallback worked | Local file preview; no hosting deployment |
| Static checks | Ruff, actionlint, documentation links, and whitespace checks passed | Remote workflow execution remains separate |

The first remote run passed Linux, Windows, FastAPI, and existing local application tests.
The macOS demo repeatedly exceeded its fifteen-second test deadline.
The fixture now avoids reverse hostname resolution when binding its numeric loopback address.
Its regression test rejects hostname lookups; the original test deadline remains unchanged.
The legacy Vercel preview returned HTTP 500 after deployment.
The new package metadata changed dependency selection; an explicit install script preserves legacy web dependencies.
The updated web installer and deployed preview tests pass remotely.
See [pull request checks](https://github.com/firetix/vibe-coding-penetration-tester/pull/29/checks) for current remote results.

## Reproduce

```sh
uv sync --extra dev
uv run ruff check vibe_pentest guard_tests examples/fastapi examples/supabase scripts/refresh_landing_demo.py
uv run ruff format --check vibe_pentest guard_tests examples/fastapi examples/supabase scripts/refresh_landing_demo.py
uv run pytest guard_tests -q -o addopts='' -o log_cli=false
uv run --isolated --python 3.11 --extra dev pytest guard_tests -q -o addopts='' -o log_cli=false
uv run --with fastapi --with uvicorn python examples/fastapi/verify.py
uv build
actionlint .github/workflows/guard.yml .github/workflows/guard-release.yml
```

Follow the [Supabase example](../../examples/supabase/README.md) to start and verify its real local services.
Refresh the landing evidence after that verifier passes:

```sh
uv run python scripts/refresh_landing_demo.py --supabase-report .cache/supabase-verification.json
```

The legacy tests used a separate Python 3.11 environment with `requirements.txt` installed through uv.
Command: `python -m pytest tests/unit tests/e2e/api -q -o addopts='' -o log_cli=false`.

## Unmeasured product outcomes

No customer onboarding, retention, revenue, comparative accuracy, or growth result has been observed for this alpha.
The [business gates](business.md) and [distribution experiments](distribution.md) define the next evidence to collect.
