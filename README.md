# VibePenTester

**Keep Alice's data out of Bob's response.**

Repeatable authorization tests for the apps you build with AI.
Use your existing coding agent to prepare a test, fix the route, and verify the result.
Run the same contract in your terminal and continuous integration (CI).

**Version 2 alpha. Apache-2.0. No model key, account, Docker, or browser download for the new runner.**

[Try the demo](#try-it) · [Use your agent](docs/agent-integration.md) · [FastAPI example](examples/fastapi/README.md) · [Contract reference](docs/authorization-contract.md)

## The check that matters

Your invoice endpoint works for Alice. Does it also work for Bob from another tenant?

```text
                         Broken app       Fixed app
Alice reads her invoice  PASS · 200        PASS · 200
Bob reads Alice's data   FAIL · 200        PASS · 403
Anonymous reads it       FAIL · 200        PASS · 401

Same contract. The private fixture canary proves the leak.
```

The runner first proves each user's identity and tenant.
Then it confirms the owner can read the expected private record.
Expired tokens, missing fixtures, and login pages produce an inconclusive result.
They cannot produce a passing run.

## Try it

Requires Python 3.11 or later and [uv](https://docs.astral.sh/uv/getting-started/installation/).
Run from a checkout containing this alpha:

```sh
uv run vpt demo
```

The demo starts a disposable application on loopback, checks its broken and fixed versions, then stops it.
It uses synthetic data and never contacts an external target.
The fixture binds directly to its numeric address without a hostname lookup.
The source build works now. Registry publication is a separate release step.

## Test your app

```sh
uv run vpt init --base-url http://127.0.0.1:8000
```

Edit `vpt-contract.json` with your identity route, two tenant fixtures, and a private record.
Seed a unique canary in a private field of that record.
Use your test login helper to supply `VPT_ALICE_TOKEN` and `VPT_BOB_TOKEN` through environment variables.

```sh
uv run vpt validate vpt-contract.json
uv run vpt check vpt-contract.json --allow-origin http://127.0.0.1:8000
```

Start with the [complete FastAPI example](examples/fastapi/README.md) if you need a working fixture.

| Outcome | Meaning | Exit code |
| --- | --- | --- |
| Pass | Every configured control and denial passed | `0` |
| Fail | A forbidden actor received the private fixture canary | `1` |
| Inconclusive | Input, identity, fixture, or response evidence is incomplete | `2` |

Both `1` and `2` should fail CI. Errors take precedence when a run also contains violations.

## Bring your coding agent

Use the [portable skill](skills/vpt-authz/SKILL.md) with Codex, Claude Code, or another compatible agent.
It guides fixture setup, contract creation, server-side fixes, and repeat checks.

Prefer tools? Install the optional Model Context Protocol (MCP) adapter:

```sh
uv run --extra mcp vpt serve \
  --config vpt-contract.json \
  --allow-origin http://127.0.0.1:8000
```

The server exposes `describe_contract` and `run_checks`.
Both tools use the contract fixed at startup.
[Client configuration and credential setup →](docs/agent-integration.md)

## Keep the evidence

```sh
uv run vpt check vpt-contract.json \
  --allow-origin http://127.0.0.1:8000 \
  --format json --output authorization.json
```

Use `--format markdown` for review or `--format sarif` for compatible code-scanning tools.
Reports contain check outcomes and HTTP status codes.
They omit tokens, response bodies, target URLs, identity values, and private canaries.
[Add checks to CI →](docs/ci.md)

## What this release covers

Cross-tenant `GET` requests on JSON APIs using bearer tokens.
Two to eight users. One to fifty configured records. Anonymous access checks.
Private canary detection also catches leaks inside denial responses.

It does not test writes, browser sessions, same-tenant roles, or every possible data leak.
A passing contract does not certify an application as secure.
Use broader testing tools for discovery and manual testing for complex business rules.
Read the [evidence boundaries](docs/authorization-contract.md#boundaries).

## The original scanner

The browser-based scanner and web application remain available.
Use their existing entrypoints: `main.py`, `run_web.py`, and `web_ui.py`.
Their model and browser dependencies are separate from the new runner.
[Legacy setup and usage →](docs/legacy-scanner.md)

## Build with us

We want useful contracts for real applications, with a broken example and a verified fix.
Start with a [contribution](CONTRIBUTING.md) or a report about setup friction.
The local runner, contracts, agent skill, and report formats remain open source.

- [Why this direction](docs/product/direction.md)
- [Competition and evidence](docs/research/competition.md)
- [Product and business proposal](docs/product/business.md)
- [Distribution experiments](docs/product/distribution.md)

Use only applications you own or have permission to test.
Licensed under [Apache-2.0](LICENSE).
