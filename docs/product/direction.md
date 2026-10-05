# VibePenTester 2: authorization checks for coding agents

Status: alpha implemented; independent review findings addressed. Decision date: 2026-10-04.

## The problem

An engineer changes an API route with an AI coding agent.
The route still works for its owner.
Another tenant can now read the same record.
The engineer needs a repeatable test that proves both outcomes.

The current project runs a separate model and browser orchestration system.
Its latest source already includes evidence probes for a specific training application.
Reuse that evidence principle. Keep the existing scanner available.

## The decision

Build a small, local authorization regression runner.
Use the engineer's existing agent to inspect code, prepare fixtures, and fix failures.
Provide skills for that workflow.
Provide Model Context Protocol (MCP) access to the same runner.
The protocol is an interface. Repeatable authorization evidence is the product.

Initial users: engineers building JSON APIs with bearer authentication and multiple tenants.
Initial task: prove that Alice's private record stays private after a code change.

## Alternatives

| Approach | Strength | Main cost | Decision |
| --- | --- | --- | --- |
| Another autonomous pentester | Broad discovery | Competes directly with established agent systems | Keep legacy mode; do not lead with it |
| Skills or tool wrappers alone | Easy installation | Easy to copy; weak evidence contract | Include as interfaces |
| Explicit authorization contracts | Fast reruns; app-specific evidence | Requires fixtures and known identities | Build first |

This is a product hypothesis, not proven demand or a unique technical invention.
Normal integration tests can do this work. Our proposed value is faster setup across agents and frameworks.

## Scope

Ship a dependency-free Python command-line interface (CLI), a local demo, reports, and a versioned JSON contract.
Ship optional MCP support using the official Python SDK.
Ship a portable skill, continuous integration (CI) example, package build, and release workflow.
Ship a clear README, public product strategy, launch drafts, and measurable distribution experiments.
Keep the Apache-2.0 license.

Do not promise broad vulnerability discovery, compliance certification, or complete authorization coverage.
Do not introduce a hosted scanner or charge customers in this release.
Do not change legacy scan routes or existing billing behavior.

## Architecture review

    coding agent + skill ---- CLI ---+
                                   +-- contract validation -- fixed-origin HTTP GET -- evidence checks
    MCP client --- stdio server ---+                                         |
                                                                            +-- JSON / Markdown / SARIF
    legacy browser scanner ---------------------------------------- remains independent

The contract fixes one origin and limits requests to explicit paths.
The launch command separately pins that origin with `--allow-origin`.
The MCP server loads its contract at startup. Tools cannot supply URLs, files, tokens, or shell commands.
Credentials come only from dedicated `VPT_<ACTOR>_TOKEN` variables.
Reports omit credentials, bodies, canaries, identity values, and URLs.
The runner validates distinct subject and tenant identifiers before testing records.
Each record requires an owner control with exact record and private-canary markers.
Other authenticated actors and an anonymous request must receive configured denial statuses.
A returned private canary proves a violation. Unexpected responses produce an inconclusive result.
A record identifier without private evidence remains inconclusive.

## Error and rescue map

| Path | Failure | Result |
| --- | --- | --- |
| Contract loading | Invalid JSON, unknown keys, empty cases | Actionable validation error; exit 2 |
| Credentials | Missing, equal, malformed tokens | Stop before networking; exit 2 |
| Identity controls | Expired token or wrong identity | Inconclusive; no record checks; exit 2 |
| Owner control | Missing fixture, wrong object, HTML login | Inconclusive; exit 2 |
| HTTP | Timeout, redirect, connection failure, oversized body | Inconclusive; exit 2 |
| Access check | Forbidden actor receives private canary | Confirmed contract violation; exit 1 |
| Access check | Configured denial with empty or valid JSON body | Pass for this exact request |
| Access check | Malformed JSON or duplicate response fields | Inconclusive; exit 2 |
| Report write | Invalid output destination | Clear failure; exit 2 |

A run with any inconclusive check never returns success.
A report can contain both violations and errors; errors take exit-code precedence.

## Security review

Threat: tokens leave through redirects or environment proxies. Block redirects and disable proxy discovery.
Threat: configuration changes scope. Validate all paths before requests and freeze the MCP contract at startup.
Threat: HTTP exposes tokens. Require HTTPS except explicit loopback HTTP.
Threat: reports reveal data. Emit predicates and status codes, never response bodies or headers.
Threat: invalid Bob token creates false reassurance. Validate Bob's identity before resource tests.
Threat: server returns an error with private data. Check private canaries before accepting denial statuses.
Threat: ambiguous denial bodies hide evidence. Reject malformed JSON, duplicate keys, and nonfinite numbers.
Threat: localhost fixture becomes a server. Bind demo only to loopback and terminate it after the run.
The local runner trusts operator-supplied origins and contracts. It is not a hosted SSRF boundary.
GET routes can have side effects. Operators must choose safe test routes and disposable fixtures.

## Data and edge cases

    file -> size/JSON/schema -> credentials -> identity controls -> owner control -> denied actors -> report
      |            |                |                |                 |               |
    missing      unknown          missing          invalid           no object       ambiguous
      +------------+----------------+----------------+-----------------+---------------+--> exit 2

Reject empty suites, duplicate identifiers, unknown owners, duplicate identities, and invalid JSON pointers.
Reject path escapes, absolute URLs, fragments, credential-bearing URLs, and unsafe schemes.
Reject redirects without following them. Keep cookies out of the transport.
Bound cases, response bytes, and per-request time.

## Code quality review

Place the new runner in its own installable package.
Avoid imports from the legacy model, browser, or billing layers.
Keep contract parsing, transport, execution, reporting, CLI, and MCP adapters separate.
Use standard Python libraries in the base package.
Use the official MCP SDK only in the optional extra.

## Test review

    parser -------- unit: unknown keys, identity confusion, path escape, empty suite
    transport ----- local HTTP: redirects, proxy bypass, limits, errors
    controls ------ local HTTP: expired/wrong identity, missing object, HTML login
    access -------- local HTTP: fixed app, broken app, denial with leaked object
    reports ------- secret/body absence; JSON, Markdown, SARIF structure
    CLI ----------- subprocess: demo, config, exit codes, package installation
    MCP ----------- real stdio client: initialize, list tools, run fixed suite
    packaging ----- wheel and source distribution; clean install and demo

Fixtures use loopback only. No external targets or model credentials are required.
Legacy tests run separately to detect accidental import or packaging effects.

## Performance review

Run sequentially. A small contract does not need a scheduler or database.
Limit two to eight actors and fifty cases.
Bound every response and timeout. Display request counts for troubleshooting.
A larger product would need cancellation, concurrency budgets, and credential refresh.
Defer those until usage requires them.

## Observability review

Report identity control outcomes, case outcomes, HTTP status, check reasons, and coverage totals.
Keep stable case IDs for CI comparison.
Treat errors as incomplete coverage. Never label a passing suite as a secure application.
No analytics or network telemetry in the runner.

## Rollout review

The package adds a new command without changing the legacy web app.
Build release artifacts in CI. Install from a local checkout before publication.
Pin public installation examples to a released tag after the release exists.
Rollback by restoring the previous package version. Existing web deployments need no migration.

## Long-term review

First prove repeated use by five teams across two consecutive weeks.
Next add role matrices, framework examples, and better fixture setup based on observed friction.
Then consider a paid coordination layer for teams running checks in their own CI.
See [business hypotheses](business.md) and the [six-week distribution plan](distribution.md).
Keep local execution, portable contracts, skills, and report formats open.
100,000 stars is a long-term distribution ambition, not a forecast or acceptance gate for this release.

## Experience review

    README -> one-command demo -> broken and fixed evidence -> own contract -> agent integration -> CI

The demo needs no account, model key, Docker daemon, or browser download.
Documentation starts with the exact behavior tested.
Marketing must separate implemented features from proposed paid features.

## GSTACK REVIEW REPORT

Applied gstack 1.67.2.0 CEO and engineering review frameworks.
The user delegated product and implementation choices for this work.
Routine scope choices use that authorization instead of interactive preference gates.

| Review | Runs | Status | Findings |
| --- | --- | --- | --- |
| CEO: eleven sections | 1 | Reviewed | Narrow evidence workflow; compete on setup and repeated use |
| Engineering: architecture, quality, tests, performance | 1 | Reviewed | Separate base package; strict controls; bounded transport |
| Independent specification review | 1 | Findings addressed; regression checks pass | Origin pinning, private canaries, tenant controls, token expiry, malformed denial bodies |

VERDICT: Local implementation and package checks pass. All reported release blockers have regression coverage.
The final denial-body fix passed maintainer checks after the independent review identified it.
See [validation evidence](validation.md).
NO UNRESOLVED DECISIONS
