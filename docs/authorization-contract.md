# Authorization contract version 1

VibePenTester checks explicit private reads on JSON application programming interfaces (APIs).
It accepts two to eight users and one to fifty private records.
Tenant isolation requires different tenants. User isolation requires different users, regardless of their organization.
Each request uses `GET` and optional bearer authentication.

See the complete [example contract](../examples/fastapi/contract.json).

## Inputs

| Field | Required meaning |
| --- | --- |
| `version` | Integer `1` |
| `base_url` | One HTTPS origin, or HTTP with an explicit loopback IP |
| `isolation` | Optional `tenant` or `user`; defaults to `tenant` |
| `provider` | Optional `generic` or `supabase`; defaults to `generic` |
| `identity.path` | Route that returns the authenticated user's identity |
| `identity.pointer` | JSON pointer for the subject identifier |
| `identity.tenant_pointer` | Required only for tenant isolation; omit for user isolation |
| `actors.<name>.id` | Expected subject identifier |
| `actors.<name>.tenant` | Required only for tenant isolation; unique across actors; omit for user isolation |
| `actors.<name>.token_env` | Dedicated `VPT_<ACTOR>_TOKEN` variable |
| `cases[].id` | Stable case label for reports |
| `cases[].path` | Explicit path to a private record |
| `cases[].owner` | Actor that owns this record |
| `cases[].resource` | Exact `pointer` and `equals` for the record identifier |
| `cases[].private` | Exact `pointer` and `equals` for a private fixture canary |
| `cases[].denial` | Optional `status` or `empty-array`; defaults to `status` |
| `deny_statuses` | Optional unique subset of `401`, `403`, `404`; defaults to all three |
| `timeout_seconds` | Optional network timeout from 0.1 to 10 seconds; defaults to 5 |

Unknown fields, duplicate JSON keys, empty suites, and invalid pointers fail validation.
Identifiers contain letters, digits, underscores, and hyphens. They start with a letter.
Actor names cannot use `anonymous`. That label belongs to the request without credentials.
Token variable names use uppercase actor names and replace hyphens with underscores.
Do not place secrets or customer data in actor names or case labels. Reports include those labels.

Record and identity markers support nonempty strings and safe integers.
Private canaries must be unique printable strings containing 12–256 characters.
Use disposable test data, such as a random note on a test invoice.
The runner cannot prove a canary's uniqueness or secrecy. Fixture authors must establish both.

## Evidence sequence

1. Validate the entire contract and credential environment.
2. Compare its origin with the separate `--allow-origin` argument.
3. Request the identity route with each token.
4. Require HTTP `200` and exact subject matches, plus tenant matches for tenant isolation.
5. Request each record as its owner.
6. Require HTTP `200`, its record marker, and its private canary.
7. Repeat that read with every other actor and without credentials.
8. Look for the private canary anywhere in the response before evaluating denial.

A private canary proves a violation even inside an error response.
A record marker without the canary is inconclusive. The response may expose only public fields.
A configured denial without either marker passes that exact check.
With `denial: "empty-array"`, HTTP `200` and exactly an empty JSON array also pass.
This requires the same successful owner control. Empty owner responses remain inconclusive.
Use this setting for filtered private-row reads, such as Supabase PostgREST queries.
Never filter the test by the caller's ownership column. That can conceal missing authorization rules.
Nonempty arrays, objects, `null`, and empty bodies with HTTP `200` remain inconclusive without leak evidence.
Its body must be empty or valid JSON without duplicate keys or nonfinite numbers.
Malformed or ambiguous bodies are inconclusive, even with a configured denial status.
An authenticated actor's `401` is always inconclusive, even after a successful identity control.
Only anonymous requests can pass with `401`. Renew expired credentials and rerun.
Other responses, including redirects, login pages, rate limits, and server errors, are inconclusive.
Owner failures skip that record's forbidden-actor checks. Coverage totals retain the skipped work.

## Outputs

| Exit code | Meaning |
| --- | --- |
| `0` | Every configured check completed and passed |
| `1` | At least one private canary leaked, with no inconclusive checks |
| `2` | Invalid input, transport failure, output failure, or incomplete evidence |
| `130` | The operator interrupted the command |

An error takes precedence when one run includes both failures and incomplete checks.
Inspect the report for all outcomes.
Reports support JSON, Markdown, and Static Analysis Results Interchange Format (SARIF) 2.1.0.
SARIF marks incomplete runs with `executionSuccessful: false`.
Its high severity is a triage default for private data exposure, not a calculated vulnerability score.
Reports omit target URLs, tokens, headers, bodies, identity values, and private canaries.
JSON reports also state whether the contract tests `user` or `tenant` isolation.

## Supabase provider

The Supabase preset uses user isolation and identity controls at `/auth/v1/user`, with subject pointer `/id`.
The provider requires this real identity route for both isolation modes.
Set `VPT_SUPABASE_KEY` to a publishable or legacy `anon` key.
The transport sends it as `apikey` on every request, including requests without a user token.
Secret keys and legacy keys declaring other roles fail before networking.
Local key parsing checks the declared role only. Supabase validates credentials over the network.
The runner does not mint, refresh, or store tokens.
Supabase tenant pointers must start with `/app_metadata/`. Editable user metadata is rejected as a tenant control.
See the [Supabase example](../examples/supabase/README.md) for fixture setup and scope.

## Boundaries

No redirects, browser sessions, cookies, environment proxies, shell commands, or model calls run.
The runner verifies TLS certificates. It does not offer an insecure TLS switch.
Responses are limited to one MiB. Contracts are limited to 256 KiB.
Compressed responses are inconclusive.
Socket operations use the configured timeout. Body reading also checks elapsed time between reads.
DNS resolution and blocking socket calls can extend wall time beyond that interval.
The timeout is not a hard deadline for the complete suite.

The contract and launch command are trusted operator input.
Review generated contracts before use. An agent with shell access can also change launch arguments.
The separate origin argument prevents unnoticed contract drift; it does not sandbox an untrusted agent.
This local tool is not a hosted scanning boundary against server-side request forgery.

The checks do not cover writes, same-tenant roles, public records, browser cookies, or all data fields.
They do not detect leaks that omit the declared private canary and record marker.
A successful run is evidence for configured requests, not proof that the application is secure.
