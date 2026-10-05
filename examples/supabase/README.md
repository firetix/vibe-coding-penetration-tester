# Test Supabase row-level security with real users

Check whether one application user can read another user's private row.
Supabase row-level security (RLS) normally hides a forbidden row with HTTP `200` and `[]`.
The runner verifies both users and the owner's row before accepting that empty result.

## Run the complete example

Requires Python 3.11+, uv, Docker, and the [Supabase CLI](https://supabase.com/docs/guides/local-development/cli/getting-started).
Run these commands from the repository root:

```sh
supabase start --workdir examples/supabase \
  --exclude realtime,storage-api,imgproxy,mailpit,postgres-meta,studio,edge-runtime,logflare,vector,supavisor
uv run python examples/supabase/verify.py
supabase stop --workdir examples/supabase --no-backup
```

The example uses its own project, `vpt-rls-example`, and ports `55430`–`55432`.
It runs real Supabase Auth, PostgREST, and PostgreSQL containers.
It creates two temporary users and a synthetic private row.
It changes policies only in this dedicated local database.
The verifier restores the policy and removes its fixtures when it finishes.
Run one verifier at a time because it changes the same example table.

| Scenario | Expected result |
| --- | --- |
| Correct owner policy | Pass, exit `0` |
| Publishable key instead of legacy anon key | Pass, exit `0` |
| RLS disabled | Private row leaks, exit `1` |
| Extra policy with `USING (true)` | Private row leaks, exit `1` |
| No policy allows the owner | Inconclusive, exit `2` |
| Invalid user session | Inconclusive, exit `2` |
| Alice and Bob's sessions swapped | Inconclusive, exit `2` |
| Correct policy restored | Pass, exit `0` |

Redacted reports appear in `.cache/supabase-verification.json`.
The runner needs only a public application key and two user access tokens.
The example uses local database access to create and change its disposable fixture.
The runner itself never receives database credentials or a service-role key.

## Check your own test project

Choose a table with UUID primary key `id` and a text field containing private data.
Create two ordinary test users using your existing login helpers.
Create one row owned by Alice, with a unique synthetic canary in that text field.

Generate a contract using the actual UUIDs from your fixtures:

```sh
uv run vpt init --preset supabase \
  --base-url https://YOUR_TEST_PROJECT.supabase.co \
  --table notes \
  --owner-id 11111111-1111-4111-8111-111111111111 \
  --other-id 22222222-2222-4222-8222-222222222222 \
  --row-id 33333333-3333-4333-8333-333333333333 \
  --private-column body \
  --canary vpt-private-note-fixture-7f38d2
```

The displayed UUIDs and canary are example values. Replace them with your seeded fixtures.
Omitted fixture options create the same editable template.
The generator writes a file without making network requests or creating users.

Supply these environment variables through your login helper or continuous integration (CI) secrets:

| Variable | Value |
| --- | --- |
| `VPT_SUPABASE_KEY` | Publishable key or legacy `anon` key |
| `VPT_ALICE_TOKEN` | Alice's fresh access token |
| `VPT_BOB_TOKEN` | Bob's fresh access token |

Secret keys and legacy `service_role` keys are rejected before networking.
Key parsing checks the declared type. Supabase validates credentials during requests.
Keep user access tokens out of contracts, command arguments, chat, and reports.

```sh
uv run vpt validate vpt-contract.json
uv run vpt check vpt-contract.json \
  --allow-origin https://YOUR_TEST_PROJECT.supabase.co
```

Alice must receive the expected row and private canary.
Bob and the request without a user token must receive no rows or a configured denial.
The anonymous request still sends the public application key required by Supabase.
HTTP `200` alone cannot pass. `{}`, `null`, and nonempty arrays are inconclusive without private leak evidence.
An empty owner response is inconclusive. A broken login cannot produce a passing run.

## What to change after a leak

Inspect the table's grants, RLS setting, and every applicable policy.
PostgreSQL combines permissive policies with `OR`. An extra public policy can defeat the intended owner rule.
The example's policy lives in [the migration](supabase/migrations/20261005000000_notes.sql).
Rerun the unchanged contract after fixing the database rule.

Keep only the row identifier filter in this test request.
A filter such as `owner_id=eq.<caller>` can hide a missing database rule.
The generated request selects the row identifier and private field. It never filters by the caller.

## Scope and alternatives

The preset checks user-owned rows, including users within the same organization.
It does not claim organization isolation, role coverage, write protection, or coverage of every row.
Use tenant contracts with a trustworthy tenant identity route for organization isolation.
For Supabase tenant contracts, use server-managed `app_metadata`, never editable `user_metadata`, for tenant claims.
Model membership-table authorization separately when metadata does not represent your application's tenant rules.

Use [Supabase database tests](https://supabase.com/docs/guides/database/testing) for broader SQL policy tests.
[rlsautotest](https://github.com/unitautogen/rlsautotest) offers generated pgTAP suites and fixtures.
Existing integration tests using the Supabase client can perform these same reads.
VibePenTester provides a small shared runner, credential controls, and reports across terminal and agent workflows.
