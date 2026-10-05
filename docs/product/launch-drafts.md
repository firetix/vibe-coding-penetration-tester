# Launch drafts

Status: drafts only. Replace release links after the reviewed release exists.

## Repository description

Test Supabase access rules with real users. Catch private-row leaks and retain the test in continuous integration.

## Short announcement

Your app works for Alice. Can Bob read her data too?

VibePenTester checks your Supabase table with two ordinary users and a private test row.
It works from your terminal or existing coding agent.
No separate model key is needed.

Run the local demo. See the leak, see the fix, then keep the test in CI.

[Reviewed release link]

## Launch title

Show HN: Test Supabase access rules with two real user accounts

## Launch body

I built an AI pentester, then changed direction as coding agents improved.
The useful part now is a test that stays useful after the model changes.

This alpha checks private reads through Supabase or another JSON API.
It verifies both accounts, confirms the owner can read the row, then checks another user and anonymous access.
Supabase often hides forbidden rows with an empty array. The test checks that behavior explicitly.
Expired tokens and missing fixtures produce an inconclusive result.

The same runner works through a CLI, a portable skill, or MCP.
The repository includes a real local Supabase example, a basic demo, and a FastAPI recipe.
Existing pgTAP suites and Supabase client tests can solve this too. This project provides a small shared runner.
The runner, contracts, and reports are Apache-2.0.

I would like feedback on fixture setup and retaining these checks in real projects.

[Reviewed release link]

## Forty-five second demo storyboard

| Time | Screen | Narration |
| --- | --- | --- |
| 0–7s | Supabase table with a permissive read policy | Alice can read her row. Bob can read it too. |
| 7–17s | Failing contract with Bob's result highlighted | Both accounts work. Bob receives the private test value. |
| 17–27s | Remove the extra permissive policy | Restore the intended database access rule. |
| 27–37s | Run the unchanged contract | The owner still has access. Bob now receives an empty array. |
| 37–45s | Commit the contract and show CI command | Keep the check after the conversation ends. |

Record actual command output. Do not substitute a simulated dashboard for execution evidence.
Use synthetic fixture data throughout.
