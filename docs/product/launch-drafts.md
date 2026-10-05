# Launch drafts

Status: drafts only. Replace release links after the reviewed release exists.

## Repository description

Repeatable authorization tests for AI-built apps. CLI, agent skill, and MCP. Prove tenant isolation and retain the check in CI.

## Short announcement

Your app works for Alice. Can Bob read her data too?

VibePenTester checks that with two tenant identities, a private fixture, and a repeatable contract.
It works from your terminal or existing coding agent.
No separate model key is needed.

Run the local demo. See the leak, see the fix, then keep the test in CI.

[Reviewed release link]

## Launch title

Show HN: VibePenTester — keep Alice's data out of Bob's response

## Launch body

I built an AI pentester, then changed direction as coding agents improved.
The useful part now is a test that stays useful after the model changes.

This alpha checks a narrow case: cross-tenant reads on JSON APIs using bearer tokens.
It proves both identities, confirms the owner can read a private fixture, then checks other tenants and anonymous access.
Expired tokens and missing fixtures produce an inconclusive result.

The same runner works through a CLI, a portable skill, or MCP.
The repository includes a disposable demo and a complete FastAPI example.
The runner, contracts, and reports are Apache-2.0.

I would like feedback on fixture setup and retaining these checks in real projects.

[Reviewed release link]

## Forty-five second demo storyboard

| Time | Screen | Narration |
| --- | --- | --- |
| 0–7s | Invoice route without its tenant filter | Alice's route works. Bob can read it too. |
| 7–17s | Failing contract with Bob's result highlighted | Two identities and a private fixture prove the leak. |
| 17–27s | Add the server-side tenant check | Fix the access rule in the application. |
| 27–37s | Run the unchanged contract | The owner still has access. Bob now receives a denial. |
| 37–45s | Commit the contract and show CI command | Keep the check after the conversation ends. |

Record actual command output. Do not substitute a simulated dashboard for execution evidence.
Use synthetic fixture data throughout.
