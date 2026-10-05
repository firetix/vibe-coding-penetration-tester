# Distribution operating plan

The first distribution problem is getting an engineer to a useful retained test.
A star is a secondary sign of attention. It does not measure that outcome.

## Message

Primary: **Can one customer read another customer's data?**
Supporting: Test Supabase access rules with real user accounts before deployment.
Proof: Show a leaking RLS policy, its fix, and the unchanged test passing against real Supabase containers.
Explain that Alice and Bob are application users. The coding agent operates their tests.
Avoid claims about replacing security teams or finding every vulnerability.

## First six weeks

| Week | Ship | Distribution experiment | Evidence and decision |
| --- | --- | --- | --- |
| 1 | Reviewed Supabase recipe, basic demo, skill, MCP, release artifacts | Invite ten Supabase developers to complete setup | Record time, failures, existing substitutes, and retained tests |
| 2 | Fix the three most common setup failures | Publish the real broken/fixed RLS example | Eight of ten complete setup within fifteen minutes |
| 3 | Improve CI setup and credential renewal guidance | Invite retained users to show one teammate | Five teams run checks in two consecutive weeks |
| 4 | Add the most requested missing access test | Publish a broken/fixed example and invite contributions | At least two outside contributors submit reproducible fixtures |
| 5 | Setup assistance; coordination only with paid demand | Offer a scoped pilot to active teams | Record signed terms, paid invoices, and support time separately |
| 6 | Improve the feature retained users request most | Launch publicly with observed evidence and a short demo | Compare activation and retention by source |

Owner: project maintainer, supported by contributors after they accept specific work.
No outreach, directory submission, release publication, or social post has happened through this plan.
Those actions require the maintainer's publishing choice and actual destination accounts.

## Channels and repeatable loops

| Channel | Useful artifact | Intended loop |
| --- | --- | --- |
| Framework communities | Runnable tenant-isolation example | Reader adapts it, reports friction, contributes a variant |
| Agent skill catalogs | Small skill with exact tool and evidence requirements | Agent creates a contract that stays in the repository |
| MCP catalogs | Fixed-scope server with a documented local demo | User installs it, runs a check, retains the CLI command |
| GitHub | Clear README, issue templates, good first contributions | Maintainer reviews reproducible fixtures and credits contributors |
| Technical search | Guides about Supabase empty results, permissive policies, and real-user RLS tests | Engineer solves one problem and returns during later changes |
| Launch communities | Short broken/fixed recording and measured setup results | Interested users try a demo and become repeat users |

Do not submit the same generic announcement everywhere.
Lead each community post with the problem its users already discuss.
Ask contributors for fixtures and useful contracts, not stars.
Never buy stars, automate engagement, or send unsolicited bulk messages.
The [source ledger](../research/developer-demand.md) identifies relevant discussions, not a list for promotional replies.
Publish self-contained examples first. Link from another community only when its rules and context permit it.

## Measurement

The CLI ships without telemetry.
Use public repository metrics and explicit design-partner feedback first.
Record a pseudonymous team identifier, source, setup minutes, first successful run, second-week run, and paid status.
Do not collect tokens, private paths, customer records, or contract bodies.

Suggested funnel: relevant visitor → demo completed → own app checked → retained CI contract → two-week repeat → paid pilot.
The repository cannot observe local runs by itself.
Do not report download counts as active users or local retention.
Use volunteered session notes until a consented measurement system exists.

Keep one weekly experiment ledger with: hypothesis, artifact, audience, owner, dates, result, and next decision.
Stop a channel after three tests produce traffic but no own-app activation.
Improve setup before adding more acquisition channels when activation is poor.

## The 100,000-star ambition

Baseline: 177 observed stars on 2026-10-04 Pacific time.
Reaching 100,000 requires 99,823 additional stars.
That means about 8,319 monthly over twelve months, or 4,159 monthly over twenty-four months.
These are arithmetic requirements, not projected growth rates.

The narrow first release is unlikely to justify that scale alone.
A credible larger direction would combine a trusted runner, exceptional fixture onboarding, and widely reused security contracts.
Expansion could cover roles, writes, framework policies, and contributions from security specialists.
Let retained use choose those additions.

Milestones: 1,000 stars with reliable onboarding; 5,000 with repeated use; 10,000 with active contributors.
Treat 25,000 and beyond as outcomes of broader utility, not deadlines.
Review revenue, active teams, contributor retention, and false reassurance before celebrating star growth.

## Draft alpha links

The unpublished product page links to the reviewed working branch while the alpha remains a draft.
Replace those links with the release tag when the maintainer publishes the release.
