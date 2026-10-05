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
The maintainer authorized a small outreach test on 2026-10-05.
One Supabase community post is live. See the smoke test below.
No directory submission or release publication has happened through this plan.

## Supabase outreach smoke test

Published: [Testing Supabase row-level security with two real users](https://github.com/orgs/supabase/discussions/51252).
Author: `firetix`. Category: **Show and tell**. Published at `2026-10-05T07:10:37Z`.

The category explicitly invites people to show their projects.
The [community code of conduct](https://github.com/supabase/.github/blob/main/CODE_OF_CONDUCT.md) requires respectful participation.
We checked recent questions before posting. The inspected questions covered different problems.
For example, [discussion 51213](https://github.com/orgs/supabase/discussions/51213) asks about administrative privileges and migration recovery.
The private-row reader does not solve that question.

The post explains two application users, discloses alpha status, and links to the reviewed Supabase example.
It asks: "Would you try this on one private table, or do your existing tests already cover it?"
The linked example uses an immutable commit because the alpha is not on the default branch.

The initial readback showed zero comments and zero reactions.
Eleven of the fifteen latest showcase posts had no comments when inspected before publication.
That small snapshot suggests limited response volume. It does not measure views or reader interest.
Competing showcases establish available alternatives, not customer demand.

Two local, read-only checks are scheduled for October 6 and October 8 at 00:11 Pacific time.
They record public replies without sending follow-up messages.
They require this Mac, its logged-in account, network access, and working GitHub authentication.
Sleep can delay execution until wake. These checks are not a hosted monitoring service.
Local receipts and results live under `.cache/outreach/supabase-smoke-2026-10-05/`.

Evaluation window: seven days after publication.
Initial target: two developers describe their current tests, and one tries a fixture on their own test project.
Count replies, completed setup, retained tests, and paid work separately.
There is no click tracking or local-run telemetry. We cannot calculate conversion rates from this post.
Do not classify the product as unwanted from one unanswered post.

If developers respond, first learn what they already use and which setup step blocks them.
Offer help with synthetic fixtures. Never ask for credentials or customer data in public replies.
If the post stays silent, test a short broken/fixed demonstration in another community that permits project sharing.
Verify that community's current rules before posting.
Collaborations with Supabase template maintainers are another candidate channel after one successful external setup.

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
