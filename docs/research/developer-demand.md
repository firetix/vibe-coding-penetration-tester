# Developer demand and product decision

Observed: 2026-10-05 UTC, 2026-10-04 Pacific.
Decision: focus onboarding on testing Supabase access rules with real users.
Keep the generic API runner and existing scanner available.

## What the evidence supports

Developers request repeatable permission tests and reliable handling of multiple test accounts.
The requests establish a problem. They do not establish demand for this repository or willingness to pay.
We found several direct alternatives, including ordinary integration tests.
The Supabase workflow is a useful next experiment, not a claim of a new category.

| Source and date | Evidence type | Finding | Limit |
| --- | --- | --- | --- |
| [Supabase discussion 12269](https://github.com/orgs/supabase/discussions/12269), June 16, 2022 | Developer request | Asks for policy tests and better debugging; describes manual trial and error | Old request; later tooling addresses parts of it |
| [Strix issue 777](https://github.com/usestrix/strix/issues/777), July 15, 2026 | Developer request | Asks for separate account profiles, reliable identity comparisons, and session renewal | One request; no reactions observed; current release covers only bearer reads |
| [Supabase discussion 20286](https://github.com/orgs/supabase/discussions/20286), January 9, 2024 | Developer request | Asks how to test storage policies under different identities | Storage writes remain outside our scope |
| [sal-site issue 73](https://github.com/diese-tech/sal-site/issues/73), May 23, 2026 | Application backlog | Requests RLS integration tests against a real Supabase project | Closed issue; some requested operations are writes; author intent was not independently verified |
| [Pick issue 162](https://github.com/Strike48-public/pick/issues/162), June 24, 2026 | Vendor backlog | Describes a customer requirement for tests across users, administrators, and tenants | Customer demand is reported by the vendor, not independently confirmed |
| [Supabase RLS tester preview](https://github.com/orgs/supabase/discussions/45233), April 24, 2026 | First-party product evidence | Introduced a tester; current announcement says development is paused | Confirms investment and competition; does not prove an unsolved market |
| [Supabase empty-results guide](https://supabase.com/docs/guides/troubleshooting/why-is-my-select-returning-an-empty-data-array-and-i-have-data-in-the-table-xvOPgx), accessed October 5, 2026 | Technical documentation | RLS can hide rows without returning an error | Documents behavior, not buying intent |
| [Lovable incident response](https://lovable.dev/blog/our-response-to-the-april-2026-incident), April 22, 2026 | First-party incident report | Reports unintended access to public-project chat and source code | Different application boundary; does not show our fixture would catch that incident |

Read original GitHub bodies through the public API and first-party documentation.
Search results containing product promotions were treated as supply, not independent demand.
Cross-posted promotions were not counted as separate users.
No affected application was scanned during research.

## Compare the alternatives

| Direction | User value | Existing substitutes | Decision |
| --- | --- | --- | --- |
| Broad autonomous pentester | Discover many vulnerability classes | Strix, Shannon, existing scanner | High execution burden; insufficient evidence to replace established systems |
| General security skills or MCP wrapper | Convenient agent access | Agent instructions and existing tools | Keep as interfaces; weak standalone product |
| General multi-account authorization framework | Test users, roles, tenants, and sessions | Autorize, AuthMatrix, integration tests | Genuine requests; broader session and write semantics need more work |
| Supabase database test generator | Generate policy fixtures and SQL checks | pgTAP, Basejump helpers, rlsautotest, Supashield | Existing tools already offer this; avoid rebuilding their engine |
| Supabase reads through real user sessions | Check the deployed API behavior and retain a repeatable test | Supabase client integration tests | Implement a small provider workflow using the existing runner |
| Static launch-security checklist | Find common configuration mistakes | Supabase advisors and many scanners | Useful supplement; insufficient proof of actual access rules |

[rlsautotest](https://github.com/unitautogen/rlsautotest) describes generated fixtures and tests across reads and writes.
[Supashield](https://github.com/Rodrigotari1/supashield) describes automated Supabase policy testing.
These are repository claims. We did not benchmark their accuracy or onboarding against this release.
Supabase's [testing guide](https://supabase.com/docs/guides/database/testing) recommends database and client tests.
Recommend those alternatives when they already meet the engineer's needs.

## What changes now

Replace agent-centered marketing with a concrete application-user question.
Lead with: **Can one customer read another customer's data?**
The engineer operates the tool. Alice and Bob are test accounts inside the engineer's application.

Add a Supabase contract preset, public-key support, and explicit user isolation.
Accept an empty JSON array only for a configured filtered read, after a successful owner control.
Keep old contracts strict: HTTP `200` with `[]` still cannot pass without that explicit setting.
Ship a real local Supabase example that introduces and repairs known policy defects.
Keep the CLI, contracts, agent skill, and reports open source.

## Gstack review

Applied the installed CEO review's premise challenge and three-approach comparison.
The user delegated implementation choices after reviewing the previous alpha.

| Approach | Effort | Main tradeoff |
| --- | --- | --- |
| Copy changes and generic API tutorial | Small | Clearer message, but leaves a common provider unsupported |
| Provider workflow using the existing runner | Medium | Concrete value and real verification; fixture setup remains manual on existing apps |
| Complete policy generator and session platform | Large | Broad potential utility; duplicates tools and lacks retention evidence |

Choose the provider workflow. Reuse contract validation, transport, identity controls, reports, and MCP.
Ideal later product: an agent prepares reliable tests from existing fixtures and reruns them after each relevant change.
Expand only when users repeatedly need the same missing capability.

## Validation that remains

Recruit ten engineers who currently use Supabase RLS.
Measure setup time, wrong-result reports, and whether they keep the test in their repository.
Ask what they already use, including plain integration tests.
Count repeated runs only with volunteered evidence. The runner has no telemetry.
Continue after five teams rerun their own checks across two weeks.
Change direction if setup costs exceed a small client test or users only run the demonstration once.
No interviews, paid commitments, or retained users were observed during this work.
