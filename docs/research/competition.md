# Competition and product evidence

Research date: 2026-10-04 Pacific time, 2026-10-05 UTC.
GitHub values below came from live repository API calls.
They measure attention, not active use, customer retention, or revenue.
The [snapshot](competitor-snapshot.json) preserves the observed fields.

## What the market already provides

| Product | Observed public offer | Implication for this project |
| --- | --- | --- |
| [Strix](https://github.com/usestrix/strix) | 66,534 stars; Apache-2.0; autonomous pentesting | A general agent competes with a much larger project |
| [Shannon](https://github.com/KeygraphHQ/shannon) | 48,580 stars; AGPL-3.0; source-aware pentesting | Model orchestration alone is a weak differentiator |
| [HexStrike](https://github.com/0x4m4/hexstrike-ai) | 12,369 stars; MIT; security tool access through MCP | A protocol wrapper is already available |
| [PentestGPT](https://github.com/GreyDGL/PentestGPT) | 15,729 stars; MIT; agentic pentest framework | Another general framework needs distinct evidence of value |
| [Semgrep](https://github.com/semgrep/semgrep) | 16,874 stars; repository reports LGPL-2.1; static analysis | Integrate with established code checks rather than copy them |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | 31,728 stars; MIT; community templates | Reusable, reviewable test content can support distribution |
| [ZAP](https://github.com/zaproxy/zaproxy) | 15,868 stars; Apache-2.0; established web testing | Broad scanning is already well served |
| This repository | 177 stars; 35 forks; Apache-2.0 | Existing attention is small; activation needs proof |

Repository licenses are snapshots, not a legal analysis of every component or commercial edition.
Vendor capability statements remain claims until independently tested.
No comparative accuracy benchmark ran during this work.

Strix already publishes [agent workflows](https://github.com/usestrix/strix/blob/main/AGENTS.md).
Those workflows include managed testing, remediation, and CI.
Therefore, adding skills is a useful distribution interface, not a new category.

Shannon describes its [open and commercial editions](https://keygraph.io/docs/explanations/editions/).
Its commercial layer extends the lifecycle around the open engine.
That supports an open execution layer with paid team coordination as a plausible model.
It does not prove customers will pay this project.

## Direct substitutes for the chosen task

| Substitute | Relevant capability | Our proposed reason to try | Evidence limit |
| --- | --- | --- | --- |
| [StackHawk business logic testing](https://docs.stackhawk.com/hawkscan/business-logic-testing/) | Multiple user profiles and object/function authorization checks | Small local contract without adopting a wider platform | No setup-time comparison measured |
| [AuthMatrix](https://github.com/PortSwigger/auth-matrix) | Authorization matrices inside Burp Suite | Agent and CI workflow without a Burp session | Feature parity is not claimed |
| [Autorize](https://github.com/PortSwigger/autorize) | Automated authorization enforcement checks in Burp | Explicit fixture controls and portable reports | Existing tool may suit security specialists better |
| [Schemathesis](https://schemathesis.readthedocs.io/) | Schema-driven API testing | Explicit cross-tenant policy and private fixture canary | Broader schema testing remains complementary |
| Existing pytest or integration tests | Arbitrary application assertions | Quicker setup across agents and shared report format | This is the strongest free substitute |

Authorization testing is not an empty market.
Our hypothesis is that a small, reviewable workflow can reduce setup effort for application engineers.
The first experiment must measure fixture setup and repeat use, not vulnerability counts alone.

## Pricing observations

[Strix pricing](https://www.strix.ai/pricing) showed $29 per seat monthly for Pro.
The page states pentests are billed separately. It lists custom enterprise pricing.
[Semgrep pricing](https://semgrep.dev/pricing/) showed a free edition and Teams starting at $30 monthly per contributor.
Its Code and Supply Chain products list $30; Secrets lists $15.
[Aikido](https://www.aikido.dev/pricing) publishes multiple product and plan choices.
This research did not verify a directly comparable all-in quote.

These are observed list prices, not verified invoices, realized revenue, or willingness to pay.
Do not compare our proposed team fee with a competitor's partial price as if coverage were equal.

## GBrain and gstack use

GBrain searches covered the repository name and developer security concepts.
Returned results were weak semantic matches; they did not establish demand for this project.
No private customer material is used as public market evidence here.

The gstack CEO and engineering frameworks challenged the product premise and implementation plan.
An independent specification review identified credential, tenant-proof, and denial-response gaps.
The implementation added a separate allowed origin, dedicated token variables, tenant controls, and private canaries.

## What still needs evidence

1. Can eight of ten engineers finish setup in fifteen minutes without maintainer help?
2. Do at least five teams rerun a retained contract during the next two weeks?
3. Does a maintained contract catch a real regression or prevent repeated manual testing?
4. Do three teams agree to a paid pilot for coordination after local execution works?
5. Can the same onboarding method work in a second framework without custom consulting?

Do not claim product-market fit, superior accuracy, or a path to 100,000 stars before these results exist.
