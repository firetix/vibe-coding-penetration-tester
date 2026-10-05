# Product and revenue proposal

Status: hypotheses for customer tests. Paid features are not implemented or offered for purchase.

## Position

Catch bugs that let one application user read another user's private data.
Start with Supabase developers who need repeatable checks before deployment.
The runner now supports real user sessions and RLS empty-array responses.
The generic API path remains available for teams with existing bearer authentication.
Public requests support the problem; they do not validate this product or its pricing.
See the [demand review](../research/developer-demand.md) and its competing tools.

MCP and skills are both useful. Neither is the business by itself.
The durable asset would be a maintained collection of application-specific authorization contracts.
A stronger model can help create these contracts and fix code.
It does not remove the need to rerun them against real application behavior.

## Open and paid boundary

| Open under Apache-2.0 | Proposed paid coordination |
| --- | --- |
| Local runner and all current checks | Organization history across repositories |
| Agent skill and MCP adapter | Ownership, approvals, and exceptions |
| Contract format and framework examples | Scheduled runs using customer-controlled runners |
| JSON, Markdown, and SARIF exports | Access roles and centralized retention controls |
| Fix verification and ordinary CI use | Audit exports, support, and service commitments |

Keep useful execution free. Do not charge for revealing findings or exporting a user's own test evidence.
Keep credentials and response bodies inside customer infrastructure.
Begin the paid system with redacted run metadata, not arbitrary hosted scanning.
Even metadata requires access controls, deletion rules, tenant isolation, and an incident process.

## Price tests

These numbers are proposals, not validated willingness to pay.
First test a fixed-scope setup service: help a team retain tests for its own critical private reads.
Consider a $500 one-time pilot after scope and delivery effort are known.
Deliver repository-owned tests and handover notes. Do not sell a security certification.
No such service has been purchased or offered through this work.
Build hosted coordination only if active teams repeatedly request it and commit to paying.

| Offer | Price hypothesis | Buyer and limit |
| --- | --- | --- |
| Design partner pilot | $99 monthly after a successful trial | One small team; manual onboarding; explicit pilot terms |
| Team | $149 monthly | Up to ten connected applications; history and policy coordination |
| Growth | $499 monthly | Up to fifty applications; team roles and longer history |
| Enterprise | Quote only after demand exists | Customer-specific access, deployment, support, and contract needs |

Avoid unlimited hosted scans. Their runtime and support costs are unknown.
Avoid per-finding pricing. It rewards noise and discourages honest coverage reporting.
Do not activate the repository's existing billing hooks for these offers.
Its legacy SaaS readiness document identifies gaps that this release does not resolve.

## Example economics

Thirty Team customers and ten Growth customers would produce $9,460 in monthly recurring revenue.
That arithmetic is a scenario, not a forecast.
At an 80% gross-margin target, total direct monthly delivery cost must stay below $1,892.
Include support time, infrastructure, payment fees, and customer onboarding in that estimate.
Track support minutes per active team before pricing an enterprise support commitment.

Five pilots at $99 would produce $495 monthly.
That amount would validate payment behavior, not sustain a business by itself.
Do not build a broad enterprise dashboard before a repeated workflow supports a paid ask.

## Decision gates

| Gate | Evidence needed | Decision |
| --- | --- | --- |
| Useful local product | Eight of ten users complete setup in fifteen minutes | Improve fixtures until this works |
| Repeated use | Five teams run contracts in two consecutive weeks | Add requested workflow improvements |
| Paid demand | Three teams sign paid pilot terms | Build the smallest coordination feature they share |
| Sustainable delivery | Support and infrastructure fit the cost envelope | Scale acquisition |
| Broader product | Users retain the Supabase workflow without bespoke support | Add their most frequent missing workflow |

The targets are operating goals. No such results have been observed yet.
If users want only a free example they run once, treat that as failed retention.
If they already solve this easily with integration tests, change the onboarding offer or narrow the audience.
