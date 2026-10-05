# Product and revenue proposal

Status: hypotheses for customer tests. Paid features are not implemented or offered for purchase.

## Position

Keep private records inside their tenant after AI-assisted code changes.
Sell faster setup and repeatable evidence to engineers building multi-tenant applications.
Start with FastAPI teams that already have bearer authentication and test fixtures.
Expand to another framework only after repeated use establishes the workflow's value.

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
| Broader product | Second framework retains users without bespoke support | Expand content and integrations |

The targets are operating goals. No such results have been observed yet.
If users want only a free example they run once, treat that as failed retention.
If they already solve this easily with integration tests, change the onboarding offer or narrow the audience.
