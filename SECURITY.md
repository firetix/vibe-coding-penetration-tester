# Security

Run tests only against applications you own or have permission to test.
Use disposable fixtures and short-lived test credentials.

The new runner trusts its launch command and reviewed contract.
It does not provide isolation for an untrusted agent or a hosted scanning service.
Read the [contract boundaries](docs/authorization-contract.md#boundaries) before integration.

For sensitive vulnerabilities, use GitHub's private reporting option if it is available.
Do not post credentials, customer records, or active exploit details in public issues.
If private reporting is unavailable, open a minimal issue requesting a private reporting channel.

The legacy web scanner has separate deployment risks and dependencies.
The new runner does not resolve the gaps in [SaaS readiness](docs/saas_readiness.md).
