# VibePenTester 2.0.0a1

Keep private records inside their tenant after AI-assisted code changes.

This alpha adds a local authorization runner with no model dependency.
It checks two distinct authenticated identities, an owner control, other tenants, and anonymous access.
Private fixture canaries provide repeatable evidence of data exposure.

- Run `vpt demo` without credentials, Docker, or browser downloads.
- Retain versioned JSON contracts and JSON, Markdown, or SARIF reports.
- Use a portable agent skill or the optional Model Context Protocol server.
- Try the complete broken-and-fixed FastAPI example.
- Fail CI when checks fail or evidence is incomplete.

The existing browser scanner remains available through its original entrypoints.
The project remains Apache-2.0 licensed.

This release covers configured cross-tenant GET requests with bearer tokens.
It does not provide a complete penetration test or compliance certification.
Hosted coordination and paid features remain proposals.
