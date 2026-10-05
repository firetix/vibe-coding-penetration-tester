# VibePenTester 2.0.0a2

Catch bugs that let one application user read another user’s private data.

This alpha adds a local authorization runner with no model dependency.
It checks distinct authenticated users, an owner control, other users, and anonymous access.
Tenant contracts also verify distinct tenant identities.
Private fixture canaries provide repeatable evidence of data exposure.

- Run `vpt demo` without credentials, Docker, or browser downloads.
- Retain versioned JSON contracts and JSON, Markdown, or SARIF reports.
- Use a portable agent skill or the optional Model Context Protocol server.
- Generate a Supabase contract with `vpt init --preset supabase`.
- Use publishable or legacy anon keys, real user tokens, and explicit empty-array denials.
- Run the real Supabase example through eight broken, fixed, and invalid-input scenarios.
- Try the complete broken-and-fixed FastAPI example.
- Fail CI when checks fail or evidence is incomplete.

The existing browser scanner remains available through its original entrypoints.
The project remains Apache-2.0 licensed.

This release covers configured user-owned or tenant-owned GET requests with bearer tokens.
It does not provide a complete penetration test or compliance certification.
Hosted coordination and paid features remain proposals.
