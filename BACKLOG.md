# Vibe Pentester - Backlog

## Completed

### 2026-02-03
- ✅ **API Security Agent** (PR #6)
  - Created `APISecurityAgent` for REST API vulnerability testing
  - Tests for: Broken Auth, Rate Limiting, Sensitive Data Exposure, CORS issues, Mass Assignment, Error Handling
  - Branch: `feature/api-security-agent`
  - PR: https://github.com/firetix/vibe-coding-penetration-tester/pull/6

## In Progress

*None currently*

## Backlog (from README TODOs)

### High Priority
- [ ] Integrate vision API capabilities for visual analysis
  - Could detect visual vulnerabilities, CAPTCHAs, UI-based security issues
  
- [ ] Run against HackerOne reports to find first LLM-powered vulnerability in the wild
  - Validate agent effectiveness on real-world bug bounty targets

### Medium Priority
- [ ] Add collaborative testing capabilities
  - Multi-agent coordination for complex attack chains
  - Shared context between agents for stateful testing

- [ ] Improve subdomain enumeration techniques
  - Additional DNS record types
  - Certificate transparency logs
  - More comprehensive wordlists

### Ideas / Future
- [ ] GraphQL introspection and security testing
- [ ] WebSocket security testing
- [ ] OAuth/OIDC flow testing
- [ ] File upload security testing
- [ ] Server-side template injection (SSTI) detection
- [ ] Prototype pollution detection
- [ ] CI/CD integration for automated security testing
