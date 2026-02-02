# Vibe Pentester - Development Backlog

## ✅ Recently Completed

### Enhanced Subdomain Enumeration (PR #5) - 2026-02-02
- Added `utils/subdomain_discovery.py` with multi-technique enumeration:
  - Certificate Transparency log parsing via crt.sh API
  - Concurrent DNS brute-forcing with ThreadPoolExecutor
  - Permutation-based discovery for deeper enumeration
  - HTTP/HTTPS alive checking with service detection
- Updated `network_utils.py` to use enhanced enumeration by default
- Updated `scanning_tools.py` with improved `enumerate_subdomains` function
- Added comprehensive unit tests in `tests/unit/test_subdomain_discovery.py`
- Expanded common prefixes list to 200+ entries
- **PR**: https://github.com/firetix/vibe-coding-penetration-tester/pull/5

### API Security Testing (PR #4) - 2026-02-01
- Added `APISecurityAgent` for REST/GraphQL endpoint testing
- Implemented 7 new security testing tools:
  - `discover_api_endpoints` - Find endpoints from JS/page content
  - `test_bola_vulnerability` - BOLA/IDOR testing
  - `test_api_authentication` - Auth bypass & JWT vulnerabilities
  - `test_rate_limiting` - Rate limit verification
  - `test_mass_assignment` - Parameter injection testing
  - `analyze_api_response` - Data exposure analysis
  - `test_graphql_introspection` - GraphQL security testing
- Covers OWASP API Security Top 10
- **PR**: https://github.com/firetix/vibe-coding-penetration-tester/pull/4

## 🔜 Remaining TODOs

### High Priority
1. **Integrate vision API capabilities for visual analysis**
   - Use LLM vision to identify UI elements for testing
   - Visual CAPTCHA detection and handling
   - Screenshot-based vulnerability confirmation

2. **Run against HackerOne reports**
   - Train/validate on real-world vulnerability reports
   - Goal: Find first LLM-powered vulnerability in the wild
   - Build benchmark dataset

### Medium Priority
3. **Add collaborative testing capabilities**
   - Multi-agent coordination for complex attacks
   - Session sharing between agents
   - Attack chain orchestration

### Backlog
- Performance optimizations for large scans
- Report export formats (PDF, HTML, SARIF)
- CI/CD integration guide
- Docker compose setup for easy deployment
- Plugin system for custom agents

## 📊 Agent Coverage

| Agent | Status | OWASP Coverage |
|-------|--------|----------------|
| XSS Agent | ✅ | A7:2017 |
| SQLi Agent | ✅ | A1:2017 |
| CSRF Agent | ✅ | - |
| Auth Agent | ✅ | A2:2017 |
| IDOR Agent | ✅ | A5:2017 |
| Access Control | ✅ | A5:2017 |
| Crypto Agent | ✅ | A3:2017 |
| Insecure Design | ✅ | A4:2021 |
| Data Integrity | ✅ | A8:2021 |
| SSRF Agent | ✅ | A10:2021 |
| **API Security** | ✅ NEW | API Top 10 |
| Validator | ✅ | - |

---
*Last updated: 2026-02-01*
