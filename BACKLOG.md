# Vibe Pentester Backlog

*Last updated: 2026-01-31*

## Current Status
- **Deployment**: ✅ Live at https://vibehack.io (redirects to www.vibehack.io)
- **Repo**: https://github.com/firetix/vibe-coding-penetration-tester
- **GitHub Issues**: No open issues found

## Tech Stack
- Python + OpenAI Swarm multi-agent
- Playwright for browser automation
- Supports OpenAI, Anthropic, Ollama
- Deployed on Vercel (vibehack.io)
- Flask web UI
- OWASP Top 10 coverage

## Top Priorities (from README TODOs)

### Unchecked Items
- [ ] **Integrate vision API capabilities for visual analysis** - Could detect visual security issues (CAPTCHA weaknesses, UI redressing)
- [ ] **Run against HackerOne reports** - Find first LLM-powered vulnerability in the wild
- [ ] **Add collaborative testing capabilities** - Multi-user testing sessions
- [ ] **Improve subdomain enumeration techniques** - Better DNS enumeration
- [ ] **Add API security testing capabilities** - OWASP API Top 10 coverage ⬅️ *DRAFTED*

### Completed Items
- [x] Add support for Anthropic Claude models
- [x] Support for custom LLM model deployment (via Ollama integration)
- [x] Enhanced PlannerAgent to support smaller models
- [x] Implement more sophisticated planning algorithms
- [x] Add better execution strategies for Ollama models
- [x] Add basic documentation and examples

## Drafted Improvements

### 1. API Security Agent (DRAFTED - Ready for Integration)
**File**: `agents/security/api_security_agent.py`

New agent that tests REST/GraphQL APIs for OWASP API Security Top 10:
- BOLA (Broken Object Level Authorization)
- Broken Authentication
- Mass Assignment
- Security Misconfiguration
- GraphQL-specific vulnerabilities

**Integration needed in**:
- `agents/security/__init__.py` - Add import
- `agents/security_swarm.py` - Add to agents dict
- `config/default.yaml` - Add API security config section

## Code Quality Notes

### Files with FIXME/HACK/BUG markers
- `utils/logging_manager.py` - DEBUG level hardcoded
- `utils/logger.py` - Clean implementation
- `main.py` - Force DEBUG logging (line 27)
- `web_api/middleware/error_handler.py` - Debug level check
- `tests/conftest.py` - Test configuration

### Potential Improvements Identified
1. **Logging Configuration**: Currently hardcoded to DEBUG level in multiple places
   - `main.py:27` - `log_level = "DEBUG"  # Force debug logging`
   - Should be configurable via CLI arg or env var

2. **Test Coverage**: Good coverage for XSS/SQLI, could add:
   - API security tests
   - CSRF validation tests
   - Rate limiting tests

3. **Session Management**: Complex session handling in `web_ui.py` (800+ lines)
   - Could benefit from refactoring into smaller modules

4. **Error Handling**: Generic exception handlers could be more specific

## Agent Architecture

Current agents in `agents/security/`:
| Agent | Lines | Purpose |
|-------|-------|---------|
| xss_agent.py | 31,945 | XSS detection (comprehensive) |
| security_swarm.py | 51,123 | Main coordination |
| ssrf_agent.py | 19,320 | SSRF detection |
| auth_agent.py | 14,503 | Authentication testing |
| validator_agent.py | 14,212 | Validation |
| sqli_agent.py | 13,788 | SQL Injection |
| csrf_agent.py | 13,050 | CSRF detection |
| idor_agent.py | 12,777 | IDOR testing |
| discovery_swarm.py | 12,261 | URL discovery |
| access_control_agent.py | 4,303 | Access control |
| crypto_agent.py | 4,383 | Crypto failures |
| insecure_design_agent.py | 3,394 | Insecure design |
| data_integrity_agent.py | 3,258 | Data integrity |
| **api_security_agent.py** | *NEW* | API security (DRAFTED) |

## Next Steps
1. [ ] Integrate API Security Agent into security_swarm.py
2. [ ] Add tests for API Security Agent
3. [ ] Consider adding rate limiting detection
4. [ ] Add vision API integration for visual security analysis
5. [ ] Improve subdomain enumeration with passive DNS

## Useful Commands
```bash
# Run tests
./run_tests.sh

# Run locally
python main.py --url https://target.com --provider openai --model gpt-4o

# Run web UI
python run_web.py
```

## Notes
- Web UI at vibehack.io is functional and responsive
- LLM provider selection works (OpenAI, Anthropic, Ollama)
- Agent swarm shows real-time status in UI
