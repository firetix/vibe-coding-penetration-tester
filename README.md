<p align="center">
  <img src="logo.webp" alt="VibePenTester logo" width="270"/>
</p>

# Vibe Coding Penetration Tester

AI-assisted web application security testing with CLI and web interfaces.

VibePenTester coordinates specialized security agents to discover and validate common web vulnerabilities, then generates reproducible Markdown and JSON reports.

## Key Capabilities

- Multi-agent scan workflow for discovery, planning, and vulnerability testing
- LLM provider support: OpenAI, Anthropic, and local/remote Ollama
- Playwright-powered browser automation for realistic interaction testing
- Scope-aware scanning (`url`, `domain`, `subdomain`)
- Report generation in both `report.md` and `report.json`
- Flask web UI and API for session-based scan orchestration
- Hosted-mode entitlement and billing hooks for SaaS deployments

## Repository Structure

- `main.py`: CLI scanner entrypoint
- `run_web.py`: Modular Flask web API entrypoint (recommended for local web runs)
- `wsgi.py`: WSGI app entrypoint for production servers
- `web_ui.py`: Legacy all-in-one web server kept for compatibility
- `web_api/`: Refactored modular routes, middleware, and helpers
- `agents/`: Discovery and security testing agent implementations
- `tools/`: Browser and security testing tool wrappers
- `reports_samples/`: Example generated reports
- `tests/`: Unit, integration, API E2E, frontend E2E, and Vercel preview tests

## Prerequisites

- Python 3.8+
- Playwright browser binaries
- At least one LLM provider:
  - OpenAI API key (`OPENAI_API_KEY`)
  - Anthropic API key (`ANTHROPIC_API_KEY`)
  - Ollama server (`OLLAMA_BASE_URL`, default `http://localhost:11434`)

## Installation

```bash
git clone https://github.com/firetix/vibe-coding-penetration-tester.git
cd vibe-coding-penetration-tester

python -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
playwright install

cp .env.example .env
```

## Configuration

### Core Environment Variables

- `OPENAI_API_KEY`: Required for `--provider openai`
- `ANTHROPIC_API_KEY`: Required for `--provider anthropic`
- `PORT`: Web server port (default `5050`)
- `SECRET_KEY`: Flask session secret
- `OLLAMA_BASE_URL`: Optional Ollama endpoint (default `http://localhost:11434`)

### Hosted/Billing Environment Variables (Optional)

- `VPT_HOSTED_MODE`: Enable hosted entitlement enforcement (`1` to enable)
- `VPT_BILLING_DB_PATH`: SQLite database path for billing/entitlements
- `VPT_TRUST_PROXY_HEADERS`: Trust `X-Forwarded-For` when deployed behind proxies
- `VPT_ENABLE_MOCK_CHECKOUT`: Allow local mock checkout flows
- `VPT_ALLOW_UNVERIFIED_WEBHOOKS`: Relax Stripe webhook verification (test-only)
- `STRIPE_SECRET_KEY`: Stripe API key
- `STRIPE_WEBHOOK_SECRET`: Stripe webhook signing secret
- `STRIPE_PRICE_PRO_MONTHLY`: Stripe price ID for subscription mode
- `STRIPE_PRICE_CREDIT_PACK`: Stripe price ID for credit pack purchases

## Usage

### CLI Scanning

```bash
# Default OpenAI model
python main.py --url https://example.com

# Domain-level scan with OpenAI
python main.py --url https://example.com --scope domain --provider openai --model gpt-4o

# OpenAI Codex model
python main.py --url https://example.com --provider openai --model gpt-5.3-codex

# Subdomain scan with Anthropic
python main.py --url https://example.com --scope subdomain --provider anthropic --model claude-3-7-sonnet-20250219

# Anthropic Opus model
python main.py --url https://example.com --provider anthropic --model claude-opus-4.6

# Local scan with Ollama
python main.py --url https://example.com --provider ollama --model llama3

# Ollama with custom endpoint
python main.py --url https://example.com --provider ollama --model mixtral --ollama-url http://localhost:11434
```

### Model Catalog

Use any provider model ID accepted by your account/runtime. Common options:

- OpenAI:
  - `gpt-4o`
  - `gpt-4.1`
  - `gpt-5`
  - `gpt-5.3-codex`
  - `o3`
- Anthropic:
  - `claude-3-7-sonnet-20250219`
  - `claude-opus-4.6`
  - `claude-3-5-haiku-20241022`
- Ollama (example local tags):
  - `llama3`
  - `mixtral`
  - `deepseek-r1`
  - `mistral`
  - `gemma`

### CLI Options

| Option | Description |
| --- | --- |
| `--url` | Target URL to test (required) |
| `--model` | LLM model identifier (default `gpt-4o`) |
| `--provider` | LLM provider: `openai`, `anthropic`, `ollama` |
| `--scope` | Scan scope: `url`, `domain`, `subdomain` |
| `--output` | Output directory root (default `reports`) |
| `--verbose` | Enable verbose logging |
| `--ollama-url` | Ollama server URL override |

Reports are written to:

- `reports/<normalized_target>_<timestamp>/report.json`
- `reports/<normalized_target>_<timestamp>/report.md`

### Web Application (Recommended Modular App)

```bash
python run_web.py
```

Open [http://localhost:5050](http://localhost:5050).

### Legacy Web Application (Compatibility)

```bash
python web_ui.py
```

This path is maintained for backward compatibility with older route behavior.

## Web API Endpoints (Modular App)

Core:

- `POST /api/session/init`
- `POST /api/session/check`
- `POST /api/session/reset`
- `GET|POST /api/session/state`
- `POST /api/scan/start`
- `POST /api/scan/status`
- `POST /api/scan/cancel`
- `POST /api/scan/list`
- `POST /api/activity`
- `GET /status`
- `GET /api/logs`
- `GET /api/reports`
- `GET /api/report/<report_id>`

Hosted/billing:

- `GET /api/entitlements`
- `POST /api/billing/checkout`
- `POST /api/billing/webhook`
- `GET /billing/checkout`
- `GET /mock-checkout/<checkout_session_id>` (mock flow in local/test setups)

Compatibility routes are also registered for older clients (for example: `/scan`, `/report`, `/reset`, `/api/state`).

## Testing

Run all standard suites:

```bash
./run_tests.sh
```

Run focused suites:

```bash
pytest tests/unit -v
pytest tests/integration -v
pytest tests/e2e/api -m e2e_api_critical -v
pytest tests/e2e/frontend -m e2e_frontend_smoke -v
pytest tests/e2e/vercel -m e2e_vercel_preview -v
```

Additional marker groups are defined in `pytest.ini` for full/nightly E2E coverage.

## Deployment

- Vercel deployment guide: [`VERCEL_DEPLOYMENT.md`](VERCEL_DEPLOYMENT.md)
- Deployment helper script: [`deploy-to-vercel.sh`](deploy-to-vercel.sh)
- WSGI entrypoint: `wsgi:app`

## Sample Reports

See generated examples in:

- `reports_samples/http_testhtml5.vulnweb.com__20250319_004520/report.md`
- `reports_samples/http_testhtml5.vulnweb.com__20250319_004520/report.json`

## Security and Legal Notice

Use this tool only against targets you own or have explicit authorization to test. Unauthorized scanning may violate law and policy.

## Contributing

Contributions are welcome through pull requests and issues. For larger changes, open an issue first to discuss design and scope.

## License

GPL-3.0. See [`LICENSE`](LICENSE).
