# VibePenTester

An advanced AI security testing agent that leverages Large Language Models to intelligently discover and validate web application vulnerabilities. Unlike traditional scanners that follow predefined patterns, VibePenTester thinks like a human penetration tester - analyzing application behavior, generating sophisticated test cases, and validating findings through autonomous decision making.

## Features

- **Advanced LLM-Powered Analysis**: Uses state-of-the-art language models to understand application context and behavior
- **Multi-Agent Swarm Intelligence**: Deploys coordinated agent swarms for comprehensive security testing
- **Autonomous Vulnerability Validation**: Self-validates findings to minimize false positives
- **Modern Web Interface**: Clean, intuitive browser-based UI for managing scans
- **Detailed Reporting**: Generates comprehensive reports with remediation recommendations
- **Extensible Architecture**: Modular design allows for easy integration of new tools and techniques

## Installation

```bash
git clone https://github.com/yourusername/vibe_pen_tester.git
cd vibe_pen_tester
pip install -r requirements.txt
playwright install
```

## Usage

### Command Line

```bash
python main.py --url https://example.com --model gpt-4o
```

### Web Interface

For a graphical interface, run:

```bash
python web_ui.py
```

Then open your browser to [http://localhost:5050](http://localhost:5050)

The web interface provides:
- A simple form to enter the target URL
- Real-time progress monitoring with status updates
- Beautifully formatted vulnerability reports
- Options to download reports in Markdown format

See [Web UI Instructions](README_WEB_UI.md) for more details.

## Options

- `--url`: Target URL to scan
- `--model`: LLM model to use (default: gpt-4o)
- `--provider`: LLM provider (openai or anthropic, default: openai)
- `--scope`: Scan scope (url, domain, or subdomain, default: url)
- `--output`: Output directory for reports
- `--verbose`: Enable verbose logging

## Architecture

VibePenTester uses a swarm-based architecture where multiple specialized agents collaborate to thoroughly test application security. The system intelligently coordinates agent activities to maximize effectiveness while minimizing redundancy.

### Core Components

- **SwarmCoordinator**: Manages the overall testing process and agent coordination
- **LLMProvider**: Unified interface to different LLM providers (OpenAI, Anthropic)
- **Scanner**: Handles browser automation and page analysis
- **Agents**: Specialized security testing agents focusing on different aspects
  - Discovery agents for URL and attack surface identification
  - Security testing agents for specific vulnerability types
- **Tools**: Collection of security testing functions that agents can use

### Security Lists

VibePenTester uses several wordlists for security testing:

- `lists/common_passwords.txt`: Common passwords for authentication testing
- `lists/fuzz_dirs.txt`: Directory paths for brute force discovery
- `lists/subdomains.txt`: Subdomain names for enumeration

These lists power the security testing capabilities, allowing for comprehensive vulnerability assessment.

## Development

### Running Tests

VibePenTester includes a comprehensive test suite:

```bash
# Run all tests with coverage
./run_tests.sh

# Run specific tests
pytest tests/
```

### Web UI Development

The web interface is built using:
- Flask (backend)
- Bootstrap 5 (frontend styling)
- Marked.js (Markdown rendering)
- Highlight.js (syntax highlighting)

To modify the web interface:
1. Edit templates in the `templates/` directory
2. Update the Flask routes in `web_ui.py`
3. Run the server with `python web_ui.py` to test changes

### Adding New Security Tools

1. Add the tool function to `tools/general_tools.py` or the appropriate specialized tool module
2. Update relevant agent classes to include the new tool in their available tools
3. Make sure the tool integrates with the wordlists in the `lists/` directory when appropriate
4. Add appropriate tests for the new tool

## License

MIT
