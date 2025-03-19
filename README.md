<p align="center">
  <img src="logo.webp" alt="Vibe tester Logo" width="270"/>
</p>


# Vibe Penetration Tester  🎯
> An intelligent web vulnerability scanner agent powered by Large Language Models
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL%203.0-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

**Vibe Coding**? Cool story. But your vibe might be "security breach waiting to happen." Introducing VibePenTester, the AI pen-tester who rolls its eyes at your half-baked code, discovers your vulnerabilities faster than your coworkers discover free pizza, and gently bullies your web app into compliance. Less "vibe check," more "reality check."

## 🌟 Key Features

- **Intelligent Vulnerability Discovery**: Uses LLMs (OpenAI and Anthropic Claude) to understand application context and identify potential security weaknesses (and your career weaknesses too)
- **Advanced Payload Generation**: Creates sophisticated test payloads tailored to the target application (more creative than your dating app profile)
- **Context-Aware Testing**: Analyzes application behavior and responses to guide testing strategy (unlike your ex who never listened)
- **Automated Exploit Verification**: Validates findings to eliminate false positives (we wish dating apps had this feature)
- **Comprehensive Reporting**: Generates detailed vulnerability reports with reproduction steps (that even your manager can understand)
- **Subdomain Enumeration**: Optional discovery of related subdomains (finds all your app's secret hangout spots)
- **Traffic Monitoring**: Built-in proxy captures and analyzes all web traffic (like that one friend who knows all the gossip)
- **Expandable Scope**: Option to recursively test discovered URLs (goes down rabbit holes so you don't have to)

## 🚀 Quick Start

### Prerequisites

- Python 3.8+ (like your coffee, best when hot and fresh)
- OpenAI API key (for using OpenAI models)
- Anthropic API key (optional, for using Claude models)
- Playwright (no actual playwright experience required)

### Installation

```bash
# Clone the repository (like stealing someone's homework, but legal)
git clone https://github.com/yourusername/vibe_pen_tester.git
cd vibe_pen_tester

# Install dependencies (the digital equivalent of assembling IKEA furniture)
pip install -r requirements.txt
playwright install
```

### Basic Usage

```bash
# Basic scan of a single URL (for commitment-phobes)
python main.py --url https://example.com

# Advanced scan with subdomain enumeration and URL discovery (OpenAI)
python main.py --url https://example.com --scope subdomain --model gpt-4o

# Using Anthropic Claude models (for the AI hipsters)
python main.py --url https://example.com --provider anthropic --model claude-3-7-sonnet-20250219

# Using Anthropic Claude with extended thinking capabilities (when you want it to overthink like you do)
python main.py --url https://example.com --provider anthropic --model claude-3-7-sonnet-latest --scope domain

# Using faster Anthropic Claude model (for the impatient security professionals)
python main.py --url https://example.com --provider anthropic --model claude-3-5-haiku-20241022
```

### Web Interface

For a graphical interface (because command lines are so 1980s), run:

```bash
python web_ui.py
```

Then open your browser to [http://localhost:5050](http://localhost:5050)

## 🛠️ Command Line Options

| Option | Description |
|--------|-------------|
| `--url` | Target URL to test (required, unless you want to test the void) |
| `--scope` | Scan scope (url, domain, or subdomain, default: url) |
| `--provider` | LLM provider to use (openai or anthropic, default: openai) |
| `--model` | LLM model to use (OpenAI: gpt-4o; Anthropic: claude-3-7-sonnet-20250219, claude-3-7-sonnet-latest, claude-3-5-haiku-20241022) |
| `--output` | Output directory for results (where the digital dirt gets stored) |
| `--verbose` | Enable verbose logging (for those who enjoy reading horror stories in real-time) |

## 🏗️ Architecture

VibePenTester is built with a modular architecture consisting of several key components (like a well-designed sandwich):

- **OpenAI Swarm**: The backbone of our multi-agent system, leveraging OpenAI's powerful swarm architecture to coordinate multiple specialized agents (it's like The Avengers, but for hacking)
- **SwarmCoordinator**: Orchestrates the scanning process and manages other components (the micromanager you actually want)
- **LLMProvider**: Unified interface to different LLM providers (OpenAI and Anthropic) (the universal translator of AI dialects)
- **Scanner**: Handles web page interaction and data collection (digital detective with OCD)
- **Agents**: Specialized security testing agents focusing on different aspects
  - Discovery agents for URL and attack surface identification (the nosy neighbors of the internet)
  - Security testing agents for specific vulnerability types (specialized in judging your code choices)
- **Tools**: Collection of testing and exploitation tools (like a Swiss Army knife, but for breaking things ethically)
- **Proxy**: Monitors and captures network traffic (the internet equivalent of reading someone's diary)
- **Reporter**: Analyzes findings and generates detailed reports (turns chaos into PowerPoint-ready content)

## 📊 Example Report

Reports are generated in both text and markdown formats, containing:

- Executive summary (for people who don't read past the first paragraph)
- Detailed findings with severity ratings (from "meh" to "update your resume")
- Technical details and reproduction steps (so detailed even your intern can understand)
- Evidence and impact analysis (proof that we're not making this up)
- Remediation recommendations (how to fix your life...err, code)

## 🔒 Security Considerations

- Always obtain proper authorization before testing (breaking and entering is only cool in movies)
- Use responsibly and ethically (don't be that person)
- Follow security testing best practices (like washing hands, but for hacking)
- Be mindful of potential impact on target systems (they have feelings too...sort of)

## 📋 TODOs

- [x] Add support for Anthropic Claude models
- [ ] Integrate vision API capabilities for visual analysis
- [ ] Run against HackerOne reports to find first LLM-powered vulnerability in the wild
- [ ] Implement more sophisticated planning algorithms
- [ ] Add better execution strategies and error handling
- [ ] Support for custom LLM model deployment
- [ ] Add collaborative testing capabilities
- [ ] Improve subdomain enumeration techniques
- [ ] Add API security testing capabilities
- [x] Add basic documentation and examples

## 🛡️ OWASP Top 10 Coverage

We're working hard to cover all OWASP Top 10 vulnerabilities, but we need your help! Currently, we have decent coverage for:

- ✅ Injection (SQL, NoSQL, Command)
- ✅ Broken Authentication
- ✅ Cross-Site Scripting (XSS)
- ✅ Insecure Direct Object References (IDOR) 
- ✅ Security Misconfiguration

But we still need help with:

- ❌ Broken Access Control (advanced scenarios)
- ❌ Cryptographic Failures (comprehensive detection)
- ❌ Insecure Design patterns
- ❌ Software and Data Integrity Failures
- ❌ Server-Side Request Forgery (SSRF) detection improvements

If you're knowledgeable in these areas, we desperately need your contributions! Help us make the internet slightly less terrible, one fixed vulnerability at a time. Your expertise could save countless developers from embarrassing security incidents and awkward conversations with their CISOs.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository (copy someone else's work, but legally)
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request (and pray someone reviews it this century)

## 📝 License

This project is licensed under the GPL3 - see the [LICENSE](LICENSE) file for details (the fine print nobody reads).

## ⚠️ Disclaimer

This tool is intended for security professionals and researchers. Always obtain proper authorization before testing any systems you don't own. The authors are not responsible for any misuse or damage caused by this tool. If you get fired or arrested, that's on you.

## 🙏 Acknowledgments

- OpenAI for their powerful language models (thanks for the AI that writes better code than most humans)
- Playwright for web automation capabilities (making browsers do things they regret)
- The security research community for inspiration and guidance (the real MVPs)

## 📧 Contact

For questions, feedback, or issues, please:
- Open an issue in this repository (the digital equivalent of yelling into the void)
- Contact the maintainers at [your-email@example.com]

---
Made with ❤️ and excessive caffeine by You