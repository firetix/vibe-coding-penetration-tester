<p align="center">
  <img src="logo.webp" alt="Vibe tester Logo" width="270"/>
</p>


# Vibe Coding Penetration Tester  🎯
> An intelligent web vulnerability scanner agent powered by Large Language Models

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL%203.0-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

**✨ Live Demo: [vibehack.io](http://vibehack.io/)** 

**Vibe Coding**? Cool story. But your vibe might be "security breach waiting to happen." Introducing VibePenTester, the AI pen-tester who rolls its eyes at your half-baked code, discovers your vulnerabilities faster than your coworkers discover free pizza, and gently bullies your web app into compliance. Less "vibe check," more "reality check."

<p align="center">
  <img src="demo.gif" alt="demo"/>
</p>



## 🌟 Key Features

- **Intelligent Vulnerability Discovery**: Uses LLMs (OpenAI, Anthropic Claude, and local Ollama models) to understand application context and identify potential security weaknesses (and your career weaknesses too)
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
- Ollama (optional, for running models locally without API keys)
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

# Using Ollama with Llama 3 locally (for the privacy-focused or those without API keys)
python main.py --url https://example.com --provider ollama --model llama3

# Using Ollama with a more capable model (best for thorough security testing)
python main.py --url https://example.com --provider ollama --model mixtral

# Using Ollama with a lightweight model (faster but with fallback mechanisms)
python main.py --url https://example.com --provider ollama --model deepseek-r1

# Using Ollama with a custom server URL (for remote Ollama instances)
python main.py --url https://example.com --provider ollama --model llama3 --ollama-url http://ollama-server:11434
```

### Web Interface

For a graphical interface (because command lines are so 1980s), run:

```bash
python web_ui.py
```

Then open your browser to [http://localhost:5050](http://localhost:5050)

#### Web Interface Features

- **Direct API Key Input**: You can now enter your OpenAI or Anthropic API keys directly in the web interface, without setting environment variables
- **Local Model Support**: Run security tests using Ollama with any locally available model
- **Customizable Ollama Settings**: Configure Ollama server URL and model selection in the UI
- **Smart Model Detection**: Automatic adjustment for smaller models with appropriate fallbacks
- **Real-time Scan Progress**: Watch as the AI agents work through the security testing process
- **Interactive Reports**: View detailed findings with vulnerability explanations and remediation suggestions
- **Mobile Responsive**: Works on desktops, tablets, and mobile devices

### Vercel Deployment

You can now deploy VibePenTester to Vercel as a web application:

1. Follow the instructions in [VERCEL_DEPLOYMENT.md](VERCEL_DEPLOYMENT.md)
2. Set up environment variables for API keys (optional)
3. Connect Google Analytics to track usage

#### Vercel-Specific Implementation Details

This application has been specially adapted to work with Vercel's serverless architecture:

1. **Progressive Scan Architecture**: Rather than using background threads (which don't work in serverless environments), the application uses a progressive scan approach where the `/status` endpoint advances the scan state in increments.

2. **XSS Detection Implementation**: The application directly calls security testing functions during scan progression to detect XSS vulnerabilities in real-time.

3. **Stateful Operation**: The application maintains state between serverless function invocations using file system storage in the `/tmp` directory.

### 🔬 Sample Reports & Live Demo

Why take our word for it? We've got receipts for days. Check out the `/reports_samples/` directory to see actual vulnerabilities detected in the wild. These aren't made-up examples — they're real bugs that could have tanked someone's weekend if we hadn't vibed with their code first.

**✨ Live Demo: [vibehack.io](http://vibehack.io/)** 

We've deployed a fully functional instance to Vercel because we're that confident in our tool (or possibly that reckless with our API credits). Test it out before installing — your DevOps team will thank you later.

Remember: Your code might be passing all the tests, but are those tests passing the vibe check? Probably not. Good vibes don't protect against XSS, and your DevSecOps pipeline probably smells like corporate middle-management. Let us help before your "move fast and break things" philosophy becomes "move fast and break customer data regulations."

## 🛠️ Command Line Options

| Option | Description |
|--------|-------------|
| `--url` | Target URL to test (required, unless you want to test the void) |
| `--scope` | Scan scope (url, domain, or subdomain, default: url) |
| `--provider` | LLM provider to use (openai, anthropic, or ollama, default: openai) |
| `--model` | LLM model to use (OpenAI: gpt-4o; Anthropic: claude-3-7-sonnet-20250219, claude-3-7-sonnet-latest, claude-3-5-haiku-20241022; Ollama: llama3, mixtral, etc.) |
| `--output` | Output directory for results (where the digital dirt gets stored) |
| `--verbose` | Enable verbose logging (for those who enjoy reading horror stories in real-time) |
| `--ollama-url` | Ollama server URL (used only with --provider=ollama, default: http://localhost:11434) |

## 🏗️ Architecture

VibePenTester is built with a modular architecture consisting of several key components (like a well-designed sandwich):

- **OpenAI Swarm**: The backbone of our multi-agent system, leveraging OpenAI's powerful swarm architecture to coordinate multiple specialized agents (it's like The Avengers, but for hacking)
- **SwarmCoordinator**: Orchestrates the scanning process and manages other components (the micromanager you actually want)
- **LLMProvider**: Unified interface to different LLM providers (OpenAI, Anthropic, and Ollama) (the universal translator of AI dialects)
- **Scanner**: Handles web page interaction and data collection (digital detective with OCD)
- **Agents**: Specialized security testing agents focusing on different aspects
  - Discovery agents for URL and attack surface identification (the nosy neighbors of the internet)
  - Security testing agents for specific vulnerability types (specialized in judging your code choices)
- **Tools**: Collection of testing and exploitation tools (like a Swiss Army knife, but for breaking things ethically)
- **Proxy**: Monitors and captures network traffic (the internet equivalent of reading someone's diary)
- **Reporter**: Analyzes findings and generates detailed reports (turns chaos into PowerPoint-ready content)

## 🔄 Small Model Support

When using resource-constrained local models via Ollama, VibePenTester adapts intelligently:

- **Smart Function Calling**: Advanced JSON extraction capabilities for models with limited function calling abilities
- **Fallback Mechanisms**: Multi-tiered fallbacks when tool calls aren't generated properly:
  - Text parsing to extract test plans from unstructured outputs
  - Default security plans based on OWASP top vulnerabilities
- **Context Optimization**: Reduced memory context window to stay within token limits of smaller models
- **Temperature Tuning**: Lower temperature settings (0.2) for more deterministic outputs with local models
- **Prompt Engineering**: Simplified system prompts with explicit examples for models like deepseek-r1
- **Default Testing Plans**: Automatic generation of sensible testing plans when a model can't create one

These features ensure VibePenTester works effectively even with smaller open-source models (deepseek-r1, phi, gemma, mistral) that may have limited tool usage capabilities.

### Troubleshooting Ollama Integration

If you encounter issues with Ollama:

1. **Connectivity Problems**: 
   - Ensure Ollama is running with `ollama serve`
   - Check that the default URL (http://localhost:11434) is accessible
   - For remote servers, verify network connectivity and firewall settings

2. **Model Availability**:
   - Pull required models first: `ollama pull llama3`
   - For smaller models, try using our built-in fallbacks: `--provider ollama --model deepseek-r1`

3. **Performance Issues**:
   - For local resource constraints, use smaller models like Phi-2 or Gemma
   - For comprehensive security testing, prefer larger models like Llama3, Mixtral, or DeepSeek-Coder
   - Set appropriate CUDA environment variables for GPU acceleration

4. **Function Calling Problems**:
   - If security plans seem incomplete, the fallback mechanisms will automatically engage
   - For best results with smaller models, stick to simpler target websites

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
- [x] Support for custom LLM model deployment (via Ollama integration)
- [x] Enhanced PlannerAgent to support smaller models with limited capabilities (like deepseek-r1)
- [ ] Integrate vision API capabilities for visual analysis
- [ ] Run against HackerOne reports to find first LLM-powered vulnerability in the wild
- [x] Implement more sophisticated planning algorithms with fallback mechanisms
- [x] Add better execution strategies and error handling for Ollama models
- [ ] Add collaborative testing capabilities
- [x] Improve subdomain enumeration techniques (CT logs, zone transfers, parallel resolution)
- [x] Add API security testing capabilities
- [x] Add basic documentation and examples

## 🛡️ OWASP Top 10 Coverage

We provide comprehensive coverage for all OWASP Top 10 vulnerabilities, with specialized agents for each category:

- ✅ Injection (SQL, NoSQL, Command)
- ✅ Broken Authentication
- ✅ Cross-Site Scripting (XSS)
- ✅ Insecure Direct Object References (IDOR) 
- ✅ Security Misconfiguration
- ✅ Broken Access Control (advanced scenarios)
- ✅ Cryptographic Failures (comprehensive detection)
- ✅ Insecure Design patterns
- ✅ Software and Data Integrity Failures
- ✅ Server-Side Request Forgery (SSRF) detection

Each vulnerability type is handled by dedicated security agents with specialized knowledge and testing techniques. Our multi-agent approach ensures thorough coverage across the entire OWASP threat landscape.

We welcome contributions to enhance our detection capabilities and effectiveness! If you have expertise in any of these security areas, consider contributing to make our tool even better. Help us make the internet slightly less terrible, one fixed vulnerability at a time.

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
- [Rogue](https://github.com/faizann24/rogue/) by Faizan Ahmad for inspiration and pioneering LLM-powered security testing (the OG security AI whisperer - thank you Faizan!)
- The security research community for inspiration and guidance (the real MVPs)

## 📧 Contact

For questions, feedback, or issues, please:
- Open an issue in this repository (the digital equivalent of yelling into the void)
- Contact the maintainers at [vibe_tester@r1015.org]

---
Made with ❤️ and excessive caffeine by Simo
