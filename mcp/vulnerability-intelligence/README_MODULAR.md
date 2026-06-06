# MCP Vulnerability Checker Server - Modular Architecture

This is a Model Context Protocol (MCP) server that provides comprehensive security vulnerability intelligence tools organized in a modular architecture. The server includes tools for CVE lookup, EPSS scoring, CVSS calculation, exploit detection, vulnerability search, timeline analysis, VEX status checking, and Python package vulnerability checking.

## 🏗️ Architecture

The server has been refactored into a modular structure for better maintainability and extensibility:

```
mcp_simple_tool/
├── server.py                           # Main MCP server
├── __init__.py
├── __main__.py
└── tools/                              # Tool modules
    ├── __init__.py                     # Tool package exports
    ├── cve_lookup.py                   # CVE vulnerability lookup
    ├── epss_lookup.py                  # EPSS score lookup
    ├── cvss_calculator.py              # CVSS score calculator
    ├── vulnerability_search.py         # Advanced vulnerability search
    ├── exploit_availability.py         # Exploit and PoC detection
    ├── vulnerability_timeline.py       # Timeline and patch status
    ├── vex_status.py                   # VEX status checking
    └── package_vulnerability.py        # Python package security check
tests/                                  # Test suite
├── __init__.py                         # Test package
├── run_tests.py                        # Test runner
├── test_modular_server.py              # Modular structure tests
├── test_cve_lookup.py                  # CVE lookup tests
├── test_package_vulnerability.py       # Package vulnerability tests
└── test_stdio.py                       # Original stdio tests
```

## 🔧 Available Tools

### 1. CVE Lookup (`cve_lookup`)
Lookup detailed vulnerability information from the National Vulnerability Database (NVD).

**Parameters:**
- `cve_id` (required): CVE identifier in format CVE-YYYY-NNNN (e.g., CVE-2021-44228)

**Example Usage:**
```python
# Via MCP client
await call_tool("cve_lookup", {"cve_id": "CVE-2021-44228"})
```

### 2. Python Package Vulnerability Check (`package_vulnerability_check`)
Check for known vulnerabilities in Python packages using the OSV (Open Source Vulnerabilities) database.

**Parameters:**
- `package_name` (required): Name of Python package (e.g., 'requests', 'django', 'flask')
- `version` (optional): Specific version to check

**Example Usage:**
```python
# Check all versions
await call_tool("package_vulnerability_check", {"package_name": "requests"})

# Check specific version
await call_tool("package_vulnerability_check", {
    "package_name": "django", 
    "version": "3.2.0"
})
```

### 3. EPSS Score Lookup (`get_epss_score`)
Get Exploit Prediction Scoring System (EPSS) scores for CVEs to assess exploitation probability.

**Parameters:**
- `cve_id` (required): CVE identifier in format CVE-YYYY-NNNN

### 4. CVSS Score Calculator (`calculate_cvss_score`)
Calculate CVSS base scores from vector strings for severity assessment.

**Parameters:**
- `vector` (required): CVSS vector string (e.g., CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

### 5. Vulnerability Search (`search_vulnerabilities`)
Search vulnerability databases with advanced filtering capabilities.

**Parameters:**
- `keywords` (optional): Keywords to search for in vulnerability descriptions
- `severity` (optional): Filter by severity level (CRITICAL, HIGH, MEDIUM, LOW)
- `date_range` (optional): Date range filter (30d, 90d, 1y, 2y, or custom)

### 6. Exploit Availability Check (`get_exploit_availability`)
Check for public exploits and proof-of-concepts (PoCs) across multiple sources.

**Parameters:**
- `cve_id` (required): CVE identifier in format CVE-YYYY-NNNN

### 7. Vulnerability Timeline (`get_vulnerability_timeline`)
Get comprehensive timeline and patch status information for vulnerabilities.

**Parameters:**
- `cve_id` (required): CVE identifier in format CVE-YYYY-NNNN

### 8. VEX Status Check (`get_vex_status`)
Check Vulnerability Exploitability eXchange (VEX) status for specific products.

**Parameters:**
- `cve_id` (required): CVE identifier in format CVE-YYYY-NNNN
- `product` (optional): Product name or identifier

## 🚀 Usage

### Running the Server

**Standard I/O mode (default):**
```bash
python -m mcp_simple_tool.server
```

**SSE mode:**
```bash
python -m mcp_simple_tool.server --transport sse --port 8000
```

### Testing Individual Tools

You can test the modular tools using the organized test suite:

```bash
# Run all tests
python tests/run_tests.py

# Or run individual tests
python tests/test_modular_server.py
python tests/test_package_vulnerability.py
python tests/test_cve_lookup.py
```

## 📦 Dependencies

- `httpx` - HTTP client for API requests
- `mcp` - Model Context Protocol SDK
- `click` - Command line interface
- `anyio` - Async I/O framework
- `starlette` & `uvicorn` - For SSE mode

## 🔍 Data Sources

- **CVE Lookup**: [National Vulnerability Database (NVD)](https://nvd.nist.gov/)
- **Package Vulnerabilities**: [OSV (Open Source Vulnerabilities)](https://osv.dev/)
- **Package Info**: [PyPI (Python Package Index)](https://pypi.org/)

## 🛡️ Security Features

### CVE Lookup Tool
- Fetches comprehensive vulnerability data from NVD API 2.0
- Includes CVSS scores (v2.0, v3.0, v3.1)
- Provides vulnerability descriptions, references, and weaknesses
- Shows affected configurations and remediation guidance

### Package Vulnerability Tool
- Queries OSV database for Python package vulnerabilities
- Shows affected version ranges and fix information
- Provides vulnerability severity scores and references
- Includes package metadata from PyPI
- Handles both specific version and general package queries

## 🔧 Extension Guide

The modular architecture makes it easy to add new tools:

### Adding a New Tool

1. **Create a new tool module** in `mcp_simple_tool/tools/`:
```python
# mcp_simple_tool/tools/my_new_tool.py
import mcp.types as types
from typing import List

async def my_tool_function(
    param1: str,
    param2: str = None
) -> List[types.TextContent]:
    """Your tool implementation."""
    # Tool logic here
    return [types.TextContent(type="text", text="Result")]
```

2. **Export the tool** in `mcp_simple_tool/tools/__init__.py`:
```python
from .my_new_tool import my_tool_function

__all__ = [
    # ... existing tools ...
    "my_tool_function"
]
```

3. **Register the tool** in `mcp_simple_tool/server.py`:
```python
# Import
from .tools.my_new_tool import my_tool_function

# Add to call_tool handler
elif name == "my_new_tool":
    return await my_tool_function(arguments["param1"], arguments.get("param2"))

# Add to list_tools
types.Tool(
    name="my_new_tool",
    description="Description of my new tool",
    inputSchema={
        "type": "object",
        "required": ["param1"],
        "properties": {
            "param1": {"type": "string", "description": "Parameter description"},
            "param2": {"type": "string", "description": "Optional parameter"}
        }
    }
)
```

## 📝 Example Reports

### CVE Report Example
```
🔍 **CVE Vulnerability Report: CVE-2021-44228**

📅 **Timeline:**
   • Published: 2021-12-10T10:15:09.847
   • Last Modified: 2023-11-07T04:10:58.217

📝 **Description:**
   Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.

⚠️ **CVSS Scores:**
   • CVSS 3.1: 10.0 (CRITICAL)
     Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
     Source: nvd@nist.gov
```

### Package Vulnerability Report Example
```
🚨 **Python Package Security Report: requests**

⚠️ **Found 11 known vulnerabilities**

📦 **Package Information:**
   • Latest Version: 2.32.3
   • Summary: Python HTTP for Humans.
   • Author: Kenneth Reitz
   • PyPI: https://pypi.org/project/requests/

🔍 **Vulnerability #1: CVE-2024-35195**
   📝 **Summary:** Requests Session object does not verify requests after making first request with verify=False
   🔥 **Severity:** HIGH
   📅 **Published:** 2024-05-20T20:15:00Z
   📊 **Affected Versions:**
      • Introduced: 0
      • Fixed: 2.32.0
```

## 🤝 Contributing

When adding new tools, please:

1. Follow the existing modular structure
2. Add comprehensive error handling
3. Include proper type hints
4. Add tests for your tools
5. Update this README with new tool documentation

## 📄 License

This project maintains the same license as the original MCP server implementation. 