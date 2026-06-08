# 🧪 Vulnerability Intelligence MCP Server - Test Suite

This directory contains comprehensive tests for all vulnerability intelligence tools in the MCP server.

## 📁 Test Structure

### **Vulnerability Intelligence Tests**
- `test_vulnerability_intelligence.py` - **Comprehensive test suite** (pytest compatible)
- `test_all_tools.py` - **Story-based integration test**
- `test_epss.py` - EPSS score lookup test
- `test_cvss.py` - CVSS calculator test  
- `test_search.py` - Vulnerability search test
- `test_exploit.py` - Exploit availability test
- `test_timeline.py` - Vulnerability timeline test
- `test_vex.py` - VEX status test

### **Existing MCP Tests**
- `test_cve_lookup.py` - CVE lookup functionality
- `test_package_vulnerability.py` - Package vulnerability scanning
- `test_modular_server.py` - MCP server functionality
- `test_stdio.py` - STDIO transport tests
- `run_tests.py` - Original test runner

## 🚀 Running Tests

### **Quick Test - All Vulnerability Tools**
```bash
# Run comprehensive vulnerability intelligence test suite
cd tests
python test_vulnerability_intelligence.py
```

### **Story-Based Demo Test**
```bash
# Run the complete security engineer workflow demo
cd tests  
python test_all_tools.py
```

### **Individual Tool Tests**
```bash
# Test specific tools individually
cd tests
python test_epss.py      # EPSS scores
python test_cvss.py      # CVSS calculator
python test_search.py    # Vulnerability search
python test_exploit.py   # Exploit availability
python test_timeline.py  # Timeline analysis
python test_vex.py       # VEX status
```

### **Pytest Compatibility**
```bash
# Install pytest-asyncio for async test support
pip install pytest pytest-asyncio

# Run with pytest
cd tests
pytest test_vulnerability_intelligence.py -v

# Run all tests
pytest . -v
```

### **All Tests (Legacy + New)**
```bash
# Run the original test suite
cd tests
python run_tests.py
```

## 🎯 Test Scenarios

All tests use **CVE-2021-44228 (Log4Shell)** as the primary test case because:
- ✅ Well-documented and stable
- ✅ Has EPSS scores available
- ✅ Known CVSS vector (10.0 Critical)
- ✅ Active exploitation history
- ✅ Multiple vendor advisories
- ✅ Patch timeline available

## 📊 Expected Test Results

When running the comprehensive test suite, you should see:

```
🔍 **Running Vulnerability Intelligence Test Suite**

🧪 Testing CVE Lookup...
✅ CVE Lookup: CVE-2021-44228 found

🧪 Testing EPSS Score...
✅ EPSS Score: Retrieved for CVE-2021-44228

🧪 Testing CVSS Calculator...
✅ CVSS Calculator: Calculated score for vector

🧪 Testing Vulnerability Search...
✅ Vulnerability Search: Found Apache vulnerabilities

🧪 Testing Exploit Availability...
✅ Exploit Availability: Checked for CVE-2021-44228

🧪 Testing Vulnerability Timeline...
✅ Vulnerability Timeline: Retrieved for CVE-2021-44228

🧪 Testing VEX Status...
✅ VEX Status: Checked for CVE-2021-44228 on Apache Log4j

📊 **Test Results: 7 passed, 0 failed**
🎉 **All vulnerability intelligence tools working perfectly!**
```

## 🔧 Troubleshooting

### **Import Errors**
If you see import errors, make sure you're running from the correct directory:
```bash
# From project root
cd tests
python test_vulnerability_intelligence.py

# NOT from project root (will fail)
python tests/test_vulnerability_intelligence.py
```

### **Network Issues**
Tests require internet access for:
- NVD API (CVE data)
- FIRST.org API (EPSS scores)
- MITRE website (additional CVE info)

### **Rate Limiting**
If you encounter rate limiting:
- Wait a few minutes between test runs
- The NVD API has rate limits that may affect rapid testing

## 🎬 Video Demo Tests

For creating security engineer workflow videos, use these tests in sequence:

1. `test_epss.py` - "Risk prioritization"
2. `test_cvss.py` - "Severity verification" 
3. `test_search.py` - "Related threat discovery"
4. `test_exploit.py` - "Threat intelligence"
5. `test_timeline.py` - "Patch planning"
6. `test_vex.py` - "Product impact"
7. `test_all_tools.py` - "Complete workflow"

## ✅ Success Criteria

All tests should:
- ✅ Return non-empty results
- ✅ Include expected content strings
- ✅ Handle network requests gracefully
- ✅ Complete within reasonable timeouts
- ✅ Provide actionable vulnerability intelligence

---

**🏆 Complete Test Coverage for Production-Ready Vulnerability Intelligence Platform** 