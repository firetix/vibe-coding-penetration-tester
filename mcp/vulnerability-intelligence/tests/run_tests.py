#!/usr/bin/env python3
"""
Test runner for MCP Vulnerability Checker Server

This script runs all available tests to verify the modular server functionality.
"""

import os
import subprocess
import sys

# Add parent directory to path so we can import mcp_simple_tool
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def run_test_script(script_name: str) -> bool:
    """Run a test script and return success status."""
    try:
        print(f"🧪 Running {script_name}...")
        print("=" * 60)

        result = subprocess.run(
            [
                sys.executable,
                os.path.join(os.path.dirname(__file__), script_name),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode == 0:
            print(result.stdout)
            print(f"✅ {script_name} passed!")
            return True
        else:
            print(f"❌ {script_name} failed!")
            print("STDOUT:", result.stdout)
            print("STDERR:", result.stderr)
            return False

    except subprocess.TimeoutExpired:
        print(f"⏰ {script_name} timed out!")
        return False
    except Exception as e:
        print(f"💥 Error running {script_name}: {e}")
        return False
    finally:
        print("\n" + "=" * 60 + "\n")


def main():
    """Run all tests."""
    print("🚀 MCP Vulnerability Checker Server - Test Suite")
    print("=" * 60)
    print()

    tests = [
        "test_modular_server.py",
        "test_cve_lookup.py",
        "test_package_vulnerability.py",
    ]

    results = []

    for test in tests:
        success = run_test_script(test)
        results.append((test, success))

    # Summary
    print("📊 Test Results Summary:")
    print("=" * 40)

    passed = 0
    total = len(results)

    for test, success in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"  {test:<30} {status}")
        if success:
            passed += 1

    print("=" * 40)
    print(f"Tests passed: {passed}/{total}")

    if passed == total:
        print("🎉 All tests passed!")
        return 0
    else:
        print("😞 Some tests failed.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
