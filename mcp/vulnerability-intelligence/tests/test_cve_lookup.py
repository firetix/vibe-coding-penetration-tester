#!/usr/bin/env python3
"""Quick test to lookup CVE-2021-44228 using our CVE lookup tool"""

import asyncio
import os
import sys

# Add parent directory to path so we can import mcp_simple_tool
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp_simple_tool.tools.cve_lookup import lookup_cve


async def main():
    print("🔍 Looking up CVE-2021-44228 (Log4Shell vulnerability)...")
    print("=" * 60)

    result = await lookup_cve("CVE-2021-44228")
    print(result[0].text)


if __name__ == "__main__":
    asyncio.run(main())
