#!/usr/bin/env python3
import asyncio
import os
import sys

# Add parent directory to path so we can import mcp_simple_tool
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp_simple_tool.tools.cve_lookup import lookup_cve


async def main():
    result = await lookup_cve("CVE-2021-44228")
    print(result[0].text)


if __name__ == "__main__":
    asyncio.run(main())
