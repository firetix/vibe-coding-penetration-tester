#!/usr/bin/env python3
"""Test script for VEX status tool"""

import asyncio
import sys
from pathlib import Path

import pytest

# Add parent directory to path so we can import mcp_simple_tool
sys.path.append(str(Path(__file__).parent.parent))

from mcp_simple_tool.tools.vex_status import get_vex_status


@pytest.mark.asyncio
async def test_vex():
    """Test the VEX status tool with different scenarios"""

    print("=" * 60)
    print("Testing VEX status with CVE-2021-44228 (Log4Shell) and Apache")
    print("=" * 60)
    result = await get_vex_status("CVE-2021-44228", "Apache HTTP Server")
    print(
        result[0].text[:1500] + "..." if len(result[0].text) > 1500 else result[0].text
    )

    print("\n" + "=" * 60)
    print("Testing VEX status with CVE-2021-44228 without specific product")
    print("=" * 60)
    result = await get_vex_status("CVE-2021-44228")
    print(
        result[0].text[:1500] + "..." if len(result[0].text) > 1500 else result[0].text
    )


if __name__ == "__main__":
    asyncio.run(test_vex())
