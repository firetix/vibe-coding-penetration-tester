#!/usr/bin/env python3
"""Test script for vulnerability timeline tool"""

import asyncio
import sys
from pathlib import Path

import pytest

# Add parent directory to path so we can import mcp_simple_tool
sys.path.append(str(Path(__file__).parent.parent))

from mcp_simple_tool.tools.vulnerability_timeline import (
    get_vulnerability_timeline,
)


@pytest.mark.asyncio
async def test_timeline():
    """Test the vulnerability timeline tool with Log4Shell"""
    print("Testing vulnerability timeline with CVE-2021-44228 (Log4Shell)...")
    result = await get_vulnerability_timeline("CVE-2021-44228")
    print("\n" + "=" * 60)
    print(result[0].text)
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(test_timeline())
