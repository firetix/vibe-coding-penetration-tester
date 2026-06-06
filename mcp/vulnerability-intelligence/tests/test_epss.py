#!/usr/bin/env python3
"""Test script for EPSS lookup tool"""

import asyncio
import sys
from pathlib import Path

import pytest

# Add parent directory to path so we can import mcp_simple_tool
sys.path.append(str(Path(__file__).parent.parent))

from mcp_simple_tool.tools.epss_lookup import get_epss_score


@pytest.mark.asyncio
async def test_epss():
    """Test the EPSS tool with Log4Shell CVE"""
    print("Testing EPSS tool with CVE-2021-44228 (Log4Shell)...")
    result = await get_epss_score("CVE-2021-44228")
    print("\n" + "=" * 60)
    print(result[0].text)
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(test_epss())
