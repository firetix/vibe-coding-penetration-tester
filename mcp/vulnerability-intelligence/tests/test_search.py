#!/usr/bin/env python3
"""Test script for vulnerability search tool"""

import asyncio
import sys
from pathlib import Path

import pytest

# Add parent directory to path so we can import mcp_simple_tool
sys.path.append(str(Path(__file__).parent.parent))

from mcp_simple_tool.tools.vulnerability_search import search_vulnerabilities


@pytest.mark.asyncio
async def test_search():
    """Test the vulnerability search tool with different parameters"""

    print("=" * 60)
    print("Testing vulnerability search with keywords: 'log4j'")
    print("=" * 60)
    result = await search_vulnerabilities(
        keywords="log4j", severity="CRITICAL", date_range="90d"
    )
    print(
        result[0].text[:1000] + "..." if len(result[0].text) > 1000 else result[0].text
    )

    print("\n" + "=" * 60)
    print("Testing vulnerability search with recent high severity")
    print("=" * 60)
    result = await search_vulnerabilities(severity="HIGH", date_range="30d")
    print(
        result[0].text[:1000] + "..." if len(result[0].text) > 1000 else result[0].text
    )


if __name__ == "__main__":
    asyncio.run(test_search())
