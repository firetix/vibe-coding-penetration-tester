#!/usr/bin/env python3
"""Test script for CVSS calculator tool"""

import asyncio
import sys
from pathlib import Path

import pytest

# Add parent directory to path so we can import mcp_simple_tool
sys.path.append(str(Path(__file__).parent.parent))

from mcp_simple_tool.tools.cvss_calculator import calculate_cvss_score


@pytest.mark.asyncio
async def test_cvss():
    """Test the CVSS calculator tool with different vector strings"""
    # Test cases with different severity levels
    test_vectors = [
        (
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "Critical - Network accessible, no privileges",
        ),
        (
            "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N",
            "Low - Local access, high complexity",
        ),
        (
            "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
            "Critical - Network with scope change",
        ),
        (
            "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            "Medium - Adjacent network DoS",
        ),
    ]

    for vector, description in test_vectors:
        print(f"\n{'=' * 60}")
        print(f"Testing: {description}")
        print(f"Vector: {vector}")
        print("=" * 60)

        result = await calculate_cvss_score(vector)
        print(result[0].text)


if __name__ == "__main__":
    asyncio.run(test_cvss())
