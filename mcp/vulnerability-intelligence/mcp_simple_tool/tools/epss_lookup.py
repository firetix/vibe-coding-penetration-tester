"""
EPSS Lookup Tool

This module provides functionality to lookup EPSS (Exploit Prediction Scoring System)
scores from FIRST.org. EPSS provides a probability estimate of exploitation
in the wild within 30 days.
"""

import json
import re
from typing import List

import httpx
import mcp.types as types


async def get_epss_score(
    cve_id: str,
) -> List[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    """
    Get EPSS (Exploit Prediction Scoring System) score for a CVE.
    EPSS provides probability estimates of exploitation in the wild.

    Args:
        cve_id: CVE identifier in format CVE-YYYY-NNNN

    Returns:
        List of content containing EPSS score information or error messages
    """
    # Clean up CVE ID format
    cve_id = cve_id.upper().strip()
    if not cve_id.startswith("CVE-"):
        cve_id = f"CVE-{cve_id}"

    # Validate CVE ID format (CVE-YYYY-NNNN)
    if not re.match(r"^CVE-\d{4}-\d{4,}$", cve_id):
        return [
            types.TextContent(
                type="text",
                text=f"Error: Invalid CVE ID format. Expected format: CVE-YYYY-NNNN (e.g., CVE-2021-44228). Got: {cve_id}",
            )
        ]

    headers = {
        "User-Agent": "MCP EPSS Lookup Tool v1.0",
        "Accept": "application/json",
    }

    try:
        timeout = httpx.Timeout(15.0, connect=10.0)
        async with httpx.AsyncClient(
            follow_redirects=True, headers=headers, timeout=timeout
        ) as client:
            # FIRST.org EPSS API endpoint
            url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
            response = await client.get(url)
            response.raise_for_status()

            data = response.json()

            if data.get("status") != "OK":
                return [
                    types.TextContent(
                        type="text",
                        text=f"Error: EPSS API returned status: {data.get('status', 'Unknown')}",
                    )
                ]

            epss_data = data.get("data", [])
            if not epss_data:
                return [
                    types.TextContent(
                        type="text",
                        text=f"No EPSS score found for {cve_id}. This CVE might be too new or not in the EPSS database.",
                    )
                ]

            cve_epss = epss_data[0]  # EPSS API returns array, we want first item

            # Extract EPSS information
            epss_score = float(cve_epss.get("epss", 0))
            percentile = float(cve_epss.get("percentile", 0))
            date = cve_epss.get("date", "Unknown")

            # Convert EPSS score to percentage and risk level
            epss_percentage = epss_score * 100

            # Determine risk level based on EPSS score
            if epss_score >= 0.7:
                risk_level = "🔴 CRITICAL"
                risk_desc = "Extremely high likelihood of exploitation"
            elif epss_score >= 0.3:
                risk_level = "🟠 HIGH"
                risk_desc = "High likelihood of exploitation"
            elif epss_score >= 0.1:
                risk_level = "🟡 MEDIUM"
                risk_desc = "Moderate likelihood of exploitation"
            elif epss_score >= 0.01:
                risk_level = "🟢 LOW"
                risk_desc = "Low likelihood of exploitation"
            else:
                risk_level = "⚪ VERY LOW"
                risk_desc = "Very low likelihood of exploitation"

            # Determine percentile interpretation
            if percentile >= 95:
                percentile_desc = "Top 5% most likely to be exploited"
            elif percentile >= 90:
                percentile_desc = "Top 10% most likely to be exploited"
            elif percentile >= 75:
                percentile_desc = "Top 25% most likely to be exploited"
            elif percentile >= 50:
                percentile_desc = "Above average exploitation likelihood"
            else:
                percentile_desc = "Below average exploitation likelihood"

            # Format the response
            result = f"📊 **EPSS Vulnerability Exploit Prediction: {cve_id}**\n\n"

            result += f"🎯 **EPSS Score:** {epss_score:.6f} ({epss_percentage:.4f}%)\n"
            result += f"📈 **Percentile:** {percentile:.2f}% - {percentile_desc}\n"
            result += f"⚠️ **Risk Level:** {risk_level}\n"
            result += f"📝 **Risk Description:** {risk_desc}\n"
            result += f"📅 **Data Date:** {date}\n\n"

            result += "🔍 **Understanding EPSS Scores:**\n"
            result += "   • EPSS predicts the probability of exploitation in the wild within 30 days\n"
            result += "   • Scores range from 0 (0%) to 1 (100%)\n"
            result += (
                "   • Higher scores indicate higher likelihood of active exploitation\n"
            )
            result += "   • Percentile shows how this CVE ranks against all CVEs\n\n"

            result += "📋 **Prioritization Guidance:**\n"
            if epss_score >= 0.3:
                result += "   🚨 **URGENT:** This CVE should be prioritized for immediate patching\n"
                result += (
                    "   🛡️ Consider implementing additional monitoring and controls\n"
                )
            elif epss_score >= 0.1:
                result += "   ⚡ **HIGH PRIORITY:** Schedule patching within your next maintenance window\n"
                result += "   👀 Monitor for signs of exploitation attempts\n"
            elif epss_score >= 0.01:
                result += (
                    "   📋 **MEDIUM PRIORITY:** Include in regular patching cycle\n"
                )
                result += "   📊 Continue monitoring threat landscape\n"
            else:
                result += "   🕐 **LOW PRIORITY:** Can be addressed during routine maintenance\n"
                result += "   📈 Monitor for changes in threat landscape\n"

            result += "\n📊 **Data Source:** FIRST.org Exploit Prediction Scoring System (EPSS)\n"
            result += "🌐 **EPSS Project:** https://www.first.org/epss/"

            return [types.TextContent(type="text", text=result)]

    except httpx.TimeoutException:
        return [
            types.TextContent(
                type="text",
                text="Error: Request timed out while fetching EPSS score from FIRST.org.",
            )
        ]
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            return [
                types.TextContent(
                    type="text",
                    text=f"EPSS score for {cve_id} not found. This CVE might be too new or not in the EPSS database.",
                )
            ]
        return [
            types.TextContent(
                type="text",
                text=f"Error: HTTP {e.response.status_code} error while fetching EPSS data.",
            )
        ]
    except json.JSONDecodeError:
        return [
            types.TextContent(
                type="text", text="Error: Invalid JSON response from EPSS API."
            )
        ]
    except (ValueError, TypeError) as e:
        return [
            types.TextContent(
                type="text",
                text=f"Error: Failed to parse EPSS score data: {str(e)}",
            )
        ]
    except Exception as e:
        return [
            types.TextContent(
                type="text",
                text=f"Error: Failed to fetch EPSS information: {str(e)}",
            )
        ]
