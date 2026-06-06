"""
CVE Lookup Tool

This module provides functionality to lookup CVE vulnerability information
from the National Vulnerability Database (NVD).
"""

import json
import re
from typing import List

import httpx
import mcp.types as types


async def lookup_cve(
    cve_id: str,
) -> List[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    """
    Lookup CVE vulnerability information from the National Vulnerability Database (NVD).
    Provides detailed information about Common Vulnerabilities and Exposures.

    Args:
        cve_id: CVE identifier in format CVE-YYYY-NNNN

    Returns:
        List of content containing CVE information or error messages
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

    headers = {"User-Agent": "MCP CVE Lookup Tool v1.0"}

    try:
        timeout = httpx.Timeout(15.0, connect=10.0)
        async with httpx.AsyncClient(
            follow_redirects=True, headers=headers, timeout=timeout
        ) as client:
            # NVD API 2.0 endpoint
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            response = await client.get(url)
            response.raise_for_status()

            data = response.json()

            if data.get("totalResults", 0) == 0:
                return [
                    types.TextContent(
                        type="text",
                        text=f"CVE {cve_id} not found in the National Vulnerability Database.",
                    )
                ]

            cve_item = data["vulnerabilities"][0]["cve"]

            # Extract key information
            cve_info = {
                "id": cve_item["id"],
                "published": cve_item.get("published", "Unknown"),
                "lastModified": cve_item.get("lastModified", "Unknown"),
                "descriptions": [],
                "cvss_scores": [],
                "references": [],
                "configurations": [],
                "weaknesses": [],
            }

            # Get descriptions
            for desc in cve_item.get("descriptions", []):
                if desc.get("lang") == "en":
                    cve_info["descriptions"].append(desc.get("value", ""))

            # Get CVSS scores
            metrics = cve_item.get("metrics", {})

            # CVSS 3.1
            if "cvssMetricV31" in metrics:
                for metric in metrics["cvssMetricV31"]:
                    cvss_data = metric.get("cvssData", {})
                    cve_info["cvss_scores"].append(
                        {
                            "version": "3.1",
                            "score": cvss_data.get("baseScore", "N/A"),
                            "severity": cvss_data.get("baseSeverity", "N/A"),
                            "vector": cvss_data.get("vectorString", "N/A"),
                            "source": metric.get("source", "N/A"),
                        }
                    )

            # CVSS 3.0
            if "cvssMetricV30" in metrics:
                for metric in metrics["cvssMetricV30"]:
                    cvss_data = metric.get("cvssData", {})
                    cve_info["cvss_scores"].append(
                        {
                            "version": "3.0",
                            "score": cvss_data.get("baseScore", "N/A"),
                            "severity": cvss_data.get("baseSeverity", "N/A"),
                            "vector": cvss_data.get("vectorString", "N/A"),
                            "source": metric.get("source", "N/A"),
                        }
                    )

            # CVSS 2.0
            if "cvssMetricV2" in metrics:
                for metric in metrics["cvssMetricV2"]:
                    cvss_data = metric.get("cvssData", {})
                    cve_info["cvss_scores"].append(
                        {
                            "version": "2.0",
                            "score": cvss_data.get("baseScore", "N/A"),
                            "severity": cvss_data.get("baseSeverity", "N/A"),
                            "vector": cvss_data.get("vectorString", "N/A"),
                            "source": metric.get("source", "N/A"),
                        }
                    )

            # Get references
            for ref in cve_item.get("references", []):
                cve_info["references"].append(
                    {
                        "url": ref.get("url", ""),
                        "source": ref.get("source", ""),
                        "tags": ref.get("tags", []),
                    }
                )

            # Get weaknesses (CWE)
            for weakness in cve_item.get("weaknesses", []):
                for desc in weakness.get("description", []):
                    if desc.get("lang") == "en":
                        cve_info["weaknesses"].append(desc.get("value", ""))

            # Format the response
            result = f"🔍 **CVE Vulnerability Report: {cve_info['id']}**\n\n"

            # Published/Modified dates
            result += "📅 **Timeline:**\n"
            result += f"   • Published: {cve_info['published']}\n"
            result += f"   • Last Modified: {cve_info['lastModified']}\n\n"

            # Description
            if cve_info["descriptions"]:
                result += "📝 **Description:**\n"
                for desc in cve_info["descriptions"]:
                    result += f"   {desc}\n\n"

            # CVSS Scores
            if cve_info["cvss_scores"]:
                result += "⚠️ **CVSS Scores:**\n"
                for score in cve_info["cvss_scores"]:
                    result += f"   • CVSS {score['version']}: {score['score']} ({score['severity']})\n"
                    result += f"     Vector: {score['vector']}\n"
                    result += f"     Source: {score['source']}\n"
                result += "\n"

            # Weaknesses (CWE)
            if cve_info["weaknesses"]:
                result += "🛡️ **Weaknesses (CWE):**\n"
                for weakness in cve_info["weaknesses"]:
                    result += f"   • {weakness}\n"
                result += "\n"

            # References
            if cve_info["references"]:
                result += "🔗 **References:**\n"
                for ref in cve_info["references"][:10]:  # Limit to first 10 references
                    tags = ", ".join(ref["tags"]) if ref["tags"] else "General"
                    result += f"   • [{ref['source']}] {ref['url']}\n"
                    result += f"     Tags: {tags}\n"

                if len(cve_info["references"]) > 10:
                    result += f"   ... and {len(cve_info['references']) - 10} more references\n"
                result += "\n"

            result += "📊 **Data Source:** National Vulnerability Database (NVD)\n"
            result += f"🌐 **Official CVE URL:** https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_info['id']}"

            return [types.TextContent(type="text", text=result)]

    except httpx.TimeoutException:
        return [
            types.TextContent(
                type="text",
                text="Error: Request timed out while fetching CVE information from NVD.",
            )
        ]
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            return [
                types.TextContent(
                    type="text",
                    text=f"CVE {cve_id} not found in the National Vulnerability Database.",
                )
            ]
        return [
            types.TextContent(
                type="text",
                text=f"Error: HTTP {e.response.status_code} error while fetching CVE data.",
            )
        ]
    except json.JSONDecodeError:
        return [
            types.TextContent(
                type="text", text="Error: Invalid JSON response from NVD API."
            )
        ]
    except Exception as e:
        return [
            types.TextContent(
                type="text",
                text=f"Error: Failed to fetch CVE information: {str(e)}",
            )
        ]
