"""
VEX Status Checker Tool

This module provides functionality to check VEX (Vulnerability Exploitability eXchange)
status for vulnerabilities in specific products. VEX communicates the exploitability
status of vulnerabilities in products.
"""

import re
from datetime import datetime
from typing import List, Optional

import httpx
import mcp.types as types


async def get_vex_status(
    cve_id: str,
    product: Optional[str] = None,
) -> List[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    """
    Check VEX (Vulnerability Exploitability eXchange) status for a CVE and product.

    VEX Status definitions:
    - not_affected: Product is not affected by the vulnerability
    - affected: Product is affected and vulnerable
    - fixed: Vulnerability has been fixed in the product
    - under_investigation: Vendor is investigating the impact

    Args:
        cve_id: CVE identifier in format CVE-YYYY-NNNN
        product: Product name or identifier (optional)

    Returns:
        List of content containing VEX status information or guidance
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
        "User-Agent": "MCP VEX Status Checker v1.0",
        "Accept": "application/json",
    }

    vex_data = {}
    vendor_statements = []

    try:
        timeout = httpx.Timeout(15.0, connect=10.0)
        async with httpx.AsyncClient(
            follow_redirects=True, headers=headers, timeout=timeout
        ) as client:
            # Check 1: NVD for vendor statements and VEX-like information
            try:
                nvd_url = (
                    f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
                )
                nvd_response = await client.get(nvd_url)
                if nvd_response.status_code == 200:
                    nvd_data = nvd_response.json()
                    if nvd_data.get("totalResults", 0) > 0:
                        cve_item = nvd_data["vulnerabilities"][0]["cve"]

                        # Analyze references for vendor statements
                        for ref in cve_item.get("references", []):
                            url = ref.get("url", "").lower()
                            tags = ref.get("tags", [])
                            source = ref.get("source", "")

                            # Look for vendor statements
                            if (
                                "vendor advisory" in tags
                                or "vendor" in url
                                or any(
                                    vendor in url
                                    for vendor in [
                                        "microsoft",
                                        "oracle",
                                        "redhat",
                                        "ubuntu",
                                        "debian",
                                        "apache",
                                        "cisco",
                                        "vmware",
                                    ]
                                )
                            ):
                                # Try to determine VEX-like status from URL/tags
                                status = "under_investigation"  # Default
                                confidence = "low"

                                if any(
                                    keyword in url
                                    for keyword in [
                                        "patch",
                                        "fix",
                                        "update",
                                        "resolved",
                                    ]
                                ):
                                    status = "fixed"
                                    confidence = "medium"
                                elif any(
                                    keyword in url
                                    for keyword in [
                                        "not-affected",
                                        "unaffected",
                                        "not_affected",
                                    ]
                                ):
                                    status = "not_affected"
                                    confidence = "high"
                                elif any(
                                    keyword in url
                                    for keyword in ["affected", "vulnerable"]
                                ):
                                    status = "affected"
                                    confidence = "medium"

                                vendor_statements.append(
                                    {
                                        "vendor": source,
                                        "url": ref.get("url", ""),
                                        "inferred_status": status,
                                        "confidence": confidence,
                                        "tags": tags,
                                    }
                                )

                        vex_data["nvd_vendor_statements"] = vendor_statements

            except Exception as e:
                vex_data["nvd_error"] = str(e)

            # Check 2: GitHub for VEX documents (CSAF format)
            # Note: This would require GitHub API for full search
            vex_data["github_vex_search"] = {
                "status": "manual_check_recommended",
                "search_urls": [
                    f"https://github.com/search?q={cve_id}+VEX&type=code",
                    f"https://github.com/search?q={cve_id}+CSAF&type=code",
                    f"https://github.com/search?q={cve_id}+vulnerability+status&type=code",
                ],
            }

            # Check 3: Known VEX data sources
            vex_sources = {
                "CISA": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                "RedHat": f"https://access.redhat.com/security/cve/{cve_id}",
                "Microsoft": f"https://msrc.microsoft.com/blog/tag/cve-{cve_id.lower()}/",
                "Ubuntu": f"https://ubuntu.com/security/{cve_id}",
                "Debian": f"https://security-tracker.debian.org/tracker/{cve_id}",
            }

            vex_data["recommended_vex_sources"] = vex_sources

    except Exception as e:
        return [
            types.TextContent(
                type="text",
                text=f"Error: Failed to check VEX status: {str(e)}",
            )
        ]

    # Format the response
    result = f"📋 **VEX Status Report: {cve_id}**\n"
    if product:
        result += f"🔍 **Product:** {product}\n"
    result += "\n"

    # VEX Overview
    result += "💡 **What is VEX?**\n"
    result += "VEX (Vulnerability Exploitability eXchange) communicates the exploitability status of vulnerabilities in specific products.\n\n"

    result += "📊 **VEX Status Categories:**\n"
    result += "   • 🔴 **affected** - Product is vulnerable and exploitable\n"
    result += (
        "   • 🟢 **not_affected** - Product is not affected by this vulnerability\n"
    )
    result += "   • ✅ **fixed** - Vulnerability has been patched/fixed\n"
    result += "   • 🟡 **under_investigation** - Vendor is investigating impact\n\n"

    # Vendor Statement Analysis
    vendor_statements = vex_data.get("nvd_vendor_statements", [])
    if vendor_statements:
        result += f"🏭 **Vendor Statements Analysis:** Found {len(vendor_statements)} vendor reference(s)\n\n"

        # Group by inferred status
        status_groups = {}
        for stmt in vendor_statements:
            status = stmt["inferred_status"]
            if status not in status_groups:
                status_groups[status] = []
            status_groups[status].append(stmt)

        for status, statements in status_groups.items():
            status_emoji = {
                "fixed": "✅",
                "not_affected": "🟢",
                "affected": "🔴",
                "under_investigation": "🟡",
            }.get(status, "⚪")

            result += f"**{status_emoji} {status.replace('_', ' ').title()}:** {len(statements)} statement(s)\n"
            for stmt in statements[:3]:  # Show first 3
                confidence_emoji = {
                    "high": "🔥",
                    "medium": "⚡",
                    "low": "💫",
                }.get(stmt["confidence"], "❓")
                result += f"   • {stmt.get('vendor', 'Unknown')} {confidence_emoji}\n"
                result += f"     URL: {stmt.get('url', 'N/A')[:80]}...\n"
            if len(statements) > 3:
                result += f"   ... and {len(statements) - 3} more\n"
            result += "\n"
    else:
        result += "🏭 **Vendor Statements:** ⚪ No vendor statements found in NVD references\n\n"

    # Product-specific guidance
    if product:
        result += f"🎯 **Product-Specific Guidance for '{product}':**\n"

        # Try to match product with known vendors
        product_lower = product.lower()
        if any(
            vendor in product_lower
            for vendor in ["microsoft", "windows", "office", "azure"]
        ):
            result += "   • Check Microsoft Security Response Center (MSRC)\n"
            result += (
                f"   • URL: https://msrc.microsoft.com/blog/tag/{cve_id.lower()}/\n"
            )
        elif any(
            vendor in product_lower for vendor in ["redhat", "rhel", "centos", "fedora"]
        ):
            result += "   • Check Red Hat Security Portal\n"
            result += f"   • URL: https://access.redhat.com/security/cve/{cve_id}\n"
        elif any(vendor in product_lower for vendor in ["ubuntu", "canonical"]):
            result += "   • Check Ubuntu Security Notices\n"
            result += f"   • URL: https://ubuntu.com/security/{cve_id}\n"
        elif any(vendor in product_lower for vendor in ["debian"]):
            result += "   • Check Debian Security Tracker\n"
            result += (
                f"   • URL: https://security-tracker.debian.org/tracker/{cve_id}\n"
            )
        elif any(vendor in product_lower for vendor in ["apache"]):
            result += "   • Check Apache Security Reports\n"
            result += (
                "   • URL: https://httpd.apache.org/security/vulnerabilities_24.html\n"
            )
        else:
            result += "   • Check the vendor's security advisory page\n"
            result += f"   • Search for '{cve_id}' on the vendor's website\n"
        result += "\n"

    # Manual VEX Check Guidance
    result += "🔍 **Manual VEX Verification:**\n\n"

    vex_sources = vex_data.get("recommended_vex_sources", {})
    for source, url in vex_sources.items():
        result += f"**{source}:**\n"
        result += f"   • URL: {url}\n"
        if source == "CISA":
            result += f"   • Check if {cve_id} is in Known Exploited Vulnerabilities Catalog\n"
        else:
            result += "   • Look for VEX statements or vulnerability status\n"
        result += "\n"

    # GitHub VEX Search
    github_data = vex_data.get("github_vex_search", {})
    if github_data.get("search_urls"):
        result += "**🐙 GitHub VEX Document Search:**\n"
        for url in github_data["search_urls"]:
            result += f"   • {url}\n"
        result += "   • Look for CSAF/VEX documents mentioning this CVE\n\n"

    # Creating VEX Statements
    result += "📝 **Creating VEX Statements:**\n"
    result += "If you're a vendor/maintainer, create VEX statements using:\n"
    result += "   • **CSAF Format:** Common Security Advisory Framework\n"
    result += "   • **OpenVEX:** Simplified VEX format\n"
    result += "   • **SARIF:** Static Analysis Results Interchange Format\n\n"

    result += "💻 **VEX Tools:**\n"
    result += "   • OpenVEX CLI: https://github.com/openvex/vexctl\n"
    result += "   • CSAF Validator: https://github.com/csaf-poc/csaf_distribution\n"
    result += "   • VEX Hub: https://vexhub.org/\n\n"

    # Current VEX Ecosystem Status
    result += "🌐 **VEX Ecosystem Status:**\n"
    result += "   • 📈 **Adoption:** Growing, but still early stage\n"
    result += (
        "   • 🏢 **Major Vendors:** Microsoft, Red Hat, Google starting adoption\n"
    )
    result += "   • 🔧 **Tools:** Limited but improving tooling ecosystem\n"
    result += "   • 📋 **Standards:** CSAF 2.0, OpenVEX gaining traction\n\n"

    result += "⚠️ **Important Notes:**\n"
    result += (
        "   • VEX adoption is still developing - many vendors don't provide VEX yet\n"
    )
    result += "   • Manual verification of vendor advisories is still necessary\n"
    result += "   • VEX statements are authoritative only from the product vendor\n"
    result += "   • Absence of VEX statement doesn't mean product is affected\n\n"

    result += f"📊 **Report Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"

    return [types.TextContent(type="text", text=result)]
