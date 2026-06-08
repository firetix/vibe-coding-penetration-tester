"""
CVSS Calculator Tool

This module provides functionality to calculate CVSS (Common Vulnerability Scoring System)
scores from vector strings. Supports CVSS v3.0 and v3.1.
"""

import re
from typing import Any, Dict, List

import mcp.types as types


def parse_cvss_vector(vector: str) -> Dict[str, Any]:
    """
    Parse a CVSS vector string and extract metrics.

    Args:
        vector: CVSS vector string (e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    Returns:
        Dictionary containing parsed metrics
    """
    # Clean up vector string
    vector = vector.strip()

    # Extract version
    version_match = re.match(r"^CVSS:(\d+\.\d+)/", vector)
    if not version_match:
        raise ValueError("Invalid CVSS vector format. Must start with CVSS:x.x/")

    version = version_match.group(1)
    if version not in ["3.0", "3.1"]:
        raise ValueError(
            f"Unsupported CVSS version: {version}. Only 3.0 and 3.1 are supported."
        )

    # Parse metrics
    metrics = {}
    metrics["version"] = version

    # Split the vector into components
    vector_parts = vector.split("/")[1:]  # Skip the CVSS:x.x part

    for part in vector_parts:
        if ":" not in part:
            continue
        key, value = part.split(":", 1)
        metrics[key] = value

    return metrics


def calculate_cvss3_base_score(metrics: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calculate CVSS v3.0/3.1 base score from parsed metrics.

    Args:
        metrics: Parsed CVSS metrics dictionary

    Returns:
        Dictionary containing calculated scores and interpretations
    """
    # CVSS v3.x base metric values
    av_values = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    ac_values = {"L": 0.77, "H": 0.44}
    pr_values = {
        "N": {"unchanged": 0.85, "changed": 0.85},
        "L": {"unchanged": 0.62, "changed": 0.68},
        "H": {"unchanged": 0.27, "changed": 0.50},
    }
    ui_values = {"N": 0.85, "R": 0.62}
    s_values = {"U": "unchanged", "C": "changed"}
    cia_values = {"H": 0.56, "L": 0.22, "N": 0.0}

    # Extract required metrics
    try:
        av = metrics.get("AV", "")
        ac = metrics.get("AC", "")
        pr = metrics.get("PR", "")
        ui = metrics.get("UI", "")
        s = metrics.get("S", "")
        c = metrics.get("C", "")
        i = metrics.get("I", "")
        a = metrics.get("A", "")

        # Validate all required metrics are present
        required = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
        missing = [metric for metric in required if metrics.get(metric, "") == ""]
        if missing:
            raise ValueError(f"Missing required metrics: {', '.join(missing)}")

        # Get numeric values
        av_score = av_values[av]
        ac_score = ac_values[ac]
        ui_score = ui_values[ui]
        scope = s_values[s]
        pr_score = pr_values[pr][scope]
        c_score = cia_values[c]
        i_score = cia_values[i]
        a_score = cia_values[a]

        # Calculate Impact Sub Score (ISS)
        iss = 1 - ((1 - c_score) * (1 - i_score) * (1 - a_score))

        # Calculate Impact Score
        if scope == "unchanged":
            impact = 6.42 * iss
        else:  # scope == "changed"
            impact = 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15)

        # Calculate Exploitability Score
        exploitability = 8.22 * av_score * ac_score * pr_score * ui_score

        # Calculate Base Score
        if impact <= 0:
            base_score = 0.0
        elif scope == "unchanged":
            base_score = min(10.0, impact + exploitability)
        else:  # scope == "changed"
            base_score = min(10.0, 1.08 * (impact + exploitability))

        # Round to one decimal place
        base_score = round(base_score, 1)

        # Determine severity rating
        if base_score >= 9.0:
            severity = "CRITICAL"
            severity_color = "🔴"
        elif base_score >= 7.0:
            severity = "HIGH"
            severity_color = "🟠"
        elif base_score >= 4.0:
            severity = "MEDIUM"
            severity_color = "🟡"
        elif base_score > 0.0:
            severity = "LOW"
            severity_color = "🟢"
        else:
            severity = "NONE"
            severity_color = "⚪"

        return {
            "base_score": base_score,
            "impact_score": round(impact, 1),
            "exploitability_score": round(exploitability, 1),
            "severity": severity,
            "severity_color": severity_color,
            "scope": scope,
            "metrics": {
                "attack_vector": {"value": av, "score": av_score},
                "attack_complexity": {"value": ac, "score": ac_score},
                "privileges_required": {"value": pr, "score": pr_score},
                "user_interaction": {"value": ui, "score": ui_score},
                "scope": {"value": s, "description": scope},
                "confidentiality": {"value": c, "score": c_score},
                "integrity": {"value": i, "score": i_score},
                "availability": {"value": a, "score": a_score},
            },
        }

    except KeyError as e:
        raise ValueError(f"Invalid metric value: {e}")


async def calculate_cvss_score(
    vector: str,
) -> List[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    """
    Calculate CVSS base score from a CVSS vector string.

    Args:
        vector: CVSS vector string (e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    Returns:
        List of content containing CVSS calculation results or error messages
    """
    try:
        # Parse the vector
        metrics = parse_cvss_vector(vector)

        # Calculate score
        if metrics["version"] in ["3.0", "3.1"]:
            result = calculate_cvss3_base_score(metrics)
        else:
            return [
                types.TextContent(
                    type="text",
                    text=f"Error: CVSS version {metrics['version']} is not supported. Only versions 3.0 and 3.1 are supported.",
                )
            ]

        # Format the response
        response = "🧮 **CVSS Score Calculator Results**\n\n"
        response += f"📊 **Base Score:** {result['base_score']} / 10.0\n"
        response += f"⚠️ **Severity:** {result['severity_color']} {result['severity']}\n"
        response += f"📈 **Impact Score:** {result['impact_score']}\n"
        response += f"🎯 **Exploitability Score:** {result['exploitability_score']}\n"
        response += f"🔄 **Scope:** {result['scope'].title()}\n"
        response += f"📋 **CVSS Version:** {metrics['version']}\n\n"

        response += "🔍 **Metric Breakdown:**\n"
        response += f"   • **Attack Vector (AV):** {result['metrics']['attack_vector']['value']} (Score: {result['metrics']['attack_vector']['score']})\n"
        response += f"   • **Attack Complexity (AC):** {result['metrics']['attack_complexity']['value']} (Score: {result['metrics']['attack_complexity']['score']})\n"
        response += f"   • **Privileges Required (PR):** {result['metrics']['privileges_required']['value']} (Score: {result['metrics']['privileges_required']['score']})\n"
        response += f"   • **User Interaction (UI):** {result['metrics']['user_interaction']['value']} (Score: {result['metrics']['user_interaction']['score']})\n"
        response += f"   • **Scope (S):** {result['metrics']['scope']['value']} ({result['metrics']['scope']['description']})\n"
        response += f"   • **Confidentiality (C):** {result['metrics']['confidentiality']['value']} (Score: {result['metrics']['confidentiality']['score']})\n"
        response += f"   • **Integrity (I):** {result['metrics']['integrity']['value']} (Score: {result['metrics']['integrity']['score']})\n"
        response += f"   • **Availability (A):** {result['metrics']['availability']['value']} (Score: {result['metrics']['availability']['score']})\n\n"

        response += "📖 **Metric Meanings:**\n"
        response += "   • **AV** - N:Network, A:Adjacent, L:Local, P:Physical\n"
        response += "   • **AC** - L:Low, H:High\n"
        response += "   • **PR** - N:None, L:Low, H:High\n"
        response += "   • **UI** - N:None, R:Required\n"
        response += "   • **S** - U:Unchanged, C:Changed\n"
        response += "   • **C/I/A** - H:High, L:Low, N:None\n\n"

        response += "🎯 **Severity Ranges:**\n"
        response += "   • 🔴 **CRITICAL:** 9.0 - 10.0\n"
        response += "   • 🟠 **HIGH:** 7.0 - 8.9\n"
        response += "   • 🟡 **MEDIUM:** 4.0 - 6.9\n"
        response += "   • 🟢 **LOW:** 0.1 - 3.9\n"
        response += "   • ⚪ **NONE:** 0.0\n\n"

        response += f"📚 **Original Vector:** `{vector}`\n"
        response += "🌐 **CVSS Specification:** https://www.first.org/cvss/specification-document"

        return [types.TextContent(type="text", text=response)]

    except ValueError as e:
        return [
            types.TextContent(
                type="text",
                text=f"Error: {str(e)}\n\nExample valid vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            )
        ]
    except Exception as e:
        return [
            types.TextContent(
                type="text",
                text=f"Error: Failed to calculate CVSS score: {str(e)}",
            )
        ]
