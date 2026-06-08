import anyio
import click
import mcp.types as types
from mcp.server.lowlevel import Server

# Import tools from modules
from .tools.cve_lookup import lookup_cve
from .tools.cvss_calculator import calculate_cvss_score
from .tools.epss_lookup import get_epss_score
from .tools.exploit_availability import get_exploit_availability
from .tools.package_vulnerability import check_package_vulnerabilities
from .tools.vex_status import get_vex_status
from .tools.vulnerability_search import search_vulnerabilities
from .tools.vulnerability_timeline import get_vulnerability_timeline


@click.command()
@click.option("--port", default=8000, help="Port to listen on for SSE")
@click.option(
    "--transport",
    type=click.Choice(["stdio", "sse"]),
    default="stdio",
    help="Transport type",
)
def main(port: int, transport: str) -> int:
    app = Server("mcp-vulnerability-checker")

    # Tool descriptions
    cve_description: str = (
        "Lookup detailed information about a CVE (Common Vulnerabilities and Exposures) "
        "from the National Vulnerability Database. Provide a CVE ID in the format "
        "CVE-YYYY-NNNN (e.g., CVE-2021-44228 for Log4Shell). Returns comprehensive "
        "vulnerability details including CVSS scores, descriptions, references, and "
        "associated weaknesses to help engineers understand security implications."
    )


    epss_description: str = (
        "Get Exploit Prediction Scoring System (EPSS) scores for a CVE to assess "
        "the probability of exploitation in the wild within 30 days. Provide a CVE ID "
        "in the format CVE-YYYY-NNNN (e.g., CVE-2021-44228). Returns AI-powered risk "
        "prioritization scores with percentile rankings to help security teams focus "
        "on vulnerabilities most likely to be exploited by attackers."
    )

    cvss_description: str = (
        "Calculate CVSS (Common Vulnerability Scoring System) base scores from vector "
        "strings to assess vulnerability severity. Provide a CVSS vector string in the "
        "format CVSS:x.x/AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X (e.g., "
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H). Supports CVSS v3.0 and v3.1 "
        "with detailed metric breakdown and severity level mapping."
    )

    vuln_search_description: str = (
        "Search vulnerability databases with advanced filtering capabilities to find "
        "relevant security threats. Filter by keywords (e.g., 'apache', 'sql injection'), "
        "severity levels (CRITICAL, HIGH, MEDIUM, LOW), and date ranges (30d, 90d, 1y, 2y). "
        "Enables comprehensive threat research and vulnerability landscape analysis across "
        "multiple CVE and vulnerability databases."
    )

    exploit_description: str = (
        "Check for public exploits and proof-of-concepts (PoCs) for a CVE across multiple "
        "sources including ExploitDB, Metasploit, GitHub, and NVD references. Provide a "
        "CVE ID in the format CVE-YYYY-NNNN (e.g., CVE-2021-44228). Returns threat "
        "intelligence about exploit availability, active exploitation indicators, and "
        "weaponization status to assess immediate risk."
    )

    timeline_description: str = (
        "Get comprehensive timeline and patch status information for a vulnerability "
        "including publication dates, disclosure timeline, patch availability, vendor "
        "advisories, and remediation guidance. Provide a CVE ID in the format "
        "CVE-YYYY-NNNN (e.g., CVE-2021-44228). Essential for understanding vulnerability "
        "lifecycle and planning patch management strategies."
    )

    vex_description: str = (
        "Check Vulnerability Exploitability eXchange (VEX) status for specific products "
        "to determine actual impact and exploitability. Provide a CVE ID in format "
        "CVE-YYYY-NNNN and optionally a product name (e.g., 'Windows 11', 'RHEL 8', "
        "'Apache HTTP Server'). Returns vendor-provided exploitability statements, "
        "false positive filtering, and product-specific impact assessment."
    )

    @app.call_tool()
    async def fetch_tool(  # type: ignore[unused-function]
        name: str, arguments: dict
    ) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
        if name == "cve_lookup":
            if "cve_id" not in arguments:
                return [
                    types.TextContent(
                        type="text", text="Error: Missing required argument 'cve_id'"
                    )
                ]
            return await lookup_cve(arguments["cve_id"])
        elif name == "package_vulnerability_check":
            if "package_name" not in arguments:
                return [
                    types.TextContent(
                        type="text",
                        text="Error: Missing required argument 'package_name'",
                    )
                ]
            version = arguments.get("version")  # Optional parameter
            return await check_package_vulnerabilities(
                arguments["package_name"], version
            )
        elif name == "get_epss_score":
            if "cve_id" not in arguments:
                return [
                    types.TextContent(
                        type="text", text="Error: Missing required argument 'cve_id'"
                    )
                ]
            return await get_epss_score(arguments["cve_id"])
        elif name == "calculate_cvss_score":
            if "vector" not in arguments:
                return [
                    types.TextContent(
                        type="text", text="Error: Missing required argument 'vector'"
                    )
                ]
            return await calculate_cvss_score(arguments["vector"])
        elif name == "search_vulnerabilities":
            # All parameters are optional for search
            keywords = arguments.get("keywords")
            severity = arguments.get("severity")
            date_range = arguments.get("date_range")
            return await search_vulnerabilities(keywords, severity, date_range)
        elif name == "get_exploit_availability":
            if "cve_id" not in arguments:
                return [
                    types.TextContent(
                        type="text", text="Error: Missing required argument 'cve_id'"
                    )
                ]
            return await get_exploit_availability(arguments["cve_id"])
        elif name == "get_vulnerability_timeline":
            if "cve_id" not in arguments:
                return [
                    types.TextContent(
                        type="text", text="Error: Missing required argument 'cve_id'"
                    )
                ]
            return await get_vulnerability_timeline(arguments["cve_id"])
        elif name == "get_vex_status":
            if "cve_id" not in arguments:
                return [
                    types.TextContent(
                        type="text", text="Error: Missing required argument 'cve_id'"
                    )
                ]
            product = arguments.get("product")  # Optional parameter
            return await get_vex_status(arguments["cve_id"], product)
        else:
            return [types.TextContent(type="text", text=f"Error: Unknown tool: {name}")]

    @app.list_tools()
    async def list_tools() -> list[types.Tool]:  # type: ignore[unused-function]
        return [
            types.Tool(
                name="cve_lookup",
                description="Lookup CVE vulnerability information from the National Vulnerability Database",
                inputSchema={
                    "type": "object",
                    "required": ["cve_id"],
                    "properties": {
                        "cve_id": {
                            "type": "string",
                            "description": cve_description,
                        }
                    },
                },
            ),
            types.Tool(
                name="package_vulnerability_check",
                description="Check for known vulnerabilities in Python packages using OSV database",
                inputSchema={
                    "type": "object",
                    "required": ["package_name"],
                    "properties": {
                        "package_name": {
                            "type": "string",
                            "description": "Name of the Python package to check for vulnerabilities (e.g., 'requests', 'django', 'flask')",
                        },
                        "version": {
                            "type": "string",
                            "description": "Specific version to check (optional). If not provided, checks all known versions.",
                        },
                    },
                },
            ),
            types.Tool(
                name="get_epss_score",
                description="Get EPSS exploitability prediction score for a CVE",
                inputSchema={
                    "type": "object",
                    "required": ["cve_id"],
                    "properties": {
                        "cve_id": {
                            "type": "string",
                            "description": epss_description,
                        }
                    },
                },
            ),
            types.Tool(
                name="calculate_cvss_score",
                description="Calculate CVSS base score from vector string",
                inputSchema={
                    "type": "object",
                    "required": ["vector"],
                    "properties": {
                        "vector": {
                            "type": "string",
                            "description": cvss_description,
                        }
                    },
                },
            ),
            types.Tool(
                name="search_vulnerabilities",
                description="Search vulnerability databases with advanced filtering",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "keywords": {
                            "type": "string",
                            "description": vuln_search_description,
                        },
                        "severity": {
                            "type": "string",
                            "description": "Filter by severity level: CRITICAL, HIGH, MEDIUM, LOW, NONE",
                        },
                        "date_range": {
                            "type": "string",
                            "description": "Date range filter. Use predefined ranges (30d, 90d, 1y, 2y) or custom format YYYY-MM-DD,YYYY-MM-DD",
                        },
                    },
                },
            ),
            types.Tool(
                name="get_exploit_availability",
                description="Check for public exploits and PoCs for a CVE",
                inputSchema={
                    "type": "object",
                    "required": ["cve_id"],
                    "properties": {
                        "cve_id": {
                            "type": "string",
                            "description": exploit_description,
                        }
                    },
                },
            ),
            types.Tool(
                name="get_vulnerability_timeline",
                description="Get vulnerability timeline and patch status information",
                inputSchema={
                    "type": "object",
                    "required": ["cve_id"],
                    "properties": {
                        "cve_id": {
                            "type": "string",
                            "description": timeline_description,
                        }
                    },
                },
            ),
            types.Tool(
                name="get_vex_status",
                description="Check VEX vulnerability status for specific products",
                inputSchema={
                    "type": "object",
                    "required": ["cve_id"],
                    "properties": {
                        "cve_id": {
                            "type": "string",
                            "description": vex_description,
                        },
                        "product": {
                            "type": "string",
                            "description": "Product name or identifier to check VEX status for (optional). Examples: 'Windows 11', 'RHEL 8', 'Ubuntu 22.04', 'Apache HTTP Server'",
                        },
                    },
                },
            ),
        ]

    if transport == "sse":
        from mcp.server.sse import SseServerTransport
        from starlette.applications import Starlette
        from starlette.routing import Mount, Route

        sse = SseServerTransport("/messages/")

        async def handle_sse(request):
            async with sse.connect_sse(
                request.scope, request.receive, request._send
            ) as streams:
                await app.run(
                    streams[0], streams[1], app.create_initialization_options()
                )

        starlette_app = Starlette(
            debug=True,
            routes=[
                Route("/sse", endpoint=handle_sse),
                Mount("/messages/", app=sse.handle_post_message),
            ],
        )

        import uvicorn

        uvicorn.run(starlette_app, host="0.0.0.0", port=port)
    else:
        from mcp.server.stdio import stdio_server

        async def arun():
            async with stdio_server() as streams:
                await app.run(
                    streams[0], streams[1], app.create_initialization_options()
                )

        anyio.run(arun)

    return 0
