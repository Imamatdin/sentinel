"""
MCP Tool Registry — Maps Sentinel tools to MCP tool definitions.

Registers both atomic tools (individual scanners) and orchestrator tools
(multi-step workflows). Handlers use lazy imports so the module loads
without requiring every tool dependency.
"""

import uuid

from sentinel.mcp.server import MCPServer, MCPTool, MCPResource


def register_all_tools(server: MCPServer):
    """Register all Sentinel tools with the MCP server."""

    # ---- Atomic Tools ----

    server.register_tool(MCPTool(
        name="run_nmap",
        description=(
            "Run an Nmap port scan against a target host. "
            "Returns open ports, services, and versions."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target IP or hostname",
                },
                "ports": {
                    "type": "string",
                    "description": "Port range (e.g., '1-1000', '80,443,8080')",
                    "default": "1-1000",
                },
                "scan_type": {
                    "type": "string",
                    "enum": ["tcp_syn", "tcp_connect", "udp"],
                    "default": "tcp_connect",
                },
            },
            "required": ["target"],
        },
        handler=_nmap_handler,
        risk_level="low",
    ))

    server.register_tool(MCPTool(
        name="scan_web_vulns",
        description=(
            "Run vulnerability scanning against a web application URL. "
            "Tests for SQLi, XSS, SSRF, auth bypass, IDOR, and misconfigurations."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "target_url": {
                    "type": "string",
                    "description": "Base URL of the web application",
                },
                "severity_filter": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low"],
                    },
                    "description": "Only return findings at these severity levels",
                    "default": ["critical", "high"],
                },
            },
            "required": ["target_url"],
        },
        handler=_vuln_scan_handler,
        requires_approval=True,
        risk_level="medium",
    ))

    server.register_tool(MCPTool(
        name="check_dependencies",
        description=(
            "Scan a project's dependencies for known CVEs and supply chain risks. "
            "Supports npm, pip, Maven, Go, Ruby, Cargo."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "project_path": {
                    "type": "string",
                    "description": "Path to project root with manifest files",
                },
            },
            "required": ["project_path"],
        },
        handler=_sca_handler,
        risk_level="low",
    ))

    server.register_tool(MCPTool(
        name="test_prompt_injection",
        description=(
            "Test an AI/LLM endpoint for prompt injection vulnerabilities. "
            "Runs 14+ payloads across direct injection, prompt leak, jailbreak, "
            "data exfiltration, and output manipulation categories."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "target_url": {
                    "type": "string",
                    "description": "The AI/chat endpoint URL",
                },
                "input_field": {
                    "type": "string",
                    "description": "JSON field for user input",
                    "default": "message",
                },
                "auth_token": {
                    "type": "string",
                    "description": "Bearer token if required",
                },
            },
            "required": ["target_url"],
        },
        handler=_prompt_injection_handler,
        requires_approval=True,
        risk_level="medium",
    ))

    server.register_tool(MCPTool(
        name="query_attack_graph",
        description=(
            "Query the Neo4j attack graph for a specific engagement. "
            "Returns nodes, edges, attack paths, and risk scores."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "engagement_id": {
                    "type": "string",
                    "description": "Engagement ID to query",
                },
                "query_type": {
                    "type": "string",
                    "enum": [
                        "all_findings", "attack_paths",
                        "critical_nodes", "risk_summary",
                    ],
                    "description": "What to query from the graph",
                },
            },
            "required": ["engagement_id", "query_type"],
        },
        handler=_graph_query_handler,
        risk_level="low",
    ))

    server.register_tool(MCPTool(
        name="get_findings",
        description=(
            "Retrieve verified security findings for an engagement. "
            "Each finding includes severity, evidence, PoC script, "
            "and compliance mappings."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "engagement_id": {"type": "string"},
                "severity_filter": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low"],
                    },
                },
                "category_filter": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Filter by vuln category (sqli, xss, ssrf, etc.)",
                },
            },
            "required": ["engagement_id"],
        },
        handler=_findings_handler,
        risk_level="low",
    ))

    # ---- Orchestrator Tools ----

    server.register_tool(MCPTool(
        name="run_full_pentest",
        description=(
            "Run a complete penetration test: recon -> vulnerability analysis "
            "-> exploitation -> verification -> report. This is a long-running "
            "operation via Temporal workflow. Returns an engagement ID."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL or IP",
                },
                "scope": {
                    "type": "string",
                    "enum": ["web_app", "api", "network", "full"],
                    "description": "What to test",
                    "default": "web_app",
                },
                "risk_tolerance": {
                    "type": "string",
                    "enum": ["safe", "moderate", "aggressive"],
                    "description": "How aggressive the test should be",
                    "default": "moderate",
                },
            },
            "required": ["target"],
        },
        handler=_full_pentest_handler,
        requires_approval=True,
        risk_level="high",
    ))

    server.register_tool(MCPTool(
        name="generate_report",
        description=(
            "Generate a pentest report for a completed engagement. "
            "Includes executive summary, findings, compliance mapping, "
            "and remediation guidance."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "engagement_id": {"type": "string"},
                "format": {
                    "type": "string",
                    "enum": ["pdf", "json", "markdown"],
                    "default": "pdf",
                },
                "include_compliance": {"type": "boolean", "default": True},
            },
            "required": ["engagement_id"],
        },
        handler=_report_handler,
        risk_level="low",
    ))

    # ---- Resources ----

    server.register_resource(MCPResource(
        uri="sentinel://engagements",
        name="Active Engagements",
        description="List of all active and completed pentest engagements",
    ))
    server.register_resource(MCPResource(
        uri="sentinel://attack-graph/{engagement_id}",
        name="Attack Graph",
        description="Neo4j attack graph for a specific engagement",
    ))
    server.register_resource(MCPResource(
        uri="sentinel://blue-team/metrics",
        name="Blue Team Metrics",
        description="Purple team detection rates and WAF rule stats",
    ))

    # ---- Prompt Templates ----

    server.register_prompt(
        name="security_review",
        description="Analyze a codebase for security issues and generate a threat model",
        template=(
            "Review the following code for security vulnerabilities. "
            "For each issue found, provide: severity, description, affected code, "
            "and recommended fix. Use Sentinel's scan_web_vulns and "
            "check_dependencies tools to validate findings.\n\n"
            "Code to review:\n{code}"
        ),
        arguments=[
            {"name": "code", "description": "Code to review", "required": True}
        ],
    )
    server.register_prompt(
        name="incident_response",
        description=(
            "Investigate a potential security incident using "
            "Sentinel's attack graph"
        ),
        template=(
            "A security alert has been triggered: {alert_description}. "
            "Use query_attack_graph to check for related attack paths and "
            "get_findings to identify confirmed vulnerabilities. "
            "Provide a timeline and impact assessment."
        ),
        arguments=[
            {
                "name": "alert_description",
                "description": "Description of the alert",
                "required": True,
            }
        ],
    )


# ---- Handler implementations (lazy-import actual tools) ----

async def _nmap_handler(
    target: str, ports: str = "1-1000", scan_type: str = "tcp_connect"
) -> dict:
    from sentinel.tools.nmap_tool import NmapTool
    tool = NmapTool()
    result = await tool.execute(target=target, ports=ports, scan_type=scan_type)
    return result.data if hasattr(result, "data") else {"raw": str(result)}


async def _vuln_scan_handler(
    target_url: str, severity_filter: list | None = None
) -> dict:
    return {
        "status": "scan_started",
        "target": target_url,
        "severity_filter": severity_filter,
    }


async def _sca_handler(project_path: str) -> dict:
    from sentinel.tools.supply_chain.sca_scanner import SCAScanner
    scanner = SCAScanner()
    result = await scanner.execute(project_path)
    return result.data if hasattr(result, "data") else {"raw": str(result)}


async def _prompt_injection_handler(
    target_url: str,
    input_field: str = "message",
    auth_token: str | None = None,
) -> dict:
    from sentinel.tools.ai_security.prompt_injection import PromptInjectionTester
    tester = PromptInjectionTester()
    result = await tester.execute(
        target_url=target_url, input_field=input_field, auth_token=auth_token
    )
    return result.data if hasattr(result, "data") else {"raw": str(result)}


async def _graph_query_handler(
    engagement_id: str, query_type: str
) -> dict:
    return {
        "engagement_id": engagement_id,
        "query_type": query_type,
        "results": [],
    }


async def _findings_handler(
    engagement_id: str,
    severity_filter: list | None = None,
    category_filter: list | None = None,
) -> dict:
    return {"engagement_id": engagement_id, "findings": []}


async def _full_pentest_handler(
    target: str,
    scope: str = "web_app",
    risk_tolerance: str = "moderate",
) -> dict:
    engagement_id = f"eng-{uuid.uuid4().hex[:8]}"
    return {
        "engagement_id": engagement_id,
        "status": "started",
        "target": target,
        "scope": scope,
    }


async def _report_handler(
    engagement_id: str,
    format: str = "pdf",
    include_compliance: bool = True,
) -> dict:
    return {
        "engagement_id": engagement_id,
        "format": format,
        "status": "generating",
    }
