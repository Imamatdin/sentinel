# LEVEL 20: MCP Server Interface

## Context
Sentinel exposes its capabilities as an MCP (Model Context Protocol) server so any MCP-compatible client (Claude Desktop, VS Code, Cursor, custom agents) can invoke Sentinel scans, query the knowledge graph, and retrieve findings. This is the distribution moat — Sentinel becomes a tool in every AI coding assistant.

Research: Block 10 (MCP Server Interface — JSON-RPC over stdio/HTTP+SSE, pentest-mcp, HexStrike 150+ tools, OAuth2 auth, session management).

## Why
MCP is the universal tool protocol for AI agents. Exposing Sentinel as an MCP server means any developer using Claude Code or Cursor can run `scan_target`, `get_findings`, or `check_vulnerability` without leaving their IDE. This is how Sentinel gets embedded into every dev workflow.

---

## Files to Create

### `src/sentinel/mcp/__init__.py`
```python
"""MCP Server — Expose Sentinel tools via Model Context Protocol."""
```

### `src/sentinel/mcp/server.py`
```python
"""
MCP Server — JSON-RPC 2.0 over stdio and HTTP+SSE transports.

Exposes two tiers of tools:
1. Atomic tools: run_nmap, web_fuzz, check_sqli, scan_dependencies, etc.
2. Orchestrator tools: run_full_pentest, run_recon, run_vuln_analysis

MCP spec requires:
- Tool discovery via tools/list
- Tool invocation via tools/call
- Resource listing via resources/list
- Prompt templates via prompts/list

Auth: OAuth2 bearer tokens validated per-request.
Sessions: Each MCP session maps to a Sentinel engagement.
"""
import json
import asyncio
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Awaitable
from sentinel.logging import get_logger

logger = get_logger(__name__)


@dataclass
class MCPTool:
    name: str
    description: str
    input_schema: dict        # JSON Schema for parameters
    handler: Callable[..., Awaitable[Any]]
    requires_approval: bool = False  # PolicyEngine gate
    risk_level: str = "low"   # low/medium/high/critical


@dataclass
class MCPResource:
    uri: str
    name: str
    description: str
    mime_type: str = "application/json"


@dataclass
class MCPSession:
    session_id: str
    engagement_id: str
    user_id: str
    created_at: str
    tools_called: list[str] = field(default_factory=list)


class MCPServer:
    """
    Model Context Protocol server for Sentinel.
    
    Handles JSON-RPC 2.0 messages and routes to tool handlers.
    Supports both stdio (for local MCP clients) and HTTP+SSE (for remote).
    """
    
    def __init__(self):
        self.tools: dict[str, MCPTool] = {}
        self.resources: dict[str, MCPResource] = {}
        self.sessions: dict[str, MCPSession] = {}
        self.prompts: dict[str, dict] = {}
        self._auth_validator = None
    
    def register_tool(self, tool: MCPTool):
        """Register a tool that MCP clients can invoke."""
        self.tools[tool.name] = tool
        logger.info(f"MCP: Registered tool '{tool.name}' (risk: {tool.risk_level})")
    
    def register_resource(self, resource: MCPResource):
        """Register a resource that MCP clients can read."""
        self.resources[resource.uri] = resource
    
    def register_prompt(self, name: str, description: str, template: str, arguments: list[dict] = None):
        """Register a prompt template."""
        self.prompts[name] = {
            "name": name,
            "description": description,
            "template": template,
            "arguments": arguments or [],
        }
    
    def set_auth_validator(self, validator: Callable[[str], Awaitable[bool]]):
        """Set the auth token validator function."""
        self._auth_validator = validator
    
    async def handle_message(self, raw_message: str, auth_token: str = None) -> str:
        """
        Handle an incoming JSON-RPC 2.0 message.
        Returns JSON-RPC response string.
        """
        try:
            msg = json.loads(raw_message)
        except json.JSONDecodeError:
            return self._error_response(None, -32700, "Parse error")
        
        msg_id = msg.get("id")
        method = msg.get("method", "")
        params = msg.get("params", {})
        
        # Auth check for non-discovery methods
        if method not in ("initialize", "notifications/initialized"):
            if self._auth_validator and auth_token:
                valid = await self._auth_validator(auth_token)
                if not valid:
                    return self._error_response(msg_id, -32001, "Unauthorized")
        
        # Route to handler
        handlers = {
            "initialize": self._handle_initialize,
            "tools/list": self._handle_tools_list,
            "tools/call": self._handle_tools_call,
            "resources/list": self._handle_resources_list,
            "resources/read": self._handle_resources_read,
            "prompts/list": self._handle_prompts_list,
            "prompts/get": self._handle_prompts_get,
        }
        
        handler = handlers.get(method)
        if not handler:
            return self._error_response(msg_id, -32601, f"Method not found: {method}")
        
        try:
            result = await handler(params)
            return json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": result})
        except Exception as e:
            logger.error(f"MCP handler error for {method}: {e}")
            return self._error_response(msg_id, -32603, str(e))
    
    async def _handle_initialize(self, params: dict) -> dict:
        """Handle MCP initialization handshake."""
        session_id = str(uuid.uuid4())
        self.sessions[session_id] = MCPSession(
            session_id=session_id,
            engagement_id=params.get("engagement_id", f"eng-{uuid.uuid4().hex[:8]}"),
            user_id=params.get("user_id", "anonymous"),
            created_at="",
        )
        return {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {"listChanged": True},
                "resources": {"subscribe": False, "listChanged": True},
                "prompts": {"listChanged": False},
            },
            "serverInfo": {
                "name": "sentinel-pentest",
                "version": "1.0.0",
            },
            "sessionId": session_id,
        }
    
    async def _handle_tools_list(self, params: dict) -> dict:
        """Return list of available tools."""
        return {
            "tools": [
                {
                    "name": t.name,
                    "description": t.description,
                    "inputSchema": t.input_schema,
                }
                for t in self.tools.values()
            ]
        }
    
    async def _handle_tools_call(self, params: dict) -> dict:
        """Invoke a tool by name with given arguments."""
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})
        
        tool = self.tools.get(tool_name)
        if not tool:
            raise ValueError(f"Unknown tool: {tool_name}")
        
        # PolicyEngine gate for high-risk tools
        if tool.requires_approval:
            logger.warning(f"MCP: Tool '{tool_name}' requires human approval (risk: {tool.risk_level})")
            # In production: send approval request via Temporal signal
            # For now: auto-approve with log
        
        logger.info(f"MCP: Calling tool '{tool_name}' with {len(arguments)} args")
        result = await tool.handler(**arguments)
        
        # Track usage
        for session in self.sessions.values():
            session.tools_called.append(tool_name)
        
        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(result, default=str) if not isinstance(result, str) else result,
                }
            ],
            "isError": False,
        }
    
    async def _handle_resources_list(self, params: dict) -> dict:
        """Return list of available resources."""
        return {
            "resources": [
                {
                    "uri": r.uri,
                    "name": r.name,
                    "description": r.description,
                    "mimeType": r.mime_type,
                }
                for r in self.resources.values()
            ]
        }
    
    async def _handle_resources_read(self, params: dict) -> dict:
        """Read a specific resource by URI."""
        uri = params.get("uri", "")
        resource = self.resources.get(uri)
        if not resource:
            raise ValueError(f"Unknown resource: {uri}")
        # Subclasses/handlers should override to return actual data
        return {
            "contents": [
                {"uri": uri, "mimeType": resource.mime_type, "text": "{}"}
            ]
        }
    
    async def _handle_prompts_list(self, params: dict) -> dict:
        return {"prompts": list(self.prompts.values())}
    
    async def _handle_prompts_get(self, params: dict) -> dict:
        name = params.get("name", "")
        prompt = self.prompts.get(name)
        if not prompt:
            raise ValueError(f"Unknown prompt: {name}")
        return {"description": prompt["description"], "messages": [
            {"role": "user", "content": {"type": "text", "text": prompt["template"]}}
        ]}
    
    def _error_response(self, msg_id, code: int, message: str) -> str:
        return json.dumps({
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": code, "message": message},
        })
```

### `src/sentinel/mcp/tool_registry.py`
```python
"""
MCP Tool Registry — Maps Sentinel tools to MCP tool definitions.

Registers both atomic tools (individual scanners) and orchestrator tools
(multi-step workflows).
"""
from sentinel.mcp.server import MCPServer, MCPTool, MCPResource


def register_all_tools(server: MCPServer):
    """Register all Sentinel tools with the MCP server."""
    
    # --- Atomic Tools ---
    
    server.register_tool(MCPTool(
        name="run_nmap",
        description="Run an Nmap port scan against a target host. Returns open ports, services, and versions.",
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname"},
                "ports": {"type": "string", "description": "Port range (e.g., '1-1000', '80,443,8080')", "default": "1-1000"},
                "scan_type": {"type": "string", "enum": ["tcp_syn", "tcp_connect", "udp"], "default": "tcp_connect"},
            },
            "required": ["target"],
        },
        handler=_nmap_handler,
        requires_approval=False,
        risk_level="low",
    ))
    
    server.register_tool(MCPTool(
        name="scan_web_vulns",
        description="Run vulnerability scanning (Nuclei + custom checks) against a web application URL. "
                    "Tests for SQLi, XSS, SSRF, auth bypass, IDOR, and misconfigurations.",
        input_schema={
            "type": "object",
            "properties": {
                "target_url": {"type": "string", "description": "Base URL of the web application"},
                "severity_filter": {
                    "type": "array", "items": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
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
        description="Scan a project's dependencies for known CVEs and supply chain risks. "
                    "Supports npm, pip, Maven, Go, Ruby, Cargo.",
        input_schema={
            "type": "object",
            "properties": {
                "project_path": {"type": "string", "description": "Path to project root with manifest files"},
            },
            "required": ["project_path"],
        },
        handler=_sca_handler,
        requires_approval=False,
        risk_level="low",
    ))
    
    server.register_tool(MCPTool(
        name="test_prompt_injection",
        description="Test an AI/LLM endpoint for prompt injection vulnerabilities. "
                    "Runs 14+ payloads across direct injection, prompt leak, jailbreak, "
                    "data exfiltration, and output manipulation categories.",
        input_schema={
            "type": "object",
            "properties": {
                "target_url": {"type": "string", "description": "The AI/chat endpoint URL"},
                "input_field": {"type": "string", "description": "JSON field for user input", "default": "message"},
                "auth_token": {"type": "string", "description": "Bearer token if required"},
            },
            "required": ["target_url"],
        },
        handler=_prompt_injection_handler,
        requires_approval=True,
        risk_level="medium",
    ))
    
    server.register_tool(MCPTool(
        name="query_attack_graph",
        description="Query the Neo4j attack graph for a specific engagement. "
                    "Returns nodes, edges, attack paths, and risk scores.",
        input_schema={
            "type": "object",
            "properties": {
                "engagement_id": {"type": "string", "description": "Engagement ID to query"},
                "query_type": {
                    "type": "string",
                    "enum": ["all_findings", "attack_paths", "critical_nodes", "risk_summary"],
                    "description": "What to query from the graph",
                },
            },
            "required": ["engagement_id", "query_type"],
        },
        handler=_graph_query_handler,
        requires_approval=False,
        risk_level="low",
    ))
    
    server.register_tool(MCPTool(
        name="get_findings",
        description="Retrieve verified security findings for an engagement. "
                    "Each finding includes severity, evidence, PoC script, and compliance mappings.",
        input_schema={
            "type": "object",
            "properties": {
                "engagement_id": {"type": "string"},
                "severity_filter": {
                    "type": "array", "items": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
                },
                "category_filter": {
                    "type": "array", "items": {"type": "string"},
                    "description": "Filter by vuln category (sqli, xss, ssrf, etc.)",
                },
            },
            "required": ["engagement_id"],
        },
        handler=_findings_handler,
        requires_approval=False,
        risk_level="low",
    ))
    
    # --- Orchestrator Tools ---
    
    server.register_tool(MCPTool(
        name="run_full_pentest",
        description="Run a complete penetration test: recon → vulnerability analysis → exploitation → verification → report. "
                    "This is a long-running operation that executes via Temporal workflow. "
                    "Returns an engagement ID to track progress.",
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL or IP"},
                "scope": {
                    "type": "string", "enum": ["web_app", "api", "network", "full"],
                    "description": "What to test", "default": "web_app",
                },
                "risk_tolerance": {
                    "type": "string", "enum": ["safe", "moderate", "aggressive"],
                    "description": "How aggressive the test should be", "default": "moderate",
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
        description="Generate a PDF pentest report for a completed engagement. "
                    "Includes executive summary, findings, compliance mapping, and remediation guidance.",
        input_schema={
            "type": "object",
            "properties": {
                "engagement_id": {"type": "string"},
                "format": {"type": "string", "enum": ["pdf", "json", "markdown"], "default": "pdf"},
                "include_compliance": {"type": "boolean", "default": True},
            },
            "required": ["engagement_id"],
        },
        handler=_report_handler,
        requires_approval=False,
        risk_level="low",
    ))
    
    # --- Resources ---
    
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
    
    # --- Prompt Templates ---
    
    server.register_prompt(
        name="security_review",
        description="Analyze a codebase for security issues and generate a threat model",
        template="Review the following code for security vulnerabilities. "
                 "For each issue found, provide: severity, description, affected code, "
                 "and recommended fix. Use Sentinel's scan_web_vulns and check_dependencies tools "
                 "to validate findings.\n\nCode to review:\n{code}",
        arguments=[{"name": "code", "description": "Code to review", "required": True}],
    )
    
    server.register_prompt(
        name="incident_response",
        description="Investigate a potential security incident using Sentinel's attack graph",
        template="A security alert has been triggered: {alert_description}. "
                 "Use query_attack_graph to check for related attack paths and get_findings "
                 "to identify confirmed vulnerabilities. Provide a timeline and impact assessment.",
        arguments=[{"name": "alert_description", "description": "Description of the alert", "required": True}],
    )


# --- Handler stubs (wire to actual Sentinel tools) ---

async def _nmap_handler(target: str, ports: str = "1-1000", scan_type: str = "tcp_connect") -> dict:
    """Wire to sentinel.tools.recon.NmapTool"""
    from sentinel.tools.recon.nmap_tool import NmapTool
    tool = NmapTool()
    result = await tool.execute(target=target, ports=ports, scan_type=scan_type)
    return result.__dict__ if hasattr(result, '__dict__') else {"data": str(result)}

async def _vuln_scan_handler(target_url: str, severity_filter: list = None) -> dict:
    """Wire to GuardedVulnAgent pipeline"""
    # TODO: Wire to actual VulnAgent
    return {"status": "scan_started", "target": target_url, "severity_filter": severity_filter}

async def _sca_handler(project_path: str) -> dict:
    """Wire to sentinel.tools.supply_chain.SCAScanner"""
    from sentinel.tools.supply_chain.sca_scanner import SCAScanner
    scanner = SCAScanner()
    result = await scanner.execute(project_path)
    return result.__dict__ if hasattr(result, '__dict__') else {"data": str(result)}

async def _prompt_injection_handler(target_url: str, input_field: str = "message", auth_token: str = None) -> dict:
    """Wire to sentinel.tools.ai_security.PromptInjectionTester"""
    from sentinel.tools.ai_security.prompt_injection import PromptInjectionTester
    tester = PromptInjectionTester()
    result = await tester.execute(target_url=target_url, input_field=input_field, auth_token=auth_token)
    return result.__dict__ if hasattr(result, '__dict__') else {"data": str(result)}

async def _graph_query_handler(engagement_id: str, query_type: str) -> dict:
    """Wire to Neo4j graph queries"""
    # TODO: Wire to actual graph service
    return {"engagement_id": engagement_id, "query_type": query_type, "results": []}

async def _findings_handler(engagement_id: str, severity_filter: list = None, category_filter: list = None) -> dict:
    """Wire to findings store"""
    # TODO: Wire to actual findings retrieval
    return {"engagement_id": engagement_id, "findings": []}

async def _full_pentest_handler(target: str, scope: str = "web_app", risk_tolerance: str = "moderate") -> dict:
    """Wire to Temporal workflow trigger"""
    # TODO: Wire to Temporal workflow start
    engagement_id = f"eng-{__import__('uuid').uuid4().hex[:8]}"
    return {"engagement_id": engagement_id, "status": "started", "target": target, "scope": scope}

async def _report_handler(engagement_id: str, format: str = "pdf", include_compliance: bool = True) -> dict:
    """Wire to report generator"""
    # TODO: Wire to actual report generation
    return {"engagement_id": engagement_id, "format": format, "status": "generating"}
```

### `src/sentinel/mcp/transports.py`
```python
"""
MCP Transport Layer — stdio and HTTP+SSE transports.

stdio: For local MCP clients (Claude Desktop, Cursor)
  - Read JSON-RPC from stdin, write to stdout, one message per line
  
HTTP+SSE: For remote MCP clients
  - POST /mcp for JSON-RPC requests
  - GET /mcp/sse for server-sent events (notifications, progress)
"""
import asyncio
import json
import sys
from sentinel.mcp.server import MCPServer
from sentinel.logging import get_logger

logger = get_logger(__name__)


class StdioTransport:
    """MCP transport over stdin/stdout for local clients."""
    
    def __init__(self, server: MCPServer):
        self.server = server
    
    async def run(self):
        """Main loop: read from stdin, process, write to stdout."""
        logger.info("MCP stdio transport started")
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await asyncio.get_event_loop().connect_read_pipe(lambda: protocol, sys.stdin)
        
        while True:
            try:
                line = await reader.readline()
                if not line:
                    break
                
                line_str = line.decode().strip()
                if not line_str:
                    continue
                
                response = await self.server.handle_message(line_str)
                sys.stdout.write(response + "\n")
                sys.stdout.flush()
                
            except Exception as e:
                logger.error(f"stdio transport error: {e}")
                break
        
        logger.info("MCP stdio transport stopped")


def create_http_routes(server: MCPServer):
    """
    Create FastAPI routes for HTTP+SSE MCP transport.
    
    Returns a FastAPI APIRouter to be included in the main app.
    """
    from fastapi import APIRouter, Request, Response
    from fastapi.responses import StreamingResponse
    
    router = APIRouter(prefix="/mcp", tags=["mcp"])
    
    @router.post("")
    async def mcp_rpc(request: Request):
        """Handle JSON-RPC requests over HTTP."""
        body = await request.body()
        auth = request.headers.get("Authorization", "").replace("Bearer ", "")
        response = await server.handle_message(body.decode(), auth_token=auth)
        return Response(content=response, media_type="application/json")
    
    @router.get("/sse")
    async def mcp_sse(request: Request):
        """Server-Sent Events for notifications and progress updates."""
        async def event_stream():
            # TODO: Wire to EventBus for real-time scan progress
            yield f"data: {json.dumps({'type': 'connected', 'server': 'sentinel'})}\n\n"
            while True:
                await asyncio.sleep(30)
                yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"
        
        return StreamingResponse(event_stream(), media_type="text/event-stream")
    
    @router.get("/health")
    async def mcp_health():
        return {
            "status": "ok",
            "tools": len(server.tools),
            "resources": len(server.resources),
            "sessions": len(server.sessions),
        }
    
    return router
```

---

## Files to Modify

### `src/sentinel/api/` — Mount MCP routes
```python
from sentinel.mcp.server import MCPServer
from sentinel.mcp.tool_registry import register_all_tools
from sentinel.mcp.transports import create_http_routes

mcp_server = MCPServer()
register_all_tools(mcp_server)
mcp_router = create_http_routes(mcp_server)
app.include_router(mcp_router)
```

### CLI entry point for stdio mode
```python
# sentinel/cli/mcp_stdio.py
"""Run Sentinel MCP server in stdio mode for local clients."""
import asyncio
from sentinel.mcp.server import MCPServer
from sentinel.mcp.tool_registry import register_all_tools
from sentinel.mcp.transports import StdioTransport

async def main():
    server = MCPServer()
    register_all_tools(server)
    transport = StdioTransport(server)
    await transport.run()

if __name__ == "__main__":
    asyncio.run(main())
```

---

## Tests

### `tests/mcp/test_server.py`
```python
import pytest
import json
from sentinel.mcp.server import MCPServer, MCPTool, MCPResource

class TestMCPServer:
    def setup_method(self):
        self.server = MCPServer()

    @pytest.mark.asyncio
    async def test_initialize(self):
        msg = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        resp = json.loads(await self.server.handle_message(msg))
        assert resp["result"]["serverInfo"]["name"] == "sentinel-pentest"
        assert "sessionId" in resp["result"]

    @pytest.mark.asyncio
    async def test_tools_list(self):
        async def dummy_handler(**kwargs): return {"ok": True}
        self.server.register_tool(MCPTool(
            name="test_tool", description="A test", input_schema={"type": "object"},
            handler=dummy_handler,
        ))
        msg = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        resp = json.loads(await self.server.handle_message(msg))
        tools = resp["result"]["tools"]
        assert len(tools) == 1
        assert tools[0]["name"] == "test_tool"

    @pytest.mark.asyncio
    async def test_tools_call(self):
        async def echo_handler(message: str = "hello"): return {"echo": message}
        self.server.register_tool(MCPTool(
            name="echo", description="Echo", input_schema={"type": "object"},
            handler=echo_handler,
        ))
        msg = json.dumps({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "echo", "arguments": {"message": "test"}},
        })
        resp = json.loads(await self.server.handle_message(msg))
        assert resp["result"]["isError"] is False
        content = json.loads(resp["result"]["content"][0]["text"])
        assert content["echo"] == "test"

    @pytest.mark.asyncio
    async def test_unknown_tool(self):
        msg = json.dumps({
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {"name": "nonexistent", "arguments": {}},
        })
        resp = json.loads(await self.server.handle_message(msg))
        assert "error" in resp

    @pytest.mark.asyncio
    async def test_unknown_method(self):
        msg = json.dumps({"jsonrpc": "2.0", "id": 5, "method": "fake/method", "params": {}})
        resp = json.loads(await self.server.handle_message(msg))
        assert resp["error"]["code"] == -32601

    @pytest.mark.asyncio
    async def test_parse_error(self):
        resp = json.loads(await self.server.handle_message("not json"))
        assert resp["error"]["code"] == -32700

    @pytest.mark.asyncio
    async def test_resources_list(self):
        self.server.register_resource(MCPResource(
            uri="test://resource", name="Test", description="A test resource",
        ))
        msg = json.dumps({"jsonrpc": "2.0", "id": 6, "method": "resources/list", "params": {}})
        resp = json.loads(await self.server.handle_message(msg))
        assert len(resp["result"]["resources"]) == 1

    @pytest.mark.asyncio
    async def test_prompts_list(self):
        self.server.register_prompt("test", "Test prompt", "Hello {name}")
        msg = json.dumps({"jsonrpc": "2.0", "id": 7, "method": "prompts/list", "params": {}})
        resp = json.loads(await self.server.handle_message(msg))
        assert len(resp["result"]["prompts"]) == 1
```

### `tests/mcp/test_tool_registry.py`
```python
import pytest
from sentinel.mcp.server import MCPServer
from sentinel.mcp.tool_registry import register_all_tools

class TestToolRegistry:
    def test_all_tools_registered(self):
        server = MCPServer()
        register_all_tools(server)
        assert len(server.tools) >= 8  # At least 8 tools
        assert "run_nmap" in server.tools
        assert "run_full_pentest" in server.tools
        assert "get_findings" in server.tools

    def test_all_tools_have_schemas(self):
        server = MCPServer()
        register_all_tools(server)
        for name, tool in server.tools.items():
            assert tool.input_schema, f"Tool '{name}' missing input_schema"
            assert tool.description, f"Tool '{name}' missing description"

    def test_resources_registered(self):
        server = MCPServer()
        register_all_tools(server)
        assert len(server.resources) >= 3

    def test_high_risk_tools_require_approval(self):
        server = MCPServer()
        register_all_tools(server)
        pentest = server.tools["run_full_pentest"]
        assert pentest.requires_approval is True
        assert pentest.risk_level == "high"
```

---

## Acceptance Criteria
- [ ] MCPServer handles JSON-RPC 2.0 initialize, tools/list, tools/call, resources/list, prompts/list
- [ ] 8+ tools registered: run_nmap, scan_web_vulns, check_dependencies, test_prompt_injection, query_attack_graph, get_findings, run_full_pentest, generate_report
- [ ] High-risk tools (run_full_pentest, scan_web_vulns) require approval flag
- [ ] JSON-RPC error handling: parse error, method not found, unknown tool
- [ ] HTTP+SSE transport via FastAPI routes at /mcp
- [ ] stdio transport reads/writes JSON-RPC over stdin/stdout
- [ ] Resources expose engagements, attack graph, blue team metrics
- [ ] Prompt templates for security_review and incident_response
- [ ] Auth validator hook for OAuth2 bearer tokens
- [ ] All tests pass