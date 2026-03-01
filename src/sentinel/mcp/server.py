"""
MCP Server — JSON-RPC 2.0 message handler for Model Context Protocol.

Exposes two tiers of tools:
1. Atomic tools: run_nmap, scan_web_vulns, check_dependencies, etc.
2. Orchestrator tools: run_full_pentest, run_recon, run_vuln_analysis

MCP spec compliance:
- Tool discovery via tools/list
- Tool invocation via tools/call
- Resource listing via resources/list
- Prompt templates via prompts/list and prompts/get

Auth: OAuth2 bearer tokens validated per-request via configurable hook.
Sessions: Each MCP session maps to a Sentinel engagement.
"""

import json
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Awaitable

from sentinel.core import get_logger

logger = get_logger(__name__)


@dataclass
class MCPTool:
    name: str
    description: str
    input_schema: dict
    handler: Callable[..., Awaitable[Any]]
    requires_approval: bool = False
    risk_level: str = "low"


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

    Handles JSON-RPC 2.0 messages and routes to registered tool handlers.
    Supports both stdio (for local MCP clients) and HTTP+SSE (for remote).
    """

    PROTOCOL_VERSION = "2024-11-05"
    SERVER_NAME = "sentinel-pentest"
    SERVER_VERSION = "1.0.0"

    def __init__(self):
        self.tools: dict[str, MCPTool] = {}
        self.resources: dict[str, MCPResource] = {}
        self.sessions: dict[str, MCPSession] = {}
        self.prompts: dict[str, dict] = {}
        self._auth_validator: Callable[[str], Awaitable[bool]] | None = None

    def register_tool(self, tool: MCPTool):
        self.tools[tool.name] = tool
        logger.info("mcp_tool_registered", tool=tool.name, risk=tool.risk_level)

    def register_resource(self, resource: MCPResource):
        self.resources[resource.uri] = resource

    def register_prompt(
        self,
        name: str,
        description: str,
        template: str,
        arguments: list[dict] | None = None,
    ):
        self.prompts[name] = {
            "name": name,
            "description": description,
            "template": template,
            "arguments": arguments or [],
        }

    def set_auth_validator(self, validator: Callable[[str], Awaitable[bool]]):
        self._auth_validator = validator

    async def handle_message(
        self, raw_message: str, auth_token: str | None = None
    ) -> str:
        """Handle an incoming JSON-RPC 2.0 message. Returns JSON-RPC response."""
        try:
            msg = json.loads(raw_message)
        except json.JSONDecodeError:
            return self._error_response(None, -32700, "Parse error")

        msg_id = msg.get("id")
        method = msg.get("method", "")
        params = msg.get("params", {})

        # Auth check for non-initialization methods
        if method not in ("initialize", "notifications/initialized"):
            if self._auth_validator and auth_token:
                valid = await self._auth_validator(auth_token)
                if not valid:
                    return self._error_response(msg_id, -32001, "Unauthorized")

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
            return self._error_response(
                msg_id, -32601, f"Method not found: {method}"
            )

        try:
            result = await handler(params)
            return json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": result})
        except Exception as e:
            logger.error("mcp_handler_error", method=method, error=str(e))
            return self._error_response(msg_id, -32603, str(e))

    async def _handle_initialize(self, params: dict) -> dict:
        session_id = str(uuid.uuid4())
        self.sessions[session_id] = MCPSession(
            session_id=session_id,
            engagement_id=params.get(
                "engagement_id", f"eng-{uuid.uuid4().hex[:8]}"
            ),
            user_id=params.get("user_id", "anonymous"),
            created_at="",
        )
        return {
            "protocolVersion": self.PROTOCOL_VERSION,
            "capabilities": {
                "tools": {"listChanged": True},
                "resources": {"subscribe": False, "listChanged": True},
                "prompts": {"listChanged": False},
            },
            "serverInfo": {
                "name": self.SERVER_NAME,
                "version": self.SERVER_VERSION,
            },
            "sessionId": session_id,
        }

    async def _handle_tools_list(self, params: dict) -> dict:
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
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})

        tool = self.tools.get(tool_name)
        if not tool:
            raise ValueError(f"Unknown tool: {tool_name}")

        if tool.requires_approval:
            logger.warning(
                "mcp_approval_required",
                tool=tool_name,
                risk=tool.risk_level,
            )

        logger.info("mcp_tool_call", tool=tool_name, arg_count=len(arguments))
        result = await tool.handler(**arguments)

        for session in self.sessions.values():
            session.tools_called.append(tool_name)

        text = (
            json.dumps(result, default=str)
            if not isinstance(result, str)
            else result
        )
        return {"content": [{"type": "text", "text": text}], "isError": False}

    async def _handle_resources_list(self, params: dict) -> dict:
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
        uri = params.get("uri", "")
        resource = self.resources.get(uri)
        if not resource:
            raise ValueError(f"Unknown resource: {uri}")
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
        return {
            "description": prompt["description"],
            "messages": [
                {
                    "role": "user",
                    "content": {"type": "text", "text": prompt["template"]},
                }
            ],
        }

    def _error_response(self, msg_id: Any, code: int, message: str) -> str:
        return json.dumps({
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": code, "message": message},
        })
