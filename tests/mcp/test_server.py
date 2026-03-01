"""Tests for MCP Server."""

import json
import pytest

from sentinel.mcp.server import MCPServer, MCPTool, MCPResource


class TestMCPServer:
    def setup_method(self):
        self.server = MCPServer()

    @pytest.mark.asyncio
    async def test_initialize(self):
        msg = json.dumps({
            "jsonrpc": "2.0", "id": 1,
            "method": "initialize", "params": {},
        })
        resp = json.loads(await self.server.handle_message(msg))
        assert resp["result"]["serverInfo"]["name"] == "sentinel-pentest"
        assert "sessionId" in resp["result"]
        assert resp["result"]["protocolVersion"] == "2024-11-05"

    @pytest.mark.asyncio
    async def test_initialize_with_engagement(self):
        msg = json.dumps({
            "jsonrpc": "2.0", "id": 1,
            "method": "initialize",
            "params": {"engagement_id": "eng-abc", "user_id": "tester"},
        })
        resp = json.loads(await self.server.handle_message(msg))
        session_id = resp["result"]["sessionId"]
        assert self.server.sessions[session_id].engagement_id == "eng-abc"
        assert self.server.sessions[session_id].user_id == "tester"

    @pytest.mark.asyncio
    async def test_tools_list_empty(self):
        msg = json.dumps({
            "jsonrpc": "2.0", "id": 2,
            "method": "tools/list", "params": {},
        })
        resp = json.loads(await self.server.handle_message(msg))
        assert resp["result"]["tools"] == []

    @pytest.mark.asyncio
    async def test_tools_list_with_tool(self):
        async def dummy(**kw):
            return {"ok": True}

        self.server.register_tool(MCPTool(
            name="test_tool", description="A test",
            input_schema={"type": "object"}, handler=dummy,
        ))
        msg = json.dumps({
            "jsonrpc": "2.0", "id": 2,
            "method": "tools/list", "params": {},
        })
        resp = json.loads(await self.server.handle_message(msg))
        tools = resp["result"]["tools"]
        assert len(tools) == 1
        assert tools[0]["name"] == "test_tool"

    @pytest.mark.asyncio
    async def test_tools_call(self):
        async def echo(message: str = "hello"):
            return {"echo": message}

        self.server.register_tool(MCPTool(
            name="echo", description="Echo",
            input_schema={"type": "object"}, handler=echo,
        ))
        msg = json.dumps({
            "jsonrpc": "2.0", "id": 3,
            "method": "tools/call",
            "params": {"name": "echo", "arguments": {"message": "test"}},
        })
        resp = json.loads(await self.server.handle_message(msg))
        assert resp["result"]["isError"] is False
        content = json.loads(resp["result"]["content"][0]["text"])
        assert content["echo"] == "test"

    @pytest.mark.asyncio
    async def test_unknown_tool_error(self):
        msg = json.dumps({
            "jsonrpc": "2.0", "id": 4,
            "method": "tools/call",
            "params": {"name": "nonexistent", "arguments": {}},
        })
        resp = json.loads(await self.server.handle_message(msg))
        assert "error" in resp

    @pytest.mark.asyncio
    async def test_unknown_method_error(self):
        msg = json.dumps({
            "jsonrpc": "2.0", "id": 5,
            "method": "fake/method", "params": {},
        })
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
        msg = json.dumps({
            "jsonrpc": "2.0", "id": 6,
            "method": "resources/list", "params": {},
        })
        resp = json.loads(await self.server.handle_message(msg))
        assert len(resp["result"]["resources"]) == 1
        assert resp["result"]["resources"][0]["uri"] == "test://resource"

    @pytest.mark.asyncio
    async def test_resources_read_unknown(self):
        msg = json.dumps({
            "jsonrpc": "2.0", "id": 7,
            "method": "resources/read",
            "params": {"uri": "unknown://thing"},
        })
        resp = json.loads(await self.server.handle_message(msg))
        assert "error" in resp

    @pytest.mark.asyncio
    async def test_prompts_list(self):
        self.server.register_prompt("test", "Test prompt", "Hello {name}")
        msg = json.dumps({
            "jsonrpc": "2.0", "id": 8,
            "method": "prompts/list", "params": {},
        })
        resp = json.loads(await self.server.handle_message(msg))
        prompts = resp["result"]["prompts"]
        assert len(prompts) == 1
        assert prompts[0]["name"] == "test"

    @pytest.mark.asyncio
    async def test_prompts_get(self):
        self.server.register_prompt(
            "greet", "Greeting", "Hello {name}",
            arguments=[{"name": "name", "required": True}],
        )
        msg = json.dumps({
            "jsonrpc": "2.0", "id": 9,
            "method": "prompts/get",
            "params": {"name": "greet"},
        })
        resp = json.loads(await self.server.handle_message(msg))
        assert resp["result"]["description"] == "Greeting"
        assert "Hello {name}" in resp["result"]["messages"][0]["content"]["text"]

    @pytest.mark.asyncio
    async def test_auth_rejection(self):
        async def reject(token: str) -> bool:
            return False

        self.server.set_auth_validator(reject)
        msg = json.dumps({
            "jsonrpc": "2.0", "id": 10,
            "method": "tools/list", "params": {},
        })
        resp = json.loads(
            await self.server.handle_message(msg, auth_token="bad-token")
        )
        assert resp["error"]["code"] == -32001

    @pytest.mark.asyncio
    async def test_tool_call_tracks_usage(self):
        async def noop():
            return "ok"

        self.server.register_tool(MCPTool(
            name="tracker", description="Track",
            input_schema={"type": "object"}, handler=noop,
        ))
        # Create a session first
        init_msg = json.dumps({
            "jsonrpc": "2.0", "id": 1,
            "method": "initialize", "params": {},
        })
        await self.server.handle_message(init_msg)

        call_msg = json.dumps({
            "jsonrpc": "2.0", "id": 2,
            "method": "tools/call",
            "params": {"name": "tracker", "arguments": {}},
        })
        await self.server.handle_message(call_msg)

        session = list(self.server.sessions.values())[0]
        assert "tracker" in session.tools_called
