"""Tests for MCP Tool Registry."""

from sentinel.mcp.server import MCPServer
from sentinel.mcp.tool_registry import register_all_tools


class TestToolRegistry:
    def test_all_tools_registered(self):
        server = MCPServer()
        register_all_tools(server)
        assert len(server.tools) >= 8
        assert "run_nmap" in server.tools
        assert "scan_web_vulns" in server.tools
        assert "check_dependencies" in server.tools
        assert "test_prompt_injection" in server.tools
        assert "query_attack_graph" in server.tools
        assert "get_findings" in server.tools
        assert "run_full_pentest" in server.tools
        assert "generate_report" in server.tools

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

    def test_prompts_registered(self):
        server = MCPServer()
        register_all_tools(server)
        assert "security_review" in server.prompts
        assert "incident_response" in server.prompts

    def test_high_risk_tools_require_approval(self):
        server = MCPServer()
        register_all_tools(server)
        pentest = server.tools["run_full_pentest"]
        assert pentest.requires_approval is True
        assert pentest.risk_level == "high"

    def test_vuln_scan_requires_approval(self):
        server = MCPServer()
        register_all_tools(server)
        vuln = server.tools["scan_web_vulns"]
        assert vuln.requires_approval is True

    def test_low_risk_tools_no_approval(self):
        server = MCPServer()
        register_all_tools(server)
        nmap = server.tools["run_nmap"]
        assert nmap.requires_approval is False
        assert nmap.risk_level == "low"
