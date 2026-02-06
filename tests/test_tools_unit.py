"""Unit tests for SENTINEL security tools."""

import asyncio
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from sentinel.tools import (
    ToolExecutor,
    create_red_team_executor,
    create_blue_team_executor,
)
from sentinel.tools.base import ToolOutput
from sentinel.tools.blue.monitor import NetworkMonitor, RequestLog
from sentinel.tools.blue.waf import WAFEngine


# === ToolExecutor Tests ===

def test_create_red_team_executor():
    """Red team executor should register all expected tools."""
    executor, registry = create_red_team_executor()
    tools = registry.list_tools()

    assert "http_request" in tools
    assert "port_scan" in tools
    assert "path_scan" in tools
    assert "sql_injection_test" in tools
    assert "xss_test" in tools
    assert "login_attempt" in tools
    assert "idor_test" in tools
    assert "api_discover" in tools
    assert "check_challenges" in tools


def test_create_blue_team_executor():
    """Blue team executor should register all defense tools."""
    executor, registry = create_blue_team_executor()
    tools = registry.list_tools()

    assert "get_network_logs" in tools
    assert "analyze_attack_pattern" in tools
    assert "deploy_waf_rule" in tools
    assert "get_waf_status" in tools
    assert "log_defense_action" in tools


@pytest.mark.asyncio
async def test_executor_unknown_tool():
    """Executor should handle unknown tool names gracefully."""
    executor = ToolExecutor()
    result = await executor.execute_tool("nonexistent_tool", {})
    assert not result.success
    assert "Unknown tool" in result.error


def test_tool_schemas_valid():
    """All tool schemas should be valid OpenAI function calling format."""
    _, registry = create_red_team_executor()
    schemas = registry.get_schemas()

    for schema in schemas:
        assert schema["type"] == "function"
        assert "name" in schema["function"]
        assert "description" in schema["function"]
        assert "parameters" in schema["function"]
        assert schema["function"]["parameters"]["type"] == "object"
        # strict mode must be enabled for Cerebras
        assert schema["function"].get("strict") is True


# === NetworkMonitor Tests ===

def test_monitor_flags_sqli():
    """Monitor should flag SQL injection patterns."""
    monitor = NetworkMonitor()
    request = RequestLog(
        timestamp=1000.0,
        source_ip="10.0.0.1",
        method="GET",
        path="/api/search",
        query_string="q=' OR 1=1--",
        headers={},
        body="",
    )
    monitor.log_request(request)

    assert request.flagged
    assert any("sqli" in r for r in request.flag_reasons)


def test_monitor_flags_xss():
    """Monitor should flag XSS patterns."""
    monitor = NetworkMonitor()
    request = RequestLog(
        timestamp=1000.0,
        source_ip="10.0.0.1",
        method="POST",
        path="/api/feedback",
        query_string="",
        headers={},
        body='<script>alert("xss")</script>',
    )
    monitor.log_request(request)

    assert request.flagged
    assert any("xss" in r for r in request.flag_reasons)


def test_monitor_normal_traffic_not_flagged():
    """Normal traffic should not be flagged."""
    monitor = NetworkMonitor()
    request = RequestLog(
        timestamp=1000.0,
        source_ip="10.0.0.1",
        method="GET",
        path="/api/products",
        query_string="page=1",
        headers={},
        body="",
    )
    monitor.log_request(request)

    assert not request.flagged


@pytest.mark.asyncio
async def test_monitor_get_logs():
    """Monitor should return logged requests."""
    monitor = NetworkMonitor()
    import time
    monitor.log_request(RequestLog(
        timestamp=time.time(),
        source_ip="10.0.0.1",
        method="GET",
        path="/test",
        query_string="",
        headers={},
        body="",
    ))

    result = await monitor.get_logs(since_seconds="300", flagged_only="false", limit="10")
    assert result.success
    assert len(result.data["entries"]) >= 1


# === WAF Tests ===

@pytest.mark.asyncio
async def test_waf_deploy_and_block():
    """WAF should block requests matching deployed rules."""
    waf = WAFEngine()

    # Deploy a rule
    result = await waf.deploy_rule(
        rule_name="block_sqli",
        pattern=r"union\s+select",
        target="all",
        action="block",
    )
    assert result.success

    # Test blocking
    allowed, rule = waf.check_request(
        path="/search",
        query="q=' UNION SELECT 1,2,3--",
        body="",
        headers={},
        source_ip="10.0.0.1",
    )
    assert not allowed
    assert rule == "block_sqli"


@pytest.mark.asyncio
async def test_waf_allows_clean_traffic():
    """WAF should allow normal requests."""
    waf = WAFEngine()
    await waf.deploy_rule(
        rule_name="block_sqli",
        pattern=r"union\s+select",
        target="all",
        action="block",
    )

    allowed, rule = waf.check_request(
        path="/products",
        query="page=1",
        body="",
        headers={},
        source_ip="10.0.0.1",
    )
    assert allowed
    assert rule is None


@pytest.mark.asyncio
async def test_waf_invalid_regex():
    """WAF should reject invalid regex patterns."""
    waf = WAFEngine()
    result = await waf.deploy_rule(
        rule_name="bad_rule",
        pattern="[invalid",
        target="all",
        action="block",
    )
    assert not result.success
    assert "Invalid regex" in result.error


# === ToolOutput Tests ===

def test_tool_output_truncation():
    """ToolOutput should truncate long results."""
    data = {"big": "x" * 20000}
    output = ToolOutput(tool_name="test", success=True, data=data)
    result = output.to_llm_string(max_chars=1000)
    assert len(result) <= 1100  # Allow small overflow from truncation message


def test_tool_output_error_format():
    """ToolOutput errors should format cleanly."""
    output = ToolOutput(
        tool_name="test",
        success=False,
        data={},
        error="Connection refused",
    )
    assert "Error running test" in str(output)
    assert "Connection refused" in str(output)
