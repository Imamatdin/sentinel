"""Tests for agent system.

These tests mock the CerebrasClient to avoid API calls.
They verify agent construction, event emission, and orchestration logic.
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from sentinel.agents.base import BaseAgent, AgentResult
from sentinel.agents.red.recon import ReconAgent
from sentinel.agents.red.exploit import ExploitAgent
from sentinel.agents.red.report import ReportAgent
from sentinel.agents.blue.monitor import MonitorAgent
from sentinel.agents.blue.defender import DefenderAgent
from sentinel.agents.blue.forensics import ForensicsAgent
from sentinel.core.client import CerebrasClient, ChatMessage, CompletionMetrics
from sentinel.core.tools import ToolRegistry, Tool
from sentinel.events.bus import EventBus, Event, EventType


def _mock_client() -> CerebrasClient:
    """Create a mock CerebrasClient that returns canned responses."""
    with patch("sentinel.core.client.AsyncOpenAI"):
        client = CerebrasClient(api_key="csk-test-key", model="zai-glm-4.7")

    # Mock chat to return a simple response
    async def mock_chat(messages, tools=None, temperature=None, max_tokens=None, model=None):
        return (
            ChatMessage(role="assistant", content="Test response from agent."),
            CompletionMetrics(total_time=0.5, input_tokens=100, output_tokens=50, model="zai-glm-4.7"),
        )

    client.chat = AsyncMock(side_effect=mock_chat)

    # Mock tool_loop to return conversation + metrics
    async def mock_tool_loop(messages, tools, tool_executor, max_iterations=None, on_tool_call=None, on_tool_result=None):
        response = ChatMessage(role="assistant", content="Tool loop completed. Found SQL injection on /search endpoint.")
        return (
            messages + [response],
            CompletionMetrics(total_time=1.0, input_tokens=200, output_tokens=100, model="zai-glm-4.7"),
        )

    client.tool_loop = AsyncMock(side_effect=mock_tool_loop)

    return client


def _mock_registry() -> ToolRegistry:
    """Create a registry with some test tools."""
    registry = ToolRegistry()
    registry.register(Tool(name="http_request", description="HTTP"))
    registry.register(Tool(name="port_scan", description="Scan"))
    registry.register(Tool(name="path_scan", description="Paths"))
    registry.register(Tool(name="api_discover", description="API"))
    registry.register(Tool(name="check_challenges", description="Challenges"))
    registry.register(Tool(name="sql_injection_test", description="SQLi"))
    registry.register(Tool(name="xss_test", description="XSS"))
    registry.register(Tool(name="login_attempt", description="Login"))
    registry.register(Tool(name="idor_test", description="IDOR"))
    registry.register(Tool(name="get_network_logs", description="Logs"))
    registry.register(Tool(name="analyze_attack_pattern", description="Analysis"))
    registry.register(Tool(name="deploy_waf_rule", description="WAF"))
    registry.register(Tool(name="get_waf_status", description="WAF Status"))
    registry.register(Tool(name="log_defense_action", description="Log"))
    return registry


@pytest.mark.asyncio
async def test_recon_agent_runs():
    """ReconAgent completes and produces findings."""
    client = _mock_client()
    registry = _mock_registry()
    executor = MagicMock()
    bus = EventBus()

    agent = ReconAgent(
        target_url="http://localhost:3000",
        name="recon_agent",
        client=client,
        event_bus=bus,
        tool_executor=executor,
        tool_registry=registry,
    )

    result = await agent.run()

    assert result.success is True
    assert result.agent_name == "recon_agent"
    assert result.duration > 0
    assert "target_url" in result.findings
    assert result.findings["target_url"] == "http://localhost:3000"


@pytest.mark.asyncio
async def test_recon_agent_filters_tools():
    """ReconAgent only exposes recon tools, not exploit tools."""
    client = _mock_client()
    registry = _mock_registry()

    agent = ReconAgent(
        target_url="http://localhost:3000",
        name="recon_agent",
        client=client,
        tool_registry=registry,
    )

    schemas = agent.tool_schemas
    tool_names = {s["function"]["name"] for s in schemas}

    assert "http_request" in tool_names
    assert "port_scan" in tool_names
    assert "path_scan" in tool_names
    assert "api_discover" in tool_names
    assert "check_challenges" in tool_names
    # Exploit tools should NOT be present
    assert "sql_injection_test" not in tool_names
    assert "xss_test" not in tool_names
    assert "login_attempt" not in tool_names


@pytest.mark.asyncio
async def test_exploit_agent_filters_tools():
    """ExploitAgent has exploit tools but not recon-only tools."""
    client = _mock_client()
    registry = _mock_registry()

    agent = ExploitAgent(
        target_url="http://localhost:3000",
        name="exploit_agent",
        client=client,
        tool_registry=registry,
    )

    schemas = agent.tool_schemas
    tool_names = {s["function"]["name"] for s in schemas}

    assert "sql_injection_test" in tool_names
    assert "xss_test" in tool_names
    assert "login_attempt" in tool_names
    assert "idor_test" in tool_names
    assert "http_request" in tool_names
    assert "check_challenges" in tool_names
    # Recon-only tools should NOT be present
    assert "port_scan" not in tool_names
    assert "path_scan" not in tool_names
    assert "api_discover" not in tool_names


@pytest.mark.asyncio
async def test_report_agent_no_tools():
    """ReportAgent has no tools (pure LLM synthesis)."""
    client = _mock_client()

    agent = ReportAgent(
        name="red_report_agent",
        client=client,
    )

    assert agent.tool_schemas == []


@pytest.mark.asyncio
async def test_report_agent_runs():
    """ReportAgent generates a report from context."""
    client = _mock_client()

    agent = ReportAgent(
        name="red_report_agent",
        client=client,
    )

    result = await agent.run(context={
        "recon_findings": {"summary": "Found open ports 80, 3000"},
        "exploit_findings": {"summary": "SQL injection on /search"},
    })

    assert result.success is True
    assert "report" in result.findings


@pytest.mark.asyncio
async def test_event_bus_receives_agent_events():
    """Events from agent actions appear on the event bus."""
    client = _mock_client()
    registry = _mock_registry()
    executor = MagicMock()
    bus = EventBus()

    # Subscribe to agent events
    all_events = bus.subscribe("*")

    agent = ReconAgent(
        target_url="http://localhost:3000",
        name="recon_agent",
        client=client,
        event_bus=bus,
        tool_executor=executor,
        tool_registry=registry,
    )

    await agent.run()

    # Should have received: agent_start, red.finding, red.phase_complete
    events = []
    while not all_events.empty():
        events.append(await all_events.get())

    event_types = [e.type for e in events]
    assert EventType.AGENT_START.value in event_types
    assert EventType.RED_FINDING.value in event_types
    assert EventType.RED_PHASE_COMPLETE.value in event_types


@pytest.mark.asyncio
async def test_monitor_agent_stops_on_signal():
    """MonitorAgent stops gracefully when stop() is called."""
    client = _mock_client()
    registry = _mock_registry()
    executor = MagicMock()
    bus = EventBus()

    agent = MonitorAgent(
        poll_interval=0.1,
        max_cycles=100,  # Would take forever without stop
        name="monitor_agent",
        client=client,
        event_bus=bus,
        tool_executor=executor,
        tool_registry=registry,
    )

    async def stop_after_delay():
        await asyncio.sleep(0.5)
        agent.stop()

    # Run monitor and stop signal concurrently
    stop_task = asyncio.create_task(stop_after_delay())
    result = await agent.run()
    await stop_task

    assert result.success is True
    # Should have run some cycles but not all 100
    assert result.findings["cycles_completed"] < 100


@pytest.mark.asyncio
async def test_defender_agent_responds_to_alerts():
    """DefenderAgent processes alerts from the event bus."""
    client = _mock_client()
    registry = _mock_registry()
    executor = MagicMock()
    bus = EventBus()

    agent = DefenderAgent(
        max_responses=2,
        response_timeout=5.0,
        name="defender_agent",
        client=client,
        event_bus=bus,
        tool_executor=executor,
        tool_registry=registry,
    )

    async def send_alerts():
        await asyncio.sleep(0.2)
        await bus.publish(Event(
            type=EventType.BLUE_ALERT.value,
            data={"analysis": "SQL injection detected on /search", "cycle": 1},
            source="monitor_agent",
        ))
        await asyncio.sleep(0.2)
        await bus.publish(Event(
            type=EventType.BLUE_ALERT.value,
            data={"analysis": "XSS attempt on /profile", "cycle": 2},
            source="monitor_agent",
        ))

    alert_task = asyncio.create_task(send_alerts())
    result = await agent.run()
    await alert_task

    assert result.success is True
    assert result.findings["total_responses"] == 2


@pytest.mark.asyncio
async def test_defender_agent_timeout_no_alerts():
    """DefenderAgent exits cleanly when no alerts arrive."""
    client = _mock_client()
    bus = EventBus()

    agent = DefenderAgent(
        max_responses=5,
        response_timeout=0.5,  # Short timeout
        name="defender_agent",
        client=client,
        event_bus=bus,
    )

    result = await agent.run()

    assert result.success is True
    assert result.findings["total_responses"] == 0
