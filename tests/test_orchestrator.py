"""Tests for the engagement orchestrator.

These tests mock the CerebrasClient and verify the orchestration logic:
phase sequencing, concurrent agent execution, and result collection.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from sentinel.orchestrator.engine import EngagementOrchestrator, EngagementResult
from sentinel.core.client import ChatMessage, CompletionMetrics
from sentinel.events.bus import EventBus


def _mock_settings():
    """Create mock settings."""
    settings = MagicMock()
    settings.cerebras_api_key = "csk-test-key"
    settings.cerebras_base_url = "https://api.cerebras.ai/v1"
    settings.primary_model = "zai-glm-4.7"
    settings.default_temperature = 0.7
    settings.default_max_tokens = 4096
    settings.tool_call_timeout = 30
    settings.max_tool_iterations = 10
    return settings


@pytest.mark.asyncio
async def test_orchestrator_initialization():
    """Orchestrator initializes with correct defaults."""
    settings = _mock_settings()
    orch = EngagementOrchestrator(
        target_url="http://localhost:3000",
        settings=settings,
    )

    assert orch.target_url == "http://localhost:3000"
    assert orch.event_bus is not None
    assert orch.network_monitor is not None
    assert orch.waf_engine is not None


@pytest.mark.asyncio
async def test_orchestrator_run_skip_all():
    """Orchestrator runs (mocked) with recon and reports skipped for speed."""
    settings = _mock_settings()

    with patch("sentinel.orchestrator.engine.CerebrasClient") as MockClient:
        # Mock the client
        mock_instance = MagicMock()

        async def mock_chat(messages, tools=None, temperature=None, max_tokens=None, model=None):
            return (
                ChatMessage(role="assistant", content="Agent response."),
                CompletionMetrics(total_time=0.1, input_tokens=50, output_tokens=25, model="zai-glm-4.7"),
            )

        async def mock_tool_loop(messages, tools, tool_executor, max_iterations=None, on_tool_call=None, on_tool_result=None):
            response = ChatMessage(role="assistant", content="Done.")
            return (
                messages + [response],
                CompletionMetrics(total_time=0.2, input_tokens=100, output_tokens=50, model="zai-glm-4.7"),
            )

        mock_instance.chat = AsyncMock(side_effect=mock_chat)
        mock_instance.tool_loop = AsyncMock(side_effect=mock_tool_loop)
        mock_instance.model = "zai-glm-4.7"
        MockClient.return_value = mock_instance

        orch = EngagementOrchestrator(
            target_url="http://localhost:3000",
            settings=settings,
            skip_recon=True,
            skip_reports=True,
            monitor_max_cycles=2,
            monitor_poll_interval=0.1,
            defender_max_responses=2,
        )

        result = await orch.run()

    assert result.success is True
    assert result.target_url == "http://localhost:3000"
    assert result.duration > 0
    assert result.event_count > 0
    assert "exploit" in result.agent_results
    assert "monitor" in result.agent_results
    assert "defender" in result.agent_results


def test_engagement_result_summary():
    """EngagementResult.summary() produces readable output."""
    result = EngagementResult(
        success=True,
        target_url="http://localhost:3000",
        duration=45.0,
        event_count=150,
        speed_stats={"avg_tokens_per_second": 1200},
    )

    summary = result.summary()
    assert "SENTINEL" in summary
    assert "localhost:3000" in summary
    assert "45.0s" in summary
