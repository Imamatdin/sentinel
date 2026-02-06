"""Tests for Cerebras client."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from sentinel.core.client import CerebrasClient, ChatMessage, ToolCall, ToolResult


@pytest.fixture
def client():
    """Create test client with mocked OpenAI SDK."""
    with patch("sentinel.core.client.AsyncOpenAI"):
        c = CerebrasClient(
            api_key="csk-test-key-123",
            model="zai-glm-4.7",
        )
        return c


def test_client_initialization(client):
    """Client stores model, temperature, and max_tokens."""
    assert client.model == "zai-glm-4.7"
    assert client.temperature == 0.7
    assert client.max_tokens == 4096
    assert client.tool_call_timeout == 30
    assert client.max_tool_iterations == 10


@pytest.mark.asyncio
async def test_chat_basic(client):
    """Basic chat returns assistant message and metrics."""
    mock_response = MagicMock()
    mock_response.choices = [
        MagicMock(
            message=MagicMock(
                role="assistant",
                content="Hello! How can I help?",
                tool_calls=None,
            )
        )
    ]
    mock_response.usage = MagicMock(prompt_tokens=15, completion_tokens=8)
    mock_response.model = "zai-glm-4.7"

    client.client.chat.completions.create = AsyncMock(return_value=mock_response)

    response, metrics = await client.chat(
        messages=[ChatMessage(role="user", content="Hello")]
    )

    assert response.role == "assistant"
    assert response.content == "Hello! How can I help?"
    assert response.tool_calls is None
    assert metrics.input_tokens == 15
    assert metrics.output_tokens == 8
    assert metrics.total_time > 0


@pytest.mark.asyncio
async def test_chat_with_tool_calls(client):
    """Chat with tools returns parsed ToolCall objects."""
    mock_tc = MagicMock()
    mock_tc.id = "call_abc123"
    mock_func = MagicMock()
    mock_func.name = "port_scan"
    mock_func.arguments = '{"target": "localhost", "scan_type": "quick"}'
    mock_tc.function = mock_func

    mock_response = MagicMock()
    mock_response.choices = [
        MagicMock(
            message=MagicMock(
                role="assistant",
                content="",
                tool_calls=[mock_tc],
            )
        )
    ]
    mock_response.usage = MagicMock(prompt_tokens=50, completion_tokens=20)
    mock_response.model = "zai-glm-4.7"

    client.client.chat.completions.create = AsyncMock(return_value=mock_response)

    response, _ = await client.chat(
        messages=[ChatMessage(role="user", content="Scan the target")],
        tools=[{"type": "function", "function": {"name": "port_scan"}}],
    )

    assert response.tool_calls is not None
    assert len(response.tool_calls) == 1
    assert response.tool_calls[0].name == "port_scan"
    assert response.tool_calls[0].arguments == {"target": "localhost", "scan_type": "quick"}


@pytest.mark.asyncio
async def test_chat_malformed_tool_json(client):
    """Malformed tool call JSON should result in empty arguments, not crash."""
    mock_tc = MagicMock()
    mock_tc.id = "call_bad"
    mock_func = MagicMock()
    mock_func.name = "broken_tool"
    mock_func.arguments = '{invalid json!!!}'
    mock_tc.function = mock_func

    mock_response = MagicMock()
    mock_response.choices = [
        MagicMock(message=MagicMock(role="assistant", content="", tool_calls=[mock_tc]))
    ]
    mock_response.usage = MagicMock(prompt_tokens=10, completion_tokens=5)
    mock_response.model = "zai-glm-4.7"

    client.client.chat.completions.create = AsyncMock(return_value=mock_response)

    response, _ = await client.chat(
        messages=[ChatMessage(role="user", content="test")]
    )

    # Should not crash, should return empty arguments
    assert response.tool_calls[0].arguments == {}


@pytest.mark.asyncio
async def test_tool_loop_completes(client):
    """Tool loop should iterate until model stops making tool calls."""
    # First call: model makes a tool call
    tc = MagicMock()
    tc.id = "call_1"
    tc_func = MagicMock()
    tc_func.name = "test_tool"
    tc_func.arguments = '{"key": "value"}'
    tc.function = tc_func

    response_with_tool = MagicMock()
    response_with_tool.choices = [
        MagicMock(message=MagicMock(role="assistant", content="", tool_calls=[tc]))
    ]
    response_with_tool.usage = MagicMock(prompt_tokens=20, completion_tokens=10)
    response_with_tool.model = "zai-glm-4.7"

    # Second call: model returns text (no tool calls)
    response_text = MagicMock()
    response_text.choices = [
        MagicMock(message=MagicMock(role="assistant", content="Done!", tool_calls=None))
    ]
    response_text.usage = MagicMock(prompt_tokens=30, completion_tokens=5)
    response_text.model = "zai-glm-4.7"

    client.client.chat.completions.create = AsyncMock(
        side_effect=[response_with_tool, response_text]
    )

    # Mock tool executor
    mock_executor = MagicMock()
    mock_executor.execute_tool = AsyncMock(return_value="tool output here")

    messages = [ChatMessage(role="user", content="Do something")]
    conversation, metrics = await client.tool_loop(
        messages=messages,
        tools=[{"type": "function", "function": {"name": "test_tool"}}],
        tool_executor=mock_executor,
    )

    # Should have: user + assistant(tool_call) + tool(result) + assistant(text)
    assert len(conversation) == 4
    assert conversation[-1].content == "Done!"
    assert metrics.total_time > 0

    # Tool executor should have been called once
    mock_executor.execute_tool.assert_called_once_with("test_tool", {"key": "value"})


def test_format_messages(client):
    """_format_messages converts ChatMessages to OpenAI SDK format."""
    messages = [
        ChatMessage(role="system", content="You are a pentester."),
        ChatMessage(role="user", content="Scan the target."),
        ChatMessage(
            role="assistant",
            content="",
            tool_calls=[ToolCall(id="call_1", name="port_scan", arguments={"target": "localhost"})],
        ),
        ChatMessage(role="tool", content='{"ports": [80, 3000]}', tool_call_id="call_1", name="port_scan"),
    ]

    formatted = client._format_messages(messages)

    assert len(formatted) == 4
    assert formatted[0]["role"] == "system"
    assert formatted[1]["role"] == "user"
    assert formatted[2]["role"] == "assistant"
    assert formatted[2]["tool_calls"][0]["function"]["name"] == "port_scan"
    assert formatted[3]["role"] == "tool"
    assert formatted[3]["tool_call_id"] == "call_1"


@pytest.mark.asyncio
async def test_tool_execution_timeout(client):
    """Tool execution that exceeds timeout returns error result."""
    import asyncio

    async def slow_tool(name, args):
        await asyncio.sleep(100)
        return "should not reach"

    mock_executor = MagicMock()
    mock_executor.execute_tool = slow_tool

    # Set very short timeout
    client.tool_call_timeout = 0.1

    tc = ToolCall(id="call_slow", name="slow_tool", arguments={})
    results = await client._execute_tools([tc], mock_executor)

    assert len(results) == 1
    assert results[0].error is not None
    assert "timed out" in results[0].error
