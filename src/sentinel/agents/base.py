"""Base agent class for all SENTINEL agents.

Every agent in SENTINEL (red or blue) inherits from BaseAgent. The base class handles:
- LLM client setup (CerebrasClient)
- Tool executor integration
- Event bus publishing (tool calls, results, agent lifecycle)
- Conversation management (system prompt + message history)
- Metrics collection
- Error handling with structured logging

Subclasses implement:
- system_prompt property: The agent's role-specific system prompt
- tool_names property: Which tools this agent has access to (empty for report agents)
- run() method: The agent's main execution logic
"""

import json
import time
from abc import ABC, abstractmethod
from typing import Any, Optional
from dataclasses import dataclass, field

from sentinel.core.client import CerebrasClient, ChatMessage, ToolCall, ToolResult, CompletionMetrics
from sentinel.core.tools import ToolRegistry
from sentinel.events.bus import EventBus, Event, EventType
from sentinel.logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class AgentResult:
    """Result from an agent's run() execution.

    Attributes:
        agent_name: Identifier for the agent
        success: Whether the agent completed without errors
        conversation: Full conversation history
        metrics: Cumulative LLM metrics
        findings: Any discoveries or outputs (agent-specific structure)
        error: Error message if success is False
        start_time: When the agent started
        end_time: When the agent finished
    """

    agent_name: str
    success: bool
    conversation: list[ChatMessage] = field(default_factory=list)
    metrics: CompletionMetrics = field(default_factory=CompletionMetrics)
    findings: dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    start_time: float = 0.0
    end_time: float = 0.0

    @property
    def duration(self) -> float:
        """Total wall-clock time in seconds."""
        return self.end_time - self.start_time

    @property
    def tool_calls_made(self) -> int:
        """Count of tool calls in the conversation."""
        count = 0
        for msg in self.conversation:
            if msg.tool_calls:
                count += len(msg.tool_calls)
        return count


class BaseAgent(ABC):
    """Abstract base class for all SENTINEL agents.

    Construction requires a CerebrasClient and optionally a ToolExecutor,
    ToolRegistry, and EventBus. The base class wires everything together.
    """

    def __init__(
        self,
        name: str,
        client: CerebrasClient,
        event_bus: Optional[EventBus] = None,
        tool_executor: Optional[Any] = None,
        tool_registry: Optional[ToolRegistry] = None,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_iterations: Optional[int] = None,
    ):
        """Initialize base agent.

        Args:
            name: Agent identifier (e.g. "recon_agent", "monitor_agent")
            client: CerebrasClient instance
            event_bus: Optional event bus for inter-agent communication
            tool_executor: Optional ToolExecutor with execute_tool(name, args)
            tool_registry: Optional ToolRegistry for generating tool schemas
            model: Override the client's default model for this agent
            temperature: Override temperature for this agent
            max_iterations: Override max tool loop iterations for this agent
        """
        self.name = name
        self.client = client
        self.event_bus = event_bus
        self.tool_executor = tool_executor
        self.tool_registry = tool_registry
        self._model = model
        self._temperature = temperature
        self._max_iterations = max_iterations

        # Conversation state
        self._messages: list[ChatMessage] = []
        self._findings: dict[str, Any] = {}

        logger.info("agent_initialized", agent=self.name, model=model or client.model)

    @property
    @abstractmethod
    def system_prompt(self) -> str:
        """Return the agent's system prompt. Subclasses must implement."""
        ...

    @property
    def tool_schemas(self) -> list[dict[str, Any]]:
        """Get OpenAI tool schemas for this agent's tools.

        Override in subclasses to filter to specific tools.
        Returns empty list if no tool_registry is set.
        """
        if self.tool_registry is None:
            return []
        return self.tool_registry.get_schemas()

    @abstractmethod
    async def run(self, context: Optional[dict[str, Any]] = None) -> AgentResult:
        """Execute the agent's main logic.

        Args:
            context: Optional context from orchestrator or previous agents.
                    For ExploitAgent: contains recon findings.
                    For DefenderAgent: contains current alerts.
                    For ReportAgent/ForensicsAgent: contains all events/findings.

        Returns:
            AgentResult with conversation, metrics, and findings
        """
        ...

    async def _run_tool_loop(
        self,
        user_message: str,
        context: Optional[dict[str, Any]] = None,
    ) -> tuple[list[ChatMessage], CompletionMetrics]:
        """Run a single tool loop iteration with the agent's tools.

        This is the primary execution method for tool-using agents.
        It builds the conversation (system prompt + context + user message),
        runs the tool loop, and publishes events.

        Args:
            user_message: The task instruction for this iteration
            context: Optional additional context to include in the user message

        Returns:
            Tuple of (conversation history, metrics)
        """
        # Build initial messages
        messages = [ChatMessage(role="system", content=self.system_prompt)]

        # Carry forward previous conversation if exists (multi-turn)
        for msg in self._messages:
            if msg.role != "system":
                messages.append(msg)

        # Build user message with context
        full_user_message = user_message
        if context:
            context_str = "\n\n## Context from previous agents:\n"
            for key, value in context.items():
                if isinstance(value, (dict, list)):
                    context_str += f"\n### {key}:\n```json\n{json.dumps(value, indent=2, default=str)[:4000]}\n```\n"
                else:
                    context_str += f"\n### {key}:\n{str(value)[:4000]}\n"
            full_user_message = user_message + context_str

        messages.append(ChatMessage(role="user", content=full_user_message))

        # Emit agent start event
        await self._emit(EventType.AGENT_START, {
            "agent": self.name,
            "task": user_message[:200],
        })

        # Create event-emitting callbacks
        async def on_tool_call(tc: ToolCall) -> None:
            event_type = (
                EventType.RED_TOOL_CALL
                if self._is_red_team()
                else EventType.BLUE_DEFENSE_ACTION
            )
            await self._emit(event_type, {
                "agent": self.name,
                "tool": tc.name,
                "arguments": tc.arguments,
                "tool_call_id": tc.id,
            })

        async def on_tool_result(tr: ToolResult) -> None:
            event_type = (
                EventType.RED_TOOL_RESULT
                if self._is_red_team()
                else EventType.BLUE_DEFENSE_ACTION
            )
            # Truncate result for event (full result stays in conversation)
            result_preview = tr.result[:500] if tr.result else ""
            await self._emit(event_type, {
                "agent": self.name,
                "tool": tr.tool_name,
                "tool_call_id": tr.tool_call_id,
                "success": tr.error is None,
                "error": tr.error,
                "result_preview": result_preview,
                "execution_time": tr.execution_time,
            })

        # Run the tool loop
        tools = self.tool_schemas
        if not tools or self.tool_executor is None:
            # No tools: single chat call
            response, metrics = await self.client.chat(
                messages=messages,
                model=self._model,
                temperature=self._temperature,
            )
            conversation = messages + [response]
        else:
            conversation, metrics = await self.client.tool_loop(
                messages=messages,
                tools=tools,
                tool_executor=self.tool_executor,
                max_iterations=self._max_iterations,
                on_tool_call=on_tool_call,
                on_tool_result=on_tool_result,
            )

        # Store conversation for multi-turn
        self._messages = conversation

        return conversation, metrics

    async def _emit(self, event_type: str | EventType, data: dict[str, Any]) -> None:
        """Publish an event to the event bus if connected."""
        if self.event_bus is None:
            return
        event_type_str = event_type.value if isinstance(event_type, EventType) else event_type
        await self.event_bus.publish(Event(
            type=event_type_str,
            data=data,
            source=self.name,
        ))

    def _is_red_team(self) -> bool:
        """Determine if this is a red team agent (by name convention)."""
        return any(
            tag in self.name.lower()
            for tag in ("recon", "exploit", "red", "report")
        )

    def _extract_last_response(self, conversation: list[ChatMessage]) -> str:
        """Get the last assistant message's content from a conversation."""
        for msg in reversed(conversation):
            if msg.role == "assistant" and msg.content and not msg.tool_calls:
                return msg.content
        return ""
