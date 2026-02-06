"""In-memory event bus using asyncio queues.

The event bus is the communication backbone of SENTINEL. It enables:
- Red team tool calls/results to be visible to blue team agents
- Blue team alerts to trigger defender actions
- The orchestrator to monitor overall engagement progress
- The frontend (Phase 4) to receive real-time updates via WebSocket

Design:
- Each subscriber gets its own asyncio.Queue (no message loss)
- Subscriptions support exact match ("red.tool_call") or prefix wildcard ("red.*")
- Event history buffer for late-joining subscribers (frontend reconnection)
- Zero external dependencies. Single-process only.
"""

import asyncio
import time
from typing import Any, Optional
from dataclasses import dataclass, field
from enum import Enum


class EventType(str, Enum):
    """All event types in the system.

    Naming convention: {team}.{action}
    """

    # Red team events
    RED_TOOL_CALL = "red.tool_call"
    RED_TOOL_RESULT = "red.tool_result"
    RED_FINDING = "red.finding"
    RED_PHASE_COMPLETE = "red.phase_complete"

    # Blue team events
    BLUE_ALERT = "blue.alert"
    BLUE_WAF_RULE = "blue.waf_rule"
    BLUE_DEFENSE_ACTION = "blue.defense_action"
    BLUE_PHASE_COMPLETE = "blue.phase_complete"

    # Orchestrator events
    ENGAGEMENT_START = "orchestrator.engagement_start"
    PHASE_TRANSITION = "orchestrator.phase_transition"
    ENGAGEMENT_END = "orchestrator.engagement_end"

    # Agent lifecycle
    AGENT_START = "agent.start"
    AGENT_COMPLETE = "agent.complete"
    AGENT_ERROR = "agent.error"


@dataclass
class Event:
    """An event in the system.

    Attributes:
        type: The event type (from EventType enum or custom string)
        data: Arbitrary payload. Structure depends on event type.
        source: The agent or component that emitted the event (e.g. "recon_agent")
        timestamp: When the event was created (epoch seconds)
        event_id: Auto-incrementing unique ID for ordering
    """

    type: str
    data: dict[str, Any]
    source: str = ""
    timestamp: float = field(default_factory=time.time)
    event_id: int = 0  # Set by EventBus on publish


@dataclass
class _Subscription:
    """Internal: a subscriber's queue and its event type filter."""

    queue: asyncio.Queue[Event]
    pattern: str  # Exact event type or prefix with "*" (e.g. "red.*")

    def matches(self, event_type: str) -> bool:
        """Check if an event type matches this subscription's pattern."""
        if self.pattern == "*":
            return True
        if self.pattern.endswith(".*"):
            prefix = self.pattern[:-2]
            return event_type.startswith(prefix + ".")
        return self.pattern == event_type


class EventBus:
    """In-memory publish/subscribe event bus.

    Thread-safe via asyncio primitives. Single-process only.

    Usage:
        bus = EventBus()

        # Subscribe to specific events
        queue = bus.subscribe("red.tool_call")

        # Subscribe to all red team events
        queue = bus.subscribe("red.*")

        # Subscribe to everything
        queue = bus.subscribe("*")

        # Publish
        await bus.publish(Event(type="red.tool_call", data={...}, source="recon_agent"))

        # Consume
        event = await queue.get()

        # Unsubscribe
        bus.unsubscribe(queue)
    """

    def __init__(self, history_size: int = 1000) -> None:
        """Initialize the event bus.

        Args:
            history_size: Max number of events to keep in history buffer.
                         Used by Phase 4 frontend for reconnection/replay.
        """
        self._subscriptions: list[_Subscription] = []
        self._history: list[Event] = []
        self._history_size = history_size
        self._event_counter = 0
        self._lock = asyncio.Lock()

    def subscribe(
        self,
        pattern: str,
        queue_size: int = 1000,
    ) -> asyncio.Queue[Event]:
        """Subscribe to events matching a pattern.

        Args:
            pattern: Event type to match. Supports:
                     - Exact: "red.tool_call"
                     - Prefix wildcard: "red.*" (matches red.tool_call, red.finding, etc.)
                     - Global wildcard: "*" (matches everything)
            queue_size: Max queue depth before backpressure (oldest events dropped)

        Returns:
            asyncio.Queue that will receive matching events
        """
        queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=queue_size)
        self._subscriptions.append(_Subscription(queue=queue, pattern=pattern))
        return queue

    def unsubscribe(self, queue: asyncio.Queue[Event]) -> None:
        """Remove a subscription by its queue reference."""
        self._subscriptions = [
            sub for sub in self._subscriptions if sub.queue is not queue
        ]

    async def publish(self, event: Event) -> int:
        """Publish an event to all matching subscribers.

        Args:
            event: The event to publish

        Returns:
            Number of subscribers that received the event
        """
        async with self._lock:
            self._event_counter += 1
            event.event_id = self._event_counter

        # Add to history buffer
        self._history.append(event)
        if len(self._history) > self._history_size:
            self._history = self._history[-self._history_size:]

        delivered = 0
        for sub in self._subscriptions:
            if sub.matches(event.type):
                try:
                    sub.queue.put_nowait(event)
                    delivered += 1
                except asyncio.QueueFull:
                    # Drop oldest event and retry
                    try:
                        sub.queue.get_nowait()
                        sub.queue.put_nowait(event)
                        delivered += 1
                    except (asyncio.QueueEmpty, asyncio.QueueFull):
                        pass  # Queue is in a weird state, skip

        return delivered

    def get_history(
        self,
        event_type: Optional[str] = None,
        since_id: int = 0,
        limit: int = 100,
    ) -> list[Event]:
        """Get events from history buffer.

        Args:
            event_type: Filter to specific type (or prefix with ".*")
            since_id: Only return events with event_id > since_id
            limit: Max events to return

        Returns:
            List of matching events, oldest first
        """
        results = []
        for event in self._history:
            if event.event_id <= since_id:
                continue
            if event_type:
                sub = _Subscription(queue=asyncio.Queue(), pattern=event_type)
                if not sub.matches(event.type):
                    continue
            results.append(event)
            if len(results) >= limit:
                break
        return results

    @property
    def event_count(self) -> int:
        """Total events published since bus creation."""
        return self._event_counter

    @property
    def subscriber_count(self) -> int:
        """Current number of active subscriptions."""
        return len(self._subscriptions)

    def clear_history(self) -> None:
        """Clear the history buffer."""
        self._history.clear()
