"""Tests for the event bus system."""

import asyncio
import pytest
from sentinel.events.bus import EventBus, Event, EventType


@pytest.mark.asyncio
async def test_publish_and_subscribe():
    """Basic pub/sub: subscriber receives published events."""
    bus = EventBus()
    queue = bus.subscribe("red.tool_call")

    await bus.publish(Event(
        type="red.tool_call",
        data={"tool": "port_scan"},
        source="test",
    ))

    event = await asyncio.wait_for(queue.get(), timeout=1.0)
    assert event.type == "red.tool_call"
    assert event.data["tool"] == "port_scan"
    assert event.event_id == 1


@pytest.mark.asyncio
async def test_wildcard_subscription():
    """Wildcard subscriber receives all matching events."""
    bus = EventBus()
    queue = bus.subscribe("red.*")

    await bus.publish(Event(type="red.tool_call", data={}, source="test"))
    await bus.publish(Event(type="red.finding", data={}, source="test"))
    await bus.publish(Event(type="blue.alert", data={}, source="test"))  # Should NOT match

    event1 = await asyncio.wait_for(queue.get(), timeout=1.0)
    event2 = await asyncio.wait_for(queue.get(), timeout=1.0)

    assert event1.type == "red.tool_call"
    assert event2.type == "red.finding"
    assert queue.empty()  # blue.alert should not be in queue


@pytest.mark.asyncio
async def test_global_wildcard():
    """Global wildcard '*' receives everything."""
    bus = EventBus()
    queue = bus.subscribe("*")

    await bus.publish(Event(type="red.tool_call", data={}, source="test"))
    await bus.publish(Event(type="blue.alert", data={}, source="test"))

    assert queue.qsize() == 2


@pytest.mark.asyncio
async def test_multiple_subscribers():
    """Multiple subscribers each get their own copy."""
    bus = EventBus()
    q1 = bus.subscribe("red.tool_call")
    q2 = bus.subscribe("red.tool_call")

    delivered = await bus.publish(Event(type="red.tool_call", data={}, source="test"))

    assert delivered == 2
    assert q1.qsize() == 1
    assert q2.qsize() == 1


@pytest.mark.asyncio
async def test_unsubscribe():
    """Unsubscribed queue stops receiving events."""
    bus = EventBus()
    queue = bus.subscribe("red.tool_call")

    await bus.publish(Event(type="red.tool_call", data={"n": 1}, source="test"))
    assert queue.qsize() == 1

    bus.unsubscribe(queue)

    await bus.publish(Event(type="red.tool_call", data={"n": 2}, source="test"))
    assert queue.qsize() == 1  # Still 1, not 2


@pytest.mark.asyncio
async def test_event_history():
    """History buffer stores events for replay."""
    bus = EventBus(history_size=5)

    for i in range(10):
        await bus.publish(Event(type="red.tool_call", data={"i": i}, source="test"))

    history = bus.get_history()
    assert len(history) == 5  # Only last 5 kept
    assert history[0].data["i"] == 5  # Oldest remaining


@pytest.mark.asyncio
async def test_history_since_id():
    """History can be filtered by event_id for incremental fetching."""
    bus = EventBus()

    for i in range(5):
        await bus.publish(Event(type="red.tool_call", data={"i": i}, source="test"))

    history = bus.get_history(since_id=3)
    assert len(history) == 2
    assert history[0].event_id == 4
    assert history[1].event_id == 5


@pytest.mark.asyncio
async def test_history_type_filter():
    """History can be filtered by event type."""
    bus = EventBus()

    await bus.publish(Event(type="red.tool_call", data={}, source="test"))
    await bus.publish(Event(type="blue.alert", data={}, source="test"))
    await bus.publish(Event(type="red.finding", data={}, source="test"))

    red_history = bus.get_history(event_type="red.*")
    assert len(red_history) == 2


@pytest.mark.asyncio
async def test_queue_full_drops_oldest():
    """When queue is full, oldest event is dropped to make room."""
    bus = EventBus()
    queue = bus.subscribe("red.tool_call", queue_size=2)

    await bus.publish(Event(type="red.tool_call", data={"n": 1}, source="test"))
    await bus.publish(Event(type="red.tool_call", data={"n": 2}, source="test"))
    await bus.publish(Event(type="red.tool_call", data={"n": 3}, source="test"))  # Should drop n=1

    events = []
    while not queue.empty():
        events.append(await queue.get())

    assert len(events) == 2
    assert events[0].data["n"] == 2  # n=1 was dropped
    assert events[1].data["n"] == 3


def test_event_counter():
    """Event counter increments and is accessible."""
    bus = EventBus()
    assert bus.event_count == 0
    assert bus.subscriber_count == 0

    bus.subscribe("test")
    assert bus.subscriber_count == 1


@pytest.mark.asyncio
async def test_event_id_monotonic():
    """Event IDs are monotonically increasing."""
    bus = EventBus()
    queue = bus.subscribe("*")

    for _ in range(5):
        await bus.publish(Event(type="test", data={}, source="test"))

    ids = []
    while not queue.empty():
        event = await queue.get()
        ids.append(event.event_id)

    assert ids == [1, 2, 3, 4, 5]
