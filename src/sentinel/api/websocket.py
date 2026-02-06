"""WebSocket handler for real-time event streaming.

The WebSocket endpoint streams events from the EventBus to connected
frontend clients. Supports:
- Real-time event streaming during engagement
- Replay of missed events on reconnection
- State change notifications
- Client-initiated stop
"""

import asyncio
import json
from typing import Any

from fastapi import WebSocket, WebSocketDisconnect

from sentinel.api.manager import EngagementManager, EngagementState
from sentinel.events.bus import Event
from sentinel.logging_config import get_logger

logger = get_logger(__name__)


async def websocket_handler(
    websocket: WebSocket,
    manager: EngagementManager,
) -> None:
    """Handle a WebSocket connection for event streaming.

    Protocol:
    - Server sends events as JSON with type "event"
    - Server sends state changes with type "state"
    - Server sends final result with type "result"
    - Client can send {"type": "replay", "since_id": N} to get missed events
    - Client can send {"type": "stop"} to stop the engagement
    """
    await websocket.accept()

    logger.info("websocket_connected")

    # Subscribe to all events
    queue = manager.event_bus.subscribe("*")

    try:
        # Send current state immediately
        await _send_state(websocket, manager)

        # Two concurrent tasks: send events + receive client messages
        send_task = asyncio.create_task(_send_events(websocket, queue, manager))
        recv_task = asyncio.create_task(_receive_messages(websocket, manager))

        # Wait for either to finish (disconnect or error)
        done, pending = await asyncio.wait(
            [send_task, recv_task],
            return_when=asyncio.FIRST_COMPLETED,
        )

        # Cancel the other task
        for task in pending:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    except WebSocketDisconnect:
        logger.info("websocket_disconnected")
    except Exception as e:
        logger.error("websocket_error", error=str(e))
    finally:
        manager.event_bus.unsubscribe(queue)
        logger.info("websocket_cleanup_done")


async def _send_events(
    websocket: WebSocket,
    queue: asyncio.Queue[Event],
    manager: EngagementManager,
) -> None:
    """Send events from the queue to the WebSocket client."""
    last_state = manager.state

    while True:
        try:
            # Use timeout so we can check for state changes periodically
            try:
                event = await asyncio.wait_for(queue.get(), timeout=1.0)

                # Send the event
                await websocket.send_json({
                    "type": "event",
                    "event_id": event.event_id,
                    "event_type": event.type,
                    "source": event.source,
                    "timestamp": event.timestamp,
                    "data": _safe_json(event.data),
                })

            except asyncio.TimeoutError:
                pass  # No event, check state below

            # Check for state changes
            current_state = manager.state
            if current_state != last_state:
                last_state = current_state
                await _send_state(websocket, manager)

                # If engagement completed, send final result
                if current_state in (EngagementState.COMPLETED, EngagementState.FAILED):
                    await _send_result(websocket, manager)

        except (WebSocketDisconnect, RuntimeError):
            break
        except Exception as e:
            logger.error("ws_send_error", error=str(e))
            break


async def _receive_messages(
    websocket: WebSocket,
    manager: EngagementManager,
) -> None:
    """Receive and process client messages."""
    while True:
        try:
            raw = await websocket.receive_text()
            data = json.loads(raw)
            msg_type = data.get("type")

            if msg_type == "replay":
                since_id = data.get("since_id", 0)
                await _handle_replay(websocket, manager, since_id)

            elif msg_type == "stop":
                await manager.stop_engagement()
                await websocket.send_json({
                    "type": "state",
                    "state": "failed",
                    "phase": None,
                    "message": "Engagement stopped by client",
                })

            elif msg_type == "ping":
                await websocket.send_json({"type": "pong"})

            else:
                logger.warning("ws_unknown_message_type", msg_type=msg_type)

        except (WebSocketDisconnect, RuntimeError):
            break
        except json.JSONDecodeError:
            logger.warning("ws_invalid_json")
        except Exception as e:
            logger.error("ws_recv_error", error=str(e))
            break


async def _handle_replay(
    websocket: WebSocket,
    manager: EngagementManager,
    since_id: int,
) -> None:
    """Send missed events from history buffer."""
    events = manager.event_bus.get_history(since_id=since_id, limit=500)

    logger.info("ws_replay_requested", since_id=since_id, events_found=len(events))

    for event in events:
        await websocket.send_json({
            "type": "event",
            "event_id": event.event_id,
            "event_type": event.type,
            "source": event.source,
            "timestamp": event.timestamp,
            "data": _safe_json(event.data),
        })

    await websocket.send_json({
        "type": "replay_complete",
        "events_sent": len(events),
        "latest_id": events[-1].event_id if events else since_id,
    })


async def _send_state(
    websocket: WebSocket,
    manager: EngagementManager,
) -> None:
    """Send current engagement state to client."""
    await websocket.send_json({
        "type": "state",
        "state": manager.state.value,
        "phase": manager.phase,
        "target_url": manager.target_url,
        "elapsed_seconds": round(manager.elapsed, 2) if manager.elapsed else None,
        "event_count": manager.event_bus.event_count,
    })


async def _send_result(
    websocket: WebSocket,
    manager: EngagementManager,
) -> None:
    """Send final engagement result summary to client."""
    result = manager.result
    if result is None:
        return

    await websocket.send_json({
        "type": "result",
        "success": result.success,
        "target_url": result.target_url,
        "duration": round(result.duration, 2),
        "event_count": result.event_count,
        "speed_stats": result.speed_stats,
        "has_red_report": bool(result.red_report),
        "has_blue_report": bool(result.blue_report),
    })


def _safe_json(data: dict[str, Any]) -> dict[str, Any]:
    """Make event data JSON-safe by converting non-serializable values."""
    safe = {}
    for key, value in data.items():
        if isinstance(value, (str, int, float, bool, type(None))):
            safe[key] = value
        elif isinstance(value, dict):
            safe[key] = _safe_json(value)
        elif isinstance(value, (list, tuple)):
            safe[key] = [
                _safe_json(v) if isinstance(v, dict)
                else v if isinstance(v, (str, int, float, bool, type(None)))
                else str(v)
                for v in value
            ]
        else:
            safe[key] = str(value)
    return safe