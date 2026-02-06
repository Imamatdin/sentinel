"""REST API endpoints.

Endpoints:
- GET  /health              Health check + Juice Shop connectivity
- POST /engagement/start    Start a new engagement
- POST /engagement/stop     Stop the running engagement
- GET  /engagement/state    Get current engagement state
- GET  /engagement/result   Get engagement result (after completion)
- GET  /engagement/events   Get event history (paginated)
- GET  /engagement/reports  Get red and blue team reports
"""

from typing import Optional

from fastapi import APIRouter, HTTPException, Depends

from sentinel.api.models import (
    StartEngagementRequest,
    HealthResponse,
    EngagementStateResponse,
    EngagementResultResponse,
    AgentResultResponse,
    SpeedStatsResponse,
    EventResponse,
    EventListResponse,
)
from sentinel.api.manager import EngagementManager, EngagementState
from sentinel import __version__

router = APIRouter()


def get_manager() -> EngagementManager:
    """Dependency that returns the engagement manager.

    This is overridden in app.py to inject the actual manager instance.
    Tests can override this with a mock.
    """
    raise RuntimeError("EngagementManager not initialized. Call create_app() first.")


# ── Health ──

@router.get("/health", response_model=HealthResponse)
async def health_check(manager: EngagementManager = Depends(get_manager)):
    """Check API health and Juice Shop connectivity."""
    juice_shop_url = manager.target_url or "http://localhost:3000"
    reachable = await manager.check_juice_shop(juice_shop_url)

    return HealthResponse(
        status="ok",
        version=__version__,
        juice_shop_reachable=reachable,
        juice_shop_url=juice_shop_url,
        engagement_active=manager.state == EngagementState.RUNNING,
    )


# ── Engagement Lifecycle ──

@router.post("/engagement/start")
async def start_engagement(
    request: StartEngagementRequest,
    manager: EngagementManager = Depends(get_manager),
):
    """Start a new engagement against the target."""
    started = await manager.start_engagement(
        target_url=request.target_url,
        monitor_poll_interval=request.monitor_poll_interval,
        monitor_max_cycles=request.monitor_max_cycles,
        defender_max_responses=request.defender_max_responses,
        exploit_max_iterations=request.exploit_max_iterations,
        skip_recon=request.skip_recon,
        skip_reports=request.skip_reports,
    )

    if not started:
        raise HTTPException(
            status_code=409,
            detail="An engagement is already running. Stop it first.",
        )

    return {"status": "started", "target_url": request.target_url}


@router.post("/engagement/stop")
async def stop_engagement(
    manager: EngagementManager = Depends(get_manager),
):
    """Stop the running engagement."""
    stopped = await manager.stop_engagement()

    if not stopped:
        raise HTTPException(
            status_code=409,
            detail="No engagement is currently running.",
        )

    return {"status": "stopped"}


@router.get("/engagement/state", response_model=EngagementStateResponse)
async def get_engagement_state(
    manager: EngagementManager = Depends(get_manager),
):
    """Get the current engagement state."""
    return EngagementStateResponse(
        state=manager.state.value,
        phase=manager.phase,
        target_url=manager.target_url,
        elapsed_seconds=round(manager.elapsed, 2) if manager.elapsed else None,
        event_count=manager.event_bus.event_count,
    )


# ── Results ──

@router.get("/engagement/result", response_model=EngagementResultResponse)
async def get_engagement_result(
    manager: EngagementManager = Depends(get_manager),
):
    """Get the complete engagement result. Only available after completion."""
    result = manager.result
    if result is None:
        raise HTTPException(
            status_code=404,
            detail="No engagement result available. Start and complete an engagement first.",
        )

    # Serialize agent results
    agents = {}
    for name, ar in result.agent_results.items():
        agents[name] = AgentResultResponse(
            agent_name=ar.agent_name,
            success=ar.success,
            duration=round(ar.duration, 2),
            tool_calls_made=ar.tool_calls_made,
            input_tokens=ar.metrics.input_tokens,
            output_tokens=ar.metrics.output_tokens,
            total_llm_time=round(ar.metrics.total_time, 2),
            error=ar.error,
            findings_summary=str(ar.findings.get("summary", ""))[:500] or None,
        )

    speed = result.speed_stats
    speed_response = SpeedStatsResponse(
        total_tokens=speed.get("total_tokens", 0),
        total_llm_time_seconds=speed.get("total_llm_time_seconds", 0.0),
        total_tool_calls=speed.get("total_tool_calls", 0),
        avg_tokens_per_second=speed.get("avg_tokens_per_second", 0),
        engagement_wall_clock_seconds=speed.get("engagement_wall_clock_seconds", 0.0),
        attack_to_first_defense_seconds=speed.get("attack_to_first_defense_seconds"),
    )

    return EngagementResultResponse(
        success=result.success,
        target_url=result.target_url,
        duration=round(result.duration, 2),
        event_count=result.event_count,
        phases=result.phases,
        agents=agents,
        speed_stats=speed_response,
        red_report=result.red_report,
        blue_report=result.blue_report,
    )


@router.get("/engagement/reports")
async def get_reports(
    manager: EngagementManager = Depends(get_manager),
):
    """Get the red and blue team reports."""
    result = manager.result
    if result is None:
        raise HTTPException(status_code=404, detail="No engagement result available.")

    return {
        "red_report": result.red_report,
        "blue_report": result.blue_report,
    }


# ── Events ──

@router.get("/engagement/events", response_model=EventListResponse)
async def get_events(
    since_id: int = 0,
    event_type: Optional[str] = None,
    limit: int = 100,
    manager: EngagementManager = Depends(get_manager),
):
    """Get event history with optional filtering.

    Args:
        since_id: Only return events with ID > since_id (for pagination/polling)
        event_type: Filter by event type (exact or wildcard like "red.*")
        limit: Max events to return (default 100, max 500)
    """
    limit = min(limit, 500)

    events = manager.event_bus.get_history(
        event_type=event_type,
        since_id=since_id,
        limit=limit,
    )

    return EventListResponse(
        events=[
            EventResponse(
                event_id=e.event_id,
                event_type=e.type,
                source=e.source,
                timestamp=e.timestamp,
                data=_sanitize_event_data(e.data),
            )
            for e in events
        ],
        total=manager.event_bus.event_count,
    )


def _sanitize_event_data(data: dict) -> dict:
    """Ensure all event data values are JSON-serializable.

    Tool results can contain non-serializable objects. Convert everything
    to strings as a safety net.
    """
    sanitized = {}
    for key, value in data.items():
        if isinstance(value, (str, int, float, bool, type(None))):
            sanitized[key] = value
        elif isinstance(value, dict):
            sanitized[key] = _sanitize_event_data(value)
        elif isinstance(value, list):
            sanitized[key] = [
                _sanitize_event_data(v) if isinstance(v, dict) else str(v)
                for v in value
            ]
        else:
            sanitized[key] = str(value)
    return sanitized