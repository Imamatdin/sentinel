"""Pydantic models for API request/response validation.

These models define the API contract between the backend and frontend.
They serialize the internal dataclasses (EngagementResult, AgentResult, etc.)
into clean JSON structures.
"""

from typing import Any, Optional
from pydantic import BaseModel, Field


# ── Request Models ──

class StartEngagementRequest(BaseModel):
    """Request to start a new engagement."""

    target_url: str = Field(
        default="http://localhost:3000",
        description="Target application URL",
    )
    monitor_poll_interval: float = Field(
        default=3.0,
        ge=0.5,
        le=30.0,
        description="Seconds between monitoring cycles",
    )
    monitor_max_cycles: int = Field(
        default=10,
        ge=1,
        le=50,
        description="Maximum monitoring cycles during attack phase",
    )
    defender_max_responses: int = Field(
        default=10,
        ge=1,
        le=30,
        description="Maximum defensive responses",
    )
    exploit_max_iterations: int = Field(
        default=15,
        ge=1,
        le=30,
        description="Maximum tool loop iterations for exploit agent",
    )
    skip_recon: bool = Field(
        default=False,
        description="Skip reconnaissance phase (faster, for testing)",
    )
    skip_reports: bool = Field(
        default=False,
        description="Skip report generation phase (faster runs)",
    )


# ── Response Models ──

class HealthResponse(BaseModel):
    """Health check response."""

    status: str = "ok"
    version: str
    juice_shop_reachable: bool
    juice_shop_url: str
    engagement_active: bool


class EngagementStateResponse(BaseModel):
    """Current engagement state."""

    state: str  # "idle", "running", "completed", "failed"
    phase: Optional[str] = None  # "recon", "attack", "report", None
    target_url: Optional[str] = None
    elapsed_seconds: Optional[float] = None
    event_count: int = 0


class AgentResultResponse(BaseModel):
    """Serialized agent result."""

    agent_name: str
    success: bool
    duration: float
    tool_calls_made: int
    input_tokens: int
    output_tokens: int
    total_llm_time: float
    error: Optional[str] = None
    findings_summary: Optional[str] = None


class SpeedStatsResponse(BaseModel):
    """Speed statistics for the demo narrative."""

    total_tokens: int = 0
    total_llm_time_seconds: float = 0.0
    total_tool_calls: int = 0
    avg_tokens_per_second: int = 0
    engagement_wall_clock_seconds: float = 0.0
    attack_to_first_defense_seconds: Optional[float] = None


class EngagementResultResponse(BaseModel):
    """Complete engagement result."""

    success: bool
    target_url: str
    duration: float
    event_count: int
    phases: dict[str, Any]
    agents: dict[str, AgentResultResponse]
    speed_stats: SpeedStatsResponse
    red_report: str = ""
    blue_report: str = ""


class EventResponse(BaseModel):
    """Serialized event for REST endpoint."""

    event_id: int
    event_type: str
    source: str
    timestamp: float
    data: dict[str, Any]


class EventListResponse(BaseModel):
    """List of events."""

    events: list[EventResponse]
    total: int