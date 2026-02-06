"""Tests for the API server.

Uses FastAPI's TestClient (sync) and httpx (async) for testing.
All tests mock the EngagementManager to avoid needing real settings or API keys.
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient
from fastapi import FastAPI

from sentinel.api.app import create_app
from sentinel.api.routes import router, get_manager
from sentinel.api.manager import EngagementManager, EngagementState
from sentinel.api.models import HealthResponse
from sentinel.events.bus import EventBus, Event


@pytest.fixture
def mock_manager():
    """Create a mock EngagementManager."""
    manager = MagicMock(spec=EngagementManager)
    manager.state = EngagementState.IDLE
    manager.phase = None
    manager.target_url = None
    manager.elapsed = None
    manager.result = None
    manager.event_bus = EventBus()
    manager.check_juice_shop = AsyncMock(return_value=True)
    manager.start_engagement = AsyncMock(return_value=True)
    manager.stop_engagement = AsyncMock(return_value=True)
    return manager


@pytest.fixture
def app(mock_manager):
    """Create a FastAPI app with mocked manager."""
    test_app = FastAPI(title="SENTINEL Test")

    test_app.include_router(router, prefix="/api")

    # Override dependency
    test_app.dependency_overrides[get_manager] = lambda: mock_manager

    return test_app


@pytest.fixture
def client(app):
    """Create a test client."""
    return TestClient(app)


# ── Health ──

def test_health_check(client, mock_manager):
    """Health endpoint returns status and Juice Shop connectivity."""
    response = client.get("/api/health")
    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "ok"
    assert data["juice_shop_reachable"] is True
    assert data["engagement_active"] is False


def test_health_check_juice_shop_down(client, mock_manager):
    """Health endpoint reports when Juice Shop is unreachable."""
    mock_manager.check_juice_shop = AsyncMock(return_value=False)

    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["juice_shop_reachable"] is False


# ── Start/Stop ──

def test_start_engagement(client, mock_manager):
    """POST /engagement/start creates a new engagement."""
    response = client.post("/api/engagement/start", json={
        "target_url": "http://localhost:3000",
        "monitor_max_cycles": 5,
    })

    assert response.status_code == 200
    assert response.json()["status"] == "started"
    mock_manager.start_engagement.assert_called_once()


def test_start_engagement_conflict(client, mock_manager):
    """Starting an engagement while one is running returns 409."""
    mock_manager.start_engagement = AsyncMock(return_value=False)

    response = client.post("/api/engagement/start", json={})
    assert response.status_code == 409


def test_stop_engagement(client, mock_manager):
    """POST /engagement/stop stops the running engagement."""
    response = client.post("/api/engagement/stop")
    assert response.status_code == 200
    assert response.json()["status"] == "stopped"


def test_stop_engagement_nothing_running(client, mock_manager):
    """Stopping when nothing is running returns 409."""
    mock_manager.stop_engagement = AsyncMock(return_value=False)

    response = client.post("/api/engagement/stop")
    assert response.status_code == 409


# ── State ──

def test_get_state_idle(client, mock_manager):
    """State endpoint returns idle when nothing is running."""
    response = client.get("/api/engagement/state")
    assert response.status_code == 200

    data = response.json()
    assert data["state"] == "idle"
    assert data["phase"] is None


def test_get_state_running(client, mock_manager):
    """State endpoint returns running with phase info."""
    mock_manager.state = EngagementState.RUNNING
    mock_manager.phase = "attack"
    mock_manager.target_url = "http://localhost:3000"
    mock_manager.elapsed = 15.5

    response = client.get("/api/engagement/state")
    data = response.json()

    assert data["state"] == "running"
    assert data["phase"] == "attack"
    assert data["target_url"] == "http://localhost:3000"
    assert data["elapsed_seconds"] == 15.5


# ── Result ──

def test_get_result_not_available(client, mock_manager):
    """Result endpoint returns 404 when no result exists."""
    response = client.get("/api/engagement/result")
    assert response.status_code == 404


def test_get_result_available(client, mock_manager):
    """Result endpoint returns full engagement result."""
    from sentinel.orchestrator.engine import EngagementResult
    from sentinel.agents.base import AgentResult
    from sentinel.core.client import CompletionMetrics

    mock_result = EngagementResult(
        success=True,
        target_url="http://localhost:3000",
        duration=45.0,
        event_count=100,
        speed_stats={
            "total_tokens": 5000,
            "total_llm_time_seconds": 10.0,
            "total_tool_calls": 30,
            "avg_tokens_per_second": 500,
            "engagement_wall_clock_seconds": 45.0,
        },
        red_report="# Pentest Report\nSQL injection found.",
        blue_report="# Incident Report\nAttacks detected.",
    )
    mock_result.agent_results["recon"] = AgentResult(
        agent_name="recon_agent",
        success=True,
        metrics=CompletionMetrics(total_time=5.0, input_tokens=1000, output_tokens=500, model="zai-glm-4.7"),
        findings={"summary": "Found open ports 80, 3000"},
        start_time=100.0,
        end_time=105.0,
    )
    mock_result.phases = {"recon": {"duration": 5.0, "success": True}}

    mock_manager.result = mock_result

    response = client.get("/api/engagement/result")
    assert response.status_code == 200

    data = response.json()
    assert data["success"] is True
    assert data["target_url"] == "http://localhost:3000"
    assert data["duration"] == 45.0
    assert data["event_count"] == 100
    assert "recon" in data["agents"]
    assert data["agents"]["recon"]["success"] is True
    assert data["agents"]["recon"]["input_tokens"] == 1000
    assert data["speed_stats"]["avg_tokens_per_second"] == 500
    assert "SQL injection" in data["red_report"]


# ── Events ──

@pytest.mark.asyncio
async def test_get_events(client, mock_manager):
    """Events endpoint returns event history."""
    bus = mock_manager.event_bus
    await bus.publish(Event(type="red.tool_call", data={"tool": "port_scan"}, source="recon"))
    await bus.publish(Event(type="blue.alert", data={"analysis": "SQLi detected"}, source="monitor"))

    response = client.get("/api/engagement/events")
    assert response.status_code == 200

    data = response.json()
    assert data["total"] == 2
    assert len(data["events"]) == 2
    assert data["events"][0]["event_type"] == "red.tool_call"


@pytest.mark.asyncio
async def test_get_events_since_id(client, mock_manager):
    """Events endpoint supports since_id filtering."""
    bus = mock_manager.event_bus
    await bus.publish(Event(type="a", data={}, source="test"))
    await bus.publish(Event(type="b", data={}, source="test"))
    await bus.publish(Event(type="c", data={}, source="test"))

    response = client.get("/api/engagement/events?since_id=2")
    data = response.json()

    assert len(data["events"]) == 1
    assert data["events"][0]["event_type"] == "c"


# ── Validation ──

def test_start_engagement_validation(client, mock_manager):
    """Request validation catches invalid parameters."""
    response = client.post("/api/engagement/start", json={
        "monitor_poll_interval": 0.1,  # Below minimum 0.5
    })
    assert response.status_code == 422  # Validation error


def test_reports_not_available(client, mock_manager):
    """Reports endpoint returns 404 when no result exists."""
    response = client.get("/api/engagement/reports")
    assert response.status_code == 404