"""Dashboard API routes for the Phase 10 multi-engagement platform.

Provides REST endpoints for:
- Multi-engagement CRUD
- Findings browsing + retest
- Attack graph data
- Red vs Blue adversarial loop
- Report generation (OWASP, CIS)
- Engagement diff (CTEM)

These are stub endpoints that return mock data structures matching
the frontend TypeScript interfaces. Real implementations will wire
into Temporal workflows, Neo4j graph, and Genome pipeline.
"""

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from temporalio.client import Client

from sentinel.core.config import get_settings
from sentinel.orchestration.workflows import PentestWorkflow
from sentinel.orchestration.activities import EngagementConfig
from sentinel.core import get_logger
from sentinel.events.bus import EventBus, Event
from fastapi import WebSocket, WebSocketDisconnect
import asyncio
import json

router = APIRouter(tags=["dashboard"])
logger = get_logger(__name__)
settings = get_settings()

# Shared EventBus for emitting real-time updates
_event_bus = EventBus()

# Track workflow handles for status monitoring
_workflow_handles: dict[str, Any] = {}


# ── Request/Response Models ──────────────────────────────────────────


class CreateEngagementRequest(BaseModel):
    target_url: str = "http://localhost:3000"
    require_approval: bool = True
    scan_depth: int = 3
    llm_provider: str = "cerebras"
    excluded_paths: list[str] = []
    schedule: str | None = None


class ApproveRequest(BaseModel):
    approved: bool


class GenerateReportRequest(BaseModel):
    type: str = "executive"


class GenomeIntelRequest(BaseModel):
    tech_stack: list[str]


# ── In-memory store (stub) ───────────────────────────────────────────

_engagements: dict[str, dict[str, Any]] = {}
_findings: dict[str, dict[str, Any]] = {}
_redblue_metrics: dict[str, dict[str, Any]] = {}


# ── Workflow Monitoring ──────────────────────────────────────────────


async def _monitor_workflow(engagement_id: str, handle: Any) -> None:
    """Monitor workflow execution and emit events + update status."""
    import asyncio
    from temporalio.client import WorkflowExecutionStatus

    last_phase = None

    try:
        while True:
            # Poll workflow status every 2 seconds
            await asyncio.sleep(2)

            # Get workflow description
            desc = await handle.describe()
            status = desc.status

            eng = _engagements.get(engagement_id)
            if not eng:
                break

            # Map Temporal status to engagement status
            if status == WorkflowExecutionStatus.RUNNING:
                # Query workflow state to get current phase
                try:
                    workflow_state = await handle.query("get_state")
                    current_phase = workflow_state.get("phase", "unknown")
                    awaiting_approval = workflow_state.get("awaiting_approval", False)

                    # Update engagement status based on workflow phase
                    if awaiting_approval:
                        if eng["status"] != "paused":
                            eng["status"] = "paused"
                            eng["updated_at"] = _now()
                            await _event_bus.publish(Event(
                                type="engagement.paused",
                                data={
                                    "engagement_id": engagement_id,
                                    "message": f"Waiting for approval (found {workflow_state.get('vulnerabilities_found', 0)} vulns)"
                                },
                                source="dashboard"
                            ))
                            logger.info(f"Engagement {engagement_id} awaiting approval")
                    elif current_phase != last_phase:
                        # Phase changed - update status (map to frontend phase names)
                        phase_map = {
                            "reconnaissance": "recon",
                            "vulnerability_analysis": "vuln_analysis",
                            "awaiting_approval": "paused",
                            "exploitation": "exploitation",
                            "verification": "exploitation",  # UI doesn't have separate verification status
                            "reporting": "reporting",
                            "completed": "complete",
                        }
                        new_status = phase_map.get(current_phase, current_phase)
                        if new_status != eng["status"]:
                            eng["status"] = new_status
                            eng["updated_at"] = _now()
                            await _event_bus.publish(Event(
                                type="engagement.phase_change",
                                data={
                                    "engagement_id": engagement_id,
                                    "phase": current_phase,
                                    "message": f"Phase: {current_phase}"
                                },
                                source="dashboard"
                            ))
                            logger.info(f"Engagement {engagement_id} phase: {current_phase}")
                        last_phase = current_phase
                except Exception as e:
                    logger.warning(f"Failed to query workflow state: {e}")
                continue

            elif status == WorkflowExecutionStatus.COMPLETED:
                eng = _engagements.get(engagement_id)
                if eng:
                    eng["status"] = "complete"
                    eng["updated_at"] = _now()
                    await _event_bus.publish(Event(
                        type="engagement.complete",
                        data={"engagement_id": engagement_id, "message": "Engagement completed"},
                        source="dashboard"
                    ))
                break
            elif status in (WorkflowExecutionStatus.FAILED, WorkflowExecutionStatus.TERMINATED):
                eng = _engagements.get(engagement_id)
                if eng:
                    eng["status"] = "failed"
                    eng["updated_at"] = _now()
                    await _event_bus.publish(Event(
                        type="engagement.failed",
                        data={"engagement_id": engagement_id, "message": "Engagement failed"},
                        source="dashboard"
                    ))
                break

    except Exception as e:
        logger.error(f"Workflow monitor error for {engagement_id}: {e}")
    finally:
        # Clean up workflow handle
        _workflow_handles.pop(engagement_id, None)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


async def dashboard_websocket_handler(websocket: WebSocket) -> None:
    """Simple WebSocket handler for dashboard events."""
    await websocket.accept()
    queue = _event_bus.subscribe("*")

    try:
        while True:
            try:
                event: Event = await asyncio.wait_for(queue.get(), timeout=1.0)

                # Send event to client
                await websocket.send_json({
                    "timestamp": event.timestamp,
                    "type": event.type,
                    "data": event.data,
                })

            except asyncio.TimeoutError:
                # Send keepalive ping
                try:
                    await websocket.send_json({"type": "ping"})
                except:
                    break

    except (WebSocketDisconnect, RuntimeError):
        pass
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        _event_bus.unsubscribe(queue)


# ── Engagement CRUD ──────────────────────────────────────────────────


@router.get("/engagements")
async def list_engagements() -> list[dict[str, Any]]:
    return list(_engagements.values())


@router.post("/engagements")
async def create_engagement(req: CreateEngagementRequest) -> dict[str, Any]:
    eng_id = str(uuid4())
    engagement = {
        "id": eng_id,
        "target": req.target_url,
        "status": "initialized",
        "created_at": _now(),
        "updated_at": _now(),
        "config": {
            "target_url": req.target_url,
            "require_approval": req.require_approval,
            "scan_depth": req.scan_depth,
            "excluded_paths": req.excluded_paths,
            "llm_provider": req.llm_provider,
            "schedule": req.schedule,
        },
        "summary": None,
    }
    _engagements[eng_id] = engagement
    return engagement


@router.get("/engagements/{engagement_id}")
async def get_engagement(engagement_id: str) -> dict[str, Any]:
    eng = _engagements.get(engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found")
    return eng


@router.post("/engagements/{engagement_id}/start")
async def start_engagement(engagement_id: str) -> dict[str, str]:
    eng = _engagements.get(engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found")

    try:
        # Connect to Temporal and start workflow
        client = await Client.connect(settings.temporal_host)

        # Parse target URL to extract host/IP for scanning
        from urllib.parse import urlparse
        parsed = urlparse(eng["target"])
        target_host = parsed.hostname or eng["target"]
        target_ips = [target_host]

        # Build workflow config from engagement config
        workflow_config = EngagementConfig(
            engagement_id=engagement_id,
            target_url=eng["target"],
            target_ips=target_ips,
            scope_includes=[],
            scope_excludes=eng["config"].get("excluded_paths", []),
            max_depth=eng["config"].get("scan_depth", 2),
            max_duration_minutes=120,
            require_approval_for_exploitation=eng["config"].get("require_approval", False),
        )

        # Start the workflow
        from datetime import timedelta
        handle = await client.start_workflow(
            PentestWorkflow.run,
            workflow_config,
            id=f"pentest-{engagement_id}",
            task_queue=settings.temporal_task_queue,
            execution_timeout=timedelta(hours=2),
            run_timeout=timedelta(hours=2),
        )

        logger.info(f"Started Temporal workflow for engagement {engagement_id}: {handle.id}")

        # Store workflow handle
        _workflow_handles[engagement_id] = handle

        # Start background monitor
        import asyncio
        asyncio.create_task(_monitor_workflow(engagement_id, handle))

        # Update engagement status
        eng["status"] = "recon"
        eng["updated_at"] = _now()

        # Emit event
        await _event_bus.publish(Event(
            type="engagement.started",
            data={
                "engagement_id": engagement_id,
                "target_url": eng["target"],
                "message": "Engagement started"
            },
            source="dashboard"
        ))

        return {"status": "started", "workflow_id": handle.id}

    except Exception as e:
        logger.error(f"Failed to start workflow for engagement {engagement_id}: {e}")
        eng["status"] = "failed"
        eng["updated_at"] = _now()
        raise HTTPException(status_code=500, detail=f"Failed to start engagement: {str(e)}")


@router.post("/engagements/{engagement_id}/stop")
async def stop_engagement(engagement_id: str) -> dict[str, str]:
    eng = _engagements.get(engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found")
    eng["status"] = "failed"
    eng["updated_at"] = _now()
    return {"status": "stopped"}


@router.post("/engagements/{engagement_id}/approve")
async def approve_engagement(engagement_id: str, req: ApproveRequest) -> dict[str, str]:
    eng = _engagements.get(engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found")

    # Get workflow handle
    handle = _workflow_handles.get(engagement_id)
    if not handle:
        raise HTTPException(status_code=400, detail="No active workflow for this engagement")

    try:
        # Send approval signal to workflow
        await handle.signal("approve_critical_exploit", req.approved)

        # Update engagement status
        if req.approved:
            eng["status"] = "exploitation"
            eng["updated_at"] = _now()
            await _event_bus.publish(Event(
                type="engagement.approved",
                data={"engagement_id": engagement_id, "message": "Exploitation approved"},
                source="dashboard"
            ))
            logger.info(f"Exploitation approved for engagement {engagement_id}")
        else:
            eng["status"] = "failed"
            eng["updated_at"] = _now()
            await _event_bus.publish(Event(
                type="engagement.denied",
                data={"engagement_id": engagement_id, "message": "Exploitation denied"},
                source="dashboard"
            ))
            logger.info(f"Exploitation denied for engagement {engagement_id}")

        return {"status": "approved" if req.approved else "denied"}

    except Exception as e:
        logger.error(f"Failed to send approval signal for {engagement_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to approve: {str(e)}")


@router.get("/engagements/diff")
async def engagement_diff(e1: str, e2: str) -> dict[str, Any]:
    return {
        "engagement_1": e1,
        "engagement_2": e2,
        "new_paths": [],
        "closed_paths": [],
        "persistent_paths": [],
        "delta_count": 0,
    }


# ── Findings ─────────────────────────────────────────────────────────


@router.get("/findings")
async def list_findings(engagement_id: str | None = None) -> list[dict[str, Any]]:
    if engagement_id:
        return [f for f in _findings.values() if f.get("engagement_id") == engagement_id]
    return list(_findings.values())


@router.get("/findings/{finding_id}")
async def get_finding(finding_id: str) -> dict[str, Any]:
    finding = _findings.get(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.post("/findings/{finding_id}/retest")
async def retest_finding(finding_id: str) -> dict[str, str]:
    finding = _findings.get(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    finding["remediation_status"] = "fix_pending"
    return {"status": "retest_queued"}


# ── Attack Graph ─────────────────────────────────────────────────────


@router.get("/engagements/{engagement_id}/graph")
async def get_graph(engagement_id: str) -> dict[str, Any]:
    return {"nodes": [], "edges": []}


@router.get("/engagements/{engagement_id}/chains")
async def get_chains(engagement_id: str) -> list[dict[str, Any]]:
    return []


# ── Red vs Blue ──────────────────────────────────────────────────────


@router.post("/engagements/{engagement_id}/redblue/start")
async def start_redblue(engagement_id: str) -> dict[str, str]:
    _redblue_metrics[engagement_id] = {
        "total_rounds": 0,
        "red_successes": 0,
        "blue_detections": 0,
        "blue_blocks": 0,
        "avg_detection_latency_ms": 0,
        "avg_response_latency_ms": 0,
        "coverage_score": 0,
        "rounds": [],
    }
    return {"status": "started"}


@router.get("/engagements/{engagement_id}/redblue/metrics")
async def get_redblue_metrics(engagement_id: str) -> dict[str, Any]:
    return _redblue_metrics.get(engagement_id, {
        "total_rounds": 0,
        "red_successes": 0,
        "blue_detections": 0,
        "blue_blocks": 0,
        "avg_detection_latency_ms": 0,
        "avg_response_latency_ms": 0,
        "coverage_score": 0,
        "rounds": [],
    })


# ── Genome ───────────────────────────────────────────────────────────


@router.post("/genome/intel")
async def genome_intel(req: GenomeIntelRequest) -> dict[str, Any]:
    return {
        "tech_stack": req.tech_stack,
        "known_vulnerabilities": [],
        "recommended_techniques": [],
        "historical_success_rate": 0,
    }


# ── Reports ──────────────────────────────────────────────────────────


@router.post("/engagements/{engagement_id}/report")
async def generate_report(engagement_id: str, req: GenerateReportRequest) -> dict[str, str]:
    return {"status": "generated", "type": req.type}


@router.get("/engagements/{engagement_id}/report/owasp")
async def get_owasp_mapping(engagement_id: str) -> list[dict[str, Any]]:
    return [
        {
            "category": "A01:2021 - Broken Access Control",
            "findings_count": 0,
            "severity_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "status": "not_tested",
        },
        {
            "category": "A02:2021 - Cryptographic Failures",
            "findings_count": 0,
            "severity_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "status": "not_tested",
        },
        {
            "category": "A03:2021 - Injection",
            "findings_count": 0,
            "severity_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "status": "not_tested",
        },
    ]


@router.get("/engagements/{engagement_id}/report/cis")
async def get_cis_mapping(engagement_id: str) -> list[dict[str, Any]]:
    return []


@router.get("/engagements/{engagement_id}/report/download")
async def download_report(engagement_id: str) -> dict[str, str]:
    raise HTTPException(status_code=404, detail="No report generated yet")
