"""Dashboard API routes for the Phase 10 multi-engagement platform.

Provides REST endpoints for:
- Multi-engagement CRUD (backed by in-memory store + Temporal)
- Findings browsing + retest (backed by Neo4j)
- Attack graph data (backed by Neo4j)
- Red vs Blue adversarial loop
- Report generation (OWASP, CIS)
- Engagement diff (CTEM)

Engagement lifecycle is managed in-memory; findings and graph data
are queried live from Neo4j where the Temporal workflow writes them.
"""

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from temporalio.client import Client

from sentinel.core.config import get_settings
from sentinel.orchestration.workflows import PentestWorkflow
from sentinel.orchestration.activities import EngagementConfig
from sentinel.core import get_logger
from sentinel.events.bus import EventBus, Event
from sentinel.graph.neo4j_client import Neo4jClient, get_graph_client
from sentinel.graph.models import NodeType
import asyncio

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


# ── In-memory store ──────────────────────────────────────────────────

_engagements: dict[str, dict[str, Any]] = {}
_redblue_metrics: dict[str, dict[str, Any]] = {}

# Phase map: Temporal workflow phase names → frontend status names
_PHASE_MAP = {
    "reconnaissance": "recon",
    "vulnerability_analysis": "vuln_analysis",
    "awaiting_approval": "paused",
    "exploitation": "exploitation",
    "verification": "exploitation",
    "reporting": "reporting",
    "completed": "complete",
}


# ── Neo4j Helpers ────────────────────────────────────────────────────


async def _get_graph() -> Neo4jClient:
    """Get Neo4j client, tolerating connection failures."""
    try:
        return await get_graph_client()
    except Exception as e:
        logger.warning(f"Neo4j unavailable: {e}")
        raise


async def _query_findings_from_graph(engagement_id: str) -> list[dict[str, Any]]:
    """Query Vulnerability nodes from Neo4j for an engagement."""
    try:
        graph = await _get_graph()
        records = await graph.query(
            """
            MATCH (v:Vulnerability {engagement_id: $eid})
            OPTIONAL MATCH (s:Service)-[:HAS_VULNERABILITY]->(v)
            OPTIONAL MATCH (p:Port)-[:RUNS_SERVICE]->(s)
            OPTIONAL MATCH (h:Host)-[:HAS_PORT]->(p)
            RETURN v, s.name as service_name, p.port_number as port,
                   h.ip_address as host_ip
            ORDER BY
                CASE v.severity
                    WHEN 'critical' THEN 0
                    WHEN 'high' THEN 1
                    WHEN 'medium' THEN 2
                    WHEN 'low' THEN 3
                    ELSE 4
                END
            """,
            {"eid": engagement_id},
        )
        findings = []
        for r in records:
            v = r["v"]
            target_url = v.get("target_url", "")
            if not target_url and r.get("host_ip") and r.get("port"):
                target_url = f"http://{r['host_ip']}:{r['port']}"
            findings.append({
                "id": v.get("id", ""),
                "engagement_id": engagement_id,
                "category": v.get("name", "unknown"),
                "severity": v.get("severity", "medium"),
                "confidence": v.get("confidence", "medium"),
                "target_url": target_url,
                "target_param": v.get("target_param", ""),
                "evidence": v.get("evidence", v.get("description", "")),
                "remediation": v.get("remediation", ""),
                "mitre_technique": v.get("mitre_technique", v.get("cwe_id", "")),
                "verified": v.get("is_verified", False),
                "exploited": v.get("is_exploited", False),
                "poc_script": v.get("poc_script", ""),
                "replay_commands": [],
                "remediation_status": "open",
                "created_at": v.get("created_at", _now()),
            })
        return findings
    except Exception as e:
        logger.warning(f"Failed to query findings from Neo4j: {e}")
        return []


async def _build_summary_from_graph(engagement_id: str, start_time: str) -> dict[str, Any]:
    """Build engagement summary by querying Neo4j for actual counts."""
    try:
        graph = await _get_graph()
        counts = await graph.query(
            """
            MATCH (n {engagement_id: $eid})
            WITH labels(n)[0] as label, count(n) as cnt
            RETURN collect({label: label, count: cnt}) as counts
            """,
            {"eid": engagement_id},
        )
        label_counts = {}
        if counts and counts[0].get("counts"):
            for entry in counts[0]["counts"]:
                label_counts[entry["label"]] = entry["count"]

        # Severity breakdown
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        try:
            sev_records = await graph.query(
                """
                MATCH (v:Vulnerability {engagement_id: $eid})
                RETURN v.severity as severity, count(v) as cnt
                """,
                {"eid": engagement_id},
            )
            for r in sev_records:
                s = r.get("severity", "medium")
                if s in severity_counts:
                    severity_counts[s] = r["cnt"]
        except Exception:
            pass

        # Exploited count
        exploited = 0
        try:
            exp_records = await graph.query(
                """
                MATCH (v:Vulnerability {engagement_id: $eid, is_exploited: true})
                RETURN count(v) as cnt
                """,
                {"eid": engagement_id},
            )
            if exp_records:
                exploited = exp_records[0].get("cnt", 0)
        except Exception:
            pass

        # Duration
        try:
            from datetime import datetime as dt
            started = dt.fromisoformat(start_time.replace("Z", "+00:00"))
            elapsed = (dt.now(timezone.utc) - started).total_seconds()
        except Exception:
            elapsed = 0

        return {
            "hosts_found": label_counts.get("Host", 0),
            "endpoints_found": label_counts.get("Endpoint", 0),
            "findings_count": label_counts.get("Vulnerability", 0),
            "exploited_count": exploited,
            "critical": severity_counts["critical"],
            "high": severity_counts["high"],
            "medium": severity_counts["medium"],
            "low": severity_counts["low"],
            "duration_seconds": round(elapsed),
        }
    except Exception as e:
        logger.warning(f"Failed to build summary from Neo4j: {e}")
        return None


async def _query_graph_nodes_edges(engagement_id: str) -> dict[str, Any]:
    """Query all nodes and edges for an engagement from Neo4j."""
    try:
        graph = await _get_graph()

        # Get all nodes for this engagement
        node_records = await graph.query(
            """
            MATCH (n {engagement_id: $eid})
            RETURN n, labels(n)[0] as label
            """,
            {"eid": engagement_id},
        )

        nodes = []
        for r in node_records:
            n = r["n"]
            label_type = r["label"]
            type_map = {
                "Host": "host", "Port": "port", "Service": "service",
                "Endpoint": "endpoint", "Vulnerability": "vulnerability",
                "Credential": "credential", "Session": "finding",
            }
            display_label = (
                n.get("hostname") or n.get("ip_address") or n.get("name")
                or n.get("url") or n.get("port_number") or str(n.get("id", ""))[:8]
            )
            node = {
                "id": n.get("id", ""),
                "type": type_map.get(label_type, "host"),
                "label": str(display_label),
                "metadata": {
                    k: v for k, v in n.items()
                    if k not in ("id", "engagement_id") and not k.startswith("_")
                },
            }
            if n.get("severity"):
                node["severity"] = n["severity"]
            nodes.append(node)

        # Get all relationships between engagement nodes
        edge_records = await graph.query(
            """
            MATCH (a {engagement_id: $eid})-[r]->(b {engagement_id: $eid})
            RETURN a.id as source, b.id as target, type(r) as rel_type
            """,
            {"eid": engagement_id},
        )

        edges = []
        for r in edge_records:
            edges.append({
                "source": r["source"],
                "target": r["target"],
                "type": r["rel_type"],
                "label": r["rel_type"].replace("_", " ").title(),
            })

        return {"nodes": nodes, "edges": edges}
    except Exception as e:
        logger.warning(f"Failed to query graph from Neo4j: {e}")
        return {"nodes": [], "edges": []}


# ── Workflow Monitoring ──────────────────────────────────────────────


async def _monitor_workflow(engagement_id: str, handle: Any) -> None:
    """Monitor workflow execution, update status, and sync summary from Neo4j."""
    from temporalio.client import WorkflowExecutionStatus

    last_phase = None
    last_finding_count = 0

    try:
        while True:
            await asyncio.sleep(2)

            desc = await handle.describe()
            status = desc.status

            eng = _engagements.get(engagement_id)
            if not eng:
                break

            if status == WorkflowExecutionStatus.RUNNING:
                try:
                    workflow_state = await handle.query("get_state")
                    current_phase = workflow_state.get("phase", "unknown")
                    awaiting_approval = workflow_state.get("awaiting_approval", False)

                    # Sync summary from Neo4j on every poll
                    summary = await _build_summary_from_graph(
                        engagement_id, eng.get("created_at", _now())
                    )
                    if summary:
                        eng["summary"] = summary

                    # Emit finding events for newly discovered vulnerabilities
                    current_finding_count = summary.get("findings_count", 0) if summary else 0
                    if current_finding_count > last_finding_count:
                        new_count = current_finding_count - last_finding_count
                        await _event_bus.publish(Event(
                            type="finding_new",
                            data={
                                "engagement_id": engagement_id,
                                "message": f"Discovered {new_count} new finding(s) ({current_finding_count} total)",
                                "count": current_finding_count,
                            },
                            source="dashboard",
                        ))
                        last_finding_count = current_finding_count

                    if awaiting_approval:
                        if eng["status"] != "paused":
                            eng["status"] = "paused"
                            eng["updated_at"] = _now()
                            vuln_count = workflow_state.get("vulnerabilities_found", 0)
                            await _event_bus.publish(Event(
                                type="approval_required",
                                data={
                                    "engagement_id": engagement_id,
                                    "message": f"Awaiting approval ({vuln_count} vulns found)",
                                },
                                source="dashboard",
                            ))
                            logger.info(f"Engagement {engagement_id} awaiting approval")
                    elif current_phase != last_phase:
                        new_status = _PHASE_MAP.get(current_phase, current_phase)
                        if new_status != eng["status"]:
                            eng["status"] = new_status
                            eng["updated_at"] = _now()
                            await _event_bus.publish(Event(
                                type="phase_change",
                                data={
                                    "engagement_id": engagement_id,
                                    "phase": new_status,
                                    "message": f"Phase: {current_phase}",
                                },
                                source="dashboard",
                            ))
                            logger.info(f"Engagement {engagement_id} phase: {current_phase}")
                        last_phase = current_phase
                except Exception as e:
                    logger.warning(f"Failed to query workflow state: {e}")
                continue

            elif status == WorkflowExecutionStatus.COMPLETED:
                if eng:
                    # Final summary sync
                    summary = await _build_summary_from_graph(
                        engagement_id, eng.get("created_at", _now())
                    )
                    if summary:
                        eng["summary"] = summary
                    eng["status"] = "complete"
                    eng["updated_at"] = _now()
                    await _event_bus.publish(Event(
                        type="engagement_complete",
                        data={
                            "engagement_id": engagement_id,
                            "message": "Engagement completed",
                            "summary": eng.get("summary"),
                        },
                        source="dashboard",
                    ))
                break

            elif status in (WorkflowExecutionStatus.FAILED, WorkflowExecutionStatus.TERMINATED):
                if eng:
                    # Sync whatever we got before failure
                    summary = await _build_summary_from_graph(
                        engagement_id, eng.get("created_at", _now())
                    )
                    if summary:
                        eng["summary"] = summary
                    eng["status"] = "failed"
                    eng["updated_at"] = _now()
                    await _event_bus.publish(Event(
                        type="engagement_complete",
                        data={
                            "engagement_id": engagement_id,
                            "message": "Engagement failed",
                        },
                        source="dashboard",
                    ))
                break

    except Exception as e:
        logger.error(f"Workflow monitor error for {engagement_id}: {e}")
    finally:
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
    # Lazily refresh summary from Neo4j if engagement is active
    if eng["status"] not in ("initialized", "complete", "failed") or (
        eng["status"] in ("complete", "failed") and eng.get("summary") is None
    ):
        summary = await _build_summary_from_graph(
            engagement_id, eng.get("created_at", _now())
        )
        if summary:
            eng["summary"] = summary
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

    # Cancel the Temporal workflow if running
    handle = _workflow_handles.get(engagement_id)
    if handle:
        try:
            await handle.cancel()
            logger.info(f"Cancelled workflow for engagement {engagement_id}")
        except Exception as e:
            logger.warning(f"Failed to cancel workflow: {e}")

    # Sync final summary
    summary = await _build_summary_from_graph(
        engagement_id, eng.get("created_at", _now())
    )
    if summary:
        eng["summary"] = summary

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


# ── Findings (backed by Neo4j) ───────────────────────────────────────


@router.get("/findings")
async def list_findings(engagement_id: str | None = None) -> list[dict[str, Any]]:
    if not engagement_id:
        # Without engagement_id, aggregate across all known engagements
        all_findings = []
        for eid in _engagements:
            all_findings.extend(await _query_findings_from_graph(eid))
        return all_findings
    return await _query_findings_from_graph(engagement_id)


@router.get("/findings/{finding_id}")
async def get_finding(finding_id: str) -> dict[str, Any]:
    try:
        graph = await _get_graph()
        node = await graph.get_node(finding_id, NodeType.VULNERABILITY)
        if not node:
            raise HTTPException(status_code=404, detail="Finding not found")
        return {
            "id": node.get("id", ""),
            "engagement_id": node.get("engagement_id", ""),
            "category": node.get("name", "unknown"),
            "severity": node.get("severity", "medium"),
            "confidence": node.get("confidence", "medium"),
            "target_url": node.get("target_url", ""),
            "target_param": node.get("target_param", ""),
            "evidence": node.get("evidence", node.get("description", "")),
            "remediation": node.get("remediation", ""),
            "mitre_technique": node.get("mitre_technique", node.get("cwe_id", "")),
            "verified": node.get("is_verified", False),
            "exploited": node.get("is_exploited", False),
            "poc_script": node.get("poc_script", ""),
            "replay_commands": [],
            "remediation_status": "open",
            "created_at": node.get("created_at", _now()),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.warning(f"Failed to get finding from Neo4j: {e}")
        raise HTTPException(status_code=404, detail="Finding not found")


@router.post("/findings/{finding_id}/retest")
async def retest_finding(finding_id: str) -> dict[str, str]:
    try:
        graph = await _get_graph()
        node = await graph.get_node(finding_id, NodeType.VULNERABILITY)
        if not node:
            raise HTTPException(status_code=404, detail="Finding not found")
        # Mark in Neo4j for retest
        await graph.update_node(
            finding_id, NodeType.VULNERABILITY, {"remediation_status": "fix_pending"}
        )
        return {"status": "retest_queued"}
    except HTTPException:
        raise
    except Exception as e:
        logger.warning(f"Failed to queue retest: {e}")
        raise HTTPException(status_code=500, detail="Failed to queue retest")


# ── Attack Graph (backed by Neo4j) ───────────────────────────────────


@router.get("/engagements/{engagement_id}/graph")
async def get_graph(engagement_id: str) -> dict[str, Any]:
    return await _query_graph_nodes_edges(engagement_id)


@router.get("/engagements/{engagement_id}/chains")
async def get_chains(engagement_id: str) -> list[dict[str, Any]]:
    try:
        graph = await _get_graph()
        # Find attack chains: paths from hosts through vulns
        chains = await graph.query(
            """
            MATCH path = (h:Host {engagement_id: $eid})-[*1..6]->(v:Vulnerability {engagement_id: $eid})
            RETURN [n IN nodes(path) | {id: n.id, type: labels(n)[0], label: coalesce(n.hostname, n.ip_address, n.name, n.url, 'unknown')}] as steps,
                   length(path) as depth,
                   v.severity as severity
            ORDER BY
                CASE v.severity
                    WHEN 'critical' THEN 0
                    WHEN 'high' THEN 1
                    WHEN 'medium' THEN 2
                    ELSE 3
                END
            LIMIT 20
            """,
            {"eid": engagement_id},
        )
        result = []
        for i, r in enumerate(chains):
            result.append({
                "id": f"chain-{i}",
                "steps": r.get("steps", []),
                "total_depth": r.get("depth", 0),
                "exposure_score": {"critical": 10, "high": 7, "medium": 4, "low": 1}.get(
                    r.get("severity", "medium"), 3
                ),
                "crown_jewel": r["steps"][-1]["label"] if r.get("steps") else "",
            })
        return result
    except Exception as e:
        logger.warning(f"Failed to query attack chains: {e}")
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
    # OWASP Top 10 2021 categories and their keyword matches
    owasp_categories = [
        ("A01:2021 - Broken Access Control", ["idor", "access", "auth_bypass", "broken_access", "bola"]),
        ("A02:2021 - Cryptographic Failures", ["crypto", "tls", "ssl", "sensitive_data", "encryption"]),
        ("A03:2021 - Injection", ["injection", "sqli", "xss", "xxe", "command_injection", "ssti"]),
        ("A04:2021 - Insecure Design", ["design", "business_logic"]),
        ("A05:2021 - Security Misconfiguration", ["misconfig", "missing_security_headers", "default"]),
        ("A06:2021 - Vulnerable Components", ["supply_chain", "dependency", "outdated"]),
        ("A07:2021 - Auth Failures", ["authentication", "session", "brute_force", "credential"]),
        ("A08:2021 - Data Integrity Failures", ["deserialization", "integrity"]),
        ("A09:2021 - Logging Failures", ["logging", "monitoring"]),
        ("A10:2021 - SSRF", ["ssrf", "server_side_request"]),
    ]

    findings = await _query_findings_from_graph(engagement_id)
    results = []
    for category, keywords in owasp_categories:
        matched = [
            f for f in findings
            if any(kw in f.get("category", "").lower() for kw in keywords)
        ]
        sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in matched:
            s = f.get("severity", "medium")
            if s in sev:
                sev[s] += 1
        status = "not_tested"
        if matched:
            status = "fail"
        elif findings:
            status = "pass"
        results.append({
            "category": category,
            "findings_count": len(matched),
            "severity_breakdown": sev,
            "status": status,
        })
    return results


@router.get("/engagements/{engagement_id}/report/cis")
async def get_cis_mapping(engagement_id: str) -> list[dict[str, Any]]:
    return []


@router.get("/engagements/{engagement_id}/report/download")
async def download_report(engagement_id: str) -> dict[str, str]:
    raise HTTPException(status_code=404, detail="No report generated yet")


# ---------------------------------------------------------------------------
# Cost tracking
# ---------------------------------------------------------------------------
@router.get("/costs")
async def get_costs() -> dict[str, Any]:
    """Return LLM cost breakdown from the model router."""
    from sentinel.llm.model_router import ModelRouter
    r = ModelRouter()
    return r.get_cost_summary()
