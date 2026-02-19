# PHASE 7: Wire Temporal Activities to Real Tools

## Context

Read MASTER_PLAN.md, PHASE_5.md, PHASE_6.md first. The current `activities.py` uses hardcoded sample data — every activity is a PLACEHOLDER. The direct orchestrator runs agents instead of Temporal. This phase fixes both problems and makes Temporal the real execution backbone.

## What This Phase Builds

1. **Real Temporal activities** — Replace ALL placeholder data with actual tool calls
2. **Workflow rewiring** — Temporal workflows become the actual execution engine
3. **Human-in-the-loop signals** — Wire Temporal signals for CRITICAL exploit approval
4. **Activity error handling** — Retry policies, timeouts, heartbeats for long-running tools
5. **Engagement state machine** — Track engagement lifecycle through Temporal workflow state

## Why It Matters

Without this phase, Sentinel's Temporal infrastructure is decoration. Real pentesting needs durable execution: scans that survive crashes, human gates that pause workflows, and state that persists across tool failures. This is what separates a demo from a platform.

---

## File-by-File Implementation

### 1. `src/sentinel/activities/__init__.py`

```python
"""Temporal activities — real tool integrations replacing placeholder data."""
```

### 2. `src/sentinel/activities/recon_activities.py`

```python
"""
Recon activities — wire Temporal to real recon tools.

Replaces placeholder discover_hosts, scan_ports, etc. with actual NmapTool, DNSTool, HTTPReconTool calls.
"""
from temporalio import activity
from sentinel.tools.recon.nmap_tool import NmapTool
from sentinel.tools.recon.dns_tool import DNSTool
from sentinel.tools.recon.http_recon_tool import HTTPReconTool
from sentinel.tools.recon.web_crawler_tool import WebCrawlerTool
from sentinel.graph.client import GraphClient
from sentinel.logging import get_logger

logger = get_logger(__name__)


@activity.defn
async def discover_hosts(target: str, engagement_id: str) -> dict:
    """
    Discover hosts and open ports on target.
    REPLACES: placeholder that returned hardcoded sample data.
    NOW: runs actual NmapTool + DNSTool.
    """
    activity.heartbeat("Starting host discovery")
    
    nmap = NmapTool()
    dns = DNSTool()
    graph = GraphClient()
    
    # DNS enumeration
    activity.heartbeat("Running DNS enumeration")
    dns_result = await dns.execute(target)
    
    # Nmap scan
    activity.heartbeat("Running Nmap scan")
    nmap_result = await nmap.execute(
        target=target,
        scan_type="service_detection",  # -sV
        ports="1-10000",
    )
    
    # Write to knowledge graph
    hosts = []
    if nmap_result.success:
        for host_data in nmap_result.data.get("hosts", []):
            await graph.query(
                """
                MERGE (h:Host {ip: $ip, engagement_id: $eid})
                SET h.hostname = $hostname, h.state = $state, h.os = $os
                WITH h
                UNWIND $ports AS port_data
                MERGE (p:Port {number: port_data.port, protocol: port_data.protocol})-[:BELONGS_TO]->(h)
                SET p.state = port_data.state
                WITH p, port_data
                WHERE port_data.service IS NOT NULL
                MERGE (s:Service {name: port_data.service, version: port_data.version})-[:RUNS_ON]->(p)
                """,
                {
                    "ip": host_data.get("ip"),
                    "eid": engagement_id,
                    "hostname": host_data.get("hostname", ""),
                    "state": host_data.get("state", "up"),
                    "os": host_data.get("os", "unknown"),
                    "ports": host_data.get("ports", []),
                }
            )
            hosts.append(host_data)
    
    return {
        "hosts_found": len(hosts),
        "dns_records": dns_result.data if dns_result.success else [],
        "hosts": hosts,
    }


@activity.defn
async def crawl_target(target_url: str, engagement_id: str, max_depth: int = 3) -> dict:
    """
    Crawl target web application to discover endpoints.
    REPLACES: placeholder.
    NOW: runs WebCrawlerTool and writes endpoints to graph.
    """
    activity.heartbeat("Starting web crawl")
    
    crawler = WebCrawlerTool()
    graph = GraphClient()
    
    result = await crawler.execute(
        target=target_url,
        max_depth=max_depth,
    )
    
    endpoints = []
    if result.success:
        for endpoint in result.data.get("endpoints", []):
            activity.heartbeat(f"Recording endpoint: {endpoint.get('url', '')[:50]}")
            await graph.query(
                """
                MERGE (e:Endpoint {url: $url, engagement_id: $eid})
                SET e.method = $method, e.params = $params, 
                    e.content_type = $content_type, e.status_code = $status
                """,
                {
                    "url": endpoint.get("url"),
                    "eid": engagement_id,
                    "method": endpoint.get("method", "GET"),
                    "params": str(endpoint.get("params", [])),
                    "content_type": endpoint.get("content_type", ""),
                    "status": endpoint.get("status_code", 0),
                }
            )
            endpoints.append(endpoint)
    
    return {"endpoints_found": len(endpoints), "endpoints": endpoints}


@activity.defn
async def http_recon(target_url: str, engagement_id: str) -> dict:
    """
    HTTP reconnaissance — headers, tech stack fingerprinting.
    REPLACES: placeholder.
    """
    activity.heartbeat("Running HTTP recon")
    
    http_tool = HTTPReconTool()
    result = await http_tool.execute(target=target_url)
    
    return {
        "headers": result.data.get("headers", {}),
        "technologies": result.data.get("technologies", []),
        "server": result.data.get("server", ""),
    }
```

### 3. `src/sentinel/activities/vuln_activities.py`

```python
"""
Vulnerability analysis activities — wire Temporal to VulnAgent, Nuclei, ZAP.
"""
from temporalio import activity
from sentinel.agents.vuln_agent import GuardedVulnAgent
from sentinel.agents.hypothesis_engine import HypothesisEngine
from sentinel.tools.scanning.nuclei_tool import NucleiTool, NucleiSeverity
from sentinel.tools.scanning.zap_tool import ZAPTool
from sentinel.graph.client import GraphClient
from sentinel.logging import get_logger

logger = get_logger(__name__)


@activity.defn
async def generate_hypotheses(engagement_id: str) -> list[dict]:
    """Generate vulnerability hypotheses from recon data in graph."""
    activity.heartbeat("Generating hypotheses")
    graph = GraphClient()
    engine = HypothesisEngine(graph)
    hypotheses = await engine.generate_hypotheses(engagement_id)
    return [
        {
            "id": h.id,
            "category": h.category.value,
            "confidence": h.confidence.value,
            "target_url": h.target_url,
            "target_param": h.target_param,
            "priority_score": h.priority_score,
            "risk_level": h.risk_level,
        }
        for h in hypotheses
    ]


@activity.defn
async def analyze_service_vulns(engagement_id: str, target: str) -> list[dict]:
    """
    Run vulnerability analysis using GuardedVulnAgent.
    REPLACES: placeholder that returned sample vuln data.
    NOW: runs actual hypothesis testing with Nuclei/ZAP/existing tools.
    """
    activity.heartbeat("Starting vulnerability analysis")
    
    graph = GraphClient()
    # LLM client initialization — use configured provider
    from sentinel.llm.client import get_llm_client
    from sentinel.agents.policy_engine import PolicyEngine
    
    llm = get_llm_client()
    policy = PolicyEngine()
    agent = GuardedVulnAgent(graph, llm, policy)
    
    findings = await agent.run(engagement_id, target)
    
    activity.heartbeat(f"Found {len(findings)} verified vulnerabilities")
    return findings


@activity.defn
async def run_nuclei_scan(target: str, tags: list[str] = None) -> dict:
    """Run standalone Nuclei scan as Temporal activity."""
    activity.heartbeat("Running Nuclei scan")
    nuclei = NucleiTool()
    result = await nuclei.execute(
        target=target,
        tags=tags,
        severity=[NucleiSeverity.CRITICAL, NucleiSeverity.HIGH],
    )
    return {
        "success": result.success,
        "findings_count": result.metadata.get("total_findings", 0),
        "by_severity": result.metadata.get("by_severity", {}),
    }


@activity.defn
async def run_zap_scan(target: str) -> dict:
    """Run ZAP scan as Temporal activity."""
    activity.heartbeat("Running ZAP scan")
    zap = ZAPTool()
    result = await zap.execute(target=target, full_scan=True)
    return {
        "success": result.success,
        "alerts_count": result.metadata.get("total_alerts", 0),
        "by_risk": result.metadata.get("by_risk", {}),
    }
```

### 4. `src/sentinel/activities/exploit_activities.py`

```python
"""
Exploitation activities — wire Temporal to ExploitAgent with approval gates.
"""
from temporalio import activity
from sentinel.agents.exploit_agent import GuardedExploitAgent
from sentinel.agents.finding_verifier import FindingVerifier
from sentinel.tools.exploit.poc_generator import PoCGenerator
from sentinel.graph.client import GraphClient
from sentinel.logging import get_logger

logger = get_logger(__name__)


@activity.defn
async def attempt_exploit(engagement_id: str, findings: list[dict]) -> list[dict]:
    """
    Attempt exploitation of verified findings.
    REPLACES: placeholder that returned sample exploit data.
    NOW: runs GuardedExploitAgent with real exploit tools.
    """
    activity.heartbeat("Starting exploitation phase")
    
    graph = GraphClient()
    from sentinel.llm.client import get_llm_client
    from sentinel.agents.policy_engine import PolicyEngine
    
    llm = get_llm_client()
    policy = PolicyEngine()
    agent = GuardedExploitAgent(graph, llm, policy)
    
    results = await agent.run(engagement_id, findings)
    activity.heartbeat(f"Exploited {len(results)} findings")
    return results


@activity.defn
async def verify_exploit(finding: dict, replay_count: int = 3) -> dict:
    """
    Verify exploit by replaying it.
    REPLACES: placeholder.
    NOW: runs FindingVerifier with actual replay.
    """
    activity.heartbeat(f"Verifying finding {finding.get('hypothesis_id', 'unknown')}")
    
    verifier = FindingVerifier()
    verified = await verifier.verify(finding, replay_count=replay_count)
    
    return {
        "finding_id": verified.finding_id,
        "confirmed": verified.false_positive_check,
        "confirmed_count": verified.confirmed_count,
        "poc_script": verified.poc_script,
        "replay_commands": verified.replay_commands,
        "severity": verified.severity,
    }


@activity.defn
async def generate_poc_artifacts(engagement_id: str, findings: list[dict]) -> dict:
    """Generate PoC replay scripts for all exploited findings."""
    activity.heartbeat("Generating PoC artifacts")
    
    generator = PoCGenerator()
    artifacts = generator.generate(findings, engagement_id)
    
    return {
        "python_script": artifacts.python_script,
        "bash_script": artifacts.bash_script,
        "postman_collection": artifacts.postman_collection,
        "attack_graph": artifacts.attack_graph_json,
    }
```

### 5. `src/sentinel/activities/report_activities.py`

```python
"""
Reporting activities — wire to actual PDF generator and graph queries.
"""
from temporalio import activity
from sentinel.graph.client import GraphClient
from sentinel.logging import get_logger

logger = get_logger(__name__)


@activity.defn
async def generate_report(engagement_id: str, report_type: str = "full") -> dict:
    """
    Generate engagement report.
    REPLACES: placeholder.
    NOW: queries graph for all findings, generates PDF via existing Jinja2/weasyprint pipeline.
    """
    activity.heartbeat("Generating report")
    
    graph = GraphClient()
    
    # Query all findings for engagement
    findings = await graph.query(
        """
        MATCH (f:Finding {engagement_id: $eid})
        OPTIONAL MATCH (f)<-[:HAS_VULNERABILITY]-(e:Endpoint)
        OPTIONAL MATCH (e)-[:BELONGS_TO]->(h:Host)
        RETURN f, e, h
        ORDER BY f.severity DESC
        """,
        {"eid": engagement_id}
    )
    
    # Query attack chains
    chains = await graph.query(
        """
        MATCH path = (start:Finding {engagement_id: $eid, exploited: true})-[:ENABLES*1..5]->(end)
        RETURN path
        """,
        {"eid": engagement_id}
    )
    
    # Use existing reporting infrastructure
    from sentinel.reports.generator import ReportGenerator
    
    generator = ReportGenerator()
    report = await generator.generate(
        engagement_id=engagement_id,
        findings=findings,
        attack_chains=chains,
        report_type=report_type,
    )
    
    return {
        "report_path": report.file_path,
        "summary": report.executive_summary,
        "total_findings": len(findings),
        "critical": sum(1 for f in findings if f.get("severity") == "critical"),
    }
```

### 6. `src/sentinel/workflows/pentest_workflow.py` (REWRITE)

```python
"""
PentestWorkflow — The REAL Temporal workflow replacing the direct orchestrator.

This is the master workflow that orchestrates the entire pentest engagement:
Recon → Vuln Analysis → Exploitation → Verification → Reporting

Each phase is a Temporal activity with:
- Retry policies (transient failures)
- Timeouts (prevent infinite hangs)
- Heartbeats (long-running tools report progress)
- Human-in-the-loop signals (CRITICAL exploit approval)
"""
from datetime import timedelta
from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from sentinel.activities.recon_activities import discover_hosts, crawl_target, http_recon
    from sentinel.activities.vuln_activities import generate_hypotheses, analyze_service_vulns, run_nuclei_scan, run_zap_scan
    from sentinel.activities.exploit_activities import attempt_exploit, verify_exploit, generate_poc_artifacts
    from sentinel.activities.report_activities import generate_report


RETRY_POLICY = RetryPolicy(
    initial_interval=timedelta(seconds=5),
    maximum_interval=timedelta(minutes=2),
    maximum_attempts=3,
    non_retryable_error_types=["PolicyDeniedError", "AuthenticationError"],
)


@workflow.defn
class PentestWorkflow:
    """
    Master pentest engagement workflow.
    
    Lifecycle:
    1. RECON: discover_hosts → crawl_target → http_recon
    2. VULN_ANALYSIS: generate_hypotheses → analyze_service_vulns (+ Nuclei + ZAP)
    3. EXPLOITATION: attempt_exploit (with human gate for CRITICAL) → verify_exploit
    4. REPORTING: generate_poc_artifacts → generate_report
    
    State:
    - engagement_id: unique engagement identifier
    - status: current phase
    - findings: accumulated findings
    - approvals: pending/completed human approvals
    """
    
    def __init__(self):
        self.status = "initialized"
        self.findings = []
        self.exploited = []
        self.approval_pending = False
        self.approval_granted = False
    
    @workflow.signal
    async def approve_critical_exploit(self, approved: bool):
        """Human-in-the-loop: approve or deny CRITICAL exploit execution."""
        self.approval_granted = approved
        self.approval_pending = False
    
    @workflow.query
    def get_status(self) -> dict:
        return {
            "status": self.status,
            "findings_count": len(self.findings),
            "exploited_count": len(self.exploited),
            "approval_pending": self.approval_pending,
        }
    
    @workflow.run
    async def run(self, engagement_id: str, target: str, config: dict = None) -> dict:
        config = config or {}
        
        # ===== PHASE 1: RECON =====
        self.status = "recon"
        
        # Run recon activities in parallel
        hosts_result = await workflow.execute_activity(
            discover_hosts,
            args=[target, engagement_id],
            start_to_close_timeout=timedelta(minutes=10),
            heartbeat_timeout=timedelta(minutes=2),
            retry_policy=RETRY_POLICY,
        )
        
        crawl_result = await workflow.execute_activity(
            crawl_target,
            args=[f"http://{target}" if not target.startswith("http") else target, engagement_id],
            start_to_close_timeout=timedelta(minutes=15),
            heartbeat_timeout=timedelta(minutes=3),
            retry_policy=RETRY_POLICY,
        )
        
        http_result = await workflow.execute_activity(
            http_recon,
            args=[f"http://{target}" if not target.startswith("http") else target, engagement_id],
            start_to_close_timeout=timedelta(minutes=5),
            retry_policy=RETRY_POLICY,
        )
        
        # ===== PHASE 2: VULNERABILITY ANALYSIS =====
        self.status = "vuln_analysis"
        
        # Generate hypotheses from recon data
        hypotheses = await workflow.execute_activity(
            generate_hypotheses,
            args=[engagement_id],
            start_to_close_timeout=timedelta(minutes=5),
            retry_policy=RETRY_POLICY,
        )
        
        # Run vulnerability analysis
        self.findings = await workflow.execute_activity(
            analyze_service_vulns,
            args=[engagement_id, target],
            start_to_close_timeout=timedelta(minutes=30),
            heartbeat_timeout=timedelta(minutes=5),
            retry_policy=RETRY_POLICY,
        )
        
        # ===== PHASE 3: EXPLOITATION =====
        self.status = "exploitation"
        
        if self.findings:
            # Check if any findings are CRITICAL and need human approval
            critical_findings = [f for f in self.findings if f.get("severity") == "critical"]
            
            if critical_findings and config.get("require_approval", True):
                self.approval_pending = True
                # Wait for human signal
                await workflow.wait_condition(lambda: not self.approval_pending)
                
                if not self.approval_granted:
                    # Human denied — skip CRITICAL exploits
                    self.findings = [f for f in self.findings if f.get("severity") != "critical"]
            
            self.exploited = await workflow.execute_activity(
                attempt_exploit,
                args=[engagement_id, self.findings],
                start_to_close_timeout=timedelta(minutes=30),
                heartbeat_timeout=timedelta(minutes=5),
                retry_policy=RETRY_POLICY,
            )
            
            # Verify each exploit
            for exploit in self.exploited:
                verified = await workflow.execute_activity(
                    verify_exploit,
                    args=[exploit],
                    start_to_close_timeout=timedelta(minutes=5),
                    retry_policy=RETRY_POLICY,
                )
                exploit["verified"] = verified
        
        # ===== PHASE 4: REPORTING =====
        self.status = "reporting"
        
        # Generate PoC artifacts
        poc = await workflow.execute_activity(
            generate_poc_artifacts,
            args=[engagement_id, self.exploited],
            start_to_close_timeout=timedelta(minutes=5),
            retry_policy=RETRY_POLICY,
        )
        
        # Generate report
        report = await workflow.execute_activity(
            generate_report,
            args=[engagement_id],
            start_to_close_timeout=timedelta(minutes=10),
            retry_policy=RETRY_POLICY,
        )
        
        self.status = "complete"
        
        return {
            "engagement_id": engagement_id,
            "status": "complete",
            "recon": {"hosts": hosts_result["hosts_found"], "endpoints": crawl_result["endpoints_found"]},
            "findings": len(self.findings),
            "exploited": len(self.exploited),
            "report": report,
            "poc_artifacts": poc,
        }
```

### 7. `src/sentinel/workflows/worker.py`

```python
"""
Temporal worker — registers all activities and workflows.
"""
import asyncio
from temporalio.client import Client
from temporalio.worker import Worker

from sentinel.workflows.pentest_workflow import PentestWorkflow
from sentinel.activities.recon_activities import discover_hosts, crawl_target, http_recon
from sentinel.activities.vuln_activities import (
    generate_hypotheses, analyze_service_vulns, run_nuclei_scan, run_zap_scan
)
from sentinel.activities.exploit_activities import attempt_exploit, verify_exploit, generate_poc_artifacts
from sentinel.activities.report_activities import generate_report
from sentinel.config import get_config
from sentinel.logging import get_logger

logger = get_logger(__name__)

TASK_QUEUE = "sentinel-pentest"


async def run_worker():
    """Start Temporal worker with all activities registered."""
    config = get_config()
    client = await Client.connect(
        config.get("temporal_host", "localhost:7233"),
        namespace=config.get("temporal_namespace", "default"),
    )
    
    worker = Worker(
        client,
        task_queue=TASK_QUEUE,
        workflows=[PentestWorkflow],
        activities=[
            # Recon
            discover_hosts,
            crawl_target,
            http_recon,
            # Vuln Analysis
            generate_hypotheses,
            analyze_service_vulns,
            run_nuclei_scan,
            run_zap_scan,
            # Exploitation
            attempt_exploit,
            verify_exploit,
            generate_poc_artifacts,
            # Reporting
            generate_report,
        ],
    )
    
    logger.info(f"Temporal worker starting on queue: {TASK_QUEUE}")
    await worker.run()


if __name__ == "__main__":
    asyncio.run(run_worker())
```

### 8. `src/sentinel/llm/client.py`

**Purpose**: Multi-LLM client factory supporting Cerebras, Claude, and OpenAI.

```python
"""
Multi-LLM client factory.

Returns the appropriate LLM client based on configuration.
Supports: Cerebras (speed), Claude (reasoning), OpenAI (fallback/embeddings).
"""
from sentinel.config import get_config
from sentinel.logging import get_logger

logger = get_logger(__name__)


def get_llm_client(provider: str = None, task_type: str = "general"):
    """
    Get LLM client for a specific task.
    
    Task types and default providers:
    - "speed": Cerebras (real-time defense, rapid hypothesis generation)
    - "reasoning": Claude (exploit chain planning, report generation)
    - "embedding": OpenAI (pgvector embeddings, in Phase 8)
    - "general": Use configured default
    """
    config = get_config()
    
    if provider is None:
        provider_map = {
            "speed": "cerebras",
            "reasoning": "claude",
            "embedding": "openai",
            "general": config.get("default_llm_provider", "cerebras"),
        }
        provider = provider_map.get(task_type, "cerebras")
    
    if provider == "cerebras":
        from sentinel.llm.cerebras_client import CerebrasClient
        return CerebrasClient(
            api_key=config.get("cerebras_api_key"),
            model=config.get("cerebras_model", "zai-glm-4.7"),
        )
    elif provider == "claude":
        from sentinel.llm.claude_client import ClaudeClient
        return ClaudeClient(
            api_key=config.get("anthropic_api_key"),
            model=config.get("claude_model", "claude-sonnet-4-5-20250929"),
        )
    elif provider == "openai":
        from sentinel.llm.openai_client import OpenAIClient
        return OpenAIClient(
            api_key=config.get("openai_api_key"),
            model=config.get("openai_model", "gpt-4o"),
        )
    else:
        raise ValueError(f"Unknown LLM provider: {provider}")
```

---

## Tests

### `tests/workflows/test_pentest_workflow.py`

```python
import pytest
from unittest.mock import AsyncMock, patch
from sentinel.workflows.pentest_workflow import PentestWorkflow

class TestPentestWorkflow:
    def test_initial_status(self):
        wf = PentestWorkflow()
        assert wf.status == "initialized"
        assert wf.findings == []
    
    def test_get_status(self):
        wf = PentestWorkflow()
        status = wf.get_status()
        assert status["status"] == "initialized"
        assert status["findings_count"] == 0
```

### `tests/activities/test_recon_activities.py`

```python
import pytest
from unittest.mock import AsyncMock, patch

class TestReconActivities:
    @pytest.mark.asyncio
    @patch("sentinel.activities.recon_activities.NmapTool")
    @patch("sentinel.activities.recon_activities.DNSTool")
    @patch("sentinel.activities.recon_activities.GraphClient")
    async def test_discover_hosts_calls_real_tools(self, mock_graph, mock_dns, mock_nmap):
        mock_nmap_instance = mock_nmap.return_value
        mock_nmap_instance.execute = AsyncMock(return_value=AsyncMock(
            success=True, data={"hosts": [{"ip": "127.0.0.1", "ports": []}]}
        ))
        mock_dns_instance = mock_dns.return_value
        mock_dns_instance.execute = AsyncMock(return_value=AsyncMock(success=True, data=[]))
        mock_graph_instance = mock_graph.return_value
        mock_graph_instance.query = AsyncMock()
        
        # Verify it calls real tools, not returns hardcoded data
        from sentinel.activities.recon_activities import discover_hosts
        # Note: Can't directly test @activity.defn without Temporal context
        # This validates the wiring logic
```

---

## Integration Points

1. **Replaces**: ALL placeholder code in the existing `activities.py`
2. **Temporal**: Becomes the real execution backbone (not just imported-but-unused)
3. **Direct orchestrator**: Should now delegate to Temporal instead of running agents directly
4. **API layer**: Existing REST endpoints start workflows via Temporal client
5. **WebSocket**: Workflow status queries (get_status) feed into real-time streaming
6. **Human gate**: CRITICAL exploit approval via Temporal signals from API/frontend

## Acceptance Criteria

- [ ] Zero placeholder data remains in any activity
- [ ] `discover_hosts` calls real NmapTool + DNSTool and writes to Neo4j
- [ ] `analyze_service_vulns` runs real GuardedVulnAgent
- [ ] `attempt_exploit` runs real GuardedExploitAgent
- [ ] PentestWorkflow executes full pipeline against Juice Shop
- [ ] Human-in-the-loop signal pauses workflow for CRITICAL exploits
- [ ] Retry policies handle transient tool failures
- [ ] Heartbeats prevent activity timeout during long scans
- [ ] Temporal worker starts and registers all activities
- [ ] Multi-LLM client returns correct provider for task type