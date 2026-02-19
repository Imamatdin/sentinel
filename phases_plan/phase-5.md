# PHASE 5: Vulnerability Analysis Agent

## Context

Read MASTER_PLAN.md first for full architecture context. Phases 0-4 are complete. This phase builds the vulnerability analysis layer that sits between recon and exploitation.

## What This Phase Builds

1. **GuardedVulnAgent** — LLM-guided vulnerability hypothesis testing
2. **Nuclei integration** — template-based vulnerability scanning
3. **ZAP integration** — DAST scanning via ZAP API
4. **Hypothesis Engine** — generates and prioritizes vulnerability hypotheses from recon data
5. **Finding Verifier** — promotes hypotheses to confirmed findings with evidence
6. **Knowledge Graph integration** — recon results flow in, verified findings flow out

## Why It Matters

Without this phase, Sentinel has recon tools and attack tools but no intelligent bridge between them. The VulnAgent turns raw recon into ranked, testable hypotheses — the Shannon-style approach that separates real platforms from "nmap + GPT" toys.

---

## File-by-File Implementation

### 1. `src/sentinel/tools/scanning/__init__.py`

```python
"""Vulnerability scanning tools — Nuclei and ZAP integrations."""
```

### 2. `src/sentinel/tools/scanning/nuclei_tool.py`

**Purpose**: Wraps Nuclei CLI for template-based vulnerability scanning.

```python
"""
NucleiTool — Template-based vulnerability scanner.

Nuclei runs YAML templates against targets to detect known vulnerabilities.
This tool wraps the CLI and parses JSON output into structured findings.
"""
import asyncio
import json
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

from sentinel.tools.base import BaseTool, ToolResult
from sentinel.config import get_config
from sentinel.logging import get_logger

logger = get_logger(__name__)


class NucleiSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class NucleiResult:
    template_id: str
    name: str
    severity: NucleiSeverity
    matched_url: str
    matched_at: str
    description: str
    reference: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    curl_command: str = ""
    extracted_results: list[str] = field(default_factory=list)
    raw_response: str = ""


class NucleiTool(BaseTool):
    """
    Runs Nuclei scans against target URLs.
    
    Supports:
    - Full template scans (all templates)
    - Severity-filtered scans
    - Tag-filtered scans (e.g., cve, sqli, xss, ssrf)
    - Custom template paths
    - Rate limiting and concurrency control
    """
    
    name = "nuclei_scan"
    description = "Run Nuclei vulnerability scanner against target"
    
    def __init__(self):
        self.nuclei_binary = get_config().get("nuclei_path", "nuclei")
        self.templates_path = get_config().get("nuclei_templates", "")
        self.max_rate = get_config().get("nuclei_rate_limit", 150)
        self.concurrency = get_config().get("nuclei_concurrency", 25)
        self.timeout = get_config().get("nuclei_timeout", 10)
    
    async def execute(
        self,
        target: str,
        severity: Optional[list[NucleiSeverity]] = None,
        tags: Optional[list[str]] = None,
        templates: Optional[list[str]] = None,
        exclude_tags: Optional[list[str]] = None,
        headless: bool = False,
    ) -> ToolResult:
        """
        Run Nuclei scan.
        
        Args:
            target: URL or host to scan
            severity: Filter by severity levels
            tags: Filter by template tags (e.g., ["sqli", "xss", "ssrf"])
            templates: Specific template paths to use
            exclude_tags: Tags to exclude
            headless: Enable headless browser templates
            
        Returns:
            ToolResult with list of NucleiResult findings
        """
        cmd = [
            self.nuclei_binary,
            "-target", target,
            "-json-export", "/dev/stdout",
            "-silent",
            "-rate-limit", str(self.max_rate),
            "-concurrency", str(self.concurrency),
            "-timeout", str(self.timeout),
            "-no-color",
        ]
        
        if severity:
            cmd.extend(["-severity", ",".join(s.value for s in severity)])
        
        if tags:
            cmd.extend(["-tags", ",".join(tags)])
        
        if templates:
            for t in templates:
                cmd.extend(["-t", t])
        elif self.templates_path:
            cmd.extend(["-t", self.templates_path])
        
        if exclude_tags:
            cmd.extend(["-exclude-tags", ",".join(exclude_tags)])
        
        if headless:
            cmd.append("-headless")
        
        logger.info(f"Running Nuclei scan: {' '.join(cmd)}")
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=300  # 5 min max per scan
            )
            
            results = self._parse_output(stdout.decode())
            
            return ToolResult(
                success=True,
                data=results,
                raw_output=stdout.decode(),
                tool_name=self.name,
                metadata={
                    "target": target,
                    "total_findings": len(results),
                    "by_severity": self._count_by_severity(results),
                }
            )
        except asyncio.TimeoutError:
            return ToolResult(
                success=False,
                error="Nuclei scan timed out after 300s",
                tool_name=self.name,
            )
        except Exception as e:
            logger.error(f"Nuclei scan failed: {e}")
            return ToolResult(
                success=False,
                error=str(e),
                tool_name=self.name,
            )
    
    def _parse_output(self, output: str) -> list[NucleiResult]:
        results = []
        for line in output.strip().split("\n"):
            if not line:
                continue
            try:
                data = json.loads(line)
                results.append(NucleiResult(
                    template_id=data.get("template-id", ""),
                    name=data.get("info", {}).get("name", ""),
                    severity=NucleiSeverity(data.get("info", {}).get("severity", "info")),
                    matched_url=data.get("matched-at", ""),
                    matched_at=data.get("matched-at", ""),
                    description=data.get("info", {}).get("description", ""),
                    reference=data.get("info", {}).get("reference", []),
                    tags=data.get("info", {}).get("tags", []),
                    curl_command=data.get("curl-command", ""),
                    extracted_results=data.get("extracted-results", []),
                    raw_response=data.get("response", ""),
                ))
            except (json.JSONDecodeError, ValueError) as e:
                logger.warning(f"Failed to parse Nuclei output line: {e}")
        return results
    
    def _count_by_severity(self, results: list[NucleiResult]) -> dict[str, int]:
        counts = {}
        for r in results:
            counts[r.severity.value] = counts.get(r.severity.value, 0) + 1
        return counts
```

### 3. `src/sentinel/tools/scanning/zap_tool.py`

**Purpose**: Wraps OWASP ZAP API for dynamic application security testing.

```python
"""
ZAPTool — OWASP ZAP DAST scanner integration.

Connects to ZAP running as a daemon (Docker service) and orchestrates:
- Spider crawling
- Active scanning
- Alert retrieval and parsing
"""
import asyncio
import aiohttp
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from sentinel.tools.base import BaseTool, ToolResult
from sentinel.config import get_config
from sentinel.logging import get_logger

logger = get_logger(__name__)


class ZAPRisk(str, Enum):
    HIGH = "3"
    MEDIUM = "2"
    LOW = "1"
    INFORMATIONAL = "0"


class ZAPConfidence(str, Enum):
    HIGH = "3"
    MEDIUM = "2"
    LOW = "1"
    FALSE_POSITIVE = "0"


@dataclass
class ZAPAlert:
    alert_id: int
    name: str
    risk: str
    confidence: str
    description: str
    url: str
    method: str
    param: str
    attack: str
    evidence: str
    solution: str
    reference: str
    cwe_id: int = 0
    wasc_id: int = 0
    tags: dict = field(default_factory=dict)


class ZAPTool(BaseTool):
    """
    Orchestrates OWASP ZAP scans via its REST API.
    
    Prerequisites:
    - ZAP running as daemon: docker run -u zap -p 8080:8080 zaproxy/zap-stable zap.sh -daemon -port 8080 -config api.disablekey=true
    - Or via docker-compose service (already defined in project)
    
    Supports:
    - Spider crawling (discover pages)
    - Ajax Spider (for SPAs)
    - Active scanning (find vulns)
    - Passive scanning (analyze traffic)
    - Authentication context setup
    """
    
    name = "zap_scan"
    description = "Run OWASP ZAP dynamic application security testing"
    
    def __init__(self):
        self.base_url = get_config().get("zap_api_url", "http://localhost:8080")
        self.api_key = get_config().get("zap_api_key", "")
    
    async def _api_call(self, endpoint: str, params: dict = None) -> dict:
        """Make ZAP API call."""
        params = params or {}
        if self.api_key:
            params["apikey"] = self.api_key
        
        url = f"{self.base_url}/{endpoint}"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, params=params) as resp:
                return await resp.json()
    
    async def spider(self, target: str, max_depth: int = 5) -> ToolResult:
        """Run ZAP spider to discover URLs."""
        try:
            # Start spider
            result = await self._api_call("JSON/spider/action/scan/", {
                "url": target,
                "maxDepth": str(max_depth),
            })
            scan_id = result.get("scan")
            
            # Poll until complete
            while True:
                status = await self._api_call("JSON/spider/view/status/", {
                    "scanId": scan_id
                })
                progress = int(status.get("status", "0"))
                if progress >= 100:
                    break
                await asyncio.sleep(2)
            
            # Get results
            urls = await self._api_call("JSON/spider/view/results/", {
                "scanId": scan_id
            })
            
            return ToolResult(
                success=True,
                data=urls.get("results", []),
                tool_name=self.name,
                metadata={"phase": "spider", "urls_found": len(urls.get("results", []))}
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e), tool_name=self.name)
    
    async def active_scan(self, target: str, scan_policy: Optional[str] = None) -> ToolResult:
        """Run ZAP active scan."""
        try:
            params = {"url": target}
            if scan_policy:
                params["scanPolicyName"] = scan_policy
            
            result = await self._api_call("JSON/ascan/action/scan/", params)
            scan_id = result.get("scan")
            
            # Poll until complete
            while True:
                status = await self._api_call("JSON/ascan/view/status/", {
                    "scanId": scan_id
                })
                progress = int(status.get("status", "0"))
                logger.info(f"ZAP active scan progress: {progress}%")
                if progress >= 100:
                    break
                await asyncio.sleep(5)
            
            # Get alerts
            alerts_data = await self._api_call("JSON/core/view/alerts/", {
                "baseurl": target
            })
            
            alerts = [
                ZAPAlert(
                    alert_id=int(a.get("id", 0)),
                    name=a.get("name", ""),
                    risk=a.get("risk", ""),
                    confidence=a.get("confidence", ""),
                    description=a.get("description", ""),
                    url=a.get("url", ""),
                    method=a.get("method", ""),
                    param=a.get("param", ""),
                    attack=a.get("attack", ""),
                    evidence=a.get("evidence", ""),
                    solution=a.get("solution", ""),
                    reference=a.get("reference", ""),
                    cwe_id=int(a.get("cweid", 0)),
                    wasc_id=int(a.get("wascid", 0)),
                    tags=a.get("tags", {}),
                )
                for a in alerts_data.get("alerts", [])
            ]
            
            return ToolResult(
                success=True,
                data=alerts,
                tool_name=self.name,
                metadata={
                    "phase": "active_scan",
                    "total_alerts": len(alerts),
                    "by_risk": self._count_by_risk(alerts),
                }
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e), tool_name=self.name)
    
    async def execute(self, target: str, full_scan: bool = True) -> ToolResult:
        """Run full ZAP pipeline: spider → active scan → collect alerts."""
        spider_result = await self.spider(target)
        if not spider_result.success:
            return spider_result
        
        if full_scan:
            return await self.active_scan(target)
        
        return spider_result
    
    def _count_by_risk(self, alerts: list[ZAPAlert]) -> dict[str, int]:
        counts = {}
        for a in alerts:
            counts[a.risk] = counts.get(a.risk, 0) + 1
        return counts
```

### 4. `src/sentinel/agents/hypothesis_engine.py`

**Purpose**: Generates ranked vulnerability hypotheses from recon data by querying the knowledge graph.

```python
"""
HypothesisEngine — Generates vulnerability hypotheses from recon data.

Takes recon results (hosts, services, endpoints) and produces ranked
hypotheses about what vulnerabilities likely exist and how to validate them.

This is the Shannon-style iterative planning that separates intelligent
pentesting from dumb scanning.
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from sentinel.graph.client import GraphClient
from sentinel.logging import get_logger

logger = get_logger(__name__)


class HypothesisConfidence(str, Enum):
    HIGH = "high"       # Strong indicators (e.g., known vuln version)
    MEDIUM = "medium"   # Likely based on patterns
    LOW = "low"         # Speculative but worth testing


class HypothesisCategory(str, Enum):
    INJECTION = "injection"         # SQLi, NoSQLi, command injection
    XSS = "xss"                     # Reflected, stored, DOM
    AUTH_BYPASS = "auth_bypass"     # Broken auth, session management
    IDOR = "idor"                   # Insecure direct object references
    SSRF = "ssrf"                   # Server-side request forgery
    FILE_UPLOAD = "file_upload"     # Unrestricted file upload
    XXE = "xxe"                     # XML external entity
    DESERIALIZATION = "deserialization"  # Insecure deserialization
    MISCONFIG = "misconfig"         # Security misconfiguration
    SENSITIVE_DATA = "sensitive_data"   # Sensitive data exposure
    BROKEN_ACCESS = "broken_access"     # Broken access control


@dataclass
class VulnHypothesis:
    """A single vulnerability hypothesis to test."""
    id: str
    category: HypothesisCategory
    confidence: HypothesisConfidence
    target_url: str
    target_param: Optional[str]
    description: str
    rationale: str          # Why we think this vuln exists
    test_plan: list[str]    # Ordered steps to validate
    required_tools: list[str]  # Which tools to use
    expected_evidence: str  # What confirms the vuln
    risk_level: str         # LOW, MEDIUM, HIGH, CRITICAL
    priority_score: float   # 0.0-1.0, used for ordering
    mitre_technique: str = ""  # MITRE ATT&CK technique ID
    dependencies: list[str] = field(default_factory=list)  # Hypothesis IDs this depends on


class HypothesisEngine:
    """
    Generates and prioritizes vulnerability hypotheses.
    
    Flow:
    1. Query knowledge graph for recon data (hosts, services, endpoints)
    2. Apply hypothesis rules based on service/technology fingerprints
    3. Use LLM to generate additional hypotheses from endpoint patterns
    4. Rank by confidence × impact × exploitability
    5. Return ordered list for GuardedVulnAgent to test
    """
    
    def __init__(self, graph_client: GraphClient, llm_client=None):
        self.graph = graph_client
        self.llm = llm_client
        self._rules = self._load_hypothesis_rules()
    
    async def generate_hypotheses(self, engagement_id: str) -> list[VulnHypothesis]:
        """Generate all hypotheses for an engagement."""
        hypotheses = []
        
        # 1. Get recon data from graph
        endpoints = await self.graph.query(
            "MATCH (e:Endpoint)-[:BELONGS_TO]->(h:Host) "
            "WHERE h.engagement_id = $eid "
            "RETURN e, h",
            {"eid": engagement_id}
        )
        
        services = await self.graph.query(
            "MATCH (s:Service)-[:RUNS_ON]->(p:Port)-[:BELONGS_TO]->(h:Host) "
            "WHERE h.engagement_id = $eid "
            "RETURN s, p, h",
            {"eid": engagement_id}
        )
        
        # 2. Apply rule-based hypotheses
        for endpoint in endpoints:
            hypotheses.extend(self._apply_rules(endpoint))
        
        # 3. Use LLM for pattern-based hypotheses
        if self.llm:
            llm_hypotheses = await self._llm_generate(endpoints, services)
            hypotheses.extend(llm_hypotheses)
        
        # 4. Deduplicate and rank
        hypotheses = self._deduplicate(hypotheses)
        hypotheses = self._rank(hypotheses)
        
        logger.info(f"Generated {len(hypotheses)} hypotheses for engagement {engagement_id}")
        return hypotheses
    
    def _load_hypothesis_rules(self) -> list[dict]:
        """
        Load hypothesis generation rules.
        
        Rules map patterns in recon data to vulnerability hypotheses.
        Example: login endpoint + POST method → auth bypass, credential stuffing
        Example: endpoint accepting XML → XXE
        Example: file upload endpoint → unrestricted upload
        """
        return [
            {
                "pattern": {"path_contains": ["login", "auth", "signin"]},
                "generates": [
                    HypothesisCategory.AUTH_BYPASS,
                    HypothesisCategory.INJECTION,
                ],
                "confidence": HypothesisConfidence.HIGH,
            },
            {
                "pattern": {"path_contains": ["upload", "file", "import"]},
                "generates": [HypothesisCategory.FILE_UPLOAD],
                "confidence": HypothesisConfidence.HIGH,
            },
            {
                "pattern": {"path_contains": ["api", "rest", "graphql"]},
                "generates": [
                    HypothesisCategory.IDOR,
                    HypothesisCategory.BROKEN_ACCESS,
                    HypothesisCategory.INJECTION,
                ],
                "confidence": HypothesisConfidence.MEDIUM,
            },
            {
                "pattern": {"param_contains": ["id", "user_id", "order_id"]},
                "generates": [HypothesisCategory.IDOR],
                "confidence": HypothesisConfidence.HIGH,
            },
            {
                "pattern": {"content_type_contains": ["xml", "soap"]},
                "generates": [HypothesisCategory.XXE],
                "confidence": HypothesisConfidence.HIGH,
            },
            {
                "pattern": {"param_contains": ["url", "redirect", "next", "callback"]},
                "generates": [HypothesisCategory.SSRF],
                "confidence": HypothesisConfidence.MEDIUM,
            },
            {
                "pattern": {"param_contains": ["search", "q", "query", "name", "comment"]},
                "generates": [HypothesisCategory.XSS, HypothesisCategory.INJECTION],
                "confidence": HypothesisConfidence.MEDIUM,
            },
        ]
    
    def _apply_rules(self, endpoint: dict) -> list[VulnHypothesis]:
        """Apply rule-based hypothesis generation to a single endpoint."""
        results = []
        # Implementation: match endpoint against rules, generate VulnHypothesis objects
        # Each hypothesis gets a unique ID, test plan, and priority score
        return results
    
    async def _llm_generate(self, endpoints: list, services: list) -> list[VulnHypothesis]:
        """Use LLM to identify additional vulnerability patterns."""
        # Build context from endpoints and services
        # Prompt LLM to identify non-obvious vulnerability patterns
        # Parse structured output into VulnHypothesis objects
        return []
    
    def _deduplicate(self, hypotheses: list[VulnHypothesis]) -> list[VulnHypothesis]:
        """Remove duplicate hypotheses targeting same vuln on same endpoint."""
        seen = set()
        deduped = []
        for h in hypotheses:
            key = (h.category, h.target_url, h.target_param)
            if key not in seen:
                seen.add(key)
                deduped.append(h)
        return deduped
    
    def _rank(self, hypotheses: list[VulnHypothesis]) -> list[VulnHypothesis]:
        """
        Rank hypotheses by: confidence × impact × exploitability.
        
        Prioritize:
        1. High confidence + critical impact (known vuln in detected version)
        2. Auth-related (highest business impact)
        3. Injection (most common, most impactful)
        4. Everything else by confidence
        """
        impact_weights = {
            HypothesisCategory.AUTH_BYPASS: 1.0,
            HypothesisCategory.INJECTION: 0.95,
            HypothesisCategory.SSRF: 0.9,
            HypothesisCategory.DESERIALIZATION: 0.9,
            HypothesisCategory.FILE_UPLOAD: 0.85,
            HypothesisCategory.XXE: 0.85,
            HypothesisCategory.IDOR: 0.8,
            HypothesisCategory.BROKEN_ACCESS: 0.8,
            HypothesisCategory.XSS: 0.7,
            HypothesisCategory.SENSITIVE_DATA: 0.6,
            HypothesisCategory.MISCONFIG: 0.5,
        }
        
        confidence_weights = {
            HypothesisConfidence.HIGH: 1.0,
            HypothesisConfidence.MEDIUM: 0.6,
            HypothesisConfidence.LOW: 0.3,
        }
        
        for h in hypotheses:
            h.priority_score = (
                confidence_weights.get(h.confidence, 0.3) *
                impact_weights.get(h.category, 0.5)
            )
        
        return sorted(hypotheses, key=lambda h: h.priority_score, reverse=True)
```

### 5. `src/sentinel/agents/vuln_agent.py`

**Purpose**: The GuardedVulnAgent — LLM-guided vulnerability testing.

```python
"""
GuardedVulnAgent — LLM-guided vulnerability analysis.

Extends GuardedBaseAgent to:
1. Receive ranked hypotheses from HypothesisEngine
2. Test each hypothesis using appropriate tools (existing attack tools + Nuclei + ZAP)
3. Verify findings with evidence
4. Promote verified findings to knowledge graph
5. Generate new hypotheses based on discoveries (iterative)
"""
from sentinel.agents.guarded_base import GuardedBaseAgent
from sentinel.agents.hypothesis_engine import (
    HypothesisEngine, VulnHypothesis, HypothesisCategory
)
from sentinel.tools.scanning.nuclei_tool import NucleiTool, NucleiSeverity
from sentinel.tools.scanning.zap_tool import ZAPTool
from sentinel.tools.base import ToolResult
from sentinel.graph.client import GraphClient
from sentinel.logging import get_logger

logger = get_logger(__name__)


class GuardedVulnAgent(GuardedBaseAgent):
    """
    Vulnerability analysis agent with policy-gated tool execution.
    
    Workflow per hypothesis:
    1. Read hypothesis from queue
    2. Select appropriate tool(s) based on category
    3. Execute through policy engine (risk check)
    4. Analyze results with LLM
    5. If confirmed: create Finding node in graph, record evidence
    6. If partially confirmed: generate refined sub-hypotheses
    7. If rejected: mark as tested, move on
    """
    
    agent_name = "vuln_analyst"
    
    CATEGORY_TO_TOOLS = {
        HypothesisCategory.INJECTION: ["sqli_tool", "nuclei_scan"],
        HypothesisCategory.XSS: ["xss_tool", "nuclei_scan"],
        HypothesisCategory.AUTH_BYPASS: ["auth_brute_tool", "zap_scan"],
        HypothesisCategory.IDOR: ["idor_tool"],
        HypothesisCategory.SSRF: ["nuclei_scan"],  # Phase 6 adds dedicated SSRF tool
        HypothesisCategory.FILE_UPLOAD: ["nuclei_scan"],  # Phase 6 adds dedicated tool
        HypothesisCategory.XXE: ["nuclei_scan"],  # Phase 6 adds dedicated tool
        HypothesisCategory.DESERIALIZATION: ["nuclei_scan"],
        HypothesisCategory.MISCONFIG: ["nuclei_scan", "zap_scan"],
        HypothesisCategory.SENSITIVE_DATA: ["zap_scan"],
        HypothesisCategory.BROKEN_ACCESS: ["idor_tool", "zap_scan"],
    }
    
    def __init__(self, graph_client: GraphClient, llm_client, policy_engine):
        super().__init__(llm_client=llm_client, policy_engine=policy_engine)
        self.graph = graph_client
        self.hypothesis_engine = HypothesisEngine(graph_client, llm_client)
        self.nuclei = NucleiTool()
        self.zap = ZAPTool()
        self.findings = []
    
    async def run(self, engagement_id: str, target: str) -> list[dict]:
        """
        Run full vulnerability analysis cycle.
        
        Returns list of verified findings.
        """
        # 1. Generate hypotheses
        hypotheses = await self.hypothesis_engine.generate_hypotheses(engagement_id)
        logger.info(f"Testing {len(hypotheses)} hypotheses against {target}")
        
        # 2. Test each hypothesis
        for hypothesis in hypotheses:
            result = await self.test_hypothesis(hypothesis, target)
            if result.get("verified"):
                self.findings.append(result)
                # 3. Write finding to knowledge graph
                await self._record_finding(engagement_id, result)
                # 4. Generate follow-up hypotheses (iterative deepening)
                follow_ups = await self._generate_follow_ups(hypothesis, result)
                hypotheses.extend(follow_ups)
        
        return self.findings
    
    async def test_hypothesis(self, hypothesis: VulnHypothesis, target: str) -> dict:
        """
        Test a single vulnerability hypothesis.
        
        Selects tools, executes through policy engine, analyzes results.
        """
        tools = self.CATEGORY_TO_TOOLS.get(hypothesis.category, ["nuclei_scan"])
        results = []
        
        for tool_name in tools:
            # Check policy before execution
            action = self._build_action(tool_name, hypothesis, target)
            if not await self.policy_engine.check(action):
                logger.warning(f"Policy denied {tool_name} for {hypothesis.id}")
                continue
            
            result = await self._execute_tool(tool_name, hypothesis, target)
            results.append(result)
        
        # Analyze results with LLM
        verification = await self._verify_with_llm(hypothesis, results)
        
        return {
            "hypothesis_id": hypothesis.id,
            "category": hypothesis.category.value,
            "target_url": hypothesis.target_url,
            "target_param": hypothesis.target_param,
            "verified": verification["confirmed"],
            "confidence": verification["confidence"],
            "evidence": verification["evidence"],
            "tool_results": results,
            "severity": verification.get("severity", hypothesis.risk_level),
            "remediation": verification.get("remediation", ""),
            "mitre_technique": hypothesis.mitre_technique,
        }
    
    async def _execute_tool(self, tool_name: str, hypothesis: VulnHypothesis, target: str) -> ToolResult:
        """Execute a specific tool for hypothesis testing."""
        if tool_name == "nuclei_scan":
            # Map hypothesis category to Nuclei tags
            tag_map = {
                HypothesisCategory.INJECTION: ["sqli", "nosqli"],
                HypothesisCategory.XSS: ["xss"],
                HypothesisCategory.SSRF: ["ssrf"],
                HypothesisCategory.XXE: ["xxe"],
                HypothesisCategory.FILE_UPLOAD: ["fileupload"],
                HypothesisCategory.MISCONFIG: ["misconfig"],
            }
            tags = tag_map.get(hypothesis.category, [])
            return await self.nuclei.execute(
                target=hypothesis.target_url or target,
                tags=tags,
                severity=[NucleiSeverity.CRITICAL, NucleiSeverity.HIGH, NucleiSeverity.MEDIUM],
            )
        
        elif tool_name == "zap_scan":
            return await self.zap.active_scan(
                target=hypothesis.target_url or target
            )
        
        else:
            # Use existing attack tools from src/sentinel/tools/attack/
            return await self._execute_existing_tool(tool_name, hypothesis)
    
    async def _execute_existing_tool(self, tool_name: str, hypothesis: VulnHypothesis) -> ToolResult:
        """Bridge to existing attack tools (SQLi, XSS, IDOR, auth)."""
        # Import and execute the appropriate tool from src/sentinel/tools/attack/
        # This wires the existing Phase 0-4 attack tools into the VulnAgent pipeline
        pass
    
    async def _verify_with_llm(self, hypothesis: VulnHypothesis, results: list[ToolResult]) -> dict:
        """Use LLM to analyze tool results and confirm/deny hypothesis."""
        prompt = f"""Analyze these vulnerability testing results.

Hypothesis: {hypothesis.description}
Category: {hypothesis.category.value}
Target: {hypothesis.target_url}

Tool Results:
{self._format_results(results)}

Determine:
1. Is the vulnerability CONFIRMED with evidence? (true/false)
2. Confidence level (high/medium/low)
3. What specific evidence confirms it?
4. Severity (critical/high/medium/low)
5. Recommended remediation

Respond in JSON format:
{{"confirmed": bool, "confidence": str, "evidence": str, "severity": str, "remediation": str}}
"""
        response = await self.llm_client.complete(prompt)
        # Parse JSON response
        return self._parse_llm_response(response)
    
    async def _record_finding(self, engagement_id: str, finding: dict):
        """Write verified finding to Neo4j knowledge graph."""
        await self.graph.query(
            """
            CREATE (f:Finding {
                finding_id: $fid,
                engagement_id: $eid,
                category: $category,
                target_url: $url,
                severity: $severity,
                confidence: $confidence,
                evidence: $evidence,
                remediation: $remediation,
                mitre_technique: $mitre,
                verified: true,
                timestamp: datetime()
            })
            WITH f
            MATCH (e:Endpoint {url: $url})
            CREATE (e)-[:HAS_VULNERABILITY]->(f)
            """,
            {
                "fid": finding["hypothesis_id"],
                "eid": engagement_id,
                "category": finding["category"],
                "url": finding["target_url"],
                "severity": finding["severity"],
                "confidence": finding["confidence"],
                "evidence": str(finding["evidence"]),
                "remediation": finding["remediation"],
                "mitre": finding["mitre_technique"],
            }
        )
    
    async def _generate_follow_ups(self, hypothesis: VulnHypothesis, result: dict) -> list[VulnHypothesis]:
        """Generate refined hypotheses based on confirmed finding (iterative deepening)."""
        # If we found SQLi, generate hypotheses for:
        # - Data exfiltration via the same injection point
        # - Privilege escalation via database access
        # - OS command execution via SQLi (if MySQL/MSSQL)
        return []
    
    def _format_results(self, results: list[ToolResult]) -> str:
        return "\n".join(str(r) for r in results if r.success)
    
    def _parse_llm_response(self, response) -> dict:
        # Parse LLM JSON response with fallbacks
        import json
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return {"confirmed": False, "confidence": "low", "evidence": "", "severity": "low", "remediation": ""}
    
    def _build_action(self, tool_name: str, hypothesis: VulnHypothesis, target: str) -> dict:
        return {
            "action_type": tool_name.upper(),
            "target": target,
            "agent": self.agent_name,
            "risk_level": hypothesis.risk_level,
        }
```

### 6. `src/sentinel/agents/finding_verifier.py`

**Purpose**: Double-checks findings before they enter the final report.

```python
"""
FindingVerifier — Validates findings before they're promoted.

Implements "No Exploit, No Report" policy:
1. Replays the exploit to confirm reproducibility
2. Checks for false positives
3. Generates PoC replay scripts
4. Assigns final severity rating
"""
from dataclasses import dataclass
from sentinel.logging import get_logger

logger = get_logger(__name__)


@dataclass
class VerifiedFinding:
    finding_id: str
    category: str
    target_url: str
    severity: str
    evidence: str
    poc_script: str         # Reproducible proof-of-concept
    replay_commands: list[str]  # CLI commands to reproduce
    http_trace: list[dict]  # Full HTTP request/response log
    confirmed_count: int    # How many times exploit succeeded
    false_positive_check: bool
    remediation: str
    mitre_technique: str


class FindingVerifier:
    """
    Verifies findings by replaying exploits.
    
    For each finding:
    1. Replay the exact tool call that produced it
    2. Confirm same result (at least 2/3 replays succeed)
    3. Generate PoC script (Python, curl, or Postman)
    4. Log full HTTP trace for evidence
    """
    
    async def verify(self, finding: dict, replay_count: int = 3) -> VerifiedFinding:
        """Verify a single finding by replaying it."""
        # Replay the exploit
        successes = 0
        http_traces = []
        
        for i in range(replay_count):
            result = await self._replay_exploit(finding)
            if result["success"]:
                successes += 1
                http_traces.append(result["trace"])
        
        confirmed = successes >= 2  # At least 2/3 must succeed
        
        # Generate PoC script
        poc = self._generate_poc(finding, http_traces)
        replay_cmds = self._generate_replay_commands(finding, http_traces)
        
        return VerifiedFinding(
            finding_id=finding["hypothesis_id"],
            category=finding["category"],
            target_url=finding["target_url"],
            severity=finding["severity"],
            evidence=finding["evidence"],
            poc_script=poc,
            replay_commands=replay_cmds,
            http_trace=http_traces,
            confirmed_count=successes,
            false_positive_check=confirmed,
            remediation=finding["remediation"],
            mitre_technique=finding.get("mitre_technique", ""),
        )
    
    async def _replay_exploit(self, finding: dict) -> dict:
        """Replay the specific exploit that produced this finding."""
        # Re-execute the tool with same parameters
        # Return success/failure + HTTP trace
        return {"success": False, "trace": {}}
    
    def _generate_poc(self, finding: dict, traces: list[dict]) -> str:
        """Generate Python PoC script from HTTP traces."""
        if not traces:
            return "# No HTTP traces available for PoC generation"
        
        trace = traces[0]
        script = f'''#!/usr/bin/env python3
"""PoC for {finding["category"]} at {finding["target_url"]}"""
import requests

url = "{finding["target_url"]}"
# Reproduce the exploit
response = requests.{trace.get("method", "get").lower()}(
    url,
    headers={trace.get("headers", {})},
    data={trace.get("body", "")},
)
print(f"Status: {{response.status_code}}")
print(f"Response: {{response.text[:500]}}")
'''
        return script
    
    def _generate_replay_commands(self, finding: dict, traces: list[dict]) -> list[str]:
        """Generate curl commands for replay."""
        commands = []
        for trace in traces:
            cmd = f'curl -X {trace.get("method", "GET")} "{finding["target_url"]}"'
            for k, v in trace.get("headers", {}).items():
                cmd += f' -H "{k}: {v}"'
            if trace.get("body"):
                cmd += f' -d \'{trace.get("body")}\''
            commands.append(cmd)
        return commands
```

### 7. Docker Compose Update: `docker-compose.yml` (add ZAP service)

Add this service to the existing docker-compose file:

```yaml
  zap:
    image: zaproxy/zap-stable:latest
    command: zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true
    ports:
      - "8080:8080"
    networks:
      - sentinel_net
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/"]
      interval: 30s
      timeout: 10s
      retries: 5
```

---

## Tests

### `tests/tools/scanning/test_nuclei_tool.py`

```python
"""Tests for NucleiTool."""
import pytest
from unittest.mock import AsyncMock, patch
from sentinel.tools.scanning.nuclei_tool import NucleiTool, NucleiResult, NucleiSeverity


class TestNucleiTool:
    def setup_method(self):
        self.tool = NucleiTool()
    
    def test_parse_output_valid_json(self):
        output = '{"template-id":"cve-2021-44228","info":{"name":"Log4j RCE","severity":"critical","description":"Apache Log4j RCE","reference":[],"tags":["cve"]},"matched-at":"http://target:8080/api","curl-command":"curl http://target:8080/api","extracted-results":[],"response":""}'
        results = self.tool._parse_output(output)
        assert len(results) == 1
        assert results[0].severity == NucleiSeverity.CRITICAL
        assert results[0].template_id == "cve-2021-44228"
    
    def test_parse_output_empty(self):
        results = self.tool._parse_output("")
        assert results == []
    
    def test_parse_output_invalid_json(self):
        results = self.tool._parse_output("not json\nalso not json")
        assert results == []
    
    def test_count_by_severity(self):
        results = [
            NucleiResult(template_id="t1", name="", severity=NucleiSeverity.CRITICAL,
                        matched_url="", matched_at="", description=""),
            NucleiResult(template_id="t2", name="", severity=NucleiSeverity.CRITICAL,
                        matched_url="", matched_at="", description=""),
            NucleiResult(template_id="t3", name="", severity=NucleiSeverity.HIGH,
                        matched_url="", matched_at="", description=""),
        ]
        counts = self.tool._count_by_severity(results)
        assert counts == {"critical": 2, "high": 1}
    
    @pytest.mark.asyncio
    @patch("asyncio.create_subprocess_exec")
    async def test_execute_success(self, mock_exec):
        mock_process = AsyncMock()
        mock_process.communicate.return_value = (b'{"template-id":"test","info":{"name":"Test","severity":"low","description":"","reference":[],"tags":[]},"matched-at":"http://target","curl-command":"","extracted-results":[],"response":""}', b"")
        mock_exec.return_value = mock_process
        
        result = await self.tool.execute("http://target")
        assert result.success
        assert result.metadata["total_findings"] == 1
```

### `tests/agents/test_hypothesis_engine.py`

```python
"""Tests for HypothesisEngine."""
import pytest
from unittest.mock import AsyncMock, MagicMock
from sentinel.agents.hypothesis_engine import (
    HypothesisEngine, HypothesisCategory, HypothesisConfidence, VulnHypothesis
)


class TestHypothesisEngine:
    def setup_method(self):
        self.graph = AsyncMock()
        self.engine = HypothesisEngine(self.graph)
    
    def test_ranking_auth_bypass_highest(self):
        hypotheses = [
            VulnHypothesis(id="1", category=HypothesisCategory.XSS,
                          confidence=HypothesisConfidence.HIGH,
                          target_url="/search", target_param="q",
                          description="", rationale="", test_plan=[],
                          required_tools=[], expected_evidence="",
                          risk_level="HIGH", priority_score=0),
            VulnHypothesis(id="2", category=HypothesisCategory.AUTH_BYPASS,
                          confidence=HypothesisConfidence.HIGH,
                          target_url="/login", target_param="password",
                          description="", rationale="", test_plan=[],
                          required_tools=[], expected_evidence="",
                          risk_level="CRITICAL", priority_score=0),
        ]
        ranked = self.engine._rank(hypotheses)
        assert ranked[0].category == HypothesisCategory.AUTH_BYPASS
    
    def test_deduplication(self):
        h1 = VulnHypothesis(id="1", category=HypothesisCategory.XSS,
                           confidence=HypothesisConfidence.HIGH,
                           target_url="/search", target_param="q",
                           description="", rationale="", test_plan=[],
                           required_tools=[], expected_evidence="",
                           risk_level="HIGH", priority_score=0)
        h2 = VulnHypothesis(id="2", category=HypothesisCategory.XSS,
                           confidence=HypothesisConfidence.MEDIUM,
                           target_url="/search", target_param="q",
                           description="", rationale="", test_plan=[],
                           required_tools=[], expected_evidence="",
                           risk_level="HIGH", priority_score=0)
        deduped = self.engine._deduplicate([h1, h2])
        assert len(deduped) == 1
    
    def test_rules_loaded(self):
        assert len(self.engine._rules) > 0
```

### `tests/agents/test_vuln_agent.py`

```python
"""Tests for GuardedVulnAgent."""
import pytest
from unittest.mock import AsyncMock, MagicMock
from sentinel.agents.vuln_agent import GuardedVulnAgent


class TestGuardedVulnAgent:
    def setup_method(self):
        self.graph = AsyncMock()
        self.llm = AsyncMock()
        self.policy = AsyncMock()
        self.policy.check.return_value = True
        self.agent = GuardedVulnAgent(self.graph, self.llm, self.policy)
    
    def test_category_to_tools_mapping(self):
        from sentinel.agents.hypothesis_engine import HypothesisCategory
        # Every category should have at least one tool
        for cat in HypothesisCategory:
            assert cat in self.agent.CATEGORY_TO_TOOLS
    
    @pytest.mark.asyncio
    async def test_policy_denied_skips_tool(self):
        self.policy.check.return_value = False
        from sentinel.agents.hypothesis_engine import (
            VulnHypothesis, HypothesisCategory, HypothesisConfidence
        )
        h = VulnHypothesis(
            id="test", category=HypothesisCategory.INJECTION,
            confidence=HypothesisConfidence.HIGH,
            target_url="http://target/login", target_param="username",
            description="Test", rationale="Test", test_plan=["test"],
            required_tools=["sqli_tool"], expected_evidence="error message",
            risk_level="HIGH", priority_score=0.9
        )
        # Should not raise, just skip
        result = await self.agent.test_hypothesis(h, "http://target")
        assert isinstance(result, dict)
```

---

## Integration Points

1. **Input**: GuardedVulnAgent reads recon data from Neo4j knowledge graph (written by Phase 0-4 ReconAgent)
2. **Output**: Verified findings written back to Neo4j as Finding nodes connected to Endpoints via HAS_VULNERABILITY edges
3. **Policy**: All tool executions go through existing PolicyEngine (from `src/sentinel/agents/guarded_base.py`)
4. **Existing Attack Tools**: VulnAgent bridges to existing SQLi, XSS, IDOR, auth tools in `src/sentinel/tools/attack/`
5. **Events**: Publish finding events to existing EventBus for WebSocket streaming
6. **Config**: Nuclei/ZAP paths and settings go in existing config system

## Acceptance Criteria

- [ ] `NucleiTool` successfully scans Juice Shop and returns findings
- [ ] `ZAPTool` connects to ZAP daemon and runs spider + active scan
- [ ] `HypothesisEngine` generates hypotheses from graph data
- [ ] `GuardedVulnAgent` tests hypotheses end-to-end
- [ ] `FindingVerifier` replays exploits and generates PoC scripts
- [ ] Findings are written to Neo4j knowledge graph
- [ ] All tests pass
- [ ] Policy engine gates all tool executions