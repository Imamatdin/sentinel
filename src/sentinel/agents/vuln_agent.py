"""
GuardedVulnAgent — LLM-guided vulnerability analysis.

Extends GuardedBaseAgent to:
1. Receive ranked hypotheses from HypothesisEngine
2. Test each hypothesis using appropriate tools (existing attack tools + Nuclei + ZAP)
3. Verify findings with evidence
4. Promote verified findings to knowledge graph
5. Generate new hypotheses based on discoveries (iterative)
"""
import json

from sentinel.agents.guarded_base import GuardedBaseAgent
from sentinel.agents.hypothesis_engine import (
    HypothesisEngine, VulnHypothesis, HypothesisCategory
)
from sentinel.tools.scanning.nuclei_tool import NucleiTool, NucleiSeverity
from sentinel.tools.scanning.zap_tool import ZAPTool
from sentinel.tools.base import ToolOutput
from sentinel.graph.neo4j_client import Neo4jClient
from sentinel.logging_config import get_logger

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

    @property
    def system_prompt(self) -> str:
        """System prompt for the vulnerability analysis agent."""
        return """You are a vulnerability analysis agent. Your role is to:
1. Analyze vulnerability hypotheses based on reconnaissance data
2. Select appropriate tools to test each hypothesis
3. Verify findings with evidence
4. Provide detailed analysis of security vulnerabilities
5. Generate remediation recommendations"""

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

    def __init__(self, graph_client: Neo4jClient, llm_client, policy_engine):
        super().__init__(name=self.agent_name, llm_client=llm_client)
        self.graph = graph_client
        self.policy_engine = policy_engine
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
            if not await self.policy_engine.evaluate(action):
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

    async def _execute_tool(self, tool_name: str, hypothesis: VulnHypothesis, target: str) -> ToolOutput:
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

    async def _execute_existing_tool(self, tool_name: str, hypothesis: VulnHypothesis) -> ToolOutput:
        """Bridge to existing attack tools (SQLi, XSS, IDOR, auth)."""
        # Import and execute the appropriate tool from src/sentinel/tools/attack/
        # This wires the existing Phase 0-4 attack tools into the VulnAgent pipeline
        # TODO: Wire existing tools - for now, return placeholder
        return ToolOutput(
            success=False,
            tool_name=tool_name,
            data=None,
            error=f"Tool {tool_name} not yet wired to GuardedVulnAgent"
        )

    async def _verify_with_llm(self, hypothesis: VulnHypothesis, results: list[ToolOutput]) -> dict:
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
        try:
            response = await self.llm.complete(prompt)
            # Parse JSON response
            return self._parse_llm_response(response)
        except Exception as e:
            logger.error(f"LLM verification failed: {e}")
            return {
                "confirmed": False,
                "confidence": "low",
                "evidence": "",
                "severity": "low",
                "remediation": ""
            }

    async def _record_finding(self, engagement_id: str, finding: dict):
        """Write verified finding to Neo4j knowledge graph."""
        try:
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
                MERGE (e:Endpoint {url: $url})
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
        except Exception as e:
            logger.error(f"Failed to record finding to graph: {e}")

    async def _generate_follow_ups(self, hypothesis: VulnHypothesis, result: dict) -> list[VulnHypothesis]:
        """Generate refined hypotheses based on confirmed finding (iterative deepening)."""
        # If we found SQLi, generate hypotheses for:
        # - Data exfiltration via the same injection point
        # - Privilege escalation via database access
        # - OS command execution via SQLi (if MySQL/MSSQL)
        # TODO: Implement iterative hypothesis generation
        return []

    def _format_results(self, results: list[ToolOutput]) -> str:
        formatted = []
        for r in results:
            if r.success:
                formatted.append(f"Tool: {r.tool_name}")
                formatted.append(f"Success: {r.success}")
                if r.data:
                    formatted.append(f"Data: {str(r.data)[:500]}...")  # Truncate long data
                if r.raw_output:
                    formatted.append(f"Output: {str(r.raw_output)[:500]}...")
        return "\n".join(formatted) if formatted else "No successful tool results"

    def _parse_llm_response(self, response: str) -> dict:
        # Parse LLM JSON response with fallbacks
        try:
            # Try to extract JSON from response (handle markdown code blocks)
            if "```json" in response:
                response = response.split("```json")[1].split("```")[0].strip()
            elif "```" in response:
                response = response.split("```")[1].split("```")[0].strip()

            return json.loads(response)
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse LLM response as JSON: {e}")
            return {
                "confirmed": False,
                "confidence": "low",
                "evidence": "",
                "severity": "low",
                "remediation": ""
            }

    def _build_action(self, tool_name: str, hypothesis: VulnHypothesis, target: str) -> dict:
        return {
            "action_type": tool_name.upper(),
            "target": target,
            "agent": self.agent_name,
            "risk_level": hypothesis.risk_level,
        }

    async def _execute_action(self, action: dict) -> dict:
        """Execute an action (required by GuardedBaseAgent)."""
        # This method is called by the base class for policy-gated execution
        # For VulnAgent, we handle execution in test_hypothesis instead
        return {"success": True, "result": "Action executed"}
