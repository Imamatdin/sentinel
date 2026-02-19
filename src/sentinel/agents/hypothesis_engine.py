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
import uuid

from sentinel.graph.neo4j_client import Neo4jClient
from sentinel.logging_config import get_logger

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

    def __init__(self, graph_client: Neo4jClient, llm_client=None):
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
        for record in endpoints:
            endpoint = record.get("e")
            if endpoint:
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
        endpoint_url = endpoint.get("url", "")
        endpoint_path = endpoint.get("path", "")
        endpoint_params = endpoint.get("params", [])

        # Ensure params is always a list (Neo4j might return string)
        if isinstance(endpoint_params, str):
            endpoint_params = [p.strip() for p in endpoint_params.split(",") if p.strip()]

        for rule in self._rules:
            pattern = rule["pattern"]
            matched = False

            # Check path patterns
            if "path_contains" in pattern:
                for keyword in pattern["path_contains"]:
                    if keyword.lower() in endpoint_path.lower():
                        matched = True
                        break

            # Check param patterns
            if "param_contains" in pattern and endpoint_params:
                for keyword in pattern["param_contains"]:
                    if any(keyword.lower() in p.lower() for p in endpoint_params):
                        matched = True
                        break

            # Check content type patterns
            if "content_type_contains" in pattern:
                content_type = endpoint.get("content_type", "")
                for keyword in pattern["content_type_contains"]:
                    if keyword.lower() in content_type.lower():
                        matched = True
                        break

            # Generate hypotheses if pattern matched
            if matched:
                for category in rule["generates"]:
                    hypothesis = VulnHypothesis(
                        id=str(uuid.uuid4()),
                        category=category,
                        confidence=rule["confidence"],
                        target_url=endpoint_url,
                        target_param=endpoint_params[0] if endpoint_params else None,
                        description=f"Potential {category.value} vulnerability at {endpoint_path}",
                        rationale=f"Pattern matched: {pattern}",
                        test_plan=[
                            f"Test {category.value} on endpoint",
                            "Analyze response for indicators",
                            "Verify with multiple payloads"
                        ],
                        required_tools=self._get_tools_for_category(category),
                        expected_evidence=f"Response indicates {category.value} vulnerability",
                        risk_level=self._get_risk_level(category),
                        priority_score=0.0,  # Will be calculated in _rank()
                    )
                    results.append(hypothesis)

        return results

    def _get_tools_for_category(self, category: HypothesisCategory) -> list[str]:
        """Map category to required tools."""
        tool_map = {
            HypothesisCategory.INJECTION: ["sqli_tool", "nuclei_scan"],
            HypothesisCategory.XSS: ["xss_tool", "nuclei_scan"],
            HypothesisCategory.AUTH_BYPASS: ["auth_brute_tool", "zap_scan"],
            HypothesisCategory.IDOR: ["idor_tool"],
            HypothesisCategory.SSRF: ["nuclei_scan"],
            HypothesisCategory.FILE_UPLOAD: ["nuclei_scan"],
            HypothesisCategory.XXE: ["nuclei_scan"],
            HypothesisCategory.DESERIALIZATION: ["nuclei_scan"],
            HypothesisCategory.MISCONFIG: ["nuclei_scan", "zap_scan"],
            HypothesisCategory.SENSITIVE_DATA: ["zap_scan"],
            HypothesisCategory.BROKEN_ACCESS: ["idor_tool", "zap_scan"],
        }
        return tool_map.get(category, ["nuclei_scan"])

    def _get_risk_level(self, category: HypothesisCategory) -> str:
        """Map category to risk level."""
        high_risk = [HypothesisCategory.INJECTION, HypothesisCategory.AUTH_BYPASS,
                     HypothesisCategory.SSRF, HypothesisCategory.DESERIALIZATION]
        medium_risk = [HypothesisCategory.XSS, HypothesisCategory.IDOR,
                       HypothesisCategory.FILE_UPLOAD, HypothesisCategory.XXE,
                       HypothesisCategory.BROKEN_ACCESS]

        if category in high_risk:
            return "HIGH"
        elif category in medium_risk:
            return "MEDIUM"
        else:
            return "LOW"

    async def _llm_generate(self, endpoints: list, services: list) -> list[VulnHypothesis]:
        """Use LLM to identify additional vulnerability patterns."""
        # Build context from endpoints and services
        # Prompt LLM to identify non-obvious vulnerability patterns
        # Parse structured output into VulnHypothesis objects
        # TODO: Implement LLM-based hypothesis generation in Phase 7
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
