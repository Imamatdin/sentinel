"""Genome 2.0 -- Cross-engagement learning engine.

Upgrades the existing genome from simple pattern storage to:
- Attack technique clustering (group similar exploits)
- Payload fingerprinting (track which payloads work against which tech)
- Root cause taxonomy (map findings to root causes)
- Defense effectiveness mapping (track what defenses block what)
- Exposure scoring (chain depth x privilege x sensitivity x confidence)
"""

from dataclasses import dataclass, field
from typing import Any

from sentinel.core import get_logger
from sentinel.genome.embedding_store import EmbeddingStore
from sentinel.genome.rag_pipeline import RAGPipeline

logger = get_logger(__name__)


@dataclass
class ExposureScore:
    """Replaces static CVSS with context-aware exposure scoring.

    Score = chain_depth_factor x privilege_escalation_factor x data_sensitivity x exploit_confidence
    """

    chain_depth: int  # Steps in attack chain
    privilege_level: str  # "none", "user", "admin", "root"
    data_sensitivity: str  # "public", "internal", "confidential", "critical"
    exploit_confidence: float  # From genome: historical success rate

    PRIV_WEIGHTS: dict[str, float] = field(
        default_factory=lambda: {"none": 0.2, "user": 0.5, "admin": 0.8, "root": 1.0},
        repr=False,
    )
    SENS_WEIGHTS: dict[str, float] = field(
        default_factory=lambda: {"public": 0.2, "internal": 0.5, "confidential": 0.8, "critical": 1.0},
        repr=False,
    )

    @property
    def score(self) -> float:
        """Compute exposure score (0.0-1.0)."""
        depth_factor = 1.0 / max(self.chain_depth, 1)  # Shorter chains = higher risk
        priv = self.PRIV_WEIGHTS.get(self.privilege_level, 0.5)
        sens = self.SENS_WEIGHTS.get(self.data_sensitivity, 0.5)
        return depth_factor * priv * sens * self.exploit_confidence

    @property
    def rating(self) -> str:
        """Human-readable rating."""
        s = self.score
        if s >= 0.7:
            return "CRITICAL"
        if s >= 0.5:
            return "HIGH"
        if s >= 0.3:
            return "MEDIUM"
        return "LOW"


@dataclass
class TechniqueCluster:
    """Group of related attack techniques."""

    cluster_id: str
    techniques: list[str] = field(default_factory=list)  # MITRE ATT&CK IDs
    avg_success_rate: float = 0.0
    common_targets: list[str] = field(default_factory=list)  # Tech stacks
    effective_defenses: list[str] = field(default_factory=list)  # What blocks these


class GenomeV2:
    """Cross-engagement learning engine.

    Before new engagement:
    1. Query genome for target's tech stack -> get historical success rates
    2. Prioritize hypotheses based on what worked before
    3. Suggest payloads ranked by historical effectiveness

    After engagement:
    4. Update success/failure counts for all patterns
    5. Cluster new techniques
    6. Map defense effectiveness
    7. Store new patterns for future retrieval
    """

    def __init__(self, embedding_store: EmbeddingStore, graph: Any = None):
        """Initialize GenomeV2.

        Args:
            embedding_store: pgvector-backed embedding store
            graph: Neo4jClient instance (optional, for attack graph queries)
        """
        self.store = embedding_store
        self.graph = graph
        self.rag = RAGPipeline(embedding_store)

    async def pre_engagement_intel(self, target_tech_stack: list[str]) -> dict[str, Any]:
        """Query genome for intelligence about target's tech stack.

        Returns:
        - Historically effective techniques for this tech stack
        - Payload recommendations ranked by success rate
        - Known defense patterns to expect
        - Suggested hypothesis priority adjustments
        """
        context = await self.rag.retrieve_context(
            query=f"Vulnerabilities in {', '.join(target_tech_stack)}",
            category="vulnerability",
            limit=20,
        )

        # Aggregate by technique
        technique_stats: dict[str, dict[str, Any]] = {}
        for c in context:
            cat = c.get("metadata", {}).get("category", "unknown")
            if cat not in technique_stats:
                technique_stats[cat] = {
                    "count": 0,
                    "total_confidence": 0.0,
                    "total_success_rate": 0.0,
                }
            technique_stats[cat]["count"] += 1
            technique_stats[cat]["total_confidence"] += c.get("confidence", 0)
            technique_stats[cat]["total_success_rate"] += c.get("success_rate", 0)

        # Compute averages
        for cat, stats in technique_stats.items():
            n = stats["count"]
            stats["avg_confidence"] = stats["total_confidence"] / n
            stats["avg_success_rate"] = stats["total_success_rate"] / n

        return {
            "technique_stats": technique_stats,
            "recommended_order": sorted(
                technique_stats.keys(),
                key=lambda k: technique_stats[k].get("avg_success_rate", 0),
                reverse=True,
            ),
            "raw_context": context[:5],
        }

    async def post_engagement_learn(
        self, engagement_id: str, findings: list[dict[str, Any]]
    ) -> None:
        """Learn from completed engagement.

        1. Embed all findings
        2. Update confidence scores for similar existing patterns
        """
        for finding in findings:
            await self.rag.embed_finding(finding, engagement_id)

            # Update existing similar patterns' confidence via store directly
            try:
                query_text = f"{finding.get('category', '')} {finding.get('target_url', '')}"
                embedding = await self.rag.generate_embedding(query_text)
                existing_records = await self.store.search(
                    query_embedding=embedding,
                    category="vulnerability",
                    limit=5,
                    min_confidence=0.0,
                )
                success = finding.get("verified", False)
                for record in existing_records:
                    # Skip the record we just embedded (same engagement)
                    if record.engagement_id == engagement_id:
                        continue
                    await self.store.update_confidence(record.id, success)
            except Exception as exc:
                logger.debug(f"Failed to update existing patterns: {exc}")

    def compute_exposure_score(
        self,
        chain_depth: int,
        privilege_level: str,
        data_sensitivity: str,
        historical_success_rate: float,
    ) -> ExposureScore:
        """Compute exposure score for a finding/chain."""
        return ExposureScore(
            chain_depth=chain_depth,
            privilege_level=privilege_level,
            data_sensitivity=data_sensitivity,
            exploit_confidence=historical_success_rate,
        )

    async def get_attack_graph_diff(
        self, engagement_id_1: str, engagement_id_2: str
    ) -> dict[str, Any]:
        """Compare attack graphs across two engagements (CTEM diff).

        Returns:
        - New attack paths (appeared since last run)
        - Closed attack paths (fixed)
        - Persistent paths (still exploitable)
        """
        if not self.graph:
            return {"new_paths": [], "closed_paths": [], "persistent_paths": [], "delta_count": 0}

        try:
            graph1 = await self.graph.query(
                "MATCH (v:Vulnerability {engagement_id: $eid}) RETURN v",
                {"eid": engagement_id_1},
            )
            graph2 = await self.graph.query(
                "MATCH (v:Vulnerability {engagement_id: $eid}) RETURN v",
                {"eid": engagement_id_2},
            )

            # Extract (target_url, category) tuples as path identifiers
            def extract_paths(results: list[dict]) -> set[tuple[str, str]]:
                paths = set()
                for row in results:
                    v = row.get("v", row)
                    paths.add((v.get("target_url", ""), v.get("name", "")))
                return paths

            paths1 = extract_paths(graph1)
            paths2 = extract_paths(graph2)

            return {
                "new_paths": [list(p) for p in paths2 - paths1],
                "closed_paths": [list(p) for p in paths1 - paths2],
                "persistent_paths": [list(p) for p in paths1 & paths2],
                "delta_count": len(paths2) - len(paths1),
            }
        except Exception as exc:
            logger.warning(f"Attack graph diff failed: {exc}")
            return {"new_paths": [], "closed_paths": [], "persistent_paths": [], "delta_count": 0}
