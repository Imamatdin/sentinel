"""
Knowledge Graph Risk Analytics.

Uses Neo4j GDS (Graph Data Science) projections and algorithms:
- PageRank: Which nodes are most "important" in the attack graph?
- Betweenness Centrality: Which nodes are chokepoints (fix these first)?
- Louvain Community: Group related assets/vulns into blast radius clusters
- Shortest Path: Minimum-step attack chains from entry to crown jewel
- Reverse BFS: All paths leading TO a critical asset

Risk formula:
  risk_score = EPSS x base_severity x reachability_weight x asset_value
  reachability_weight = 1 / (shortest_path_to_crown_jewel + 1)
"""

from dataclasses import dataclass, field
from typing import Any

from sentinel.core import get_logger
from sentinel.graph.neo4j_client import Neo4jClient

logger = get_logger(__name__)


@dataclass
class AttackPath:
    source: str         # Entry node ID
    target: str         # Crown jewel node ID
    hops: int
    nodes: list[str]    # Node IDs in path order
    edges: list[str]    # Edge types in path order
    probability: float  # Product of EPSS/confidence along path
    risk_score: float


@dataclass
class RiskAnalysisResult:
    engagement_id: str
    top_chokepoints: list[dict[str, Any]]
    top_risky_nodes: list[dict[str, Any]]
    attack_paths: list[AttackPath]
    blast_radius_clusters: list[dict[str, Any]]
    summary_stats: dict[str, Any]


class GraphAnalytics:
    """Run graph algorithms on the Neo4j attack knowledge graph."""

    def __init__(self, graph_client: Neo4jClient):
        self.client = graph_client

    async def full_analysis(
        self,
        engagement_id: str,
        crown_jewels: list[str] | None = None,
    ) -> RiskAnalysisResult:
        """Run complete risk analysis pipeline."""
        crown_jewels = crown_jewels or []
        graph_name = f"attack_{engagement_id}"

        await self._project_graph(engagement_id, graph_name)

        try:
            pagerank = await self._run_pagerank(graph_name)
            betweenness = await self._run_betweenness(graph_name)
            communities = await self._run_louvain(graph_name)
            paths = await self._find_attack_paths(engagement_id, crown_jewels)

            await self._compute_risk_scores(engagement_id)

            return RiskAnalysisResult(
                engagement_id=engagement_id,
                top_chokepoints=betweenness[:10],
                top_risky_nodes=pagerank[:10],
                attack_paths=paths,
                blast_radius_clusters=communities,
                summary_stats=await self._summary_stats(engagement_id),
            )
        finally:
            await self._drop_projection(graph_name)

    async def _project_graph(self, engagement_id: str, graph_name: str) -> None:
        """Create a GDS graph projection for this engagement's subgraph."""
        query = """
        CALL gds.graph.project.cypher(
            $graph_name,
            'MATCH (n {engagement_id: $eid})
             WHERE n:Host OR n:Service OR n:Endpoint OR n:Vulnerability
             RETURN id(n) AS id,
                    labels(n) AS labels,
                    coalesce(n.epss_score, 0.0) AS epss_score,
                    coalesce(n.cvss_score, 0.0) AS severity_num,
                    coalesce(n.asset_value, 1) AS asset_value',
            'MATCH (a {engagement_id: $eid})-[r]->(b {engagement_id: $eid})
             RETURN id(a) AS source, id(b) AS target, type(r) AS type',
            {parameters: {eid: $eid}}
        )
        """
        try:
            await self.client.query(query, {"graph_name": graph_name, "eid": engagement_id})
        except Exception as e:
            logger.warning("graph_projection_error", error=str(e))

    async def _run_pagerank(self, graph_name: str) -> list[dict[str, Any]]:
        """PageRank identifies the most 'important' nodes in the attack graph."""
        query = """
        CALL gds.pageRank.stream($graph_name, {
            maxIterations: 50,
            dampingFactor: 0.85
        })
        YIELD nodeId, score
        WITH gds.util.asNode(nodeId) AS node, score
        RETURN node.id AS id, labels(node)[0] AS type,
               coalesce(node.name, node.url, node.ip_address) AS name,
               score
        ORDER BY score DESC
        LIMIT 20
        """
        return await self.client.query(query, {"graph_name": graph_name})

    async def _run_betweenness(self, graph_name: str) -> list[dict[str, Any]]:
        """Betweenness centrality finds chokepoints."""
        query = """
        CALL gds.betweenness.stream($graph_name)
        YIELD nodeId, score
        WITH gds.util.asNode(nodeId) AS node, score
        WHERE score > 0
        RETURN node.id AS id, labels(node)[0] AS type,
               coalesce(node.name, node.url, node.ip_address) AS name,
               score AS betweenness
        ORDER BY score DESC
        LIMIT 20
        """
        return await self.client.query(query, {"graph_name": graph_name})

    async def _run_louvain(self, graph_name: str) -> list[dict[str, Any]]:
        """Louvain community detection groups related assets into blast radius clusters."""
        query = """
        CALL gds.louvain.stream($graph_name)
        YIELD nodeId, communityId
        WITH gds.util.asNode(nodeId) AS node, communityId
        RETURN communityId,
               collect(coalesce(node.name, node.url, node.id)) AS members,
               count(*) AS size
        ORDER BY size DESC
        """
        return await self.client.query(query, {"graph_name": graph_name})

    async def _find_attack_paths(
        self, engagement_id: str, crown_jewels: list[str]
    ) -> list[AttackPath]:
        """Find shortest attack paths from entry points to crown jewels."""
        if not crown_jewels:
            crown_jewels = await self._detect_crown_jewels(engagement_id)

        paths: list[AttackPath] = []
        for target_id in crown_jewels:
            records = await self.client.query(
                """
                MATCH (entry:Host {engagement_id: $eid})
                MATCH (target {engagement_id: $eid, id: $target_id})
                MATCH path = shortestPath((entry)-[*..10]->(target))
                RETURN [n IN nodes(path) | n.id] AS node_ids,
                       [r IN relationships(path) | type(r)] AS edge_types,
                       length(path) AS hops
                ORDER BY hops ASC
                LIMIT 5
                """,
                {"eid": engagement_id, "target_id": target_id},
            )
            for r in records:
                node_ids = r.get("node_ids", [])
                paths.append(AttackPath(
                    source=node_ids[0] if node_ids else "",
                    target=target_id,
                    hops=r.get("hops", 0),
                    nodes=node_ids,
                    edges=r.get("edge_types", []),
                    probability=0.0,
                    risk_score=0.0,
                ))

        return paths

    async def _detect_crown_jewels(self, engagement_id: str) -> list[str]:
        """Auto-detect high-value assets: databases, auth services, admin panels."""
        records = await self.client.query(
            """
            MATCH (n {engagement_id: $eid})
            WHERE n.is_critical_asset = true
               OR n.is_database_server = true
               OR n.name =~ '(?i).*(database|db|admin|auth|vault|secret).*'
               OR any(label IN labels(n) WHERE label = 'CriticalAsset')
            RETURN n.id AS id
            LIMIT 10
            """,
            {"eid": engagement_id},
        )
        return [r["id"] for r in records]

    async def _compute_risk_scores(self, engagement_id: str) -> None:
        """Write composite risk scores back to Vulnerability nodes.

        risk = EPSS x (severity/10) x (1 / (distance_to_crown_jewel + 1))
        """
        await self.client.query(
            """
            MATCH (v:Vulnerability {engagement_id: $eid})
            OPTIONAL MATCH path = shortestPath(
                (v)-[*..10]->(cj {engagement_id: $eid})
            )
            WHERE cj.is_critical_asset = true OR cj.is_database_server = true
            WITH v, min(length(path)) AS dist_to_crown
            SET v.risk_score = coalesce(v.epss_score, 0.5)
                  * coalesce(v.cvss_score, 5.0) / 10.0
                  * (1.0 / (coalesce(dist_to_crown, 99) + 1))
            """,
            {"eid": engagement_id},
        )

    async def _summary_stats(self, engagement_id: str) -> dict[str, Any]:
        """Compute summary statistics for the engagement."""
        records = await self.client.query(
            """
            MATCH (n {engagement_id: $eid})
            WITH labels(n)[0] AS type, count(*) AS cnt
            RETURN type, cnt
            """,
            {"eid": engagement_id},
        )
        stats: dict[str, Any] = {r["type"]: r["cnt"] for r in records}

        path_records = await self.client.query(
            """
            MATCH (e:Host {engagement_id: $eid})
            MATCH (cj {engagement_id: $eid})
            WHERE cj.is_critical_asset = true OR cj.is_database_server = true
            MATCH p = shortestPath((e)-[*..10]->(cj))
            RETURN count(p) AS total_paths
            """,
            {"eid": engagement_id},
        )
        if path_records:
            stats["total_attack_paths"] = path_records[0].get("total_paths", 0)
        else:
            stats["total_attack_paths"] = 0

        return stats

    async def _drop_projection(self, graph_name: str) -> None:
        """Clean up GDS graph projection."""
        try:
            await self.client.query(
                "CALL gds.graph.drop($name, false)",
                {"name": graph_name},
            )
        except Exception:
            pass
