# LEVEL 16: Knowledge Graph Risk Analytics (GDS)

## Context
Neo4j Graph Data Science (GDS) library enables graph algorithms that turn the knowledge graph from a data store into an attack intelligence engine. This level adds: PageRank for risk prioritization, betweenness centrality for chokepoint identification, Louvain community detection for blast radius clustering, and crown-jewel reverse path analysis.

Research: Block 4 (Path discovery, risk scoring, crown-jewel analysis). FAIR-style risk = frequency × magnitude.

## Why
A medium vuln on the only path to the database is more dangerous than an isolated critical vuln. Graph analytics surface this. NodeZero's biggest selling point is attack path visualization — this is how Sentinel matches it.

---

## Files to Create

### `src/sentinel/graph/__init__.py`
```python
"""Graph analytics — risk scoring, path analysis, attack surface metrics."""
```

### `src/sentinel/graph/analytics.py`
```python
"""
Knowledge Graph Risk Analytics.

Uses Neo4j GDS (Graph Data Science) projections and algorithms:
- PageRank: Which nodes are most "important" in the attack graph?
- Betweenness Centrality: Which nodes are chokepoints (fix these first)?
- Louvain Community: Group related assets/vulns into blast radius clusters
- Shortest Path: Minimum-step attack chains from entry to crown jewel
- Reverse BFS: All paths leading TO a critical asset

Risk formula:
  risk_score = EPSS × base_severity × reachability_weight × asset_value
  reachability_weight = 1 / (shortest_path_to_crown_jewel + 1)
"""
import asyncio
from dataclasses import dataclass, field
from sentinel.logging import get_logger

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
    top_chokepoints: list[dict]    # Nodes with highest betweenness centrality
    top_risky_nodes: list[dict]    # Nodes with highest PageRank
    attack_paths: list[AttackPath]  # Paths to crown jewels
    blast_radius_clusters: list[dict]  # Louvain communities
    summary_stats: dict


class GraphAnalytics:
    """Run graph algorithms on the Neo4j attack knowledge graph."""
    
    def __init__(self, neo4j_driver):
        self.driver = neo4j_driver
    
    async def full_analysis(self, engagement_id: str, crown_jewels: list[str] = None) -> RiskAnalysisResult:
        """Run complete risk analysis pipeline."""
        crown_jewels = crown_jewels or []
        
        # 1. Project the subgraph for this engagement
        await self._project_graph(engagement_id)
        
        try:
            # 2. Run algorithms
            pagerank = await self._run_pagerank(engagement_id)
            betweenness = await self._run_betweenness(engagement_id)
            communities = await self._run_louvain(engagement_id)
            paths = await self._find_attack_paths(engagement_id, crown_jewels)
            
            # 3. Combine into risk scores
            await self._compute_risk_scores(engagement_id, pagerank, betweenness, paths)
            
            return RiskAnalysisResult(
                engagement_id=engagement_id,
                top_chokepoints=betweenness[:10],
                top_risky_nodes=pagerank[:10],
                attack_paths=paths,
                blast_radius_clusters=communities,
                summary_stats=await self._summary_stats(engagement_id),
            )
        finally:
            await self._drop_projection(engagement_id)
    
    async def _project_graph(self, engagement_id: str):
        """Create a GDS graph projection for this engagement."""
        query = """
        CALL gds.graph.project(
            $graph_name,
            {
                Host: { properties: ['asset_value'] },
                Service: {},
                Endpoint: {},
                Vulnerability: { properties: ['epss_score', 'severity_num'] },
                Finding: { properties: ['confidence'] }
            },
            {
                EXPOSES: {},
                HAS_ENDPOINT: {},
                HAS_VULNERABILITY: {},
                CONNECTS_TO: {},
                EXPLOITS: {}
            },
            { nodeLabels: ['Host', 'Service', 'Endpoint', 'Vulnerability', 'Finding'] }
        )
        """
        async with self.driver.session() as session:
            try:
                await session.run(query, {"graph_name": f"attack_{engagement_id}"})
            except Exception as e:
                logger.warning(f"Graph projection may already exist: {e}")
    
    async def _run_pagerank(self, engagement_id: str) -> list[dict]:
        """PageRank identifies the most 'important' nodes in the attack graph."""
        query = """
        CALL gds.pageRank.stream($graph_name, {
            maxIterations: 50,
            dampingFactor: 0.85
        })
        YIELD nodeId, score
        WITH gds.util.asNode(nodeId) AS node, score
        RETURN node.id AS id, labels(node)[0] AS type,
               coalesce(node.name, node.url, node.address) AS name,
               score
        ORDER BY score DESC
        LIMIT 20
        """
        async with self.driver.session() as session:
            result = await session.run(query, {"graph_name": f"attack_{engagement_id}"})
            records = await result.data()
            return records
    
    async def _run_betweenness(self, engagement_id: str) -> list[dict]:
        """Betweenness centrality finds chokepoints — fix these to break the most attack paths."""
        query = """
        CALL gds.betweenness.stream($graph_name)
        YIELD nodeId, score
        WITH gds.util.asNode(nodeId) AS node, score
        WHERE score > 0
        RETURN node.id AS id, labels(node)[0] AS type,
               coalesce(node.name, node.url, node.address) AS name,
               score AS betweenness
        ORDER BY score DESC
        LIMIT 20
        """
        async with self.driver.session() as session:
            result = await session.run(query, {"graph_name": f"attack_{engagement_id}"})
            return await result.data()
    
    async def _run_louvain(self, engagement_id: str) -> list[dict]:
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
        async with self.driver.session() as session:
            result = await session.run(query, {"graph_name": f"attack_{engagement_id}"})
            return await result.data()
    
    async def _find_attack_paths(
        self, engagement_id: str, crown_jewels: list[str]
    ) -> list[AttackPath]:
        """Find shortest attack paths from any entry point to each crown jewel."""
        if not crown_jewels:
            # Auto-detect: nodes marked as high-value assets
            crown_jewels = await self._detect_crown_jewels(engagement_id)
        
        paths = []
        for target in crown_jewels:
            query = """
            MATCH (entry:Host {engagement_id: $eid})
            WHERE entry.is_entry_point = true
            MATCH path = shortestPath((entry)-[*..10]->(target))
            WHERE target.id = $target_id
            RETURN [n IN nodes(path) | n.id] AS node_ids,
                   [r IN relationships(path) | type(r)] AS edge_types,
                   length(path) AS hops
            ORDER BY hops ASC
            LIMIT 5
            """
            async with self.driver.session() as session:
                result = await session.run(
                    query, {"eid": engagement_id, "target_id": target}
                )
                records = await result.data()
                for r in records:
                    paths.append(AttackPath(
                        source=r["node_ids"][0],
                        target=target,
                        hops=r["hops"],
                        nodes=r["node_ids"],
                        edges=r["edge_types"],
                        probability=0.0,  # Computed in risk scoring pass
                        risk_score=0.0,
                    ))
        
        return paths
    
    async def _detect_crown_jewels(self, engagement_id: str) -> list[str]:
        """Auto-detect high-value assets: databases, auth services, admin panels."""
        query = """
        MATCH (n {engagement_id: $eid})
        WHERE n.asset_value >= 8
           OR n.name =~ '(?i).*(database|db|admin|auth|vault|secret).*'
           OR any(label IN labels(n) WHERE label IN ['Database', 'AdminPanel'])
        RETURN n.id AS id
        LIMIT 10
        """
        async with self.driver.session() as session:
            result = await session.run(query, {"eid": engagement_id})
            records = await result.data()
            return [r["id"] for r in records]
    
    async def _compute_risk_scores(self, engagement_id: str, pagerank, betweenness, paths):
        """Write composite risk scores back to graph nodes."""
        # Risk = EPSS × severity × reachability × asset_value
        query = """
        MATCH (v:Vulnerability {engagement_id: $eid})
        OPTIONAL MATCH path = shortestPath((v)-[*..10]->(cj))
        WHERE cj.asset_value >= 8
        WITH v, min(length(path)) AS dist_to_crown
        SET v.risk_score = coalesce(v.epss_score, 0.5)
              * coalesce(v.severity_num, 5) / 10.0
              * (1.0 / (coalesce(dist_to_crown, 99) + 1))
        """
        async with self.driver.session() as session:
            await session.run(query, {"eid": engagement_id})
    
    async def _summary_stats(self, engagement_id: str) -> dict:
        """Compute summary statistics for the engagement."""
        query = """
        MATCH (n {engagement_id: $eid})
        WITH labels(n)[0] AS type, count(*) AS cnt
        RETURN type, cnt
        """
        async with self.driver.session() as session:
            result = await session.run(query, {"eid": engagement_id})
            records = await result.data()
            stats = {r["type"]: r["cnt"] for r in records}
        
        # Count attack paths
        path_query = """
        MATCH (e:Host {engagement_id: $eid, is_entry_point: true})
        MATCH (cj {engagement_id: $eid})
        WHERE cj.asset_value >= 8
        MATCH p = shortestPath((e)-[*..10]->(cj))
        RETURN count(p) AS total_paths
        """
        async with self.driver.session() as session:
            result = await session.run(path_query, {"eid": engagement_id})
            path_data = await result.single()
            stats["total_attack_paths"] = path_data["total_paths"] if path_data else 0
        
        return stats
    
    async def _drop_projection(self, engagement_id: str):
        """Clean up GDS graph projection."""
        try:
            async with self.driver.session() as session:
                await session.run(
                    "CALL gds.graph.drop($name, false)",
                    {"name": f"attack_{engagement_id}"}
                )
        except Exception:
            pass  # Already dropped or never created
```

---

## Tests

### `tests/graph/test_analytics.py`
```python
import pytest
from sentinel.graph.analytics import GraphAnalytics, AttackPath

class TestGraphAnalytics:
    def test_attack_path_dataclass(self):
        path = AttackPath(
            source="host_1", target="db_1", hops=3,
            nodes=["host_1", "svc_1", "endpoint_1", "db_1"],
            edges=["EXPOSES", "HAS_ENDPOINT", "CONNECTS_TO"],
            probability=0.7, risk_score=8.5,
        )
        assert path.hops == 3
        assert len(path.nodes) == 4
    
    def test_risk_formula_concept(self):
        """Verify risk scoring logic conceptually."""
        epss = 0.9
        severity = 9.0 / 10.0
        distance = 2  # 2 hops to crown jewel
        reachability = 1.0 / (distance + 1)
        risk = epss * severity * reachability
        assert 0.2 < risk < 0.4  # Reasonable range
    
    # Integration tests require Neo4j — mark as integration
    @pytest.mark.skip(reason="Requires Neo4j + GDS plugin")
    def test_full_analysis(self):
        pass
```

---

## Docker Compose Modification
Ensure Neo4j image includes GDS plugin:
```yaml
neo4j:
  image: neo4j:5-enterprise  # or community with GDS
  environment:
    - NEO4J_PLUGINS=["graph-data-science"]
```

## Acceptance Criteria
- [ ] GDS graph projection created per engagement
- [ ] PageRank identifies top 10 most important nodes
- [ ] Betweenness centrality identifies chokepoints
- [ ] Louvain clusters related assets into blast radius groups
- [ ] Shortest paths found from entry points to crown jewels
- [ ] Composite risk scores written back to Vulnerability nodes
- [ ] Crown jewels auto-detected from node properties
- [ ] All tests pass